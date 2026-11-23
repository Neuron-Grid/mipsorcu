use std::{fmt, net::IpAddr, str::FromStr, time::Duration};

use crate::domain::{
    self, CiObservation, CiStatus, ObservedFacts, State, TaskRecord, TrustedPolicy,
};
use crate::mock_github::MockGitHubJournalEntry;
use sha3::{Digest, Sha3_256};
use tokio_postgres::{Client, Config, NoTls, Row, Transaction, config::Host};
use uuid::Uuid;

const MAX_OPERATION_RESULT_BYTES: i32 = 8 * 1024 * 1024;
const ISSUE_CLOSE_OPERATION: &str = "github_issue_close";

#[derive(Debug)]
pub enum StoreError {
    Database(tokio_postgres::Error),
    InvalidRecord,
    LeaseOccupied,
    LeaseLost,
    TaskMissing,
    OperationConflict,
    InvalidInput,
    RecoveryRejected,
    HumanActionPending,
}

impl From<tokio_postgres::Error> for StoreError {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lease {
    pub task_id: Uuid,
    pub owner: String,
    pub fencing_token: i64,
}

#[derive(Clone, Eq, PartialEq)]
pub enum OperationStatus {
    NewlyPrepared,
    Ambiguous,
    Completed {
        result: serde_json::Value,
        fencing_token: i64,
    },
}

impl fmt::Debug for OperationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NewlyPrepared => f.write_str("NewlyPrepared"),
            Self::Ambiguous => f.write_str("Ambiguous"),
            Self::Completed { fencing_token, .. } => f
                .debug_struct("Completed")
                .field("result", &"[REDACTED]")
                .field("fencing_token", fencing_token)
                .finish(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NewTask {
    pub task_id: Uuid,
    pub repository: String,
    pub issue_number: i64,
    pub base_sha: String,
    pub max_attempts: i32,
    pub execution_timeout: Duration,
    pub model_budget: i64,
    pub idempotency_key: Uuid,
}

/// Implemented by the trusted supervisor, never by the task database.
/// The supervisor must independently prove that the prior worker and every
/// process it started have stopped. Returned object contents are not persisted.
pub trait RecoveryVerifier: Send + Sync {
    fn verify_stopped(
        &self,
        task_id: Uuid,
        old_owner: &str,
        expired_fencing_token: i64,
    ) -> Option<serde_json::Value>;
}

pub struct TaskStore {
    client: Client,
}

/// Deterministic task-scoped key for the one post-merge Issue-close attempt.
/// Possession of this key or its database row does not authorize a GitHub write.
pub fn issue_close_operation_key(task_id: Uuid) -> Uuid {
    let mut digest = Sha3_256::new();
    digest.update(b"mipsorcu:github-issue-close:v1:");
    digest.update(task_id.as_bytes());
    let hash = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn validate_issue_close_evidence(
    task: &TaskRecord,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
) -> Result<(), StoreError> {
    if policy.base_ref != "develop" || !facts.pr_merged {
        return Err(StoreError::InvalidRecord);
    }
    let mut completed = task.clone();
    domain::transition_from(task, &mut completed, State::Completed, policy, facts)
        .map_err(|_| StoreError::InvalidRecord)
}

fn issue_close_request_hash(
    task: &TaskRecord,
    repository: &str,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
) -> Result<[u8; 32], StoreError> {
    let issue_number = i64::try_from(task.issue_number).map_err(|_| StoreError::InvalidRecord)?;
    let pull_number = i64::try_from(facts.pr_number.ok_or(StoreError::InvalidRecord)?)
        .map_err(|_| StoreError::InvalidRecord)?;
    let issue_number_bytes = issue_number.to_be_bytes();
    let pull_number_bytes = pull_number.to_be_bytes();
    let merge_sha = facts
        .merge_commit_sha
        .as_deref()
        .ok_or(StoreError::InvalidRecord)?;
    let head_sha = task.head_sha.as_deref().ok_or(StoreError::InvalidRecord)?;
    let mut digest = Sha3_256::new();
    for field in [
        b"mipsorcu:github-issue-close-request:v1".as_slice(),
        task.task_id.as_bytes(),
        repository.as_bytes(),
        &issue_number_bytes,
        &pull_number_bytes,
        policy.base_ref.as_bytes(),
        policy.base_sha.as_bytes(),
        head_sha.as_bytes(),
        facts.head_sha.as_bytes(),
        facts.policy_base_ref.as_bytes(),
        facts.policy_base_sha.as_bytes(),
        facts
            .pr_head_sha
            .as_deref()
            .ok_or(StoreError::InvalidRecord)?
            .as_bytes(),
        facts
            .pr_base_ref
            .as_deref()
            .ok_or(StoreError::InvalidRecord)?
            .as_bytes(),
        merge_sha.as_bytes(),
        &[u8::from(facts.base_contains_merge_commit)],
    ] {
        let length = u64::try_from(field.len()).map_err(|_| StoreError::InvalidRecord)?;
        digest.update(length.to_be_bytes());
        digest.update(field);
    }
    Ok(digest.finalize().into())
}

impl TaskStore {
    /// Uses NoTls only for Unix sockets or literal loopback addresses; hostnames are never resolved.
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let config = Config::from_str(database_url).map_err(|_| StoreError::InvalidInput)?;
        validate_no_tls_target(&config)?;
        let (client, connection) = config.connect(NoTls).await.map_err(StoreError::Database)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self { client })
    }

    pub async fn create(&self, task: &NewTask) -> Result<Uuid, StoreError> {
        if task.repository.is_empty()
            || task.issue_number <= 0
            || task.max_attempts <= 0
            || task.execution_timeout.is_zero()
            || task.execution_timeout.subsec_nanos() != 0
            || task.model_budget <= 0
            || !is_sha(&task.base_sha)
        {
            return Err(StoreError::InvalidInput);
        }
        let seconds = i64::try_from(task.execution_timeout.as_secs())
            .map_err(|_| StoreError::InvalidInput)?;
        if seconds == 0 {
            return Err(StoreError::InvalidInput);
        }
        let row = self.client.query_opt(
            "INSERT INTO orchestrator.tasks (id, repository, issue_number, base_sha, max_attempts, execution_timeout_seconds, execution_deadline, model_budget, idempotency_key) VALUES ($1,$2,$3,$4,$5,$6,NULL,$7,$8) ON CONFLICT (idempotency_key) DO NOTHING RETURNING id",
            &[&task.task_id, &task.repository, &task.issue_number, &task.base_sha.to_ascii_lowercase(), &task.max_attempts, &seconds, &task.model_budget, &task.idempotency_key],
        ).await?;
        if let Some(row) = row {
            return Ok(row.get(0));
        }
        let existing = self.client.query_opt("SELECT id, repository, issue_number, base_sha, max_attempts, execution_timeout_seconds, model_budget FROM orchestrator.tasks WHERE idempotency_key = $1", &[&task.idempotency_key]).await?.ok_or(StoreError::OperationConflict)?;
        if existing.get::<_, Uuid>(0) != task.task_id
            || existing.get::<_, String>(1) != task.repository
            || existing.get::<_, i64>(2) != task.issue_number
            || existing.get::<_, String>(3) != task.base_sha.to_ascii_lowercase()
            || existing.get::<_, i32>(4) != task.max_attempts
            || existing.get::<_, i64>(5) != seconds
            || existing.get::<_, i64>(6) != task.model_budget
        {
            return Err(StoreError::OperationConflict);
        }
        Ok(task.task_id)
    }

    /// Binds an immutable mock-runtime configuration before execution starts.
    pub async fn bind_mock_runtime_config(
        &mut self,
        task_id: Uuid,
        fingerprint: &str,
    ) -> Result<(), StoreError> {
        if !is_fingerprint(fingerprint) {
            return Err(StoreError::InvalidInput);
        }
        let tx = self.client.transaction().await?;
        let row = tx
            .query_opt(
                "SELECT status::text, mock_runtime_fingerprint FROM orchestrator.tasks WHERE id=$1 FOR UPDATE",
                &[&task_id],
            )
            .await?
            .ok_or(StoreError::TaskMissing)?;
        let state: String = row.get(0);
        let current: Option<String> = row.get(1);
        match current.as_deref() {
            Some(existing) if existing == fingerprint => {}
            Some(_) => return Err(StoreError::OperationConflict),
            None if state == "queued" => {
                let changed = tx
                    .execute(
                        "UPDATE orchestrator.tasks SET mock_runtime_fingerprint=$2, updated_at=clock_timestamp() WHERE id=$1 AND status='queued' AND mock_runtime_fingerprint IS NULL",
                        &[&task_id, &fingerprint],
                    )
                    .await?;
                if changed != 1 {
                    return Err(StoreError::OperationConflict);
                }
            }
            None => return Err(StoreError::OperationConflict),
        }
        tx.commit().await?;
        Ok(())
    }

    /// Refuses mock execution unless the active connection is bound to a disposable test database.
    pub async fn assert_mock_isolated_database(&self) -> Result<(), StoreError> {
        let row = self
            .client
            .query_opt(
                "SELECT d.datname, r.rolname, r.rolsuper FROM pg_database AS d JOIN pg_roles AS r ON r.rolname = current_user WHERE d.datname = current_database()",
                &[],
            )
            .await?
            .ok_or(StoreError::InvalidInput)?;
        let database: String = row.try_get(0).map_err(|_| StoreError::InvalidInput)?;
        let role: String = row.try_get(1).map_err(|_| StoreError::InvalidInput)?;
        let is_superuser: bool = row.try_get(2).map_err(|_| StoreError::InvalidInput)?;
        if !database.starts_with("orchestrator_test_")
            || role != "orchestrator_test"
            || is_superuser
        {
            return Err(StoreError::InvalidInput);
        }
        Ok(())
    }

    /// Reads a snapshot only. Callers must revalidate policy and GitHub facts before acting.
    pub async fn get(&self, task_id: Uuid) -> Result<TaskRecord, StoreError> {
        let row = self.client.query_opt("SELECT id, issue_number, base_sha, head_sha, status::text, repair_count, issue_assignee, COALESCE((validation_result->>'passed')::boolean, false), pr_number, checkpoint, COALESCE(extract(epoch from clock_timestamp() - execution_started_at)::bigint, 0), model_usage, resume_state::text, implementer, reviewer, session_id, mock_github_journal, repair_count, mock_runtime_fingerprint, max_attempts, model_budget FROM orchestrator.tasks WHERE id = $1", &[&task_id]).await?.ok_or(StoreError::TaskMissing)?;
        decode_task(&row)
    }

    /// Returns the persisted CI snapshot for inspection only; callers must obtain fresh evidence before acting.
    pub async fn get_ci_observation(
        &self,
        task_id: Uuid,
    ) -> Result<Option<CiObservation>, StoreError> {
        let row = self
            .client
            .query_opt(
                "SELECT COALESCE(octet_length(validation_result::text),0) > 16384, CASE WHEN COALESCE(octet_length(validation_result::text),0) <= 16384 THEN validation_result END FROM orchestrator.tasks WHERE id=$1",
                &[&task_id],
            )
            .await?
            .ok_or(StoreError::TaskMissing)?;
        let oversized: bool = row.get(0);
        if oversized {
            return Err(StoreError::InvalidRecord);
        }
        let validation: Option<serde_json::Value> = row.get(1);
        match validation.as_ref() {
            Some(validation) => parse_ci_observation(validation),
            None => Ok(None),
        }
    }

    /// Claims only an unleased queued task. Expired leases remain occupied pending verified recovery.
    pub async fn claim(
        &mut self,
        task_id: Uuid,
        owner: &str,
        ttl: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        if owner.is_empty() {
            return Err(StoreError::InvalidInput);
        }
        let seconds = ttl_seconds(ttl)?;
        let tx = self.client.transaction().await?;
        let current = tx
            .query_one(
                "SELECT task_id FROM orchestrator.execution_lease WHERE singleton FOR UPDATE",
                &[],
            )
            .await?;
        let active: Option<Uuid> = current.get(0);
        if active.is_some() {
            return Err(StoreError::LeaseOccupied);
        }
        let task_row = tx.query_opt("SELECT id, issue_number, base_sha, head_sha, status::text, repair_count, issue_assignee, COALESCE((validation_result->>'passed')::boolean, false), pr_number, checkpoint, COALESCE(extract(epoch from clock_timestamp() - execution_started_at)::bigint, 0), model_usage, max_attempts, execution_deadline IS NULL OR execution_deadline > clock_timestamp(), resume_state::text, execution_timeout_seconds, implementer, reviewer, session_id, mock_github_journal, repair_count, mock_runtime_fingerprint, max_attempts, model_budget FROM orchestrator.tasks WHERE id = $1 FOR UPDATE", &[&task_id]).await?.ok_or(StoreError::TaskMissing)?;
        let mut task = decode_task(&task_row)?;
        let attempts = task_row.get::<_, i32>(5);
        let max_attempts: i32 = task_row.get(12);
        let in_time: bool = task_row.get(13);
        let timeout_seconds: i64 = task_row.get(15);
        if task.state != State::Queued || !in_time || attempts > max_attempts {
            return Err(StoreError::InvalidRecord);
        }
        task.attempts = u32::try_from(attempts).map_err(|_| StoreError::InvalidRecord)?;
        domain::transition(&mut task, State::Planning, policy, facts)
            .map_err(|_| StoreError::InvalidRecord)?;
        let token: i64 = tx
            .query_one("SELECT nextval('orchestrator.fencing_token_seq')", &[])
            .await?
            .get(0);
        tx.execute("UPDATE orchestrator.execution_lease SET task_id=$1, owner=$2, fencing_token=$3, expires_at=clock_timestamp() + make_interval(secs => $4::bigint::double precision) WHERE singleton", &[&task_id, &owner, &token, &seconds]).await?;
        let changed = tx.execute("WITH start_time AS (SELECT COALESCE(execution_started_at,clock_timestamp()) AS started_at FROM orchestrator.tasks WHERE id=$1) UPDATE orchestrator.tasks SET status='planning', attempt_count=GREATEST(attempt_count,1), assigned_worker=$2, execution_started_at=start_time.started_at, execution_deadline=COALESCE(execution_deadline,start_time.started_at + make_interval(secs => $3::bigint::double precision)), updated_at=clock_timestamp() FROM start_time WHERE id=$1 AND status='queued'", &[&task_id, &owner, &timeout_seconds]).await?;
        if changed != 1 {
            return Err(StoreError::InvalidRecord);
        }
        tx.commit().await?;
        Ok(Lease {
            task_id,
            owner: owner.to_owned(),
            fencing_token: token,
        })
    }

    /// Claims a handoff for verification; acquiring this lease does not complete the task.
    pub async fn claim_handoff(
        &mut self,
        task_id: Uuid,
        owner: &str,
        ttl: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        if owner.is_empty() {
            return Err(StoreError::InvalidInput);
        }
        let seconds = ttl_seconds(ttl)?;
        let tx = self.client.transaction().await?;
        let current = tx
            .query_one(
                "SELECT task_id FROM orchestrator.execution_lease WHERE singleton FOR UPDATE",
                &[],
            )
            .await?;
        let active: Option<Uuid> = current.get(0);
        if active.is_some() {
            return Err(StoreError::LeaseOccupied);
        }
        let task = tx.query_opt("SELECT id, issue_number, base_sha, head_sha, status::text, repair_count, issue_assignee, COALESCE((validation_result->>'passed')::boolean, false), pr_number, checkpoint, COALESCE(extract(epoch from clock_timestamp() - execution_started_at)::bigint, 0), model_usage, resume_state::text, implementer, reviewer, session_id, mock_github_journal, repair_count, mock_runtime_fingerprint, max_attempts, model_budget FROM orchestrator.tasks WHERE id=$1 FOR UPDATE", &[&task_id]).await?.ok_or(StoreError::TaskMissing).and_then(|row| decode_task(&row))?;
        match task.state {
            State::Merging if facts.pr_merged => {
                let mut completed = task.clone();
                domain::transition(&mut completed, State::Completed, policy, facts)
                    .map_err(|_| StoreError::InvalidRecord)?;
            }
            State::Merging => {}
            State::Completed => domain::validate_completed(&task, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?,
            _ => return Err(StoreError::InvalidRecord),
        }
        let token: i64 = tx
            .query_one("SELECT nextval('orchestrator.fencing_token_seq')", &[])
            .await?
            .get(0);
        tx.execute("UPDATE orchestrator.execution_lease SET task_id=$1, owner=$2, fencing_token=$3, expires_at=clock_timestamp() + make_interval(secs => $4::bigint::double precision) WHERE singleton", &[&task_id,&owner,&token,&seconds]).await?;
        persist_recovered(&tx, &task, owner, facts).await?;
        tx.commit().await?;
        Ok(Lease {
            task_id,
            owner: owner.to_owned(),
            fencing_token: token,
        })
    }

    /// Explicitly resumes the same paused/blocked task after current policy and GitHub checks.
    pub async fn claim_resume(
        &mut self,
        task_id: Uuid,
        owner: &str,
        ttl: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        if owner.is_empty() {
            return Err(StoreError::InvalidInput);
        }
        let seconds = ttl_seconds(ttl)?;
        let tx = self.client.transaction().await?;
        let current = tx
            .query_one(
                "SELECT task_id FROM orchestrator.execution_lease WHERE singleton FOR UPDATE",
                &[],
            )
            .await?;
        let active: Option<Uuid> = current.get(0);
        if active.is_some() {
            return Err(StoreError::LeaseOccupied);
        }
        let mut task = tx.query_opt("SELECT id, issue_number, base_sha, head_sha, status::text, repair_count, issue_assignee, COALESCE((validation_result->>'passed')::boolean, false), pr_number, checkpoint, COALESCE(extract(epoch from clock_timestamp() - execution_started_at)::bigint, 0), model_usage, resume_state::text, implementer, reviewer, session_id, mock_github_journal, repair_count, mock_runtime_fingerprint, max_attempts, model_budget FROM orchestrator.tasks WHERE id=$1 FOR UPDATE", &[&task_id]).await?.ok_or(StoreError::TaskMissing).and_then(|row| decode_task(&row))?;
        if !matches!(task.state, State::Paused | State::Blocked) {
            return Err(StoreError::InvalidRecord);
        }
        let resume = task.checkpoint.ok_or(StoreError::InvalidRecord)?;
        if resume == State::Merging && facts.pr_merged {
            task.state = State::Merging;
            task.checkpoint = None;
            task.validate().map_err(|_| StoreError::InvalidRecord)?;
            let mut completed = task.clone();
            domain::transition(&mut completed, State::Completed, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?;
        } else {
            domain::transition(&mut task, resume, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?;
        }
        let token: i64 = tx
            .query_one("SELECT nextval('orchestrator.fencing_token_seq')", &[])
            .await?
            .get(0);
        tx.execute("UPDATE orchestrator.execution_lease SET task_id=$1, owner=$2, fencing_token=$3, expires_at=clock_timestamp() + make_interval(secs => $4::bigint::double precision) WHERE singleton", &[&task_id,&owner,&token,&seconds]).await?;
        persist_recovered(&tx, &task, owner, facts).await?;
        tx.commit().await?;
        Ok(Lease {
            task_id,
            owner: owner.to_owned(),
            fencing_token: token,
        })
    }

    pub async fn renew(&self, lease: &Lease, ttl: Duration) -> Result<(), StoreError> {
        let seconds = ttl_seconds(ttl)?;
        let changed = self.client.execute("UPDATE orchestrator.execution_lease SET expires_at=clock_timestamp() + make_interval(secs => $4::bigint::double precision) WHERE singleton AND task_id=$1 AND owner=$2 AND fencing_token=$3 AND expires_at > clock_timestamp() AND EXISTS (SELECT 1 FROM orchestrator.tasks WHERE id=$1 AND execution_deadline > clock_timestamp())", &[&lease.task_id, &lease.owner, &lease.fencing_token, &seconds]).await?;
        if changed == 1 {
            Ok(())
        } else {
            Err(StoreError::LeaseLost)
        }
    }

    /// Keeps the fenced lease alive only while checking validated merged evidence
    /// for a terminal handoff. Work leases remain deadline-bound.
    pub async fn renew_handoff_verification(
        &mut self,
        lease: &Lease,
        ttl: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<(), StoreError> {
        let seconds = ttl_seconds(ttl)?;
        let tx = self.client.transaction().await?;
        require_live_lease(&tx, lease).await?;
        let row = tx.query_opt("SELECT id, issue_number, base_sha, head_sha, status::text, repair_count, issue_assignee, COALESCE((validation_result->>'passed')::boolean, false), pr_number, checkpoint, COALESCE(extract(epoch from clock_timestamp() - execution_started_at)::bigint, 0), model_usage, resume_state::text, implementer, reviewer, session_id, mock_github_journal, repair_count, mock_runtime_fingerprint, max_attempts, model_budget FROM orchestrator.tasks WHERE id=$1 FOR UPDATE", &[&lease.task_id]).await?.ok_or(StoreError::TaskMissing)?;
        let task = decode_task(&row)?;
        match task.state {
            State::Merging => {
                let mut completed = task.clone();
                domain::transition_from(&task, &mut completed, State::Completed, policy, facts)
                    .map_err(|_| StoreError::InvalidRecord)?;
            }
            State::Completed => domain::validate_completed(&task, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?,
            _ => return Err(StoreError::InvalidRecord),
        }
        let changed = tx.execute("UPDATE orchestrator.execution_lease SET expires_at=clock_timestamp() + make_interval(secs => $4::bigint::double precision) WHERE singleton AND task_id=$1 AND owner=$2 AND fencing_token=$3 AND expires_at > clock_timestamp()", &[&lease.task_id, &lease.owner, &lease.fencing_token, &seconds]).await?;
        if changed == 1 {
            tx.commit().await?;
            Ok(())
        } else {
            Err(StoreError::LeaseLost)
        }
    }

    pub async fn work_deadline_expired(&self, lease: &Lease) -> Result<bool, StoreError> {
        let row = self.client.query_opt("SELECT t.execution_deadline <= clock_timestamp() FROM orchestrator.tasks AS t JOIN orchestrator.execution_lease AS l ON l.task_id=t.id WHERE t.id=$1 AND l.owner=$2 AND l.fencing_token=$3 AND l.expires_at > clock_timestamp()", &[&lease.task_id, &lease.owner, &lease.fencing_token]).await?.ok_or(StoreError::LeaseLost)?;
        row.try_get::<_, Option<bool>>(0)?
            .ok_or(StoreError::InvalidRecord)
    }

    /// Releases an expired BLOCKED task's global lease after independently verifying that its
    /// prior worker tree stopped. The task checkpoint and operation rows remain untouched.
    pub async fn release_expired_blocked_lease(
        &mut self,
        prior_lease: &Lease,
        verifier: &dyn RecoveryVerifier,
    ) -> Result<(), StoreError> {
        let observed = self.client.query_one(
            "SELECT task_id,owner,fencing_token,COALESCE(expires_at <= clock_timestamp(), false) FROM orchestrator.execution_lease WHERE singleton",
            &[],
        ).await?;
        let observed_task: Option<Uuid> = observed.get(0);
        let old_owner: Option<String> = observed.get(1);
        let observed_generation: i64 = observed.get(2);
        let expired: bool = observed.get(3);
        if observed_task != Some(prior_lease.task_id)
            || old_owner.as_deref() != Some(prior_lease.owner.as_str())
            || observed_generation != prior_lease.fencing_token
            || !expired
        {
            return Err(StoreError::LeaseLost);
        }
        let old_owner = old_owner.ok_or(StoreError::InvalidRecord)?;
        verifier
            .verify_stopped(prior_lease.task_id, &old_owner, observed_generation)
            .filter(serde_json::Value::is_object)
            .ok_or(StoreError::RecoveryRejected)?;

        let evidence = serde_json::json!({"supervisor_verified_worker_tree_stopped": true});
        let tx = self.client.transaction().await?;
        let lease_row = tx.query_one(
            "SELECT task_id,owner,fencing_token,COALESCE(expires_at <= clock_timestamp(), false) FROM orchestrator.execution_lease WHERE singleton FOR UPDATE",
            &[],
        ).await?;
        let locked_task: Option<Uuid> = lease_row.get(0);
        let locked_owner: Option<String> = lease_row.get(1);
        let locked_generation: i64 = lease_row.get(2);
        let locked_expired: bool = lease_row.get(3);
        if locked_task != Some(prior_lease.task_id)
            || locked_owner.as_deref() != Some(old_owner.as_str())
            || locked_generation != observed_generation
            || !locked_expired
        {
            return Err(StoreError::LeaseLost);
        }

        let task_row = tx.query_opt(
            "SELECT id, issue_number, base_sha, head_sha, status::text, repair_count, issue_assignee, COALESCE((validation_result->>'passed')::boolean, false), pr_number, checkpoint, COALESCE(extract(epoch from clock_timestamp() - execution_started_at)::bigint, 0), model_usage, resume_state::text, implementer, reviewer, session_id, mock_github_journal, repair_count, mock_runtime_fingerprint, max_attempts, model_budget FROM orchestrator.tasks WHERE id=$1 FOR UPDATE",
            &[&prior_lease.task_id],
        ).await?.ok_or(StoreError::TaskMissing)?;
        let task = decode_task(&task_row)?;
        if task.state != State::Blocked || task.checkpoint.is_none() {
            return Err(StoreError::InvalidRecord);
        }

        let confirmation_id = Uuid::new_v4();
        tx.execute(
            "INSERT INTO orchestrator.recovery_confirmations(confirmation_id,task_id,expired_fencing_token,confirmed_by,evidence) VALUES($1,$2,$3,$4,$5)",
            &[&confirmation_id, &prior_lease.task_id, &observed_generation, &old_owner, &evidence],
        ).await?;
        let changed = tx.execute(
            "UPDATE orchestrator.execution_lease SET task_id=NULL, owner=NULL, expires_at=NULL WHERE singleton AND task_id=$1 AND owner=$2 AND fencing_token=$3 AND expires_at <= clock_timestamp()",
            &[&prior_lease.task_id, &old_owner, &observed_generation],
        ).await?;
        if changed != 1 {
            return Err(StoreError::LeaseLost);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Reacquires the same expired task only after an independently verified supervisor proof.
    /// Unresolved operation rows remain ambiguous and cannot authorize replay.
    pub async fn recover(
        &mut self,
        task_id: Uuid,
        owner: &str,
        ttl: Duration,
        verifier: &dyn RecoveryVerifier,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        if owner.is_empty() {
            return Err(StoreError::InvalidInput);
        }
        let seconds = ttl_seconds(ttl)?;
        let observed = self.client.query_one("SELECT task_id,owner,fencing_token,COALESCE(expires_at <= clock_timestamp(), false) FROM orchestrator.execution_lease WHERE singleton", &[]).await?;
        let observed_task: Option<Uuid> = observed.get(0);
        let old_owner: Option<String> = observed.get(1);
        let expired_generation: i64 = observed.get(2);
        let expired: bool = observed.get(3);
        if observed_task != Some(task_id) || !expired {
            return Err(StoreError::LeaseLost);
        }
        let old_owner = old_owner.ok_or(StoreError::InvalidRecord)?;
        verifier
            .verify_stopped(task_id, &old_owner, expired_generation)
            .filter(serde_json::Value::is_object)
            .ok_or(StoreError::RecoveryRejected)?;
        let evidence = serde_json::json!({"supervisor_verified_worker_tree_stopped": true});
        let tx = self.client.transaction().await?;
        let lease_row = tx.query_one("SELECT task_id,owner,fencing_token,COALESCE(expires_at <= clock_timestamp(), false) FROM orchestrator.execution_lease WHERE singleton FOR UPDATE", &[]).await?;
        let active: Option<Uuid> = lease_row.get(0);
        let locked_owner: Option<String> = lease_row.get(1);
        let locked_generation: i64 = lease_row.get(2);
        let locked_expired: bool = lease_row.get(3);
        if active != Some(task_id)
            || locked_owner.as_deref() != Some(old_owner.as_str())
            || locked_generation != expired_generation
            || !locked_expired
        {
            return Err(StoreError::LeaseLost);
        }
        let task_row = tx.query_opt("SELECT id, issue_number, base_sha, head_sha, status::text, repair_count, issue_assignee, COALESCE((validation_result->>'passed')::boolean, false), pr_number, checkpoint, COALESCE(extract(epoch from clock_timestamp() - execution_started_at)::bigint, 0), model_usage, resume_state::text, implementer, reviewer, session_id, mock_github_journal, repair_count, mock_runtime_fingerprint, max_attempts, model_budget FROM orchestrator.tasks WHERE id=$1 FOR UPDATE", &[&task_id]).await?.ok_or(StoreError::TaskMissing)?;
        let mut task = decode_task(&task_row)?;
        if matches!(
            task.state,
            State::Queued | State::Completed | State::Paused | State::Blocked | State::Failed
        ) {
            return Err(StoreError::InvalidRecord);
        }
        if task.state == State::Merging && facts.pr_merged {
            // A human may merge after the worker stopped; completion evidence permits a closed issue.
            let mut completed = task.clone();
            domain::transition(&mut completed, State::Completed, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?;
        } else {
            let checkpoint_state = task.state;
            domain::transition(&mut task, State::Blocked, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?;
            let resume = task.checkpoint.ok_or(StoreError::InvalidRecord)?;
            if resume != checkpoint_state {
                return Err(StoreError::InvalidRecord);
            }
            domain::transition(&mut task, resume, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?;
        }
        let confirmation_id = Uuid::new_v4();
        tx.execute("INSERT INTO orchestrator.recovery_confirmations(confirmation_id,task_id,expired_fencing_token,confirmed_by,evidence) VALUES($1,$2,$3,$4,$5)", &[&confirmation_id,&task_id,&expired_generation,&old_owner,&evidence]).await?;
        let token: i64 = tx
            .query_one("SELECT nextval('orchestrator.fencing_token_seq')", &[])
            .await?
            .get(0);
        let changed = tx.execute("UPDATE orchestrator.execution_lease SET owner=$2, fencing_token=$3, expires_at=clock_timestamp() + make_interval(secs => $4::bigint::double precision) WHERE singleton AND task_id=$1 AND fencing_token=$5 AND expires_at <= clock_timestamp()", &[&task_id,&owner,&token,&seconds,&expired_generation]).await?;
        if changed != 1 {
            return Err(StoreError::LeaseLost);
        }
        persist_recovered(&tx, &task, owner, facts).await?;
        tx.commit().await?;
        Ok(Lease {
            task_id,
            owner: owner.to_owned(),
            fencing_token: token,
        })
    }

    /// Stores a caller-validated transition with compare-and-swap on state and active lease.
    pub async fn save(
        &mut self,
        lease: &Lease,
        expected: State,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<(), StoreError> {
        task.validate().map_err(|_| StoreError::InvalidRecord)?;
        let task_id = Uuid::parse_str(&task.task_id).map_err(|_| StoreError::InvalidRecord)?;
        if task_id != lease.task_id {
            return Err(StoreError::InvalidRecord);
        }
        let status = state_name(task.state);
        let head = task.head_sha.as_ref();
        let validation = validation_patch(task, facts)?;
        let checkpoint = task
            .checkpoint
            .map(|state| serde_json::json!({"state": state_name(state)}));
        let expected_name = state_name(expected);
        let tx = self.client.transaction().await?;
        if matches!(task.state, State::Paused | State::Blocked | State::Failed) {
            require_live_lease(&tx, lease).await?;
        } else {
            require_live_work_lease(&tx, lease).await?;
        }
        let old_row = tx.query_opt("SELECT id, issue_number, base_sha, head_sha, status::text, repair_count, issue_assignee, COALESCE((validation_result->>'passed')::boolean, false), pr_number, checkpoint, COALESCE(extract(epoch from clock_timestamp() - execution_started_at)::bigint, 0), model_usage, resume_state::text, implementer, reviewer, session_id, mock_github_journal, repair_count, mock_runtime_fingerprint, max_attempts, model_budget FROM orchestrator.tasks WHERE id=$1 FOR UPDATE", &[&task_id]).await?.ok_or(StoreError::TaskMissing)?;
        let old = decode_task(&old_row)?;
        if old.state != expected {
            return Err(StoreError::InvalidRecord);
        }
        validate_existing_validation(&tx, task_id).await?;
        let mut proposed = task.clone();
        proposed.elapsed = old.elapsed;
        domain::transition_from(&old, &mut proposed, task.state, policy, facts)
            .map_err(|_| StoreError::InvalidRecord)?;
        let mut persisted = task.clone();
        persisted.elapsed = old.elapsed;
        if proposed != persisted {
            return Err(StoreError::InvalidRecord);
        }
        let journal = task
            .mock_github_journal
            .as_ref()
            .map(serde_json::Value::to_owned);
        if journal
            .as_ref()
            .is_some_and(|value| !valid_mock_journal(value))
        {
            return Err(StoreError::InvalidRecord);
        }
        let changed = tx.execute("UPDATE orchestrator.tasks SET status=$2::text::orchestrator.task_state, head_sha=$3, repair_count=$4, issue_assignee=$5, validation_result=COALESCE(validation_result, '{}'::jsonb) || $6::jsonb, pr_number=$7, checkpoint=$8, resume_state=CASE WHEN $2::text IN ('paused','blocked','failed') THEN ($9::text)::orchestrator.task_state ELSE NULL END, model_usage=$10, implementer=$11, reviewer=$12, session_id=$13, mock_github_journal=$14, mock_runtime_fingerprint=$15, updated_at=clock_timestamp() WHERE id=$1 AND status=$16::text::orchestrator.task_state", &[&task_id, &status, &head, &(i32::try_from(task.attempts).map_err(|_| StoreError::InvalidRecord)?), &task.assignee, &validation, &task.pull_request.map(i64::try_from).transpose().map_err(|_| StoreError::InvalidRecord)?, &checkpoint, &task.checkpoint.map(state_name), &i64::try_from(task.model_tokens).map_err(|_| StoreError::InvalidRecord)?, &task.implementer, &task.reviewer, &task.session_id, &journal, &task.mock_runtime_fingerprint, &expected_name]).await?;
        if changed != 1 {
            return Err(StoreError::InvalidRecord);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Persists only a verified human-merge handoff. This deliberately bypasses
    /// the execution deadline for this terminal transition alone.
    pub async fn save_handoff_completed(
        &mut self,
        lease: &Lease,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<(), StoreError> {
        if task.state != State::Completed || !facts.pr_merged || facts.issue_open {
            return Err(StoreError::InvalidRecord);
        }
        task.validate().map_err(|_| StoreError::InvalidRecord)?;
        let task_id = Uuid::parse_str(&task.task_id).map_err(|_| StoreError::InvalidRecord)?;
        if task_id != lease.task_id {
            return Err(StoreError::InvalidRecord);
        }
        let tx = self.client.transaction().await?;
        require_live_lease(&tx, lease).await?;
        let old_row = tx.query_opt("SELECT id, issue_number, base_sha, head_sha, status::text, repair_count, issue_assignee, COALESCE((validation_result->>'passed')::boolean, false), pr_number, checkpoint, COALESCE(extract(epoch from clock_timestamp() - execution_started_at)::bigint, 0), model_usage, resume_state::text, implementer, reviewer, session_id, mock_github_journal, repair_count, mock_runtime_fingerprint, max_attempts, model_budget FROM orchestrator.tasks WHERE id=$1 FOR UPDATE", &[&task_id]).await?.ok_or(StoreError::TaskMissing)?;
        let old = decode_task(&old_row)?;
        if old.state != State::Merging {
            return Err(StoreError::InvalidRecord);
        }
        validate_existing_validation(&tx, task_id).await?;
        let mut proposed = task.clone();
        proposed.elapsed = old.elapsed;
        domain::transition_from(&old, &mut proposed, State::Completed, policy, facts)
            .map_err(|_| StoreError::InvalidRecord)?;
        let mut persisted = task.clone();
        persisted.elapsed = old.elapsed;
        if proposed != persisted {
            return Err(StoreError::InvalidRecord);
        }
        let validation = validation_patch(task, facts)?;
        let changed = tx.execute("UPDATE orchestrator.tasks SET status='completed', validation_result=COALESCE(validation_result, '{}'::jsonb) || $2::jsonb, updated_at=clock_timestamp() WHERE id=$1 AND status='merging'", &[&task_id, &validation]).await?;
        if changed != 1 {
            return Err(StoreError::InvalidRecord);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Records an operation before its external effect. A replayed prepared row is ambiguous,
    /// so callers must inspect the external system and must not issue the effect again.
    pub async fn prepare_operation(
        &mut self,
        lease: &Lease,
        key: Uuid,
        operation: &str,
        request_hash: &[u8; 32],
    ) -> Result<OperationStatus, StoreError> {
        if operation.is_empty() || operation == ISSUE_CLOSE_OPERATION {
            return Err(StoreError::InvalidInput);
        }
        let tx = self.client.transaction().await?;
        require_live_work_lease(&tx, lease).await?;
        let inserted = tx.execute("INSERT INTO orchestrator.task_operations(operation_key,task_id,fencing_token,operation,request_hash,result) VALUES($1,$2,$3,$4,$5,NULL) ON CONFLICT(operation_key) DO NOTHING", &[&key,&lease.task_id,&lease.fencing_token,&operation,&&request_hash[..]]).await? == 1;
        if inserted {
            tx.commit().await?;
            return Ok(OperationStatus::NewlyPrepared);
        }
        let row = tx.query_opt("SELECT task_id,fencing_token,operation,request_hash,result IS NOT NULL,COALESCE(octet_length(result::text),0) > $2,CASE WHEN result IS NULL OR octet_length(result::text) <= $2 THEN result END FROM orchestrator.task_operations WHERE operation_key=$1 FOR UPDATE", &[&key,&MAX_OPERATION_RESULT_BYTES]).await?.ok_or(StoreError::OperationConflict)?;
        let stored_hash: Vec<u8> = row.get(3);
        if row.get::<_, Uuid>(0) != lease.task_id
            || row.get::<_, String>(2) != operation
            || stored_hash.as_slice() != request_hash
        {
            return Err(StoreError::OperationConflict);
        }
        let fencing_token: i64 = row.get(1);
        if fencing_token <= 0 {
            return Err(StoreError::InvalidRecord);
        }
        if row.get::<_, bool>(5) {
            return Err(StoreError::InvalidRecord);
        }
        let has_result: bool = row.get(4);
        let result: Option<serde_json::Value> = row.get(6);
        tx.commit().await?;
        match (has_result, result) {
            (false, None) => Ok(OperationStatus::Ambiguous),
            (true, Some(result)) => Ok(OperationStatus::Completed {
                result,
                fencing_token,
            }),
            _ => Err(StoreError::InvalidRecord),
        }
    }

    pub async fn complete_operation(
        &mut self,
        lease: &Lease,
        key: Uuid,
        result: &serde_json::Value,
        model_tokens: u64,
    ) -> Result<(), StoreError> {
        if !result.is_object() {
            return Err(StoreError::InvalidInput);
        }
        let tx = self.client.transaction().await?;
        require_live_work_lease(&tx, lease).await?;
        let within_result_limit: bool = tx
            .query_one(
                "SELECT octet_length($1::jsonb::text) <= $2",
                &[result, &MAX_OPERATION_RESULT_BYTES],
            )
            .await?
            .get(0);
        if !within_result_limit {
            return Err(StoreError::InvalidInput);
        }
        let row = tx.query_opt("SELECT task_id,fencing_token,operation,result IS NOT NULL FROM orchestrator.task_operations WHERE operation_key=$1 FOR UPDATE", &[&key]).await?.ok_or(StoreError::OperationConflict)?;
        if row.get::<_, Uuid>(0) != lease.task_id
            || row.get::<_, i64>(1) != lease.fencing_token
            || row.get::<_, String>(2) == ISSUE_CLOSE_OPERATION
            || row.get::<_, bool>(3)
        {
            return Err(StoreError::OperationConflict);
        }
        let tokens = i64::try_from(model_tokens).map_err(|_| StoreError::InvalidInput)?;
        let usage_changed = tx.execute("UPDATE orchestrator.tasks SET model_usage=model_usage+$2, updated_at=clock_timestamp() WHERE id=$1", &[&lease.task_id,&tokens]).await?;
        if usage_changed != 1 {
            return Err(StoreError::TaskMissing);
        }
        let changed = tx.execute("UPDATE orchestrator.task_operations SET result=$3 WHERE operation_key=$1 AND task_id=$2 AND fencing_token=$4 AND result IS NULL", &[&key,&lease.task_id,result,&lease.fencing_token]).await?;
        if changed != 1 {
            return Err(StoreError::OperationConflict);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Creates a durable one-shot marker for a post-merge Issue close. This
    /// row prevents replay; it is not authority to perform the GitHub write.
    pub async fn prepare_issue_close(
        &mut self,
        lease: &Lease,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Option<OperationStatus>, StoreError> {
        if !facts.pr_merged {
            return Err(StoreError::InvalidRecord);
        }
        let key = issue_close_operation_key(lease.task_id);
        let tx = self.client.transaction().await?;
        require_live_lease(&tx, lease).await?;
        let row = tx.query_opt("SELECT id, issue_number, base_sha, head_sha, status::text, repair_count, issue_assignee, COALESCE((validation_result->>'passed')::boolean, false), pr_number, checkpoint, COALESCE(extract(epoch from clock_timestamp() - execution_started_at)::bigint, 0), model_usage, resume_state::text, implementer, reviewer, session_id, mock_github_journal, repair_count, mock_runtime_fingerprint, max_attempts, model_budget FROM orchestrator.tasks WHERE id=$1 FOR UPDATE", &[&lease.task_id]).await?.ok_or(StoreError::TaskMissing)?;
        let task = decode_task(&row)?;
        if task.state != State::Merging {
            return Err(StoreError::InvalidRecord);
        }
        validate_issue_close_evidence(&task, policy, facts)?;
        let repository: String = tx
            .query_one(
                "SELECT repository FROM orchestrator.tasks WHERE id=$1",
                &[&lease.task_id],
            )
            .await?
            .get(0);
        let request_hash = issue_close_request_hash(&task, &repository, policy, facts)?;
        let inserted = if facts.issue_open {
            tx.execute("INSERT INTO orchestrator.task_operations(operation_key,task_id,fencing_token,operation,request_hash,result) VALUES($1,$2,$3,$4,$5,NULL) ON CONFLICT(operation_key) DO NOTHING", &[&key,&lease.task_id,&lease.fencing_token,&ISSUE_CLOSE_OPERATION,&&request_hash[..]]).await? == 1
        } else {
            false
        };
        if inserted {
            tx.commit().await?;
            return Ok(Some(OperationStatus::NewlyPrepared));
        }
        let Some(operation) = tx.query_opt("SELECT task_id, fencing_token, operation, request_hash, result IS NOT NULL, CASE WHEN result IS NULL OR octet_length(result::text) <= $2 THEN result END FROM orchestrator.task_operations WHERE operation_key=$1 FOR UPDATE", &[&key,&MAX_OPERATION_RESULT_BYTES]).await? else {
            if facts.issue_open {
                return Err(StoreError::OperationConflict);
            }
            tx.commit().await?;
            return Ok(None);
        };
        if operation.get::<_, Uuid>(0) != lease.task_id
            || operation.get::<_, String>(2) != ISSUE_CLOSE_OPERATION
            || operation.get::<_, Vec<u8>>(3).as_slice() != request_hash
        {
            return Err(StoreError::OperationConflict);
        }
        let original_fence: i64 = operation.get(1);
        if original_fence <= 0 {
            return Err(StoreError::InvalidRecord);
        }
        let settled: bool = operation.get(4);
        let result: Option<serde_json::Value> = operation.get(5);
        if settled && result.is_none() {
            return Err(StoreError::InvalidRecord);
        }
        if settled {
            if result.as_ref() != Some(&serde_json::json!({"issue_closed_observed": true})) {
                return Err(StoreError::InvalidRecord);
            }
            if facts.issue_open {
                tx.commit().await?;
                return Ok(Some(OperationStatus::Ambiguous));
            }
            let result = result.ok_or(StoreError::InvalidRecord)?;
            tx.commit().await?;
            Ok(Some(OperationStatus::Completed {
                result,
                fencing_token: original_fence,
            }))
        } else {
            tx.commit().await?;
            Ok(Some(OperationStatus::Ambiguous))
        }
    }

    /// Records fresh evidence that the Issue is closed against a prepared close
    /// marker. The observation does not prove who closed it or authorize a write.
    pub async fn reconcile_issue_close(
        &mut self,
        lease: &Lease,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<OperationStatus, StoreError> {
        let key = issue_close_operation_key(lease.task_id);
        let tx = self.client.transaction().await?;
        require_live_lease(&tx, lease).await?;
        let row = tx.query_opt("SELECT id, issue_number, base_sha, head_sha, status::text, repair_count, issue_assignee, COALESCE((validation_result->>'passed')::boolean, false), pr_number, checkpoint, COALESCE(extract(epoch from clock_timestamp() - execution_started_at)::bigint, 0), model_usage, resume_state::text, implementer, reviewer, session_id, mock_github_journal, repair_count, mock_runtime_fingerprint, max_attempts, model_budget FROM orchestrator.tasks WHERE id=$1 FOR UPDATE", &[&lease.task_id]).await?.ok_or(StoreError::TaskMissing)?;
        let task = decode_task(&row)?;
        if task.state != State::Merging {
            return Err(StoreError::InvalidRecord);
        }
        if !facts.pr_merged {
            return Err(StoreError::InvalidRecord);
        }
        validate_issue_close_evidence(&task, policy, facts)?;
        let repository: String = tx
            .query_one(
                "SELECT repository FROM orchestrator.tasks WHERE id=$1",
                &[&lease.task_id],
            )
            .await?
            .get(0);
        let request_hash = issue_close_request_hash(&task, &repository, policy, facts)?;
        let operation = tx.query_opt("SELECT task_id, fencing_token, operation, request_hash, result IS NOT NULL, CASE WHEN result IS NULL OR octet_length(result::text) <= $2 THEN result END FROM orchestrator.task_operations WHERE operation_key=$1 FOR UPDATE", &[&key,&MAX_OPERATION_RESULT_BYTES]).await?.ok_or(StoreError::OperationConflict)?;
        if operation.get::<_, Uuid>(0) != lease.task_id
            || operation.get::<_, String>(2) != ISSUE_CLOSE_OPERATION
            || operation.get::<_, Vec<u8>>(3).as_slice() != request_hash
        {
            return Err(StoreError::OperationConflict);
        }
        let original_fence: i64 = operation.get(1);
        if original_fence <= 0 {
            return Err(StoreError::InvalidRecord);
        }
        let settled = operation.get::<_, bool>(4);
        let stored_result: Option<serde_json::Value> = operation.get(5);
        if settled {
            if stored_result.as_ref() != Some(&serde_json::json!({"issue_closed_observed": true})) {
                return Err(StoreError::InvalidRecord);
            }
            if facts.issue_open {
                tx.commit().await?;
                return Ok(OperationStatus::Ambiguous);
            }
            tx.commit().await?;
            return Ok(OperationStatus::Completed {
                result: stored_result.ok_or(StoreError::InvalidRecord)?,
                fencing_token: original_fence,
            });
        }
        if stored_result.is_some() {
            return Err(StoreError::InvalidRecord);
        }
        if facts.issue_open {
            tx.commit().await?;
            return Ok(OperationStatus::Ambiguous);
        }
        let result = serde_json::json!({"issue_closed_observed": true});
        let changed = tx.execute("UPDATE orchestrator.task_operations SET result=$2 WHERE operation_key=$1 AND task_id=$3 AND operation=$4 AND result IS NULL", &[&key,&result,&lease.task_id,&ISSUE_CLOSE_OPERATION]).await?;
        if changed != 1 {
            return Err(StoreError::OperationConflict);
        }
        tx.commit().await?;
        Ok(OperationStatus::Completed {
            result,
            fencing_token: original_fence,
        })
    }

    /// Releases only after a task reaches a state where execution has stopped.
    pub async fn release(&mut self, lease: &Lease) -> Result<(), StoreError> {
        let tx = self.client.transaction().await?;
        require_live_lease(&tx, lease).await?;
        let row = tx
            .query_opt(
                "SELECT status::text FROM orchestrator.tasks WHERE id=$1 FOR UPDATE",
                &[&lease.task_id],
            )
            .await?
            .ok_or(StoreError::TaskMissing)?;
        let status: String = row.get(0);
        if !matches!(
            status.as_str(),
            "completed" | "paused" | "blocked" | "failed" | "merging"
        ) {
            return Err(StoreError::InvalidRecord);
        }
        tx.execute("UPDATE orchestrator.execution_lease SET task_id=NULL, owner=NULL, expires_at=NULL WHERE singleton AND task_id=$1 AND owner=$2 AND fencing_token=$3 AND expires_at > clock_timestamp()", &[&lease.task_id,&lease.owner,&lease.fencing_token]).await?;
        tx.commit().await?;
        Ok(())
    }
}

fn validate_no_tls_target(config: &Config) -> Result<(), StoreError> {
    let hosts = config.get_hosts();
    let addresses = config.get_hostaddrs();
    if hosts.is_empty() && addresses.is_empty() {
        return Err(StoreError::InvalidInput);
    }
    if hosts.iter().any(|host| match host {
        Host::Tcp(host) => !host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        #[cfg(unix)]
        Host::Unix(_) => !addresses.is_empty(),
    }) || addresses.iter().any(|address| !address.is_loopback())
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}

async fn require_live_lease(tx: &Transaction<'_>, lease: &Lease) -> Result<(), StoreError> {
    let row = tx.query_opt("SELECT 1 FROM orchestrator.execution_lease WHERE singleton AND task_id=$1 AND owner=$2 AND fencing_token=$3 AND expires_at > clock_timestamp() FOR UPDATE", &[&lease.task_id,&lease.owner,&lease.fencing_token]).await?;
    if row.is_some() {
        Ok(())
    } else {
        Err(StoreError::LeaseLost)
    }
}

async fn require_live_work_lease(tx: &Transaction<'_>, lease: &Lease) -> Result<(), StoreError> {
    require_live_lease(tx, lease).await?;
    let active = tx.query_opt("SELECT 1 FROM orchestrator.tasks WHERE id=$1 AND execution_deadline > clock_timestamp() FOR UPDATE", &[&lease.task_id]).await?;
    if active.is_some() {
        Ok(())
    } else {
        Err(StoreError::InvalidRecord)
    }
}

async fn persist_recovered(
    tx: &Transaction<'_>,
    task: &TaskRecord,
    owner: &str,
    facts: &ObservedFacts,
) -> Result<(), StoreError> {
    task.validate().map_err(|_| StoreError::InvalidRecord)?;
    let id = Uuid::parse_str(&task.task_id).map_err(|_| StoreError::InvalidRecord)?;
    validate_existing_validation(tx, id).await?;
    let validation = validation_patch(task, facts)?;
    let checkpoint = task
        .checkpoint
        .map(|state| serde_json::json!({"state": state_name(state)}));
    let pr = task
        .pull_request
        .map(i64::try_from)
        .transpose()
        .map_err(|_| StoreError::InvalidRecord)?;
    let attempts = i32::try_from(task.attempts).map_err(|_| StoreError::InvalidRecord)?;
    let model_tokens = i64::try_from(task.model_tokens).map_err(|_| StoreError::InvalidRecord)?;
    if task
        .mock_github_journal
        .as_ref()
        .is_some_and(|value| !valid_mock_journal(value))
    {
        return Err(StoreError::InvalidRecord);
    }
    let changed = tx.execute("UPDATE orchestrator.tasks SET status=$2::text::orchestrator.task_state, head_sha=$3, repair_count=$4, assigned_worker=$5, issue_assignee=$6, validation_result=COALESCE(validation_result, '{}'::jsonb) || $7::jsonb, pr_number=$8, checkpoint=$9, resume_state=NULL, model_usage=$10, implementer=$11, reviewer=$12, session_id=$13, mock_github_journal=$14, mock_runtime_fingerprint=$15, updated_at=clock_timestamp() WHERE id=$1", &[&id,&state_name(task.state),&task.head_sha,&attempts,&owner,&task.assignee,&validation,&pr,&checkpoint,&model_tokens,&task.implementer,&task.reviewer,&task.session_id,&task.mock_github_journal,&task.mock_runtime_fingerprint]).await?;
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::TaskMissing)
    }
}

async fn validate_existing_validation(
    tx: &Transaction<'_>,
    task_id: Uuid,
) -> Result<(), StoreError> {
    let row = tx
        .query_opt(
            "SELECT COALESCE(octet_length(validation_result::text),0) > 16384, CASE WHEN COALESCE(octet_length(validation_result::text),0) <= 16384 THEN validation_result END FROM orchestrator.tasks WHERE id=$1 FOR UPDATE",
            &[&task_id],
        )
        .await?
        .ok_or(StoreError::TaskMissing)?;
    if row.get::<_, bool>(0) {
        return Err(StoreError::InvalidRecord);
    }
    if let Some(validation) = row.get::<_, Option<serde_json::Value>>(1) {
        parse_ci_observation(&validation)?;
    }
    Ok(())
}

fn decode_task(row: &Row) -> Result<TaskRecord, StoreError> {
    let id: Uuid = row.get(0);
    let issue: i64 = row.get(1);
    let attempts: i32 = row.get(5);
    let max_attempts: i32 = row
        .try_get(row.len() - 2)
        .map_err(|_| StoreError::InvalidRecord)?;
    let model_budget: i64 = row
        .try_get(row.len() - 1)
        .map_err(|_| StoreError::InvalidRecord)?;
    if max_attempts <= 0 || model_budget <= 0 {
        return Err(StoreError::InvalidRecord);
    }
    let pr: Option<i64> = row.get(8);
    let checkpoint: Option<serde_json::Value> = row.get(9);
    let checkpoint = checkpoint
        .map(|value| {
            value
                .get("state")
                .and_then(serde_json::Value::as_str)
                .and_then(parse_state)
                .ok_or(StoreError::InvalidRecord)
        })
        .transpose()?;
    let mut task = TaskRecord {
        task_id: id.to_string(),
        issue_number: u64::try_from(issue).map_err(|_| StoreError::InvalidRecord)?,
        base_sha: row.get(2),
        max_attempts: u32::try_from(max_attempts).map_err(|_| StoreError::InvalidRecord)?,
        head_sha: row.get(3),
        state: parse_state(&row.get::<_, String>(4)).ok_or(StoreError::InvalidRecord)?,
        attempts: u32::try_from(attempts).map_err(|_| StoreError::InvalidRecord)?,
        assignee: row.get(6),
        validation_passed: row.get(7),
        pull_request: pr
            .map(u64::try_from)
            .transpose()
            .map_err(|_| StoreError::InvalidRecord)?,
        checkpoint,
        elapsed: Duration::from_secs(
            u64::try_from(row.get::<_, i64>(10)).map_err(|_| StoreError::InvalidRecord)?,
        ),
        model_tokens: u64::try_from(row.get::<_, i64>(11))
            .map_err(|_| StoreError::InvalidRecord)?,
        model_budget: u64::try_from(model_budget).map_err(|_| StoreError::InvalidRecord)?,
        implementer: None,
        reviewer: None,
        session_id: None,
        mock_github_journal: None,
        mock_runtime_fingerprint: None,
    };
    let metadata_offset = match row.len() {
        21 => (12, 13),
        24 => (14, 16),
        _ => return Err(StoreError::InvalidRecord),
    };
    let (resume_index, metadata_offset) = metadata_offset;
    let resume_state: Option<String> = row.get(resume_index);
    if resume_state.as_deref() != checkpoint.map(state_name) {
        return Err(StoreError::InvalidRecord);
    }
    let implementer: Option<String> = row.get(metadata_offset);
    let reviewer: Option<String> = row.get(metadata_offset + 1);
    let session_id: Option<String> = row.get(metadata_offset + 2);
    let journal: Option<serde_json::Value> = row.get(metadata_offset + 3);
    let repair_count: i32 = row.get(metadata_offset + 4);
    let fingerprint: Option<String> = row
        .try_get(row.len() - 3)
        .map_err(|_| StoreError::InvalidRecord)?;
    if repair_count != attempts
        || fingerprint
            .as_deref()
            .is_some_and(|value| !is_fingerprint(value))
        || journal
            .as_ref()
            .is_some_and(|value| !valid_mock_journal(value))
        || [
            implementer.as_deref(),
            reviewer.as_deref(),
            session_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.trim().is_empty() || value.len() > 255)
    {
        return Err(StoreError::InvalidRecord);
    }
    task.implementer = implementer;
    task.reviewer = reviewer;
    task.session_id = session_id;
    task.mock_github_journal = journal;
    task.mock_runtime_fingerprint = fingerprint;
    task.validate().map_err(|_| StoreError::InvalidRecord)?;
    Ok(task)
}

fn validation_patch(
    task: &TaskRecord,
    facts: &ObservedFacts,
) -> Result<serde_json::Value, StoreError> {
    let mut patch = serde_json::json!({"passed": task.validation_passed});
    if let Some(ci) = facts.ci.as_ref() {
        if task.head_sha.as_deref() != Some(ci.head_sha.as_str())
            || task.pull_request != Some(ci.pull_request)
            || !is_sha(&ci.head_sha)
            || ci.pull_request == 0
        {
            return Err(StoreError::InvalidRecord);
        }
        let status = match ci.status {
            CiStatus::Passed => "passed",
            CiStatus::Pending => "pending",
            CiStatus::Failed => "failed",
            CiStatus::Unknown => "unknown",
        };
        patch["ci_observation"] = serde_json::json!({
            "head_sha": ci.head_sha,
            "pull_request": ci.pull_request,
            "status": status,
        });
    }
    Ok(patch)
}

fn parse_ci_observation(
    validation: &serde_json::Value,
) -> Result<Option<CiObservation>, StoreError> {
    let object = validation.as_object().ok_or(StoreError::InvalidRecord)?;
    if serde_json::to_vec(validation).map_or(true, |encoded| encoded.len() > 16 * 1024)
        || object
            .keys()
            .any(|key| !matches!(key.as_str(), "passed" | "ci_observation"))
    {
        return Err(StoreError::InvalidRecord);
    }
    if object
        .get("passed")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(StoreError::InvalidRecord);
    }
    let Some(observation) = object.get("ci_observation") else {
        return Ok(None);
    };
    let observation = observation.as_object().ok_or(StoreError::InvalidRecord)?;
    if observation.len() != 3
        || !observation.contains_key("head_sha")
        || !observation.contains_key("pull_request")
        || !observation.contains_key("status")
    {
        return Err(StoreError::InvalidRecord);
    }
    let head_sha = observation
        .get("head_sha")
        .and_then(serde_json::Value::as_str)
        .filter(|value| is_sha(value) && value.bytes().all(|byte| !byte.is_ascii_uppercase()))
        .ok_or(StoreError::InvalidRecord)?;
    let pull_request = observation
        .get("pull_request")
        .and_then(serde_json::Value::as_u64)
        .filter(|value| *value > 0 && i64::try_from(*value).is_ok())
        .ok_or(StoreError::InvalidRecord)?;
    let status = match observation
        .get("status")
        .and_then(serde_json::Value::as_str)
    {
        Some("passed") => CiStatus::Passed,
        Some("pending") => CiStatus::Pending,
        Some("failed") => CiStatus::Failed,
        Some("unknown") => CiStatus::Unknown,
        _ => return Err(StoreError::InvalidRecord),
    };
    Ok(Some(CiObservation {
        head_sha: head_sha.to_owned(),
        pull_request,
        status,
    }))
}

pub(crate) fn valid_mock_journal(value: &serde_json::Value) -> bool {
    value.is_array()
        && serde_json::to_vec(value).is_ok_and(|encoded| encoded.len() <= 65_536)
        && serde_json::from_value::<Vec<MockGitHubJournalEntry>>(value.clone()).is_ok()
}

fn ttl_seconds(ttl: Duration) -> Result<i64, StoreError> {
    let seconds = i64::try_from(ttl.as_secs()).map_err(|_| StoreError::InvalidInput)?;
    if seconds == 0 {
        Err(StoreError::InvalidInput)
    } else {
        Ok(seconds)
    }
}

fn state_name(state: State) -> &'static str {
    match state {
        State::Queued => "queued",
        State::Planning => "planning",
        State::Implementing => "implementing",
        State::Validating => "validating",
        State::Reviewing => "reviewing",
        State::Merging => "merging",
        State::Completed => "completed",
        State::Repairing => "repairing",
        State::Paused => "paused",
        State::Blocked => "blocked",
        State::Failed => "failed",
    }
}

fn parse_state(value: &str) -> Option<State> {
    match value {
        "queued" => Some(State::Queued),
        "planning" => Some(State::Planning),
        "implementing" => Some(State::Implementing),
        "validating" => Some(State::Validating),
        "reviewing" => Some(State::Reviewing),
        "merging" => Some(State::Merging),
        "completed" => Some(State::Completed),
        "repairing" => Some(State::Repairing),
        "paused" => Some(State::Paused),
        "blocked" => Some(State::Blocked),
        "failed" => Some(State::Failed),
        _ => None,
    }
}

fn is_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod connection_target_tests {
    use super::{StoreError, validate_no_tls_target};
    use std::str::FromStr;
    use tokio_postgres::Config;

    fn accepted(connection: &str) -> bool {
        Config::from_str(connection)
            .ok()
            .is_some_and(|config| validate_no_tls_target(&config).is_ok())
    }

    #[test]
    fn allows_only_explicit_loopback_ip_targets() {
        assert!(accepted("postgresql://user@127.0.0.1/orchestrator"));
        assert!(accepted("host=::1 user=orchestrator dbname=orchestrator"));
        assert!(accepted(
            "host=127.0.0.1,127.0.0.2 user=orchestrator dbname=orchestrator"
        ));
    }

    #[test]
    fn rejects_hostname_dns_and_non_loopback_targets() {
        for connection in [
            "postgresql://user@localhost/orchestrator",
            "host=database.internal user=orchestrator dbname=orchestrator",
            "host=203.0.113.8 sslmode=require user=orchestrator dbname=orchestrator",
            "host=example.com hostaddr=127.0.0.1 user=orchestrator dbname=orchestrator",
            "host=127.0.0.1 hostaddr=192.0.2.1 user=orchestrator dbname=orchestrator",
            "host=127.0.0.1,203.0.113.8 user=orchestrator dbname=orchestrator",
            "host= user=orchestrator dbname=orchestrator",
        ] {
            assert!(
                !accepted(connection),
                "accepted unsafe target: {connection}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn allows_unix_sockets_but_rejects_mixed_socket_and_hostaddr() {
        assert!(accepted(
            "host=/var/run/postgresql user=orchestrator dbname=orchestrator"
        ));
        let config = Config::from_str(
            "host=/var/run/postgresql hostaddr=127.0.0.1 user=orchestrator dbname=orchestrator",
        )
        .expect("connection settings parse");
        assert!(matches!(
            validate_no_tls_target(&config),
            Err(StoreError::InvalidInput)
        ));
    }

    #[test]
    fn rejects_missing_target_without_echoing_connection_data() {
        let result = Config::from_str("user=secret_user password=secret_password")
            .map_err(|_| StoreError::InvalidInput)
            .and_then(|config| validate_no_tls_target(&config));
        assert!(matches!(result, Err(StoreError::InvalidInput)));
        assert!(!format!("{result:?}").contains("secret_password"));
    }
}

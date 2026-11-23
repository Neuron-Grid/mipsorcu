use std::{
    env,
    net::IpAddr,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use mipsorcu_orchestrator::{
    agent::{Cancellation, Failure, Provider},
    domain::{CiObservation, CiStatus, ObservedFacts, State, TaskRecord, TrustedPolicy},
    engine::{
        Engine, EngineError, EngineStore, EvidenceSource, ExecutionBudget, OperationLookup,
        PostgresEngineStore, Stage, StageFailure, StageOutput, StageRunner, TrustedPolicySource,
        persisted_stage_result_v1, repair_result_digest,
    },
    postgres::{Lease, NewTask, RecoveryVerifier, StoreError, TaskStore},
};
use sha3::{Digest, Sha3_256};
use tokio_postgres::{Config, NoTls, config::Host};
use uuid::Uuid;

const TEST_DATABASE_URL: &str = "MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL";
const BASE_SHA: &str = "0123456789012345678901234567890123456789";
const STALE_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NON_PERSISTED_CANARY: &str = "private-plan-canary-7f14d6";
const NON_PERSISTED_PATH: &str = "private/path-canary-9e2f31.rs";
const ACTIVE_CRASH_TASK_ID: Uuid = Uuid::from_u128(0x20261121000200000000000000000001);
const ACTIVE_CRASH_IDEMPOTENCY_KEY: Uuid = Uuid::from_u128(0x20261121000200000000000000000002);
const ACTIVE_CRASH_WORKER: &str = "postgres-active-crash-worker";

fn plan_request_hash(task: &TaskRecord) -> [u8; 32] {
    let input = serde_json::json!({
        "task_id": task.task_id,
        "issue_number": task.issue_number,
        "state": "planning",
        "stage": "plan",
        "attempt": task.attempts,
        "base_sha": task.base_sha,
        "head_sha": task.head_sha,
    });
    Sha3_256::digest(serde_json::to_vec(&input).expect("encode deterministic plan request")).into()
}

struct Policy(TrustedPolicy);
impl TrustedPolicySource for Policy {
    async fn load_policy(&self, _: &TaskRecord) -> Result<TrustedPolicy, ()> {
        Ok(self.0.clone())
    }
}

struct Evidence(ObservedFacts);
impl EvidenceSource for Evidence {
    async fn observe(&self, _: &TaskRecord, _: &TrustedPolicy) -> Result<ObservedFacts, ()> {
        Ok(self.0.clone())
    }
}

#[derive(Clone)]
struct CountingEvidence {
    facts: Arc<std::sync::Mutex<ObservedFacts>>,
    observations: Arc<AtomicUsize>,
}

impl EvidenceSource for CountingEvidence {
    async fn observe(&self, _: &TaskRecord, _: &TrustedPolicy) -> Result<ObservedFacts, ()> {
        self.observations.fetch_add(1, Ordering::SeqCst);
        self.facts.lock().map(|facts| facts.clone()).map_err(|_| ())
    }
}

#[derive(Clone, Default)]
struct Runner(Arc<AtomicUsize>);
impl StageRunner for Runner {
    fn supports_cancellation(&self) -> bool {
        true
    }

    fn validate_configuration(&self) -> Result<(), mipsorcu_orchestrator::agent::ConfigError> {
        Ok(())
    }

    fn agent_roles(&self) -> (Provider, Provider) {
        (Provider::Codex, Provider::Claude)
    }

    async fn execute(
        &self,
        _: &Lease,
        _: Uuid,
        _: Stage,
        _: &TaskRecord,
        _: &TrustedPolicy,
        _: ExecutionBudget,
    ) -> Result<StageOutput, StageFailure> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(StageFailure::Agent(Failure::Unavailable))
    }

    async fn execute_with_cancellation(
        &self,
        lease: &Lease,
        operation_key: Uuid,
        stage: Stage,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        budget: ExecutionBudget,
        _: Cancellation,
    ) -> Result<StageOutput, StageFailure> {
        self.execute(lease, operation_key, stage, task, policy, budget)
            .await
    }

    async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
        Ok(())
    }
}

struct Supervisor;
impl RecoveryVerifier for Supervisor {
    fn verify_stopped(&self, _: Uuid, _: &str, _: i64) -> Option<serde_json::Value> {
        Some(serde_json::json!({"test_supervisor": "confirmed"}))
    }
}

async fn postgres_engine<R: StageRunner + Sync>(
    database_url: &str,
    policy: TrustedPolicy,
    facts: ObservedFacts,
    runner: R,
) -> Engine<PostgresEngineStore, Policy, Evidence, R, Supervisor> {
    Engine {
        store: PostgresEngineStore::new(
            TaskStore::connect(database_url)
                .await
                .expect("connect isolated PostgreSQL engine store"),
        ),
        policies: Policy(policy),
        evidence: Evidence(facts),
        runner,
        recovery: Supervisor,
        mock_github: None,
        lease_ttl: Duration::from_secs(30),
    }
}

struct FailAfterPrepare {
    inner: PostgresEngineStore,
    fired: std::sync::atomic::AtomicBool,
    failure_point: FailurePoint,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FailurePoint {
    AfterPrepare,
    BeforeComplete,
    AfterComplete,
    BeforeMergeCompletionSave,
}

#[derive(Clone)]
struct SideEffectRunner {
    database_url: String,
    calls: Arc<AtomicUsize>,
}

impl StageRunner for SideEffectRunner {
    fn supports_cancellation(&self) -> bool {
        true
    }

    fn validate_configuration(&self) -> Result<(), mipsorcu_orchestrator::agent::ConfigError> {
        Ok(())
    }

    fn agent_roles(&self) -> (Provider, Provider) {
        (Provider::Codex, Provider::Claude)
    }

    async fn execute(
        &self,
        _: &Lease,
        operation_key: Uuid,
        stage: Stage,
        _: &TaskRecord,
        _: &TrustedPolicy,
        _: ExecutionBudget,
    ) -> Result<StageOutput, StageFailure> {
        if stage != Stage::Plan {
            return Err(StageFailure::InvalidConfiguration);
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (client, connection) = tokio_postgres::connect(&self.database_url, NoTls)
            .await
            .map_err(|_| StageFailure::Internal)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
            .execute(
                "INSERT INTO orchestrator.test_external_effects(operation_key) VALUES($1)",
                &[&operation_key],
            )
            .await
            .map_err(|_| StageFailure::Internal)?;
        Ok(StageOutput {
            assignee: Some("worker".into()),
            implementer: Some("codex".into()),
            reviewer: Some("claude".into()),
            session_id: Some("7966bbf6-ab3a-4b68-8f6d-a9fb4f08ee46".into()),
            head_sha: None,
            pull_request: None,
            validation_passed: false,
            local_validation_passed: None,
            model_tokens: 7,
            mock_github_journal: None,
            plan: Some(mipsorcu_orchestrator::engine::MockPlan {
                requirements: vec!["test-only committed side effect".into()],
                steps: vec!["record operation key".into()],
            }),
            code_change: None,
        })
    }

    async fn execute_with_cancellation(
        &self,
        lease: &Lease,
        operation_key: Uuid,
        stage: Stage,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        budget: ExecutionBudget,
        _: Cancellation,
    ) -> Result<StageOutput, StageFailure> {
        self.execute(lease, operation_key, stage, task, policy, budget)
            .await
    }

    async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CompletedEvidenceMode {
    Missing,
    Valid,
    Forged,
}

#[derive(Clone, Eq, PartialEq)]
struct IndependentCompletionEvidence {
    task_id: Uuid,
    stage: Stage,
    operation_key: Uuid,
    request_hash: [u8; 32],
    original_fencing_token: i64,
    result_digest: [u8; 32],
    cumulative_model_tokens: u64,
}

#[derive(Clone)]
struct RestoreRunner {
    plan_calls: Arc<AtomicUsize>,
    implement_calls: Arc<AtomicUsize>,
    completed_evidence_mode: CompletedEvidenceMode,
    completed_evidence: Arc<std::sync::Mutex<Option<IndependentCompletionEvidence>>>,
    completed_verification_calls: Arc<AtomicUsize>,
}

impl Default for RestoreRunner {
    fn default() -> Self {
        Self::new(CompletedEvidenceMode::Valid)
    }
}

impl RestoreRunner {
    fn new(completed_evidence_mode: CompletedEvidenceMode) -> Self {
        Self {
            plan_calls: Arc::new(AtomicUsize::default()),
            implement_calls: Arc::new(AtomicUsize::default()),
            completed_evidence_mode,
            completed_evidence: Arc::new(std::sync::Mutex::new(None)),
            completed_verification_calls: Arc::new(AtomicUsize::default()),
        }
    }
}

#[derive(Clone, Default)]
struct WaitingRunner {
    entered: Arc<AtomicUsize>,
    active: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    stop_calls: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct LocalVerifierRunner {
    result: Result<bool, ()>,
    stop_success: bool,
    stage_calls: Arc<AtomicUsize>,
    verifier_calls: Arc<AtomicUsize>,
    stop_calls: Arc<AtomicUsize>,
}

impl LocalVerifierRunner {
    fn new(result: Result<bool, ()>, stop_success: bool) -> Self {
        Self {
            result,
            stop_success,
            stage_calls: Arc::new(AtomicUsize::default()),
            verifier_calls: Arc::new(AtomicUsize::default()),
            stop_calls: Arc::new(AtomicUsize::default()),
        }
    }
}

impl StageRunner for LocalVerifierRunner {
    fn supports_cancellation(&self) -> bool {
        true
    }

    fn validate_configuration(&self) -> Result<(), mipsorcu_orchestrator::agent::ConfigError> {
        Ok(())
    }

    fn agent_roles(&self) -> (Provider, Provider) {
        (Provider::Codex, Provider::Claude)
    }

    async fn execute(
        &self,
        _: &Lease,
        _: Uuid,
        _: Stage,
        _: &TaskRecord,
        _: &TrustedPolicy,
        _: ExecutionBudget,
    ) -> Result<StageOutput, StageFailure> {
        self.stage_calls.fetch_add(1, Ordering::SeqCst);
        Err(StageFailure::Agent(Failure::Unavailable))
    }

    async fn execute_with_cancellation(
        &self,
        lease: &Lease,
        operation_key: Uuid,
        stage: Stage,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        budget: ExecutionBudget,
        _: Cancellation,
    ) -> Result<StageOutput, StageFailure> {
        self.execute(lease, operation_key, stage, task, policy, budget)
            .await
    }

    async fn verify_local_validation(
        &self,
        _: &Lease,
        _: Uuid,
        _: &TaskRecord,
        _: &TrustedPolicy,
    ) -> Result<bool, ()> {
        self.verifier_calls.fetch_add(1, Ordering::SeqCst);
        self.result
    }

    async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        self.stop_success.then_some(()).ok_or(())
    }
}

struct ActiveStageGuard {
    active: Arc<AtomicBool>,
    cancellation: Option<(Arc<AtomicBool>, Cancellation)>,
}

impl Drop for ActiveStageGuard {
    fn drop(&mut self) {
        self.active.store(false, Ordering::SeqCst);
        if let Some((observed, cancellation)) = &self.cancellation {
            observed.store(cancellation.cancelled(), Ordering::SeqCst);
        }
    }
}

impl WaitingRunner {
    async fn wait_for_stage(
        &self,
        cancellation: Option<Cancellation>,
    ) -> Result<StageOutput, StageFailure> {
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.active.store(true, Ordering::SeqCst);
        let _guard = ActiveStageGuard {
            active: self.active.clone(),
            cancellation: cancellation.map(|token| (self.cancelled.clone(), token)),
        };
        std::future::pending().await
    }
}

impl StageRunner for WaitingRunner {
    fn supports_cancellation(&self) -> bool {
        true
    }

    fn validate_configuration(&self) -> Result<(), mipsorcu_orchestrator::agent::ConfigError> {
        Ok(())
    }

    fn agent_roles(&self) -> (Provider, Provider) {
        (Provider::Codex, Provider::Claude)
    }

    async fn execute(
        &self,
        _: &Lease,
        _: Uuid,
        _: Stage,
        _: &TaskRecord,
        _: &TrustedPolicy,
        _: ExecutionBudget,
    ) -> Result<StageOutput, StageFailure> {
        self.wait_for_stage(None).await
    }

    async fn execute_with_cancellation(
        &self,
        lease: &Lease,
        operation_key: Uuid,
        stage: Stage,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        budget: ExecutionBudget,
        cancellation: Cancellation,
    ) -> Result<StageOutput, StageFailure> {
        let _ = (lease, operation_key, stage, task, policy, budget);
        self.wait_for_stage(Some(cancellation)).await
    }

    async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl StageRunner for RestoreRunner {
    fn supports_cancellation(&self) -> bool {
        true
    }

    fn validate_configuration(&self) -> Result<(), mipsorcu_orchestrator::agent::ConfigError> {
        Ok(())
    }

    fn agent_roles(&self) -> (Provider, Provider) {
        (Provider::Codex, Provider::Claude)
    }

    async fn execute(
        &self,
        lease: &Lease,
        operation_key: Uuid,
        stage: Stage,
        task: &TaskRecord,
        _: &TrustedPolicy,
        _: ExecutionBudget,
    ) -> Result<StageOutput, StageFailure> {
        match stage {
            Stage::Plan => {
                self.plan_calls.fetch_add(1, Ordering::SeqCst);
                let output = StageOutput {
                    assignee: Some("worker".into()),
                    implementer: Some("codex".into()),
                    reviewer: Some("claude".into()),
                    session_id: Some("e00bd3af-6878-4aa1-889f-541079a3e653".into()),
                    head_sha: None,
                    pull_request: None,
                    validation_passed: false,
                    local_validation_passed: None,
                    model_tokens: 5,
                    mock_github_journal: None,
                    plan: Some(mipsorcu_orchestrator::engine::MockPlan {
                        requirements: vec![NON_PERSISTED_CANARY.into()],
                        steps: vec![NON_PERSISTED_PATH.into()],
                    }),
                    code_change: None,
                };
                let receipt = persisted_stage_result_v1(Stage::Plan, &output)
                    .map_err(|_| StageFailure::InvalidOperationResult)?;
                let mut result_digest =
                    repair_result_digest(&receipt).ok_or(StageFailure::InvalidOperationResult)?;
                if self.completed_evidence_mode == CompletedEvidenceMode::Forged {
                    result_digest[0] ^= 1;
                }
                let evidence = IndependentCompletionEvidence {
                    task_id: task
                        .task_id
                        .parse()
                        .map_err(|_| StageFailure::InvalidInput)?,
                    stage,
                    operation_key,
                    request_hash: plan_request_hash(task),
                    original_fencing_token: lease.fencing_token,
                    result_digest,
                    cumulative_model_tokens: task
                        .model_tokens
                        .checked_add(output.model_tokens)
                        .ok_or(StageFailure::InvalidOperationResult)?,
                };
                if self.completed_evidence_mode != CompletedEvidenceMode::Missing {
                    *self
                        .completed_evidence
                        .lock()
                        .map_err(|_| StageFailure::Internal)? = Some(evidence);
                }
                Ok(output)
            }
            Stage::Implement => {
                self.implement_calls.fetch_add(1, Ordering::SeqCst);
                Err(StageFailure::Agent(Failure::Unavailable))
            }
            _ => Err(StageFailure::InvalidConfiguration),
        }
    }

    async fn execute_with_cancellation(
        &self,
        lease: &Lease,
        operation_key: Uuid,
        stage: Stage,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        budget: ExecutionBudget,
        _: Cancellation,
    ) -> Result<StageOutput, StageFailure> {
        self.execute(lease, operation_key, stage, task, policy, budget)
            .await
    }

    async fn verify_completed_operation(
        &self,
        lease: &Lease,
        task: &TaskRecord,
        stage: Stage,
        operation_key: Uuid,
        request_hash: [u8; 32],
        original_fencing_token: i64,
        result_digest: [u8; 32],
        cumulative_model_tokens: u64,
        facts: &ObservedFacts,
    ) -> Result<(), ()> {
        self.completed_verification_calls
            .fetch_add(1, Ordering::SeqCst);
        if self.completed_evidence_mode == CompletedEvidenceMode::Missing
            || !facts.issue_open
            || lease.fencing_token < original_fencing_token
        {
            return Err(());
        }
        let evidence = self
            .completed_evidence
            .lock()
            .map_err(|_| ())?
            .clone()
            .ok_or(())?;
        let task_id = task.task_id.parse::<Uuid>().map_err(|_| ())?;
        (task_id == evidence.task_id
            && (self.completed_evidence_mode != CompletedEvidenceMode::Valid
                || lease.fencing_token > original_fencing_token)
            && task.attempts == 0
            && task.model_tokens == cumulative_model_tokens
            && stage == evidence.stage
            && operation_key == evidence.operation_key
            && request_hash == evidence.request_hash
            && original_fencing_token == evidence.original_fencing_token
            && result_digest == evidence.result_digest
            && cumulative_model_tokens == evidence.cumulative_model_tokens)
            .then_some(())
            .ok_or(())
    }

    async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
        Ok(())
    }
}

impl EngineStore for FailAfterPrepare {
    async fn get(&self, task_id: Uuid) -> Result<TaskRecord, StoreError> {
        self.inner.get(task_id).await
    }

    async fn claim(
        &self,
        task_id: Uuid,
        owner: &str,
        ttl: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        self.inner.claim(task_id, owner, ttl, policy, facts).await
    }

    async fn recover(
        &self,
        task_id: Uuid,
        owner: &str,
        ttl: Duration,
        verifier: &dyn RecoveryVerifier,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        self.inner
            .recover(task_id, owner, ttl, verifier, policy, facts)
            .await
    }

    async fn claim_handoff(
        &self,
        task_id: Uuid,
        owner: &str,
        ttl: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        self.inner
            .claim_handoff(task_id, owner, ttl, policy, facts)
            .await
    }

    async fn claim_resume(
        &self,
        task_id: Uuid,
        owner: &str,
        ttl: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        self.inner
            .claim_resume(task_id, owner, ttl, policy, facts)
            .await
    }

    async fn renew(&self, lease: &Lease, ttl: Duration) -> Result<(), StoreError> {
        self.inner.renew(lease, ttl).await
    }

    async fn renew_handoff_verification(
        &self,
        lease: &Lease,
        ttl: Duration,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<(), StoreError> {
        self.inner
            .renew_handoff_verification(lease, ttl, task, policy, facts)
            .await
    }

    async fn work_deadline_expired(
        &self,
        lease: &Lease,
        task: &TaskRecord,
        policy: &TrustedPolicy,
    ) -> Result<bool, StoreError> {
        self.inner.work_deadline_expired(lease, task, policy).await
    }

    async fn load(&self, lease: &Lease) -> Result<TaskRecord, StoreError> {
        self.inner.load(lease).await
    }

    async fn prepare_operation(
        &self,
        lease: &Lease,
        key: Uuid,
        operation: &str,
        request_hash: &[u8; 32],
    ) -> Result<OperationLookup, StoreError> {
        let prepared = self
            .inner
            .prepare_operation(lease, key, operation, request_hash)
            .await?;
        if self.failure_point == FailurePoint::AfterPrepare
            && prepared == OperationLookup::New
            && !self.fired.swap(true, Ordering::SeqCst)
        {
            return Err(StoreError::LeaseLost);
        }
        Ok(prepared)
    }

    async fn prepare_issue_close(
        &self,
        lease: &Lease,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Option<OperationLookup>, StoreError> {
        self.inner.prepare_issue_close(lease, policy, facts).await
    }

    async fn reconcile_issue_close(
        &self,
        lease: &Lease,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<OperationLookup, StoreError> {
        self.inner.reconcile_issue_close(lease, policy, facts).await
    }

    async fn complete_operation(
        &self,
        lease: &Lease,
        key: Uuid,
        result: &serde_json::Value,
        model_tokens: u64,
    ) -> Result<(), StoreError> {
        if self.failure_point == FailurePoint::BeforeComplete
            && !self.fired.swap(true, Ordering::SeqCst)
        {
            return Err(StoreError::LeaseLost);
        }
        self.inner
            .complete_operation(lease, key, result, model_tokens)
            .await?;
        if self.failure_point == FailurePoint::AfterComplete
            && !self.fired.swap(true, Ordering::SeqCst)
        {
            return Err(StoreError::LeaseLost);
        }
        Ok(())
    }

    async fn save(
        &self,
        lease: &Lease,
        expected: State,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<(), StoreError> {
        if self.failure_point == FailurePoint::BeforeMergeCompletionSave
            && expected == State::Merging
            && task.state == State::Completed
            && !self.fired.swap(true, Ordering::SeqCst)
        {
            return Err(StoreError::LeaseLost);
        }
        self.inner.save(lease, expected, task, policy, facts).await
    }

    async fn save_handoff_completed(
        &self,
        lease: &Lease,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<(), StoreError> {
        if self.failure_point == FailurePoint::BeforeMergeCompletionSave
            && task.state == State::Completed
            && !self.fired.swap(true, Ordering::SeqCst)
        {
            return Err(StoreError::LeaseLost);
        }
        self.inner
            .save_handoff_completed(lease, task, policy, facts)
            .await
    }

    async fn release(&self, lease: &Lease) -> Result<(), StoreError> {
        self.inner.release(lease).await
    }
}

#[tokio::test]
#[ignore = "requires a fresh local orchestrator_test_* PostgreSQL database"]
async fn real_engine_rejects_stale_base_and_does_not_reexecute_ambiguous_stage_after_restart() {
    let database_url = env::var(TEST_DATABASE_URL).unwrap_or_else(|_| {
        panic!("set {TEST_DATABASE_URL} to a fresh local orchestrator_test_* database")
    });
    assert_isolated_loopback_database(&database_url);

    let (bootstrap, connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("connect to isolated test database");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let schema_count: i64 = bootstrap
        .query_one(
            "SELECT count(*) FROM pg_namespace WHERE nspname = 'orchestrator'",
            &[],
        )
        .await
        .expect("inspect schemas")
        .get(0);
    let public_objects: i64 = bootstrap.query_one("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','v','m','S','f','p')", &[]).await.expect("inspect public schema").get(0);
    assert_eq!(
        (schema_count, public_objects),
        (0, 0),
        "refusing to mutate a database with an existing orchestrator schema or public objects"
    );
    bootstrap
        .batch_execute(include_str!("../migrations/0001_orchestrator.sql"))
        .await
        .expect("apply migration to throwaway database");
    bootstrap
        .batch_execute(include_str!("../migrations/0002_execution_metadata.sql"))
        .await
        .expect("apply execution metadata migration to throwaway database");
    bootstrap
        .batch_execute(include_str!(
            "../migrations/0003_mock_runtime_fingerprint.sql"
        ))
        .await
        .expect("apply mock runtime fingerprint migration to throwaway database");
    bootstrap
        .batch_execute(
            "CREATE TABLE orchestrator.test_external_effects (operation_key uuid PRIMARY KEY)",
        )
        .await
        .expect("create disposable test-only external-effect recorder");
    drop(bootstrap);

    let id = Uuid::new_v4();
    let task = NewTask {
        task_id: id,
        repository: "example/project".into(),
        issue_number: 17,
        base_sha: BASE_SHA.into(),
        max_attempts: 3,
        execution_timeout: Duration::from_secs(600),
        model_budget: 100,
        idempotency_key: Uuid::new_v4(),
    };
    let store = TaskStore::connect(&database_url)
        .await
        .expect("connect task store");
    store.create(&task).await.expect("create task");
    let policy = TrustedPolicy {
        base_ref: "develop".into(),
        base_sha: BASE_SHA.into(),
        allowed_assignee: "worker".into(),
        required_checks: vec!["ci".into()],
        max_attempts: 3,
        max_runtime: Duration::from_secs(600),
        max_model_tokens: 100,
    };
    let evidence = ObservedFacts {
        policy_base_ref: "develop".into(),
        policy_base_sha: BASE_SHA.into(),
        issue_open: true,
        base_sha: STALE_SHA.into(),
        ..ObservedFacts::default()
    };
    let runner = Arc::new(AtomicUsize::default());
    let engine = Engine {
        store: mipsorcu_orchestrator::engine::PostgresEngineStore::new(store),
        policies: Policy(policy),
        evidence: Evidence(evidence),
        runner: Runner(runner.clone()),
        recovery: Supervisor,
        mock_github: None,
        lease_ttl: Duration::from_secs(30),
    };

    assert!(matches!(
        engine.run_one(id, "worker-a").await,
        Err(EngineError::InvalidTransition(
            mipsorcu_orchestrator::domain::Error::StaleBase
        ))
    ));
    assert_eq!(
        runner.load(Ordering::SeqCst),
        0,
        "stale base must be rejected before invoking a stage"
    );
    assert_eq!(
        engine
            .store
            .get(id)
            .await
            .expect("read unchanged task")
            .state,
        State::Queued
    );

    // Inject a storage failure immediately after the real engine persists its
    // operation intent. This simulates a process stopping before stage execution;
    // recovery must treat the intent as ambiguous and fail closed.
    let ambiguous_id = Uuid::new_v4();
    let ambiguous_task = NewTask {
        task_id: ambiguous_id,
        issue_number: 18,
        idempotency_key: Uuid::new_v4(),
        ..task
    };
    let mut before_crash = TaskStore::connect(&database_url)
        .await
        .expect("connect pre-crash store");
    before_crash
        .create(&ambiguous_task)
        .await
        .expect("create restart task");
    let valid_facts = ObservedFacts {
        policy_base_ref: "develop".into(),
        policy_base_sha: BASE_SHA.into(),
        issue_open: true,
        base_sha: BASE_SHA.into(),
        ..ObservedFacts::default()
    };
    let prior = before_crash
        .claim(
            ambiguous_id,
            "worker-crashed",
            Duration::from_secs(1),
            &engine.policies.0,
            &valid_facts,
        )
        .await
        .expect("claim task before crash");
    drop(before_crash);

    let pre_crash_engine = Engine {
        store: FailAfterPrepare {
            inner: PostgresEngineStore::new(
                TaskStore::connect(&database_url)
                    .await
                    .expect("connect failure-injecting store"),
            ),
            fired: std::sync::atomic::AtomicBool::new(false),
            failure_point: FailurePoint::AfterPrepare,
        },
        policies: Policy(engine.policies.0.clone()),
        evidence: Evidence(valid_facts.clone()),
        runner: Runner(runner.clone()),
        recovery: Supervisor,
        mock_github: None,
        lease_ttl: Duration::from_secs(30),
    };
    assert!(matches!(
        pre_crash_engine.run_claimed(&prior).await,
        Err(EngineError::Store(StoreError::LeaseLost))
    ));
    assert_eq!(
        runner.load(Ordering::SeqCst),
        0,
        "injected failure happens after durable prepare and before stage invocation"
    );
    drop(pre_crash_engine);
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let recovered_engine = Engine {
        store: mipsorcu_orchestrator::engine::PostgresEngineStore::new(
            TaskStore::connect(&database_url)
                .await
                .expect("connect restarted store"),
        ),
        policies: Policy(engine.policies.0.clone()),
        evidence: Evidence(valid_facts.clone()),
        runner: Runner(runner.clone()),
        recovery: Supervisor,
        mock_github: None,
        lease_ttl: Duration::from_secs(30),
    };
    assert_eq!(
        recovered_engine
            .recover_and_run(&prior, "worker-restarted")
            .await
            .expect("recover ambiguous operation"),
        mipsorcu_orchestrator::engine::StepResult::BlockedAmbiguousOperation
    );
    assert_eq!(
        runner.load(Ordering::SeqCst),
        0,
        "an operation with no durable result must not be re-executed after restart"
    );
    assert_eq!(
        recovered_engine
            .store
            .get(ambiguous_id)
            .await
            .expect("read recovered task")
            .state,
        State::Blocked
    );

    let (effect_admin, effect_connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("connect independent test-only side-effect observer");
    tokio::spawn(async move {
        let _ = effect_connection.await;
    });
    // This side effect is a row in the disposable PostgreSQL database, not a
    // GitHub request; the test verifies fail-closed behavior after an effect.
    let effect_id = Uuid::new_v4();
    let effect_task = NewTask {
        task_id: effect_id,
        issue_number: 123,
        repository: "example/project".into(),
        base_sha: BASE_SHA.into(),
        max_attempts: 3,
        execution_timeout: Duration::from_secs(600),
        model_budget: 100,
        idempotency_key: Uuid::new_v4(),
    };
    let mut effect_store = TaskStore::connect(&database_url)
        .await
        .expect("connect task store for side-effect crash test");
    effect_store
        .create(&effect_task)
        .await
        .expect("create side-effect crash test task");
    let effect_prior = effect_store
        .claim(
            effect_id,
            "worker-effect-before-crash",
            Duration::from_secs(1),
            &engine.policies.0,
            &valid_facts,
        )
        .await
        .expect("claim task before side-effect crash");
    drop(effect_store);

    let effect_runner = SideEffectRunner {
        database_url: database_url.clone(),
        calls: Arc::new(AtomicUsize::default()),
    };
    let effect_crash_engine = Engine {
        store: FailAfterPrepare {
            inner: PostgresEngineStore::new(
                TaskStore::connect(&database_url)
                    .await
                    .expect("connect complete-operation failure injector"),
            ),
            fired: std::sync::atomic::AtomicBool::new(false),
            failure_point: FailurePoint::BeforeComplete,
        },
        policies: Policy(engine.policies.0.clone()),
        evidence: Evidence(valid_facts.clone()),
        runner: effect_runner.clone(),
        recovery: Supervisor,
        mock_github: None,
        lease_ttl: Duration::from_secs(1),
    };
    assert!(matches!(
        effect_crash_engine.run_claimed(&effect_prior).await,
        Err(EngineError::Store(StoreError::LeaseLost))
    ));
    drop(effect_crash_engine);

    let effect_row = effect_admin
        .query_one(
            "SELECT o.operation_key, o.result, t.model_usage FROM orchestrator.task_operations o JOIN orchestrator.tasks t ON t.id=o.task_id WHERE o.task_id=$1 AND o.operation='plan'",
            &[&effect_id],
        )
        .await
        .expect("inspect operation after test-only side effect commit");
    let effect_operation_key: Uuid = effect_row.get(0);
    assert!(effect_row.get::<_, Option<serde_json::Value>>(1).is_none());
    assert_eq!(effect_row.get::<_, i64>(2), 0);
    let effect_count: i64 = effect_admin
        .query_one(
            "SELECT count(*) FROM orchestrator.test_external_effects WHERE operation_key=$1",
            &[&effect_operation_key],
        )
        .await
        .expect("count committed test-only side effect")
        .get(0);
    assert_eq!(effect_count, 1);
    assert_eq!(effect_runner.calls.load(Ordering::SeqCst), 1);

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let effect_recovery_engine = Engine {
        store: PostgresEngineStore::new(
            TaskStore::connect(&database_url)
                .await
                .expect("connect side-effect recovery store"),
        ),
        policies: Policy(engine.policies.0.clone()),
        evidence: Evidence(valid_facts.clone()),
        runner: effect_runner.clone(),
        recovery: Supervisor,
        mock_github: None,
        lease_ttl: Duration::from_secs(30),
    };
    assert_eq!(
        effect_recovery_engine
            .recover_and_run(&effect_prior, "worker-after-effect-crash")
            .await
            .expect("recover ambiguous operation after test-only effect"),
        mipsorcu_orchestrator::engine::StepResult::BlockedAmbiguousOperation
    );
    let blocked_effect_task = effect_recovery_engine
        .store
        .get(effect_id)
        .await
        .expect("read task after blocking ambiguous external effect");
    assert_eq!(blocked_effect_task.state, State::Blocked);
    assert_eq!(blocked_effect_task.checkpoint, Some(State::Planning));
    assert_eq!(blocked_effect_task.model_tokens, 0);
    assert_eq!(effect_runner.calls.load(Ordering::SeqCst), 1);
    let effect_after_recovery = effect_admin
        .query_one(
            "SELECT o.result, t.model_usage, (SELECT count(*) FROM orchestrator.test_external_effects e WHERE e.operation_key=o.operation_key) FROM orchestrator.task_operations o JOIN orchestrator.tasks t ON t.id=o.task_id WHERE o.task_id=$1 AND o.operation='plan'",
            &[&effect_id],
        )
        .await
        .expect("confirm recovery neither replays nor finalizes the operation");
    assert!(
        effect_after_recovery
            .get::<_, Option<serde_json::Value>>(0)
            .is_none()
    );
    assert_eq!(effect_after_recovery.get::<_, i64>(1), 0);
    assert_eq!(effect_after_recovery.get::<_, i64>(2), 1);

    let replay_facts = ObservedFacts {
        policy_base_ref: "develop".into(),
        policy_base_sha: BASE_SHA.into(),
        issue_open: true,
        base_sha: BASE_SHA.into(),
        approved_assignee: "worker".into(),
        ..ObservedFacts::default()
    };
    let replay_id = Uuid::new_v4();
    let replay_task = NewTask {
        task_id: replay_id,
        repository: "example/project".into(),
        issue_number: 19,
        base_sha: BASE_SHA.into(),
        max_attempts: 3,
        execution_timeout: Duration::from_secs(600),
        model_budget: 100,
        idempotency_key: Uuid::new_v4(),
    };
    let mut replay_store = TaskStore::connect(&database_url)
        .await
        .expect("connect completed-result restart store");
    replay_store
        .create(&replay_task)
        .await
        .expect("create completed-result restart task");
    let replay_prior = replay_store
        .claim(
            replay_id,
            "worker-before-restart",
            Duration::from_secs(1),
            &engine.policies.0,
            &replay_facts,
        )
        .await
        .expect("claim task before completed-result restart");
    drop(replay_store);

    let restore_runner = RestoreRunner::default();
    let crash_after_result = Engine {
        store: FailAfterPrepare {
            inner: PostgresEngineStore::new(
                TaskStore::connect(&database_url)
                    .await
                    .expect("connect completed-result failure injector"),
            ),
            fired: std::sync::atomic::AtomicBool::new(false),
            failure_point: FailurePoint::AfterComplete,
        },
        policies: Policy(engine.policies.0.clone()),
        evidence: Evidence(replay_facts.clone()),
        runner: restore_runner.clone(),
        recovery: Supervisor,
        mock_github: None,
        // The injected process loss must expire before recovery is attempted.
        lease_ttl: Duration::from_secs(1),
    };
    assert!(matches!(
        crash_after_result.run_claimed(&replay_prior).await,
        Err(EngineError::Store(StoreError::LeaseLost))
    ));
    assert_eq!(restore_runner.plan_calls.load(Ordering::SeqCst), 1);
    drop(crash_after_result);

    let (inspection, inspection_connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("connect to inspect completed operation result");
    tokio::spawn(async move {
        let _ = inspection_connection.await;
    });
    let persisted_result: serde_json::Value = inspection
        .query_one(
            "SELECT result FROM orchestrator.task_operations WHERE task_id=$1 AND operation='plan'",
            &[&replay_id],
        )
        .await
        .expect("read completed plan receipt from isolated database")
        .get(0);
    let persisted_result_text = persisted_result.to_string();
    assert!(
        !persisted_result_text.contains(NON_PERSISTED_CANARY)
            && !persisted_result_text.contains(NON_PERSISTED_PATH),
        "new non-Mock operation results must omit plan prose and paths"
    );
    assert_eq!(persisted_result["result_type"], "stage_result");
    assert_eq!(persisted_result["format_version"], 1);
    assert_eq!(persisted_result["stage"], "plan");
    assert_eq!(
        persisted_result["metadata"]["session_id"],
        "e00bd3af-6878-4aa1-889f-541079a3e653"
    );
    assert_eq!(persisted_result["model_tokens"], 5);
    assert_eq!(
        persisted_result
            .as_object()
            .expect("versioned operation result is an object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "format_version",
            "metadata",
            "model_tokens",
            "result_type",
            "stage",
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        persisted_result["metadata"]
            .as_object()
            .expect("stage metadata is an object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        [
            "assignee",
            "head_sha",
            "implementer",
            "local_validation_passed",
            "pull_request",
            "reviewer",
            "session_id",
            "validation_passed",
        ]
        .into_iter()
        .collect()
    );
    drop(inspection);
    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let restarted = Engine {
        store: PostgresEngineStore::new(
            TaskStore::connect(&database_url)
                .await
                .expect("connect restarted completed-result store"),
        ),
        policies: Policy(engine.policies.0.clone()),
        evidence: Evidence(replay_facts),
        runner: restore_runner.clone(),
        recovery: Supervisor,
        mock_github: None,
        lease_ttl: Duration::from_secs(30),
    };
    assert_eq!(
        restarted
            .recover_and_run(&replay_prior, "worker-after-restart")
            .await
            .expect("resume from completed stage result"),
        mipsorcu_orchestrator::engine::StepResult::BlockedStageFailure(StageFailure::Agent(
            Failure::Unavailable
        ))
    );
    let restored_task = restarted
        .store
        .get(replay_id)
        .await
        .expect("read task after completed-result restore");
    assert_eq!(restored_task.state, State::Blocked);
    assert_eq!(restored_task.checkpoint, Some(State::Implementing));
    assert_eq!(restored_task.assignee.as_deref(), Some("worker"));
    assert_eq!(restored_task.implementer.as_deref(), Some("codex"));
    assert_eq!(restored_task.reviewer.as_deref(), Some("claude"));
    assert_eq!(
        restored_task.session_id.as_deref(),
        Some("e00bd3af-6878-4aa1-889f-541079a3e653")
    );
    assert_eq!(restored_task.model_tokens, 5);
    assert_eq!(restore_runner.plan_calls.load(Ordering::SeqCst), 1);
    assert_eq!(restore_runner.implement_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        restore_runner
            .completed_verification_calls
            .load(Ordering::SeqCst),
        1,
        "the independent test receipt authorizes exactly one completed-result replay"
    );

    for (issue_number, evidence_mode) in [
        (27, CompletedEvidenceMode::Missing),
        (28, CompletedEvidenceMode::Forged),
    ] {
        let (task_id, prior, runner) = crash_completed_plan_fixture(
            &database_url,
            issue_number,
            &engine.policies.0,
            &valid_facts,
            evidence_mode,
        )
        .await;
        if evidence_mode == CompletedEvidenceMode::Missing {
            assert!(runner.completed_evidence.lock().unwrap().is_none());
        } else {
            assert!(runner.completed_evidence.lock().unwrap().is_some());
        }
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let restarted_without_valid_evidence = Engine {
            store: PostgresEngineStore::new(
                TaskStore::connect(&database_url)
                    .await
                    .expect("connect evidence-rejection recovery store"),
            ),
            policies: Policy(engine.policies.0.clone()),
            evidence: Evidence(valid_facts.clone()),
            runner: runner.clone(),
            recovery: Supervisor,
            mock_github: None,
            lease_ttl: Duration::from_secs(30),
        };
        assert_eq!(
            restarted_without_valid_evidence
                .recover_and_run(&prior, "worker-without-valid-evidence")
                .await
                .expect("reject completed result without matching independent evidence"),
            mipsorcu_orchestrator::engine::StepResult::BlockedStageFailure(
                StageFailure::InvalidOperationResult
            )
        );
        let blocked_task = restarted_without_valid_evidence
            .store
            .get(task_id)
            .await
            .expect("read blocked task after proof rejection");
        assert_eq!(blocked_task.state, State::Blocked);
        assert_eq!(blocked_task.checkpoint, Some(State::Planning));
        assert_eq!(blocked_task.model_tokens, 5);
        assert_eq!(blocked_task.assignee, None);
        assert_eq!(runner.plan_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runner.implement_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            runner.completed_verification_calls.load(Ordering::SeqCst),
            1
        );

        let (observer, observer_connection) = tokio_postgres::connect(&database_url, NoTls)
            .await
            .expect("connect observer for rejected completed-result replay");
        tokio::spawn(async move {
            let _ = observer_connection.await;
        });
        let durable = observer
            .query_one(
                "SELECT result, fencing_token FROM orchestrator.task_operations WHERE task_id=$1 AND operation='plan'",
                &[&task_id],
            )
            .await
            .expect("inspect completed operation after proof rejection");
        assert!(durable.get::<_, Option<serde_json::Value>>(0).is_some());
        assert_eq!(durable.get::<_, i64>(1), prior.fencing_token);
        assert_eq!(
            observer
                .query_one(
                    "SELECT model_usage FROM orchestrator.tasks WHERE id=$1",
                    &[&task_id],
                )
                .await
                .expect("inspect usage after proof rejection")
                .get::<_, i64>(0),
            5
        );
    }

    // Terminate the dedicated Engine connection while its Plan stage is active.
    // The Engine must cancel the child and stop; a separate connection then
    // confirms the durable intent before a verified, post-expiry recovery.
    let connection_loss_id = Uuid::new_v4();
    let connection_loss_task = NewTask {
        task_id: connection_loss_id,
        issue_number: 20,
        repository: "example/project".into(),
        base_sha: BASE_SHA.into(),
        max_attempts: 3,
        execution_timeout: Duration::from_secs(600),
        model_budget: 100,
        idempotency_key: Uuid::new_v4(),
    };
    let setup_store = TaskStore::connect(&database_url)
        .await
        .expect("connect task setup store");
    setup_store
        .create(&connection_loss_task)
        .await
        .expect("create connection-loss task");
    drop(setup_store);

    let connection_loss_policy = TrustedPolicy {
        base_ref: "develop".into(),
        base_sha: BASE_SHA.into(),
        allowed_assignee: "worker-connection-loss".into(),
        required_checks: vec!["ci".into()],
        max_attempts: 3,
        max_runtime: Duration::from_secs(600),
        max_model_tokens: 100,
    };
    let connection_loss_facts = ObservedFacts {
        policy_base_ref: "develop".into(),
        policy_base_sha: BASE_SHA.into(),
        issue_open: true,
        base_sha: BASE_SHA.into(),
        ..ObservedFacts::default()
    };
    let application_name = format!("orchestrator-test-{}", Uuid::new_v4());
    let separator = if database_url.contains('?') { '&' } else { '?' };
    let isolated_url = format!("{database_url}{separator}application_name={application_name}");
    let connection_loss_store = PostgresEngineStore::new(
        TaskStore::connect(&isolated_url)
            .await
            .expect("connect dedicated active-engine store"),
    );
    let prior = connection_loss_store
        .claim(
            connection_loss_id,
            "worker-connection-loss",
            Duration::from_secs(1),
            &connection_loss_policy,
            &connection_loss_facts,
        )
        .await
        .expect("claim task before active connection-loss test");
    let waiting_runner = WaitingRunner::default();
    let active_engine = Engine {
        store: connection_loss_store,
        policies: Policy(connection_loss_policy.clone()),
        evidence: Evidence(connection_loss_facts.clone()),
        runner: waiting_runner.clone(),
        recovery: Supervisor,
        mock_github: None,
        lease_ttl: Duration::from_secs(1),
    };
    let active_run = tokio::spawn(async move { active_engine.run_claimed(&prior).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while waiting_runner.entered.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("Engine must enter the stage before terminating its connection");
    assert!(waiting_runner.active.load(Ordering::SeqCst));

    let (admin, connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("connect independent observer for connection-loss injection");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let terminated = admin
        .query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND application_name = $1 AND pid <> pg_backend_pid()",
            &[&application_name],
        )
        .await
        .expect("terminate only the active Engine connection");
    assert_eq!(terminated.len(), 1, "exactly one test backend is targeted");
    assert!(terminated[0].get::<_, bool>(0));

    let failed_run = tokio::time::timeout(Duration::from_secs(5), active_run)
        .await
        .expect("Engine must stop after the lease heartbeat loses its connection")
        .expect("Engine task must not panic");
    assert!(matches!(
        failed_run,
        Err(EngineError::Store(StoreError::Database(_)))
    ));
    assert!(!waiting_runner.active.load(Ordering::SeqCst));
    assert_eq!(waiting_runner.entered.load(Ordering::SeqCst), 1);
    assert_eq!(waiting_runner.stop_calls.load(Ordering::SeqCst), 1);

    let durable_state = admin
        .query_one(
            "SELECT t.status::text, l.owner, COALESCE(l.expires_at <= clock_timestamp(), false), l.fencing_token FROM orchestrator.tasks AS t CROSS JOIN orchestrator.execution_lease AS l WHERE t.id = $1",
            &[&connection_loss_id],
        )
        .await
        .expect("independently inspect task state after connection loss");
    assert_eq!(durable_state.get::<_, String>(0), "planning");
    assert_eq!(
        durable_state.get::<_, Option<String>>(1).as_deref(),
        Some("worker-connection-loss")
    );
    assert!(!durable_state.get::<_, bool>(2));
    let unresolved = admin
        .query_one(
            "SELECT result FROM orchestrator.task_operations WHERE task_id = $1",
            &[&connection_loss_id],
        )
        .await
        .expect("independently inspect prepared operation");
    assert!(unresolved.get::<_, Option<serde_json::Value>>(0).is_none());

    let mut fresh_store = TaskStore::connect(&database_url)
        .await
        .expect("connect fresh recovery store");
    let early_recovery = fresh_store
        .recover(
            connection_loss_id,
            "worker-too-early",
            Duration::from_secs(30),
            &Supervisor,
            &connection_loss_policy,
            &connection_loss_facts,
        )
        .await;
    assert!(matches!(early_recovery, Err(StoreError::LeaseLost)));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let expired: bool = admin
                .query_one(
                    "SELECT expires_at <= clock_timestamp() FROM orchestrator.execution_lease WHERE singleton",
                    &[],
                )
                .await
                .expect("poll isolated lease expiry")
                .get(0);
            if expired {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("lease must expire before independent recovery");

    let recovered_engine = Engine {
        store: PostgresEngineStore::new(fresh_store),
        policies: Policy(connection_loss_policy),
        evidence: Evidence(connection_loss_facts),
        runner: waiting_runner.clone(),
        recovery: Supervisor,
        mock_github: None,
        lease_ttl: Duration::from_secs(30),
    };
    assert_eq!(
        recovered_engine
            .recover_and_run(
                &Lease {
                    task_id: connection_loss_id,
                    owner: "worker-connection-loss".into(),
                    fencing_token: durable_state.get(3),
                },
                "worker-after-connection-loss"
            )
            .await
            .expect("recover ambiguous operation through a fresh connection"),
        mipsorcu_orchestrator::engine::StepResult::BlockedAmbiguousOperation
    );
    let recovered = recovered_engine
        .store
        .get(connection_loss_id)
        .await
        .expect("independently read recovered task");
    assert_eq!(recovered.state, State::Blocked);
    assert_eq!(recovered.checkpoint, Some(State::Planning));
    assert_eq!(waiting_runner.entered.load(Ordering::SeqCst), 1);
    assert!(!waiting_runner.active.load(Ordering::SeqCst));

    // Resume a human merge after the issue has closed. The Postgres claim is
    // lease-only for this checkpoint; only the independent verifier can allow
    // the Engine to persist Completed.
    let merged_resume_id = create_forged_authority_record(
        &database_url,
        &admin,
        &engine.policies.0,
        21,
        "paused",
        Some("merging"),
    )
    .await;
    let merged_facts = authority_facts(false, true);
    let successful_verifier = LocalVerifierRunner::new(Ok(true), true);
    let merged_resume_engine = postgres_engine(
        &database_url,
        engine.policies.0.clone(),
        merged_facts.clone(),
        successful_verifier.clone(),
    )
    .await;
    assert_eq!(
        merged_resume_engine
            .resume(merged_resume_id, "worker-merged-resume")
            .await
            .expect("verified merged resume"),
        mipsorcu_orchestrator::engine::StepResult::Finished
    );
    assert_eq!(
        merged_resume_engine
            .store
            .get(merged_resume_id)
            .await
            .expect("read verified merged task")
            .state,
        State::Completed
    );
    assert_eq!(successful_verifier.verifier_calls.load(Ordering::SeqCst), 1);
    assert_eq!(successful_verifier.stage_calls.load(Ordering::SeqCst), 0);
    let released_merged_lease: Option<Uuid> = admin
        .query_one(
            "SELECT task_id FROM orchestrator.execution_lease WHERE singleton",
            &[],
        )
        .await
        .expect("inspect released merged resume lease")
        .get(0);
    assert_eq!(released_merged_lease, None);

    // A human merge can reach GitHub before the completion transition is stored.
    // Synthetic evidence models a fresh read from the remote on each Engine pass;
    // this test does not call GitHub or perform a real merge.
    let merged_crash_id = create_forged_authority_record(
        &database_url,
        &admin,
        &engine.policies.0,
        29,
        "merging",
        None,
    )
    .await;
    let synthetic_remote_facts = authority_facts(false, true);
    let synthetic_remote = CountingEvidence {
        facts: Arc::new(std::sync::Mutex::new(synthetic_remote_facts.clone())),
        observations: Arc::new(AtomicUsize::default()),
    };
    let merged_crash_runner = LocalVerifierRunner::new(Ok(true), true);
    let merged_crash_engine = Engine {
        store: FailAfterPrepare {
            inner: PostgresEngineStore::new(
                TaskStore::connect(&database_url)
                    .await
                    .expect("connect human-merge completion failure injector"),
            ),
            fired: std::sync::atomic::AtomicBool::new(false),
            failure_point: FailurePoint::BeforeMergeCompletionSave,
        },
        policies: Policy(engine.policies.0.clone()),
        evidence: synthetic_remote.clone(),
        runner: merged_crash_runner.clone(),
        recovery: Supervisor,
        mock_github: None,
        lease_ttl: Duration::from_secs(1),
    };
    assert!(matches!(
        merged_crash_engine
            .complete_handoff(merged_crash_id, "worker-human-merge-before-crash")
            .await,
        Err(EngineError::Store(StoreError::LeaseLost))
    ));
    let task_after_failed_completion = merged_crash_engine
        .store
        .get(merged_crash_id)
        .await
        .expect("read task after failed completion persistence");
    assert_eq!(task_after_failed_completion.state, State::Merging);
    assert_eq!(merged_crash_runner.stage_calls.load(Ordering::SeqCst), 0);
    assert_eq!(merged_crash_runner.verifier_calls.load(Ordering::SeqCst), 1);
    let stranded_lease = admin
        .query_one(
            "SELECT task_id, owner, fencing_token FROM orchestrator.execution_lease WHERE singleton",
            &[],
        )
        .await
        .expect("inspect lease left by simulated crash");
    let stranded_lease = Lease {
        task_id: stranded_lease.get(0),
        owner: stranded_lease.get(1),
        fencing_token: stranded_lease.get(2),
    };
    assert_eq!(stranded_lease.task_id, merged_crash_id);
    drop(merged_crash_engine);

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let expired: bool = admin
                .query_one(
                    "SELECT expires_at <= clock_timestamp() FROM orchestrator.execution_lease WHERE singleton AND task_id=$1",
                    &[&merged_crash_id],
                )
                .await
                .expect("inspect stranded lease expiry")
                .get(0);
            if expired {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("stranded lease must expire before recovery");
    let merged_recovery_engine = Engine {
        store: PostgresEngineStore::new(
            TaskStore::connect(&database_url)
                .await
                .expect("connect human-merge recovery store"),
        ),
        policies: Policy(engine.policies.0.clone()),
        evidence: synthetic_remote.clone(),
        runner: merged_crash_runner.clone(),
        recovery: Supervisor,
        mock_github: None,
        lease_ttl: Duration::from_secs(30),
    };
    let mut incomplete_remote_facts = synthetic_remote_facts.clone();
    incomplete_remote_facts.base_contains_merge_commit = false;
    *synthetic_remote
        .facts
        .lock()
        .expect("lock synthetic remote") = incomplete_remote_facts;
    assert!(matches!(
        merged_recovery_engine
            .recover_and_run(&stranded_lease, "worker-rejected-merge-evidence")
            .await,
        Err(EngineError::InvalidTransition(
            mipsorcu_orchestrator::domain::Error::PullRequestMismatch
        ))
    ));
    assert_eq!(merged_crash_runner.stage_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        merged_recovery_engine
            .store
            .get(merged_crash_id)
            .await
            .expect("read task after rejecting merge evidence")
            .state,
        State::Merging
    );
    *synthetic_remote
        .facts
        .lock()
        .expect("lock synthetic remote") = synthetic_remote_facts;
    let observations_before_restart = synthetic_remote.observations.load(Ordering::SeqCst);
    assert_eq!(
        merged_recovery_engine
            .recover_and_run(&stranded_lease, "worker-after-human-merge-crash")
            .await
            .expect("recover using fresh synthetic merged evidence"),
        mipsorcu_orchestrator::engine::StepResult::Finished
    );
    assert!(
        synthetic_remote.observations.load(Ordering::SeqCst) > observations_before_restart,
        "recovery must read remote merge evidence again"
    );
    assert_eq!(
        merged_recovery_engine
            .store
            .get(merged_crash_id)
            .await
            .expect("read recovered human-merged task")
            .state,
        State::Completed
    );
    assert_eq!(merged_crash_runner.stage_calls.load(Ordering::SeqCst), 0);
    assert_eq!(merged_crash_runner.verifier_calls.load(Ordering::SeqCst), 2);

    // False and timed-out/error verifier results never complete a merged task.
    // Stop confirmation releases the lease; failed stop confirmation retains it.
    let false_id = create_forged_authority_record(
        &database_url,
        &admin,
        &engine.policies.0,
        22,
        "paused",
        Some("merging"),
    )
    .await;
    let false_verifier = LocalVerifierRunner::new(Ok(false), true);
    let false_engine = postgres_engine(
        &database_url,
        engine.policies.0.clone(),
        merged_facts.clone(),
        false_verifier.clone(),
    )
    .await;
    assert!(matches!(
        false_engine.resume(false_id, "worker-false-verifier").await,
        Err(EngineError::InvalidOperationResult)
    ));
    assert_eq!(
        false_engine
            .store
            .get(false_id)
            .await
            .expect("read false-verifier task")
            .state,
        State::Merging
    );
    assert_eq!(false_verifier.verifier_calls.load(Ordering::SeqCst), 1);
    assert_eq!(false_verifier.stop_calls.load(Ordering::SeqCst), 1);
    let released_false_lease: Option<Uuid> = admin
        .query_one(
            "SELECT task_id FROM orchestrator.execution_lease WHERE singleton",
            &[],
        )
        .await
        .expect("inspect false-verifier lease")
        .get(0);
    assert_eq!(released_false_lease, None);

    // A persisted Reviewing row is resumed from its checkpoint, then blocked
    // when the default runner cannot provide independent validation evidence.
    let forged_review_id = create_forged_authority_record(
        &database_url,
        &admin,
        &engine.policies.0,
        23,
        "paused",
        Some("reviewing"),
    )
    .await;
    let open_facts = authority_facts(true, false);
    let forged_review_engine = postgres_engine(
        &database_url,
        engine.policies.0.clone(),
        open_facts.clone(),
        Runner::default(),
    )
    .await;
    assert_eq!(
        forged_review_engine
            .resume(forged_review_id, "worker-forged-review")
            .await
            .expect("forged review is blocked"),
        mipsorcu_orchestrator::engine::StepResult::BlockedStageFailure(
            StageFailure::InvalidOperationResult
        )
    );
    let forged_review = forged_review_engine
        .store
        .get(forged_review_id)
        .await
        .expect("read blocked forged review");
    assert_eq!(forged_review.state, State::Blocked);
    assert_eq!(forged_review.checkpoint, Some(State::Reviewing));

    // The same guard applies to an unmerged Merging row.
    let forged_merging_id = create_forged_authority_record(
        &database_url,
        &admin,
        &engine.policies.0,
        24,
        "paused",
        Some("merging"),
    )
    .await;
    let forged_merging_engine = postgres_engine(
        &database_url,
        engine.policies.0.clone(),
        open_facts.clone(),
        Runner::default(),
    )
    .await;
    assert_eq!(
        forged_merging_engine
            .resume(forged_merging_id, "worker-forged-merging")
            .await
            .expect("forged unmerged state is blocked"),
        mipsorcu_orchestrator::engine::StepResult::BlockedStageFailure(
            StageFailure::InvalidOperationResult
        )
    );
    let forged_merging = forged_merging_engine
        .store
        .get(forged_merging_id)
        .await
        .expect("read blocked forged merging task");
    assert_eq!(forged_merging.state, State::Blocked);
    assert_eq!(forged_merging.checkpoint, Some(State::Merging));

    // A persisted Completed row still needs an independent verifier before
    // complete_handoff may report success.
    let forged_completed_id = create_forged_authority_record(
        &database_url,
        &admin,
        &engine.policies.0,
        25,
        "completed",
        None,
    )
    .await;
    let forged_completed_runner = LocalVerifierRunner::new(Err(()), true);
    let forged_completed_engine = postgres_engine(
        &database_url,
        engine.policies.0.clone(),
        merged_facts.clone(),
        forged_completed_runner.clone(),
    )
    .await;
    assert!(matches!(
        forged_completed_engine
            .complete_handoff(forged_completed_id, "worker-forged-completed")
            .await,
        Err(EngineError::InvalidOperationResult)
    ));
    assert_eq!(
        forged_completed_runner
            .verifier_calls
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        forged_completed_engine
            .store
            .get(forged_completed_id)
            .await
            .expect("read rejected forged completed task")
            .state,
        State::Completed
    );

    // Keep this as the final DB action: failed process-stop confirmation must
    // leave the Merging task and its lease intact for safe recovery.
    let timed_out_id = create_forged_authority_record(
        &database_url,
        &admin,
        &engine.policies.0,
        26,
        "paused",
        Some("merging"),
    )
    .await;
    let timeout_runner = LocalVerifierRunner::new(Err(()), false);
    let timed_out_engine = postgres_engine(
        &database_url,
        engine.policies.0.clone(),
        merged_facts,
        timeout_runner.clone(),
    )
    .await;
    assert!(matches!(
        timed_out_engine
            .resume(timed_out_id, "worker-timeout-unconfirmed-stop")
            .await,
        Err(EngineError::InvalidOperationResult)
    ));
    assert_eq!(timeout_runner.verifier_calls.load(Ordering::SeqCst), 1);
    assert_eq!(timeout_runner.stop_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        timed_out_engine
            .store
            .get(timed_out_id)
            .await
            .expect("read timed-out verifier task")
            .state,
        State::Merging
    );
    let retained_lease = admin
        .query_one(
            "SELECT task_id, owner FROM orchestrator.execution_lease WHERE singleton",
            &[],
        )
        .await
        .expect("inspect retained lease after unconfirmed stop");
    assert_eq!(retained_lease.get::<_, Option<Uuid>>(0), Some(timed_out_id));
    assert_eq!(
        retained_lease.get::<_, Option<String>>(1).as_deref(),
        Some("worker-timeout-unconfirmed-stop")
    );
}

#[tokio::test]
#[ignore = "requires the offline host controller to kill and restart its disposable PostgreSQL after the marker commit"]
async fn postgres_active_server_crash() {
    let database_url = env::var(TEST_DATABASE_URL).expect("isolated test URL required");
    assert_isolated_loopback_database(&database_url);
    let config = Config::from_str(&database_url).expect("parse isolated test URL");
    assert_eq!(config.get_dbname(), Some("orchestrator_test_active_crash"));

    let (bootstrap, connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("connect to fresh disposable database");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let dedicated_role: bool = bootstrap
        .query_one(
            "SELECT rolname = 'orchestrator_test' AND NOT rolsuper FROM pg_roles WHERE rolname = current_user",
            &[],
        )
        .await
        .expect("inspect dedicated test role")
        .get(0);
    assert!(
        dedicated_role,
        "test role must be dedicated and non-superuser"
    );
    let orchestrator_schema: i64 = bootstrap
        .query_one(
            "SELECT count(*) FROM pg_namespace WHERE nspname = 'orchestrator'",
            &[],
        )
        .await
        .expect("inspect test schemas")
        .get(0);
    let other_user_schemas: i64 = bootstrap
        .query_one(
            "SELECT count(*) FROM pg_namespace WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'public') AND nspname NOT LIKE 'pg_toast%'",
            &[],
        )
        .await
        .expect("inspect non-system schemas")
        .get(0);
    let public_objects: i64 = bootstrap
        .query_one(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','v','m','S','f','p')",
            &[],
        )
        .await
        .expect("inspect public schema")
        .get(0);
    assert_eq!(
        (orchestrator_schema, other_user_schemas, public_objects),
        (0, 0, 0),
        "refusing to mutate a database with existing application schemas or public objects"
    );
    bootstrap
        .batch_execute(include_str!("../migrations/0001_orchestrator.sql"))
        .await
        .expect("apply initial orchestrator migration");
    bootstrap
        .batch_execute(include_str!("../migrations/0002_execution_metadata.sql"))
        .await
        .expect("apply execution metadata migration");
    bootstrap
        .batch_execute(include_str!(
            "../migrations/0003_mock_runtime_fingerprint.sql"
        ))
        .await
        .expect("apply runtime fingerprint migration");
    bootstrap
        .batch_execute(
            "CREATE TABLE orchestrator.test_active_engine_crash_markers (\
                task_id uuid PRIMARY KEY, operation_key uuid NOT NULL, fencing_token bigint NOT NULL\
            )",
        )
        .await
        .expect("create logged test synchronization marker");

    let task = NewTask {
        task_id: ACTIVE_CRASH_TASK_ID,
        repository: "example/project".to_owned(),
        issue_number: 9301,
        base_sha: BASE_SHA.to_owned(),
        max_attempts: 3,
        execution_timeout: Duration::from_secs(600),
        model_budget: 100,
        idempotency_key: ACTIVE_CRASH_IDEMPOTENCY_KEY,
    };
    let policy = TrustedPolicy {
        base_ref: "develop".to_owned(),
        base_sha: BASE_SHA.to_owned(),
        allowed_assignee: ACTIVE_CRASH_WORKER.to_owned(),
        required_checks: vec!["ci".to_owned()],
        max_attempts: 3,
        max_runtime: Duration::from_secs(600),
        max_model_tokens: 100,
    };
    let facts = ObservedFacts {
        policy_base_ref: "develop".to_owned(),
        policy_base_sha: BASE_SHA.to_owned(),
        issue_open: true,
        base_sha: BASE_SHA.to_owned(),
        ..ObservedFacts::default()
    };
    let setup = TaskStore::connect(&database_url)
        .await
        .expect("connect task setup store");
    assert_eq!(
        setup.create(&task).await.expect("create fixed crash task"),
        ACTIVE_CRASH_TASK_ID
    );
    let application_name = "orchestrator-active-crash-worker";
    let separator = if database_url.contains('?') { '&' } else { '?' };
    let engine_url = format!("{database_url}{separator}application_name={application_name}");
    let store = PostgresEngineStore::new(
        TaskStore::connect(&engine_url)
            .await
            .expect("connect dedicated active Engine store"),
    );
    let prior = store
        .claim(
            ACTIVE_CRASH_TASK_ID,
            ACTIVE_CRASH_WORKER,
            Duration::from_secs(2),
            &policy,
            &facts,
        )
        .await
        .expect("claim task before active PostgreSQL crash test");
    let runner = WaitingRunner::default();
    let engine = Engine {
        store,
        policies: Policy(policy),
        evidence: Evidence(facts),
        runner: runner.clone(),
        recovery: Supervisor,
        mock_github: None,
        lease_ttl: Duration::from_secs(2),
    };
    let engine_lease = prior.clone();
    let active_run = tokio::spawn(async move { engine.run_claimed(&engine_lease).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while runner.entered.load(Ordering::SeqCst) == 0 || !runner.active.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("Engine must enter its Plan stage");
    assert!(runner.active.load(Ordering::SeqCst));

    let operation = bootstrap
        .query_one(
            "SELECT o.operation_key, o.fencing_token, o.result, t.status::text, l.owner, l.expires_at > clock_timestamp() \
             FROM orchestrator.task_operations o \
             JOIN orchestrator.tasks t ON t.id=o.task_id \
             JOIN orchestrator.execution_lease l ON l.task_id=t.id \
             WHERE o.task_id=$1 AND o.operation='plan'",
            &[&ACTIVE_CRASH_TASK_ID],
        )
        .await
        .expect("read prepared Plan operation, task and active lease");
    let operation_key: Uuid = operation.get(0);
    let operation_fencing_token: i64 = operation.get(1);
    assert!(operation.get::<_, Option<serde_json::Value>>(2).is_none());
    assert_eq!(operation.get::<_, String>(3), "planning");
    assert_eq!(operation.get::<_, String>(4), ACTIVE_CRASH_WORKER);
    assert!(operation.get::<_, bool>(5));
    assert_eq!(operation_fencing_token, prior.fencing_token);
    bootstrap
        .execute(
            "INSERT INTO orchestrator.test_active_engine_crash_markers(task_id, operation_key, fencing_token) VALUES($1, $2, $3)",
            &[&ACTIVE_CRASH_TASK_ID, &operation_key, &operation_fencing_token],
        )
        .await
        .expect("commit host-observed marker for the actual operation key");

    let marker = bootstrap
        .query_one(
            "SELECT operation_key, fencing_token FROM orchestrator.test_active_engine_crash_markers WHERE task_id=$1",
            &[&ACTIVE_CRASH_TASK_ID],
        )
        .await
        .expect("read committed crash marker");
    assert_eq!(marker.get::<_, Uuid>(0), operation_key);
    assert_eq!(marker.get::<_, i64>(1), operation_fencing_token);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(std::env::temp_dir().join("mipsorcu-active-crash-ready"))
        .expect("publish test readiness after confirming the marker commit");

    let failed_run = active_run.await.expect("Engine task must not panic");
    assert!(matches!(
        failed_run,
        Err(EngineError::Store(StoreError::Database(_)))
    ));
    assert!(!runner.active.load(Ordering::SeqCst));
    assert!(runner.cancelled.load(Ordering::SeqCst));
    assert_eq!(runner.entered.load(Ordering::SeqCst), 1);
    assert_eq!(runner.stop_calls.load(Ordering::SeqCst), 1);
    drop(setup);
}

#[tokio::test]
#[ignore = "requires postgres_active_server_crash followed by restart of the same disposable database volume"]
async fn postgres_active_server_recover() {
    let database_url = env::var(TEST_DATABASE_URL).expect("isolated test URL required");
    assert_isolated_loopback_database(&database_url);
    let config = Config::from_str(&database_url).expect("parse isolated test URL");
    assert_eq!(config.get_dbname(), Some("orchestrator_test_active_crash"));

    let (admin, connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("connect to restarted disposable PostgreSQL");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let marker = admin
        .query_one(
            "SELECT operation_key, fencing_token FROM orchestrator.test_active_engine_crash_markers WHERE task_id=$1",
            &[&ACTIVE_CRASH_TASK_ID],
        )
        .await
        .expect("read marker committed before PostgreSQL crash");
    let operation_key: Uuid = marker.get(0);
    let original_fencing_token: i64 = marker.get(1);
    let persisted = admin
        .query_one(
            "SELECT o.operation, o.fencing_token, o.result, t.status::text, l.owner, l.expires_at <= clock_timestamp() \
             FROM orchestrator.task_operations o \
             JOIN orchestrator.tasks t ON t.id=o.task_id \
             JOIN orchestrator.execution_lease l ON l.task_id=t.id \
             WHERE o.task_id=$1 AND o.operation_key=$2",
            &[&ACTIVE_CRASH_TASK_ID, &operation_key],
        )
        .await
        .expect("read durable active operation after database restart");
    assert_eq!(persisted.get::<_, String>(0), "plan");
    assert_eq!(persisted.get::<_, i64>(1), original_fencing_token);
    assert!(persisted.get::<_, Option<serde_json::Value>>(2).is_none());
    assert_eq!(persisted.get::<_, String>(3), "planning");
    assert_eq!(persisted.get::<_, String>(4), ACTIVE_CRASH_WORKER);

    let mut expired = persisted.get::<_, bool>(5);
    tokio::time::timeout(Duration::from_secs(30), async {
        while !expired {
            tokio::time::sleep(Duration::from_millis(100)).await;
            expired = admin
                .query_one(
                    "SELECT expires_at <= clock_timestamp() FROM orchestrator.execution_lease WHERE singleton AND task_id=$1",
                    &[&ACTIVE_CRASH_TASK_ID],
                )
                .await
                .expect("wait for lease expiry after PostgreSQL restart")
                .get(0);
        }
    })
    .await
    .expect("lease must expire before recovery");

    let prior = Lease {
        task_id: ACTIVE_CRASH_TASK_ID,
        owner: ACTIVE_CRASH_WORKER.to_owned(),
        fencing_token: original_fencing_token,
    };
    let policy = TrustedPolicy {
        base_ref: "develop".to_owned(),
        base_sha: BASE_SHA.to_owned(),
        allowed_assignee: ACTIVE_CRASH_WORKER.to_owned(),
        required_checks: vec!["ci".to_owned()],
        max_attempts: 3,
        max_runtime: Duration::from_secs(600),
        max_model_tokens: 100,
    };
    let facts = ObservedFacts {
        policy_base_ref: "develop".to_owned(),
        policy_base_sha: BASE_SHA.to_owned(),
        issue_open: true,
        base_sha: BASE_SHA.to_owned(),
        ..ObservedFacts::default()
    };
    let runner = WaitingRunner::default();
    let engine = postgres_engine(&database_url, policy, facts, runner.clone()).await;
    assert_eq!(
        engine
            .recover_and_run(&prior, "postgres-active-crash-recovery-worker")
            .await
            .expect("recover without replaying the ambiguous operation"),
        mipsorcu_orchestrator::engine::StepResult::BlockedAmbiguousOperation
    );
    assert_eq!(runner.entered.load(Ordering::SeqCst), 0);
    assert!(!runner.active.load(Ordering::SeqCst));
    assert_eq!(runner.stop_calls.load(Ordering::SeqCst), 1);

    let recovered = admin
        .query_one(
            "SELECT t.status::text, t.checkpoint->>'state', o.result, l.task_id, l.fencing_token \
             FROM orchestrator.tasks t \
             JOIN orchestrator.task_operations o ON o.task_id=t.id AND o.operation_key=$2 \
             CROSS JOIN orchestrator.execution_lease l \
             WHERE t.id=$1",
            &[&ACTIVE_CRASH_TASK_ID, &operation_key],
        )
        .await
        .expect("inspect recovered task and operation");
    assert_eq!(recovered.get::<_, String>(0), "blocked");
    assert_eq!(
        recovered.get::<_, Option<String>>(1).as_deref(),
        Some("planning")
    );
    assert!(recovered.get::<_, Option<serde_json::Value>>(2).is_none());
    assert_eq!(recovered.get::<_, Option<Uuid>>(3), None);
    let new_fencing_token: i64 = recovered.get(4);
    assert!(new_fencing_token > original_fencing_token);
    let old_store = TaskStore::connect(&database_url)
        .await
        .expect("connect to verify old fencing token rejection");
    assert!(matches!(
        old_store.renew(&prior, Duration::from_secs(1)).await,
        Err(StoreError::LeaseLost)
    ));
}

async fn crash_completed_plan_fixture(
    database_url: &str,
    issue_number: i64,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
    evidence_mode: CompletedEvidenceMode,
) -> (Uuid, Lease, RestoreRunner) {
    let task_id = Uuid::new_v4();
    let task = NewTask {
        task_id,
        repository: "example/project".into(),
        issue_number,
        base_sha: BASE_SHA.into(),
        max_attempts: 3,
        execution_timeout: Duration::from_secs(600),
        model_budget: 100,
        idempotency_key: Uuid::new_v4(),
    };
    let mut store = TaskStore::connect(database_url)
        .await
        .expect("connect task store for completed-result evidence test");
    store
        .create(&task)
        .await
        .expect("create completed-result evidence test task");
    let prior = store
        .claim(
            task_id,
            "worker-before-evidence-crash",
            Duration::from_secs(1),
            policy,
            facts,
        )
        .await
        .expect("claim task before completed-result evidence crash");
    drop(store);

    let runner = RestoreRunner::new(evidence_mode);
    let crashed_engine = Engine {
        store: FailAfterPrepare {
            inner: PostgresEngineStore::new(
                TaskStore::connect(database_url)
                    .await
                    .expect("connect completed-result evidence failure injector"),
            ),
            fired: std::sync::atomic::AtomicBool::new(false),
            failure_point: FailurePoint::AfterComplete,
        },
        policies: Policy(policy.clone()),
        evidence: Evidence(facts.clone()),
        runner: runner.clone(),
        recovery: Supervisor,
        mock_github: None,
        lease_ttl: Duration::from_secs(1),
    };
    assert!(matches!(
        crashed_engine.run_claimed(&prior).await,
        Err(EngineError::Store(StoreError::LeaseLost))
    ));
    assert_eq!(runner.plan_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        runner.completed_verification_calls.load(Ordering::SeqCst),
        0
    );
    drop(crashed_engine);
    (task_id, prior, runner)
}

fn assert_isolated_loopback_database(database_url: &str) {
    let config = Config::from_str(database_url).expect("valid PostgreSQL test URL");
    let loopback = config.get_hosts().iter().all(|host| match host {
        Host::Tcp(host) => IpAddr::from_str(host).is_ok_and(|ip| ip.is_loopback()),
        Host::Unix(_) => true,
    });
    let database = config.get_dbname().expect("explicit test database name");
    assert!(
        loopback,
        "test database must use only loopback TCP or Unix socket hosts"
    );
    assert!(
        database.starts_with("orchestrator_test_"),
        "test database name must start with orchestrator_test_"
    );
}

fn authority_facts(issue_open: bool, merged: bool) -> ObservedFacts {
    let head = STALE_SHA.to_owned();
    ObservedFacts {
        policy_base_ref: "develop".into(),
        policy_base_sha: BASE_SHA.into(),
        issue_open,
        base_sha: BASE_SHA.into(),
        head_sha: head.clone(),
        validated_head_sha: Some(head.clone()),
        pr_number: Some(42),
        pr_head_sha: Some(head.clone()),
        pr_base_ref: Some("develop".into()),
        pr_base_sha: Some(BASE_SHA.into()),
        pr_merged: merged,
        checks_passed: vec!["ci".into()],
        reviewer_approved: true,
        approved_assignee: "worker".into(),
        merge_commit_sha: merged.then(|| "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()),
        base_contains_merge_commit: merged,
        ci: Some(CiObservation {
            head_sha: head,
            pull_request: 42,
            status: CiStatus::Passed,
        }),
    }
}

async fn create_forged_authority_record(
    database_url: &str,
    admin: &tokio_postgres::Client,
    policy: &TrustedPolicy,
    issue_number: i64,
    state: &str,
    checkpoint: Option<&str>,
) -> Uuid {
    let id = Uuid::new_v4();
    let task = NewTask {
        task_id: id,
        repository: "example/project".into(),
        issue_number,
        base_sha: BASE_SHA.into(),
        max_attempts: 3,
        execution_timeout: Duration::from_secs(600),
        model_budget: 100,
        idempotency_key: Uuid::new_v4(),
    };
    let mut store = TaskStore::connect(database_url)
        .await
        .expect("connect disposable authority test store");
    store
        .create(&task)
        .await
        .expect("create authority test task");
    let open_facts = authority_facts(true, false);
    let lease = store
        .claim(id, "worker", Duration::from_secs(30), policy, &open_facts)
        .await
        .expect("claim task before constructing persisted test state");

    let head = STALE_SHA;
    let validation = serde_json::json!({
        "passed": true,
        "ci_observation": {
            "head_sha": head,
            "pull_request": 42,
            "status": "passed"
        }
    });
    admin
        .execute(
            "UPDATE orchestrator.tasks SET status='blocked', head_sha=$2, pr_number=42, validation_result=$3, checkpoint=jsonb_build_object('state','planning'), resume_state='planning', issue_assignee='worker', implementer='codex', reviewer='claude', session_id='postgres-authority-fixture' WHERE id=$1",
            &[&id, &head, &validation],
        )
        .await
        .expect("place task in releasable intermediate state");
    store
        .release(&lease)
        .await
        .expect("release setup lease before engine assertion");

    let checkpoint_json = checkpoint.map(|state| serde_json::json!({"state": state}));
    admin
        .execute(
            "UPDATE orchestrator.tasks SET status=$2::text::orchestrator.task_state, checkpoint=$3, resume_state=$4::text::orchestrator.task_state WHERE id=$1",
            &[&id, &state, &checkpoint_json, &checkpoint],
        )
        .await
        .expect("persist the deliberately forged authority state");
    id
}

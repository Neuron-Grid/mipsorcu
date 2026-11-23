//! Local-only demonstration of the real engine with in-memory adapters.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::Value;
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

#[cfg(test)]
use crate::engine::request_hash;

use crate::{
    agent::{
        AgentRequest, AgentRole, AgentSettings, AgentStage, Cancellation, Failure, MockAdapter,
        Outcome, Provider, TypedAgentAdapter,
    },
    domain::{self, CiObservation, CiStatus, ObservedFacts, State, TaskRecord, TrustedPolicy},
    engine::{
        Engine, EngineError, EngineStore, EvidenceSource, ExecutionBudget, MockCodeChange,
        MockPlan, OperationLookup, PostgresEngineStore, Stage, StageFailure, StageOutput,
        StageRunner, StepResult, TrustedPolicySource, mock_patch_digest, operation_key, stage_name,
    },
    mock_github::{
        MockGitHubAdapter, MockGitHubError, MockGitHubJournalEntry, MockGitHubOutput,
        MockGitHubPolicy, MockGitHubRequest,
    },
    postgres::{Lease, RecoveryVerifier, StoreError, TaskStore},
};

const TASK_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BASE_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HEAD_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const REPAIR_HEADS: [&str; 3] = [
    "cccccccccccccccccccccccccccccccccccccccc",
    "dddddddddddddddddddddddddddddddddddddddd",
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
];

fn head_for_attempt(attempt: u32) -> Result<&'static str, ()> {
    match attempt {
        0 => Ok(HEAD_SHA),
        1..=3 => REPAIR_HEADS
            .get(usize::try_from(attempt - 1).map_err(|_| ())?)
            .copied()
            .ok_or(()),
        _ => Err(()),
    }
}

#[derive(Clone)]
struct MemoryStore(Arc<Mutex<MemoryDb>>);

struct MemoryDb {
    task: TaskRecord,
    operations: HashMap<Uuid, OperationLookup>,
    stage_executions: usize,
    plan_executions: usize,
    fail_next_save: bool,
    fencing_token: i64,
}

impl MemoryStore {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MemoryDb>, StoreError> {
        self.0.lock().map_err(|_| StoreError::InvalidRecord)
    }

    fn lease(&self, task_id: Uuid, owner: &str) -> Result<Lease, StoreError> {
        let mut db = self.lock()?;
        db.fencing_token += 1;
        Ok(Lease {
            task_id,
            owner: owner.to_owned(),
            fencing_token: db.fencing_token,
        })
    }
}

impl EngineStore for MemoryStore {
    async fn get(&self, task_id: Uuid) -> Result<TaskRecord, StoreError> {
        let db = self.lock()?;
        if db.task.task_id != task_id.to_string() {
            return Err(StoreError::TaskMissing);
        }
        Ok(db.task.clone())
    }

    async fn claim(
        &self,
        task_id: Uuid,
        owner: &str,
        _: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        {
            let mut db = self.lock()?;
            if db.task.task_id != task_id.to_string() || db.task.state != State::Queued {
                return Err(StoreError::LeaseOccupied);
            }
            let mut candidate = db.task.clone();
            domain::transition(&mut candidate, State::Planning, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?;
            db.task = candidate;
        }
        self.lease(task_id, owner)
    }

    async fn recover(
        &self,
        _: Uuid,
        _: &str,
        _: Duration,
        _: &dyn RecoveryVerifier,
        _: &TrustedPolicy,
        _: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        Err(StoreError::RecoveryRejected)
    }

    async fn claim_handoff(
        &self,
        task_id: Uuid,
        owner: &str,
        _: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        let db = self.lock()?;
        if db.task.task_id != task_id.to_string() {
            return Err(StoreError::TaskMissing);
        }
        match db.task.state {
            State::Merging if facts.pr_merged => {
                let mut candidate = db.task.clone();
                domain::transition_from(&db.task, &mut candidate, State::Completed, policy, facts)
                    .map_err(|_| StoreError::InvalidRecord)?;
            }
            State::Merging => {}
            State::Completed => domain::validate_completed(&db.task, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?,
            _ => return Err(StoreError::InvalidRecord),
        }
        drop(db);
        self.lease(task_id, owner)
    }

    async fn claim_resume(
        &self,
        task_id: Uuid,
        owner: &str,
        _: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        {
            let mut db = self.lock()?;
            if db.task.task_id != task_id.to_string()
                || !matches!(db.task.state, State::Paused | State::Blocked)
            {
                return Err(StoreError::LeaseOccupied);
            }
            let checkpoint = db.task.checkpoint.ok_or(StoreError::InvalidRecord)?;
            let mut candidate = db.task.clone();
            domain::transition(&mut candidate, checkpoint, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?;
            db.task = candidate;
        }
        self.lease(task_id, owner)
    }

    async fn renew(&self, _: &Lease, _: Duration) -> Result<(), StoreError> {
        Ok(())
    }

    async fn renew_handoff_verification(
        &self,
        lease: &Lease,
        _: Duration,
        _: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<(), StoreError> {
        let db = self.lock()?;
        if db.task.task_id != lease.task_id.to_string() {
            return Err(StoreError::TaskMissing);
        }
        match db.task.state {
            State::Merging => {
                let mut completed = db.task.clone();
                domain::transition_from(&db.task, &mut completed, State::Completed, policy, facts)
                    .map_err(|_| StoreError::InvalidRecord)?;
            }
            State::Completed => domain::validate_completed(&db.task, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?,
            _ => return Err(StoreError::InvalidRecord),
        }
        Ok(())
    }

    async fn work_deadline_expired(
        &self,
        lease: &Lease,
        task: &TaskRecord,
        policy: &TrustedPolicy,
    ) -> Result<bool, StoreError> {
        if task.task_id != lease.task_id.to_string() {
            return Err(StoreError::LeaseLost);
        }
        Ok(task.elapsed >= policy.max_runtime)
    }

    async fn load(&self, lease: &Lease) -> Result<TaskRecord, StoreError> {
        let db = self.lock()?;
        if db.task.task_id != lease.task_id.to_string() {
            return Err(StoreError::TaskMissing);
        }
        Ok(db.task.clone())
    }

    async fn prepare_operation(
        &self,
        _: &Lease,
        key: Uuid,
        _: &str,
        _: &[u8; 32],
    ) -> Result<OperationLookup, StoreError> {
        let mut db = self.lock()?;
        match db.operations.get(&key) {
            Some(result @ OperationLookup::Completed { .. }) => Ok(result.clone()),
            Some(_) => Ok(OperationLookup::Ambiguous),
            None => {
                db.operations.insert(key, OperationLookup::New);
                Ok(OperationLookup::New)
            }
        }
    }

    async fn complete_operation(
        &self,
        lease: &Lease,
        key: Uuid,
        result: &Value,
        model_tokens: u64,
    ) -> Result<(), StoreError> {
        let mut db = self.lock()?;
        if !matches!(db.operations.get(&key), Some(OperationLookup::New)) {
            return Err(StoreError::OperationConflict);
        }
        db.task.model_tokens = db
            .task
            .model_tokens
            .checked_add(model_tokens)
            .ok_or(StoreError::InvalidRecord)?;
        db.operations.insert(
            key,
            OperationLookup::Completed {
                result: result.clone(),
                fencing_token: lease.fencing_token,
            },
        );
        Ok(())
    }

    async fn save(
        &self,
        lease: &Lease,
        expected: State,
        task: &TaskRecord,
        _: &TrustedPolicy,
        _: &ObservedFacts,
    ) -> Result<(), StoreError> {
        let mut db = self.lock()?;
        if db.fail_next_save {
            db.fail_next_save = false;
            return Err(StoreError::InvalidRecord);
        }
        if db.task.task_id != lease.task_id.to_string() || db.task.state != expected {
            return Err(StoreError::LeaseLost);
        }
        task.validate().map_err(|_| StoreError::InvalidRecord)?;
        db.task = task.clone();
        Ok(())
    }

    async fn save_handoff_completed(
        &self,
        lease: &Lease,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<(), StoreError> {
        if task.state != State::Completed || !facts.pr_merged || facts.issue_open {
            return Err(StoreError::InvalidRecord);
        }
        let mut db = self.lock()?;
        if db.task.task_id != lease.task_id.to_string() || db.task.state != State::Merging {
            return Err(StoreError::LeaseLost);
        }
        let mut proposed = task.clone();
        proposed.elapsed = db.task.elapsed;
        domain::transition_from(&db.task, &mut proposed, State::Completed, policy, facts)
            .map_err(|_| StoreError::InvalidRecord)?;
        let mut persisted = task.clone();
        persisted.elapsed = db.task.elapsed;
        if proposed != persisted {
            return Err(StoreError::InvalidRecord);
        }
        if db.fail_next_save {
            db.fail_next_save = false;
            return Err(StoreError::InvalidRecord);
        }
        db.task = persisted;
        Ok(())
    }

    async fn release(&self, _: &Lease) -> Result<(), StoreError> {
        Ok(())
    }
}

#[derive(Clone)]
struct MemoryPolicy(Arc<Mutex<TrustedPolicy>>);

impl TrustedPolicySource for MemoryPolicy {
    async fn load_policy(&self, _: &TaskRecord) -> Result<TrustedPolicy, ()> {
        self.0.lock().map_err(|_| ()).map(|policy| policy.clone())
    }
}

#[derive(Clone)]
struct MemoryEvidence(ObservedFacts);

impl EvidenceSource for MemoryEvidence {
    async fn observe(
        &self,
        task: &TaskRecord,
        policy: &TrustedPolicy,
    ) -> Result<ObservedFacts, ()> {
        let mut facts = self.0.clone();
        if let Some(value) = task.mock_github_journal.as_ref() {
            let implementer = task.implementer.as_deref().ok_or(())?;
            let reviewer = task.reviewer.as_deref().ok_or(())?;
            let provider = |value| match value {
                "codex" => Ok(Provider::Codex),
                "claude" => Ok(Provider::Claude),
                _ => Err(()),
            };
            let mock_policy = MockGitHubPolicy::with_agents(
                vec![policy.base_ref.clone()],
                policy.required_checks.clone(),
                provider(implementer)?,
                provider(reviewer)?,
            )
            .map_err(|_| ())?;
            let journal: Vec<MockGitHubJournalEntry> =
                serde_json::from_value(value.clone()).map_err(|_| ())?;
            let adapter = MockGitHubAdapter::restore(mock_policy, &journal).map_err(|_| ())?;
            facts.head_sha = task.head_sha.clone().unwrap_or_default();
            facts.validated_head_sha = None;
            facts.pr_number = task.pull_request;
            facts.pr_head_sha = None;
            facts.pr_base_ref = None;
            facts.pr_base_sha = None;
            facts.pr_merged = false;
            facts.merge_commit_sha = None;
            facts.base_contains_merge_commit = false;
            facts.checks_passed.clear();
            facts.reviewer_approved = false;
            facts.ci = None;
            if let Some(number) = task.pull_request {
                let head = task.head_sha.as_deref().ok_or(())?;
                let pull = adapter.pull_request(number).ok_or(())?;
                facts.pr_head_sha = Some(pull.head_sha.clone());
                facts.pr_base_ref = Some(pull.target.clone());
                facts.pr_base_sha = Some(task.base_sha.clone());
                facts.pr_merged = pull.merged;
                facts.merge_commit_sha = pull.merge_sha.clone();
                facts.base_contains_merge_commit = pull.merged;
                facts.checks_passed = adapter.checks_passed(head);
                facts.reviewer_approved = adapter.review_approved(head);
                let mut check_results = HashMap::new();
                for entry in &journal {
                    if let Ok(MockGitHubOutput::CheckUpdated {
                        head_sha,
                        name,
                        passed,
                    }) = &entry.result
                        && head_sha == &pull.head_sha
                        && policy.required_checks.contains(name)
                    {
                        check_results.insert(name.as_str(), *passed);
                    }
                }
                let status = if check_results.values().any(|passed| !passed) {
                    CiStatus::Failed
                } else if policy
                    .required_checks
                    .iter()
                    .all(|name| check_results.get(name.as_str()) == Some(&true))
                {
                    CiStatus::Passed
                } else {
                    CiStatus::Unknown
                };
                if task.validation_passed && status == CiStatus::Passed && pull.head_sha == head {
                    facts.validated_head_sha = Some(head.to_owned());
                }
                facts.ci = Some(CiObservation {
                    head_sha: pull.head_sha.clone(),
                    pull_request: number,
                    status,
                });
            }
        }
        Ok(facts)
    }
}

#[derive(Clone)]
struct MemoryRunner {
    db: Arc<Mutex<MemoryDb>>,
    github: Arc<Mutex<MockGitHubAdapter>>,
    settings: AgentSettings,
    scenario: MockScenario,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MockScenario {
    ci_failure_attempts: u32,
    review_changes_attempts: u32,
    cancel_stage: Option<Stage>,
    agent_failure: Option<(Stage, Failure)>,
    mock_github_failure: Option<(Stage, MockGitHubError)>,
}

impl MockScenario {
    pub const fn new() -> Self {
        Self {
            ci_failure_attempts: 0,
            review_changes_attempts: 0,
            cancel_stage: None,
            agent_failure: None,
            mock_github_failure: None,
        }
    }

    pub const fn with_ci_failure_attempts(mut self, attempts: u32) -> Self {
        self.ci_failure_attempts = attempts;
        self
    }

    pub const fn with_review_changes_attempts(mut self, attempts: u32) -> Self {
        self.review_changes_attempts = attempts;
        self
    }

    pub const fn with_cancelled_stage(mut self, stage: Stage) -> Self {
        self.cancel_stage = Some(stage);
        self
    }

    pub const fn with_agent_failure(mut self, stage: Stage, failure: Failure) -> Self {
        self.agent_failure = Some((stage, failure));
        self
    }

    pub const fn with_mock_github_failure(
        mut self,
        stage: Stage,
        failure: MockGitHubError,
    ) -> Self {
        self.mock_github_failure = Some((stage, failure));
        self
    }

    fn validate(&self) -> bool {
        self.ci_failure_attempts <= 4
            && self.review_changes_attempts <= 4
            && self.cancel_stage != Some(Stage::Merge)
            && self.agent_failure.is_none_or(|(stage, _)| {
                matches!(stage, Stage::Plan | Stage::Implement | Stage::Review)
                    && self.cancel_stage != Some(stage)
            })
            && self.mock_github_failure.is_none_or(|(stage, _)| {
                matches!(stage, Stage::Implement | Stage::Validate | Stage::Review)
            })
    }
}

/// Fixed inputs for a PostgreSQL-backed mock run. Reuse the same value after a
/// process restart so the immutable failure script and policy remain identical.
#[derive(Clone, Debug)]
pub struct PostgresMockConfig {
    pub policy: TrustedPolicy,
    pub facts: ObservedFacts,
    pub settings: AgentSettings,
    pub scenario: MockScenario,
    pub lease_ttl: Duration,
}

impl PostgresMockConfig {
    fn fingerprint(&self) -> Result<String, EngineError> {
        let settings =
            serde_json::to_value(&self.settings).map_err(|_| EngineError::InvalidConfiguration)?;
        let facts = &self.facts;
        let canonical = serde_json::json!({
            "mock_runtime_version": 1,
            "policy": {
                "base_ref": self.policy.base_ref,
                "base_sha": self.policy.base_sha,
                "allowed_assignee": self.policy.allowed_assignee,
                "required_checks": self.policy.required_checks,
                "max_attempts": self.policy.max_attempts,
                "max_runtime_seconds": self.policy.max_runtime.as_secs(),
                "max_runtime_subsec_nanos": self.policy.max_runtime.subsec_nanos(),
                "max_model_tokens": self.policy.max_model_tokens,
            },
            "facts": {
                "policy_base_ref": facts.policy_base_ref,
                "policy_base_sha": facts.policy_base_sha,
                "issue_open": facts.issue_open,
                "base_sha": facts.base_sha,
                "head_sha": facts.head_sha,
                "validated_head_sha": facts.validated_head_sha,
                "pr_number": facts.pr_number,
                "pr_head_sha": facts.pr_head_sha,
                "pr_base_ref": facts.pr_base_ref,
                "pr_base_sha": facts.pr_base_sha,
                "pr_merged": facts.pr_merged,
                "checks_passed": facts.checks_passed,
                "reviewer_approved": facts.reviewer_approved,
                "approved_assignee": facts.approved_assignee,
                "merge_commit_sha": facts.merge_commit_sha,
                "base_contains_merge_commit": facts.base_contains_merge_commit,
            },
            "settings": settings,
            "scenario": {
                "ci_failure_attempts": self.scenario.ci_failure_attempts,
                "review_changes_attempts": self.scenario.review_changes_attempts,
                "cancel_stage": self.scenario.cancel_stage.map(stage_name),
                "agent_failure": self.scenario.agent_failure.map(|(stage, failure)| {
                    serde_json::json!({ "stage": stage_name(stage), "failure": failure })
                }),
                "mock_github_failure": self.scenario.mock_github_failure.map(|(stage, failure)| {
                    serde_json::json!({ "stage": stage_name(stage), "failure": failure })
                }),
            },
            "lease_ttl_seconds": self.lease_ttl.as_secs(),
            "lease_ttl_subsec_nanos": self.lease_ttl.subsec_nanos(),
        });
        let bytes =
            serde_json::to_vec(&canonical).map_err(|_| EngineError::InvalidConfiguration)?;
        let digest = Sha3_256::digest(bytes);
        let mut hex = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut hex, "{byte:02x}").map_err(|_| EngineError::InvalidConfiguration)?;
        }
        Ok(hex)
    }
}

/// PostgreSQL state with local-only policy, evidence, agent, and GitHub adapters.
/// The caller supplies an already connected, disposable test database store; this
/// constructor does not create databases or apply migrations. Recovery requires
/// the caller-supplied supervisor verifier.
pub struct PostgresMockRuntime<V> {
    engine: Engine<PostgresEngineStore, MemoryPolicy, MemoryEvidence, MemoryRunner, V>,
}

impl<V: RecoveryVerifier + Sync> PostgresMockRuntime<V> {
    pub async fn connect(
        mut store: TaskStore,
        task_id: Uuid,
        config: PostgresMockConfig,
        recovery: V,
    ) -> Result<Self, EngineError> {
        config
            .settings
            .validate()
            .map_err(|_| EngineError::InvalidConfiguration)?;
        if !config.scenario.validate() {
            return Err(EngineError::InvalidConfiguration);
        }
        domain::validate_policy(&config.policy).map_err(|_| EngineError::InvalidConfiguration)?;
        if config.lease_ttl.as_secs() == 0
            || config.lease_ttl.subsec_nanos() != 0
            || i64::try_from(config.lease_ttl.as_secs()).is_err()
        {
            return Err(EngineError::InvalidConfiguration);
        }
        store.assert_mock_isolated_database().await?;
        let task = store.get(task_id).await?;
        task.validate().map_err(|_| EngineError::InvalidTask)?;
        if config.policy.max_attempts != 3
            || config.policy.max_attempts != task.max_attempts
            || config.policy.max_model_tokens != task.model_budget
            || config.policy.allowed_assignee != "mock-worker"
            || config.facts.approved_assignee != config.policy.allowed_assignee
            || !config.facts.issue_open
            || config.policy.base_ref == "main"
            || config.policy.base_ref != config.facts.policy_base_ref
            || config.policy.base_sha != config.facts.policy_base_sha
            || config.policy.base_sha != task.base_sha
            || config.policy.base_sha != config.facts.base_sha
        {
            return Err(EngineError::InvalidConfiguration);
        }
        let fingerprint = config.fingerprint()?;
        let github_policy = MockGitHubPolicy::with_agents(
            vec![config.policy.base_ref.clone()],
            config.policy.required_checks.clone(),
            config.settings.implementer,
            config.settings.reviewer,
        )
        .map_err(|_| EngineError::InvalidConfiguration)?;
        let github = Arc::new(Mutex::new(MockGitHubAdapter::new(github_policy)));
        store
            .bind_mock_runtime_config(task_id, &fingerprint)
            .await?;
        let memory = Arc::new(Mutex::new(MemoryDb {
            task,
            operations: HashMap::new(),
            stage_executions: 0,
            plan_executions: 0,
            fail_next_save: false,
            fencing_token: 0,
        }));
        Ok(Self {
            engine: Engine {
                store: PostgresEngineStore::new(store),
                policies: MemoryPolicy(Arc::new(Mutex::new(config.policy))),
                evidence: MemoryEvidence(config.facts),
                runner: MemoryRunner {
                    db: memory,
                    github: github.clone(),
                    settings: config.settings,
                    scenario: config.scenario,
                },
                recovery,
                mock_github: Some(github),
                lease_ttl: config.lease_ttl,
            },
        })
    }

    pub async fn run_one(&self, task_id: Uuid, owner: &str) -> Result<StepResult, EngineError> {
        self.engine.run_one(task_id, owner).await
    }

    pub async fn resume(&self, task_id: Uuid, owner: &str) -> Result<StepResult, EngineError> {
        self.engine.resume(task_id, owner).await
    }

    pub async fn recover_and_run(
        &self,
        prior: &Lease,
        owner: &str,
    ) -> Result<StepResult, EngineError> {
        self.engine.recover_and_run(prior, owner).await
    }

    pub async fn release_expired_blocked_lease(&self, prior: &Lease) -> Result<(), EngineError> {
        self.engine.release_expired_blocked_lease(prior).await
    }
}

impl StageRunner for MemoryRunner {
    fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError> {
        self.settings.validate()
    }

    fn agent_roles(&self) -> (Provider, Provider) {
        (self.settings.implementer, self.settings.reviewer)
    }

    fn supports_cancellation(&self) -> bool {
        true
    }

    async fn execute(
        &self,
        lease: &Lease,
        operation_id: Uuid,
        stage: Stage,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        budget: ExecutionBudget,
    ) -> Result<StageOutput, StageFailure> {
        self.execute_with_cancellation(
            lease,
            operation_id,
            stage,
            task,
            policy,
            budget,
            Cancellation::default(),
        )
        .await
    }

    async fn execute_with_cancellation(
        &self,
        lease: &Lease,
        operation_id: Uuid,
        stage: Stage,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        budget: ExecutionBudget,
        cancellation: Cancellation,
    ) -> Result<StageOutput, StageFailure> {
        self.validate_configuration()
            .map_err(|_| StageFailure::InvalidConfiguration)?;
        if cancellation.cancelled() {
            return Err(StageFailure::Cancelled);
        }
        let task_id = Uuid::parse_str(&task.task_id).map_err(|_| StageFailure::InvalidInput)?;
        if lease.task_id != task_id || lease.fencing_token <= 0 {
            return Err(StageFailure::InvalidInput);
        }
        let state = match stage {
            Stage::Implement if task.attempts == 0 => State::Implementing,
            Stage::Implement => State::Repairing,
            Stage::Validate => State::Validating,
            Stage::Review => State::Reviewing,
            Stage::Plan => State::Planning,
            Stage::Merge => return Err(StageFailure::InvalidConfiguration),
        };
        let stage_operation = operation_key(task_id, task.attempts, state, stage);
        if operation_id != stage_operation {
            return Err(StageFailure::InvalidInput);
        }
        let ci_failure =
            stage == Stage::Validate && task.attempts < self.scenario.ci_failure_attempts;
        let review_changes =
            stage == Stage::Review && task.attempts < self.scenario.review_changes_attempts;
        let cancel = self.scenario.cancel_stage == Some(stage);
        let agent = match stage {
            Stage::Plan | Stage::Implement => Some((Provider::Codex, Outcome::Completed)),
            Stage::Review => Some((
                Provider::Claude,
                if review_changes {
                    Outcome::ChangesRequested
                } else {
                    Outcome::Approved
                },
            )),
            Stage::Validate | Stage::Merge => None,
        };
        if let Some((provider, expected)) = agent {
            let (agent_stage, role) = match stage {
                Stage::Plan => (AgentStage::Plan, AgentRole::Implementer),
                Stage::Implement => (AgentStage::Implement, AgentRole::Implementer),
                Stage::Review => (AgentStage::Review, AgentRole::Reviewer),
                Stage::Validate | Stage::Merge => {
                    return Err(StageFailure::InvalidConfiguration);
                }
            };
            let request = AgentRequest {
                task_id,
                operation_id: stage_operation,
                stage: agent_stage,
                role,
                attempt: task.attempts,
            };
            let agent_result = self
                .scenario
                .agent_failure
                .filter(|(failure_stage, _)| *failure_stage == stage)
                .map_or(Ok(expected), |(_, failure)| Err(failure));
            let mut adapter = MockAdapter::new(provider, Duration::ZERO, agent_result);
            if cancel {
                cancellation.cancel();
            }
            match adapter
                .execute_request(request, cancellation, budget.remaining_runtime)
                .await
            {
                Ok(actual) if actual == expected => {}
                Ok(_) => return Err(StageFailure::Agent(Failure::InvalidSession)),
                Err(Failure::Cancelled) => return Err(StageFailure::Cancelled),
                Err(Failure::Timeout) => return Err(StageFailure::Timeout),
                Err(failure) => return Err(StageFailure::Agent(failure)),
            }
        } else if cancel {
            return Err(StageFailure::Cancelled);
        }
        if let Some((_, failure)) = self
            .scenario
            .mock_github_failure
            .filter(|(failure_stage, _)| *failure_stage == stage)
        {
            return Err(StageFailure::MockGitHub(failure));
        }
        let mut db = self.db.lock().map_err(|_| StageFailure::Internal)?;
        db.stage_executions += 1;
        if stage == Stage::Plan {
            db.plan_executions += 1;
        }
        let mut github = self.github.lock().map_err(|_| StageFailure::Internal)?;
        let _github_policy = MockGitHubPolicy::with_agents(
            vec![policy.base_ref.clone()],
            policy.required_checks.clone(),
            self.settings.implementer,
            self.settings.reviewer,
        )
        .map_err(|_| StageFailure::InvalidConfiguration)?;
        let journal: Vec<MockGitHubJournalEntry> = task
            .mock_github_journal
            .as_ref()
            .map(|value| {
                serde_json::from_value(value.clone())
                    .map_err(|_| StageFailure::InvalidOperationResult)
            })
            .transpose()?
            .unwrap_or_default();
        github
            .restore_journal(&journal)
            .map_err(|_| StageFailure::InvalidOperationResult)?;
        let operation = |suffix: &str| format!("{stage_operation}:{suffix}");
        let branch = format!("orchestrator/{}", task.task_id);
        let new_head = head_for_attempt(task.attempts)
            .map_err(|_| StageFailure::InvalidInput)?
            .to_owned();
        let mut assignee = None;
        let mut implementer = None;
        let mut reviewer = None;
        let mut head_sha = None;
        let mut pull_request = None;
        let mut validation_passed = false;
        match stage {
            Stage::Plan => {
                assignee = Some("mock-worker".into());
                implementer = Some("codex".into());
                reviewer = Some("claude".into());
            }
            Stage::Implement => {
                if task.attempts == 0 {
                    github
                        .execute(
                            &operation("branch"),
                            MockGitHubRequest::CreateBranch {
                                branch: branch.clone(),
                                base_sha: task.base_sha.clone(),
                            },
                        )
                        .map_err(StageFailure::MockGitHub)?;
                }
                github
                    .execute(
                        &operation("push"),
                        MockGitHubRequest::CommitPush {
                            branch: branch.clone(),
                            expected_head_sha: task
                                .head_sha
                                .clone()
                                .unwrap_or_else(|| task.base_sha.clone()),
                            new_head_sha: new_head.clone(),
                        },
                    )
                    .map_err(StageFailure::MockGitHub)?;
                head_sha = Some(new_head.clone());
            }
            Stage::Validate => {
                let output = github
                    .execute(
                        &operation("pull"),
                        MockGitHubRequest::UpsertPullRequest {
                            branch,
                            target: policy.base_ref.clone(),
                            title: format!("Mock task {}", task.issue_number),
                        },
                    )
                    .map_err(StageFailure::MockGitHub)?;
                let MockGitHubOutput::PullRequest(pull) = output else {
                    return Err(StageFailure::InvalidOperationResult);
                };
                for check in &policy.required_checks {
                    github
                        .execute(
                            &operation(&format!("check-{check}")),
                            MockGitHubRequest::SetCheck {
                                head_sha: new_head.clone(),
                                name: check.clone(),
                                passed: !ci_failure,
                            },
                        )
                        .map_err(StageFailure::MockGitHub)?;
                }
                let checks = github
                    .execute(
                        &operation("read-checks"),
                        MockGitHubRequest::GetChecks {
                            head_sha: new_head.clone(),
                        },
                    )
                    .map_err(StageFailure::MockGitHub)?;
                validation_passed = matches!(checks, MockGitHubOutput::CiResults { checks, .. } if checks.iter().all(|(_, passed)| *passed));
                pull_request = Some(pull.number);
                head_sha = Some(new_head.clone());
            }
            Stage::Review => {
                github
                    .execute(
                        &operation("review"),
                        MockGitHubRequest::SetReview {
                            head_sha: new_head.clone(),
                            reviewer: self.settings.reviewer,
                            approved: !review_changes,
                        },
                    )
                    .map_err(StageFailure::MockGitHub)?;
                validation_passed = !review_changes;
                head_sha = Some(new_head);
                pull_request = task.pull_request;
            }
            Stage::Merge => return Err(StageFailure::InvalidConfiguration),
        }
        let mock_github_journal = Some(
            serde_json::to_value(github.journal())
                .map_err(|_| StageFailure::InvalidOperationResult)?,
        );
        let plan = (stage == Stage::Plan).then(|| MockPlan {
            requirements: vec!["complete the requested mock task".into()],
            steps: vec!["implement".into(), "validate".into(), "review".into()],
        });
        let code_change = if stage == Stage::Implement {
            let summary = "apply the deterministic mock change".to_owned();
            let changed_files = vec!["src/mock_generated.rs".to_owned()];
            let patch_digest = mock_patch_digest(&summary, &changed_files)
                .ok_or(StageFailure::InvalidOperationResult)?;
            Some(MockCodeChange {
                summary,
                changed_files,
                patch_digest,
            })
        } else {
            None
        };
        Ok(StageOutput {
            assignee,
            implementer,
            reviewer,
            session_id: (stage == Stage::Plan).then(|| format!("mock-session-{}", task.task_id)),
            head_sha,
            pull_request,
            validation_passed,
            local_validation_passed: None,
            model_tokens: if stage == Stage::Validate { 0 } else { 1 },
            mock_github_journal,
            plan,
            code_change,
        })
    }

    async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
        Ok(())
    }
}

struct NoRecovery;

impl RecoveryVerifier for NoRecovery {
    fn verify_stopped(&self, _: Uuid, _: &str, _: i64) -> Option<Value> {
        None
    }
}

#[cfg(test)]
fn pg_policy(max_model_tokens: u64) -> TrustedPolicy {
    TrustedPolicy {
        base_ref: "develop".into(),
        base_sha: BASE_SHA.into(),
        allowed_assignee: "mock-worker".into(),
        required_checks: vec!["mock-check".into()],
        max_attempts: 3,
        max_runtime: Duration::from_secs(600),
        max_model_tokens,
    }
}

#[cfg(test)]
fn pg_facts() -> ObservedFacts {
    ObservedFacts {
        policy_base_ref: "develop".into(),
        policy_base_sha: BASE_SHA.into(),
        issue_open: true,
        base_sha: BASE_SHA.into(),
        approved_assignee: "mock-worker".into(),
        ..ObservedFacts::default()
    }
}

#[cfg(test)]
fn pg_mock_config() -> PostgresMockConfig {
    pg_mock_config_with_scenario(MockScenario::new().with_ci_failure_attempts(1))
}

#[cfg(test)]
fn pg_mock_config_with_scenario(scenario: MockScenario) -> PostgresMockConfig {
    PostgresMockConfig {
        policy: pg_policy(100),
        facts: pg_facts(),
        settings: AgentSettings::approved_mock_defaults(),
        scenario,
        lease_ttl: Duration::from_secs(30),
    }
}

#[cfg(test)]
// Test supervisor observes only the spawned test worker's exit; it is not a
// production process-tree verifier.
struct ObservedChildExit {
    owner: String,
    fencing_token: i64,
}

#[cfg(test)]
impl RecoveryVerifier for ObservedChildExit {
    fn verify_stopped(&self, _: Uuid, owner: &str, fencing_token: i64) -> Option<Value> {
        (owner == self.owner && fencing_token == self.fencing_token)
            .then(|| serde_json::json!({"test_child_exit_observed": true}))
    }
}

#[cfg(test)]
fn pg_plan_output(task_id: Uuid) -> StageOutput {
    StageOutput {
        assignee: Some("mock-worker".into()),
        implementer: Some("codex".into()),
        reviewer: Some("claude".into()),
        session_id: Some(format!("mock-session-{task_id}")),
        head_sha: None,
        pull_request: None,
        validation_passed: false,
        local_validation_passed: None,
        model_tokens: 1,
        mock_github_journal: None,
        plan: Some(MockPlan {
            requirements: vec!["complete the requested mock task".into()],
            steps: vec!["implement".into(), "validate".into(), "review".into()],
        }),
        code_change: None,
    }
}

type DemoEngine = Engine<MemoryStore, MemoryPolicy, MemoryEvidence, MemoryRunner, NoRecovery>;
type SharedPolicy = Arc<Mutex<TrustedPolicy>>;
type DemoFixture = (DemoEngine, Uuid, Arc<Mutex<MemoryDb>>, SharedPolicy);

fn fixture() -> Result<DemoFixture, String> {
    let task_id = Uuid::parse_str(TASK_ID).map_err(|_| "invalid mock task id".to_owned())?;
    let policy = TrustedPolicy {
        base_ref: "develop".into(),
        base_sha: BASE_SHA.into(),
        allowed_assignee: "mock-worker".into(),
        required_checks: vec!["mock-check".into()],
        max_attempts: 3,
        max_runtime: Duration::from_secs(600),
        max_model_tokens: 2,
    };
    let facts = ObservedFacts {
        policy_base_ref: policy.base_ref.clone(),
        policy_base_sha: policy.base_sha.clone(),
        issue_open: true,
        base_sha: policy.base_sha.clone(),
        head_sha: HEAD_SHA.into(),
        validated_head_sha: None,
        pr_number: None,
        pr_head_sha: None,
        pr_base_ref: None,
        pr_base_sha: None,
        pr_merged: false,
        checks_passed: Vec::new(),
        reviewer_approved: false,
        approved_assignee: policy.allowed_assignee.clone(),
        merge_commit_sha: None,
        base_contains_merge_commit: false,
        ci: None,
    };
    let task = TaskRecord {
        task_id: task_id.to_string(),
        issue_number: 1,
        base_sha: BASE_SHA.into(),
        max_attempts: 3,
        head_sha: None,
        state: State::Queued,
        attempts: 0,
        assignee: None,
        implementer: None,
        reviewer: None,
        session_id: None,
        mock_github_journal: None,
        mock_runtime_fingerprint: None,
        validation_passed: false,
        pull_request: None,
        checkpoint: None,
        elapsed: Duration::ZERO,
        model_tokens: 0,
        model_budget: 100,
    };
    let db = Arc::new(Mutex::new(MemoryDb {
        task,
        operations: HashMap::new(),
        stage_executions: 0,
        plan_executions: 0,
        fail_next_save: true,
        fencing_token: 0,
    }));
    let policy = Arc::new(Mutex::new(policy));
    let github_policy = MockGitHubPolicy::new(vec!["develop".into()], vec!["mock-check".into()])
        .map_err(|_| "mock GitHub policy is invalid".to_owned())?;
    let github = Arc::new(Mutex::new(MockGitHubAdapter::new(github_policy)));
    let engine = Engine {
        store: MemoryStore(db.clone()),
        policies: MemoryPolicy(policy.clone()),
        evidence: MemoryEvidence(facts),
        runner: MemoryRunner {
            db: db.clone(),
            github: github.clone(),
            settings: AgentSettings::approved_mock_defaults(),
            scenario: MockScenario::default(),
        },
        recovery: NoRecovery,
        mock_github: Some(github),
        lease_ttl: Duration::from_secs(30),
    };
    Ok((engine, task_id, db, policy))
}

pub async fn run_demo() -> Result<(), String> {
    let (engine, task_id, db, policy) = fixture()?;
    let snapshot = engine
        .store
        .get(task_id)
        .await
        .map_err(|_| "mock task lookup failed".to_owned())?;
    let policy_snapshot = engine
        .policies
        .load_policy(&snapshot)
        .await
        .map_err(|_| "mock policy lookup failed".to_owned())?;
    let facts = engine
        .evidence
        .observe(&snapshot, &policy_snapshot)
        .await
        .map_err(|_| "mock evidence lookup failed".to_owned())?;
    let lease = engine
        .store
        .claim(
            task_id,
            "mock-demo",
            engine.lease_ttl,
            &policy_snapshot,
            &facts,
        )
        .await
        .map_err(|_| "mock task claim failed".to_owned())?;

    // The mock store fails the first state save after the operation result has
    // been recorded. Calling the real engine again must replay that result.
    if !matches!(
        engine.run_claimed(&lease).await,
        Err(EngineError::Store(StoreError::InvalidRecord))
    ) {
        return Err("mock did not reach the simulated post-operation crash point".into());
    }
    let executions_after_crash = db
        .lock()
        .map_err(|_| "mock store lock failed".to_owned())?
        .stage_executions;
    println!("mock engine crash point: operation completed; state save failed");

    let paused = engine
        .run_claimed(&lease)
        .await
        .map_err(|error| format!("mock engine replay failed: {error:?}"))?;
    if paused != StepResult::Advanced(State::Paused) {
        return Err("mock engine did not pause at the configured token budget".into());
    }
    let (state, checkpoint, replay_execution_count, plan_execution_count) = {
        let db = db.lock().map_err(|_| "mock store lock failed".to_owned())?;
        (
            db.task.state,
            db.task.checkpoint,
            db.stage_executions,
            db.plan_executions,
        )
    };
    if executions_after_crash != 1 || plan_execution_count != 1 {
        return Err("engine replay executed the completed operation more than once".into());
    }
    println!(
        "mock engine replay: state={state:?}, checkpoint={checkpoint:?}, plan executions={plan_execution_count}, total executions={replay_execution_count}"
    );

    policy
        .lock()
        .map_err(|_| "mock policy lock failed".to_owned())?
        .max_model_tokens = 100;
    let resumed = engine
        .resume(task_id, "mock-demo-resume")
        .await
        .map_err(|error| format!("mock engine resume failed: {error:?}"))?;
    if resumed != StepResult::Finished {
        return Err("mock engine did not finish the simulated merge loop".into());
    }
    let final_task = engine
        .store
        .get(task_id)
        .await
        .map_err(|_| "mock final task lookup failed".to_owned())?;
    let executions = db
        .lock()
        .map_err(|_| "mock store lock failed".to_owned())?
        .stage_executions;
    let merged = final_task
        .mock_github_journal
        .as_ref()
        .and_then(|value| serde_json::from_value::<Vec<MockGitHubJournalEntry>>(value.clone()).ok())
        .is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| matches!(entry.result, Ok(MockGitHubOutput::SimulatedMerge { .. })))
        });
    if final_task.state != State::Completed || !merged {
        return Err("mock merge journal did not validate as completed".into());
    }
    println!(
        "mock engine resumed: state={:?}, simulated merge={merged}, stage executions={executions}",
        final_task.state
    );
    println!(
        "simulation only: no PostgreSQL, external GitHub, Git, filesystem write, or model was used"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mock_github::MockPullRequest,
        postgres::{NewTask, TaskStore},
    };
    use std::process::Command;
    use std::{net::IpAddr, str::FromStr};
    use tokio_postgres::{Config, NoTls, config::Host};

    async fn run_scenario(
        scenario: MockScenario,
    ) -> Result<(StepResult, TaskRecord, usize), String> {
        let (engine, task_id, db, policy) = fixture()?;
        policy
            .lock()
            .map_err(|_| "policy lock failed".to_owned())?
            .max_model_tokens = 100;
        db.lock()
            .map_err(|_| "store lock failed".to_owned())?
            .fail_next_save = false;
        // Scenario outcomes derive from the durable attempt number, so rebuilding
        // the runner after a process restart reproduces the same result.
        let engine = Engine {
            runner: MemoryRunner {
                scenario,
                ..engine.runner.clone()
            },
            ..engine
        };
        let result = engine
            .run_one(task_id, "mock-test")
            .await
            .map_err(|error| format!("mock run failed: {error:?}"))?;
        let task = engine
            .store
            .get(task_id)
            .await
            .map_err(|_| "task read failed".to_owned())?;
        let executions = db
            .lock()
            .map_err(|_| "store lock failed".to_owned())?
            .stage_executions;
        Ok((result, task, executions))
    }

    #[tokio::test]
    async fn t01_mock_only_run_reaches_completed_and_records_simulated_merge() {
        let (result, task, executions) = run_scenario(MockScenario::default()).await.unwrap();
        assert_eq!(result, StepResult::Finished);
        assert_eq!(task.state, State::Completed);
        assert_eq!(task.attempts, 0);
        assert_eq!(executions, 4);
        let entries: Vec<MockGitHubJournalEntry> =
            serde_json::from_value(task.mock_github_journal.unwrap()).unwrap();
        assert!(matches!(
            entries.last().map(|entry| &entry.result),
            Some(Ok(MockGitHubOutput::SimulatedMerge { .. }))
        ));
    }

    #[tokio::test]
    async fn t02_ci_failure_repairs_then_completes() {
        let (result, task, _) = run_scenario(MockScenario {
            ci_failure_attempts: 1,
            ..MockScenario::default()
        })
        .await
        .unwrap();
        assert_eq!(result, StepResult::Finished);
        assert_eq!(task.state, State::Completed);
        assert_eq!(task.attempts, 1);
        let entries: Vec<MockGitHubJournalEntry> =
            serde_json::from_value(task.mock_github_journal.unwrap()).unwrap();
        let pulls: Vec<MockPullRequest> = entries
            .iter()
            .filter_map(|entry| match &entry.result {
                Ok(MockGitHubOutput::PullRequest(pull)) => Some(pull.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(pulls.len(), 2);
        assert_eq!(pulls[0].number, pulls[1].number);
        assert_ne!(pulls[0].head_sha, pulls[1].head_sha);
        assert_eq!(pulls[0].head_sha, HEAD_SHA);
        assert_eq!(pulls[1].head_sha, REPAIR_HEADS[0]);
        assert!(entries.iter().any(|entry| matches!(
            &entry.result,
            Ok(MockGitHubOutput::CheckUpdated { head_sha, passed: false, .. }) if head_sha == HEAD_SHA
        )));
        assert!(entries.iter().any(|entry| matches!(
            &entry.result,
            Ok(MockGitHubOutput::CheckUpdated { head_sha, passed: true, .. }) if head_sha == REPAIR_HEADS[0]
        )));
    }

    #[tokio::test]
    async fn t03_review_changes_requested_repairs_revalidates_and_completes() {
        let (result, task, _) = run_scenario(MockScenario {
            review_changes_attempts: 1,
            ..MockScenario::default()
        })
        .await
        .unwrap();
        assert_eq!(result, StepResult::Finished);
        assert_eq!(task.state, State::Completed);
        assert_eq!(task.attempts, 1);
        let entries: Vec<MockGitHubJournalEntry> =
            serde_json::from_value(task.mock_github_journal.unwrap()).unwrap();
        let pulls: Vec<MockPullRequest> = entries
            .iter()
            .filter_map(|entry| match &entry.result {
                Ok(MockGitHubOutput::PullRequest(pull)) => Some(pull.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(pulls.len(), 2);
        assert_eq!(pulls[0].number, pulls[1].number);
        assert_ne!(pulls[0].head_sha, pulls[1].head_sha);
        assert!(entries.iter().any(|entry| matches!(
            &entry.result,
            Ok(MockGitHubOutput::ReviewUpdated { head_sha, approved: false }) if head_sha == HEAD_SHA
        )));
        assert!(entries.iter().any(|entry| matches!(
            &entry.result,
            Ok(MockGitHubOutput::ReviewUpdated { head_sha, approved: true }) if head_sha == REPAIR_HEADS[0]
        )));
    }

    #[tokio::test]
    async fn t04_repair_limit_stops_after_three_repairs() {
        let (result, task, _) = run_scenario(MockScenario {
            ci_failure_attempts: 4,
            ..MockScenario::default()
        })
        .await
        .unwrap();
        assert_eq!(result, StepResult::Advanced(State::Paused));
        assert_eq!(task.state, State::Paused);
        assert_eq!(task.attempts, 3);
        assert_eq!(task.checkpoint, Some(State::Validating));
    }

    #[tokio::test]
    async fn t14_cancelled_agent_blocks_without_discarding_checkpoint_data() {
        let (result, task, _) = run_scenario(MockScenario {
            cancel_stage: Some(Stage::Implement),
            ..MockScenario::default()
        })
        .await
        .unwrap();
        assert_eq!(
            result,
            StepResult::BlockedStageFailure(StageFailure::Cancelled)
        );
        assert_eq!(task.state, State::Blocked);
        assert_eq!(task.head_sha, None);
        assert_eq!(task.checkpoint, Some(State::Implementing));
    }

    #[tokio::test]
    async fn cancelled_engine_token_prevents_mock_stage_side_effects() {
        let (engine, task_id, db, policy) = fixture().unwrap();
        let task = db.lock().unwrap().task.clone();
        let policy = policy.lock().unwrap().clone();
        let lease = Lease {
            task_id,
            owner: "worker".into(),
            fencing_token: 1,
        };
        let cancellation = Cancellation::default();
        cancellation.cancel();
        let result = engine
            .runner
            .execute_with_cancellation(
                &lease,
                operation_key(task_id, 0, State::Planning, Stage::Plan),
                Stage::Plan,
                &task,
                &policy,
                ExecutionBudget {
                    remaining_runtime: Duration::from_secs(1),
                    remaining_model_tokens: 100,
                },
                cancellation,
            )
            .await;
        assert!(matches!(result, Err(StageFailure::Cancelled)));
        assert_eq!(db.lock().unwrap().stage_executions, 0);
    }

    #[tokio::test]
    async fn mock_agent_failure_is_returned_as_a_structured_block_reason() {
        let (result, task, _) =
            run_scenario(MockScenario::new().with_agent_failure(Stage::Plan, Failure::Unavailable))
                .await
                .unwrap();
        assert_eq!(
            result,
            StepResult::BlockedStageFailure(StageFailure::Agent(Failure::Unavailable))
        );
        assert_eq!(task.state, State::Blocked);
        assert_eq!(task.checkpoint, Some(State::Planning));
    }

    #[tokio::test]
    async fn mock_github_failure_is_returned_as_a_structured_block_reason() {
        let (result, task, _) = run_scenario(
            MockScenario::new()
                .with_mock_github_failure(Stage::Implement, MockGitHubError::HeadMismatch),
        )
        .await
        .unwrap();
        assert_eq!(
            result,
            StepResult::BlockedStageFailure(StageFailure::MockGitHub(
                MockGitHubError::HeadMismatch
            ))
        );
        assert_eq!(task.state, State::Blocked);
        assert_eq!(task.checkpoint, Some(State::Implementing));
    }

    #[tokio::test]
    #[ignore = "requires a fresh isolated orchestrator_test_* PostgreSQL database"]
    async fn postgres_mock_loop_survives_child_process_crash_and_scripted_ci_repair() {
        let database_url = std::env::var("MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL")
            .expect("set MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL to a disposable test database");
        TaskStore::connect(&database_url)
            .await
            .expect("connect disposable mock test database")
            .assert_mock_isolated_database()
            .await
            .expect("require orchestrator_test_* database and non-superuser test role");
        if let Ok(phase) = std::env::var("MIPSORCU_MOCK_RESTART_PHASE") {
            let task_id = Uuid::parse_str(
                &std::env::var("MIPSORCU_MOCK_RESTART_TASK_ID").expect("child task ID"),
            )
            .expect("valid child task ID");
            match phase.as_str() {
                "plan" => {
                    let binder = PostgresMockRuntime::connect(
                        TaskStore::connect(&database_url)
                            .await
                            .expect("connect config binder"),
                        task_id,
                        pg_mock_config(),
                        NoRecovery,
                    )
                    .await
                    .expect("bind fixed mock configuration before claim");
                    drop(binder);
                    let store = PostgresEngineStore::new(
                        TaskStore::connect(&database_url)
                            .await
                            .expect("connect first process store"),
                    );
                    let policy = pg_policy(100);
                    let facts = pg_facts();
                    store.get(task_id).await.expect("load queued task");
                    let lease = store
                        .claim(
                            task_id,
                            "mock-process-1",
                            Duration::from_secs(1),
                            &policy,
                            &facts,
                        )
                        .await
                        .expect("claim task before crash");
                    let task = store.load(&lease).await.expect("load planning task");
                    let key = operation_key(task_id, task.attempts, State::Planning, Stage::Plan);
                    let hash = request_hash(&task, Stage::Plan);
                    assert_eq!(
                        store
                            .prepare_operation(&lease, key, "plan", &hash)
                            .await
                            .expect("prepare plan operation"),
                        OperationLookup::New
                    );
                    let output = pg_plan_output(task_id);
                    let serialized = serde_json::to_value(output).expect("serialize plan output");
                    store
                        .complete_operation(&lease, key, &serialized, 1)
                        .await
                        .expect("persist operation result before crash");
                    // Simulate abrupt termination after operation commit and before task checkpoint save.
                    std::process::exit(86);
                }
                "resume" => {
                    let owner = std::env::var("MIPSORCU_MOCK_RESTART_LEASE_OWNER")
                        .expect("expired lease owner");
                    let fencing_token = std::env::var("MIPSORCU_MOCK_RESTART_FENCING_TOKEN")
                        .expect("expired fencing token")
                        .parse()
                        .expect("valid fencing token");
                    let prior = Lease {
                        task_id,
                        owner: owner.clone(),
                        fencing_token,
                    };
                    let changed_config = PostgresMockRuntime::connect(
                        TaskStore::connect(&database_url)
                            .await
                            .expect("connect mismatched-config process store"),
                        task_id,
                        pg_mock_config_with_scenario(MockScenario::new()),
                        ObservedChildExit {
                            owner: owner.clone(),
                            fencing_token,
                        },
                    )
                    .await;
                    assert!(
                        changed_config.is_err(),
                        "restart with a changed CI failure script must be rejected"
                    );
                    let runtime = PostgresMockRuntime::connect(
                        TaskStore::connect(&database_url)
                            .await
                            .expect("connect recovery process store"),
                        task_id,
                        pg_mock_config(),
                        ObservedChildExit {
                            owner,
                            fencing_token,
                        },
                    )
                    .await
                    .expect("assemble PostgreSQL mock runtime");
                    assert_eq!(
                        runtime
                            .recover_and_run(&prior, "mock-process-2")
                            .await
                            .unwrap(),
                        StepResult::Finished
                    );
                    return;
                }
                _ => panic!("unknown child phase"),
            }
        }
        let config = Config::from_str(&database_url).expect("valid test database URL");
        let loopback = config.get_hosts().iter().all(|host| match host {
            Host::Tcp(host) => IpAddr::from_str(host).is_ok_and(|ip| ip.is_loopback()),
            Host::Unix(_) => true,
        });
        assert!(loopback, "test database must be loopback or Unix socket");
        assert!(
            config
                .get_dbname()
                .is_some_and(|name| name.starts_with("orchestrator_test_")),
            "test database name must start with orchestrator_test_"
        );
        assert_eq!(
            config.get_user(),
            Some("orchestrator_test"),
            "test database must use the dedicated non-production role"
        );

        let (bootstrap, connection) = tokio_postgres::connect(&database_url, NoTls)
            .await
            .expect("connect isolated database");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let role_is_superuser: bool = bootstrap
            .query_one(
                "SELECT rolsuper FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .expect("inspect dedicated test role")
            .get(0);
        assert!(
            !role_is_superuser,
            "test role must not be a PostgreSQL superuser"
        );
        let schema_count: i64 = bootstrap
            .query_one(
                "SELECT count(*) FROM pg_namespace WHERE nspname = 'orchestrator'",
                &[],
            )
            .await
            .expect("inspect orchestrator schema")
            .get(0);
        let public_objects: i64 = bootstrap
            .query_one("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','v','m','S','f','p')", &[])
            .await
            .expect("inspect public objects")
            .get(0);
        assert_eq!(
            (schema_count, public_objects),
            (0, 0),
            "database must be fresh"
        );
        bootstrap
            .batch_execute(include_str!("../migrations/0001_orchestrator.sql"))
            .await
            .expect("apply orchestrator schema");
        bootstrap
            .batch_execute(include_str!("../migrations/0002_execution_metadata.sql"))
            .await
            .expect("apply execution metadata migration");
        bootstrap
            .batch_execute(include_str!(
                "../migrations/0003_mock_runtime_fingerprint.sql"
            ))
            .await
            .expect("apply mock runtime fingerprint migration");
        let task_id = Uuid::new_v4();
        let store = TaskStore::connect(&database_url)
            .await
            .expect("connect task store");
        store
            .create(&NewTask {
                task_id,
                repository: "example/project".into(),
                issue_number: 1,
                base_sha: BASE_SHA.into(),
                max_attempts: 3,
                execution_timeout: Duration::from_secs(600),
                model_budget: 100,
                idempotency_key: Uuid::new_v4(),
            })
            .await
            .expect("create queued task");
        let child = |phase: &str| {
            Command::new(std::env::current_exe().expect("current test binary"))
                .args([
                    "--exact",
                    "mock::tests::postgres_mock_loop_survives_child_process_crash_and_scripted_ci_repair",
                    "--ignored",
                    "--nocapture",
                ])
                .env_clear()
                .env("MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL", &database_url)
                .env("MIPSORCU_MOCK_RESTART_PHASE", phase)
                .env("MIPSORCU_MOCK_RESTART_TASK_ID", task_id.to_string())
                .output()
                .expect("run isolated child process")
        };
        let crashed = child("plan");
        assert_eq!(
            crashed.status.code(),
            Some(86),
            "first child must exit at the crash point: {}",
            String::from_utf8_lossy(&crashed.stderr)
        );
        let checkpoint = store.get(task_id).await.expect("read child checkpoint");
        assert_eq!(checkpoint.state, State::Planning);
        assert_eq!(checkpoint.model_tokens, 1);
        assert_eq!(checkpoint.session_id, None);
        let lease_row = bootstrap
            .query_one(
                "SELECT owner, fencing_token FROM orchestrator.execution_lease WHERE task_id = $1",
                &[&task_id],
            )
            .await
            .expect("read abandoned active lease");
        let owner: String = lease_row.get(0);
        let fencing_token: i64 = lease_row.get(1);
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let resumed = Command::new(std::env::current_exe().expect("current test binary"))
            .args([
                "--exact",
                "mock::tests::postgres_mock_loop_survives_child_process_crash_and_scripted_ci_repair",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL", &database_url)
            .env("MIPSORCU_MOCK_RESTART_PHASE", "resume")
            .env("MIPSORCU_MOCK_RESTART_TASK_ID", task_id.to_string())
            .env("MIPSORCU_MOCK_RESTART_LEASE_OWNER", &owner)
            .env("MIPSORCU_MOCK_RESTART_FENCING_TOKEN", fencing_token.to_string())
            .output()
            .expect("run isolated recovery process");
        assert!(
            resumed.status.success(),
            "restart child failed: {}",
            String::from_utf8_lossy(&resumed.stderr)
        );
        let completed = store.get(task_id).await.expect("read completed task");
        assert_eq!(completed.state, State::Completed);
        assert_eq!(completed.attempts, 1);
        assert_eq!(completed.model_tokens, 4);
        let verified_recoveries: i64 = bootstrap
            .query_one(
                "SELECT count(*) FROM orchestrator.recovery_confirmations WHERE task_id = $1 AND expired_fencing_token = $2 AND confirmed_by = $3",
                &[&task_id, &fencing_token, &owner],
            )
            .await
            .expect("read supervisor recovery confirmation")
            .get(0);
        assert_eq!(verified_recoveries, 1);
        let recovery_evidence: Value = bootstrap
            .query_one(
                "SELECT evidence FROM orchestrator.recovery_confirmations WHERE task_id = $1 AND expired_fencing_token = $2 AND confirmed_by = $3",
                &[&task_id, &fencing_token, &owner],
            )
            .await
            .expect("read redacted supervisor recovery evidence")
            .get(0);
        assert_eq!(
            recovery_evidence,
            serde_json::json!({"supervisor_verified_worker_tree_stopped": true})
        );
        let journal: Vec<MockGitHubJournalEntry> = serde_json::from_value(
            completed
                .mock_github_journal
                .expect("persisted mock journal"),
        )
        .expect("valid persisted mock journal");
        assert!(matches!(
            journal.last().map(|entry| &entry.result),
            Some(Ok(MockGitHubOutput::SimulatedMerge { .. }))
        ));
        drop(bootstrap);
    }
}

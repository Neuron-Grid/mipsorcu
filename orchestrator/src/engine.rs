//! One-step-at-a-time orchestration. External work is injectable and operation
//! records make an interrupted side effect fail closed on the next invocation.

use std::{
    future::Future,
    path::{Component, Path},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

use crate::{
    agent::{AutonomyConfig, Failure, Provider},
    domain::{self, ObservedFacts, State, TaskRecord, TrustedPolicy},
    mock_github::{
        MockGitHubAdapter, MockGitHubError, MockGitHubJournalEntry, MockGitHubOutput,
        MockGitHubPolicy, MockGitHubRequest,
    },
    postgres::{Lease, OperationStatus, RecoveryVerifier, StoreError, TaskStore},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Plan,
    Implement,
    Validate,
    Review,
    Merge,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MockPlan {
    pub requirements: Vec<String>,
    pub steps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MockCodeChange {
    pub summary: String,
    pub changed_files: Vec<String>,
    /// SHA3-256 over the deterministic mock patch descriptor, separate from Git's head SHA.
    pub patch_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StageOutput {
    pub assignee: Option<String>,
    pub implementer: Option<String>,
    pub reviewer: Option<String>,
    pub session_id: Option<String>,
    pub head_sha: Option<String>,
    pub pull_request: Option<u64>,
    pub validation_passed: bool,
    pub model_tokens: u64,
    pub mock_github_journal: Option<serde_json::Value>,
    #[serde(default)]
    pub plan: Option<MockPlan>,
    #[serde(default)]
    pub code_change: Option<MockCodeChange>,
}

#[derive(Clone, Copy, Debug)]
pub struct ExecutionBudget {
    pub remaining_runtime: Duration,
    pub remaining_model_tokens: u64,
}

/// Machine-readable stage failure returned to callers after the engine has
/// persisted a blocked checkpoint and attempted to stop the active operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "code", rename_all = "snake_case")]
pub enum StageFailure {
    Timeout,
    Cancelled,
    Agent(Failure),
    MockGitHub(MockGitHubError),
    InvalidConfiguration,
    InvalidInput,
    InvalidOperationResult,
    EvidenceUnavailable,
    LeaseUnavailable,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepResult {
    Advanced(State),
    WaitingForHuman,
    BlockedAmbiguousOperation,
    BlockedStageFailure(StageFailure),
    Finished,
}

#[derive(Debug)]
pub enum EngineError {
    Store(StoreError),
    InvalidConfiguration,
    PolicyUnavailable,
    EvidenceUnavailable,
    InvalidTask,
    InvalidOperationResult,
    InvalidTransition(domain::Error),
}

impl From<StoreError> for EngineError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Implement this trait with PostgreSQL. `prepare_operation` must atomically
/// return `New` only when it inserted the prepared row; a pre-existing row with
/// no result is `Ambiguous` and must never authorize execution again.
pub trait EngineStore {
    fn get(&self, task_id: Uuid) -> impl Future<Output = Result<TaskRecord, StoreError>> + Send;
    fn claim(
        &self,
        task_id: Uuid,
        owner: &str,
        ttl: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> impl Future<Output = Result<Lease, StoreError>> + Send;
    fn recover(
        &self,
        task_id: Uuid,
        owner: &str,
        ttl: Duration,
        verifier: &dyn RecoveryVerifier,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> impl Future<Output = Result<Lease, StoreError>> + Send;
    fn claim_handoff(
        &self,
        task_id: Uuid,
        owner: &str,
        ttl: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> impl Future<Output = Result<Lease, StoreError>> + Send;
    fn claim_resume(
        &self,
        task_id: Uuid,
        owner: &str,
        ttl: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> impl Future<Output = Result<Lease, StoreError>> + Send;
    fn renew(
        &self,
        lease: &Lease,
        ttl: Duration,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn load(&self, lease: &Lease) -> impl Future<Output = Result<TaskRecord, StoreError>> + Send;
    fn prepare_operation(
        &self,
        lease: &Lease,
        key: Uuid,
        operation: &str,
        request_hash: &[u8; 32],
    ) -> impl Future<Output = Result<OperationLookup, StoreError>> + Send;
    fn complete_operation(
        &self,
        lease: &Lease,
        key: Uuid,
        result: &serde_json::Value,
        model_tokens: u64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn save(
        &self,
        lease: &Lease,
        expected: State,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn release(&self, lease: &Lease) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Serializes the mutable PostgreSQL client while allowing the engine to keep
/// its adapter interfaces shared across asynchronous evidence and runner calls.
pub struct PostgresEngineStore {
    inner: tokio::sync::Mutex<TaskStore>,
}

impl PostgresEngineStore {
    pub fn new(store: TaskStore) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(store),
        }
    }
}

impl EngineStore for PostgresEngineStore {
    async fn get(&self, task_id: Uuid) -> Result<TaskRecord, StoreError> {
        self.inner.lock().await.get(task_id).await
    }

    async fn claim(
        &self,
        task_id: Uuid,
        owner: &str,
        ttl: Duration,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        self.inner
            .lock()
            .await
            .claim(task_id, owner, ttl, policy, facts)
            .await
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
            .lock()
            .await
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
            .lock()
            .await
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
            .lock()
            .await
            .claim_resume(task_id, owner, ttl, policy, facts)
            .await
    }

    async fn renew(&self, lease: &Lease, ttl: Duration) -> Result<(), StoreError> {
        self.inner.lock().await.renew(lease, ttl).await
    }

    async fn load(&self, lease: &Lease) -> Result<TaskRecord, StoreError> {
        self.inner.lock().await.get(lease.task_id).await
    }

    async fn prepare_operation(
        &self,
        lease: &Lease,
        key: Uuid,
        operation: &str,
        request_hash: &[u8; 32],
    ) -> Result<OperationLookup, StoreError> {
        let status = self
            .inner
            .lock()
            .await
            .prepare_operation(lease, key, operation, request_hash)
            .await?;
        Ok(match status {
            OperationStatus::NewlyPrepared => OperationLookup::New,
            OperationStatus::Ambiguous => OperationLookup::Ambiguous,
            OperationStatus::Completed(value) => OperationLookup::Completed(value),
        })
    }

    async fn complete_operation(
        &self,
        lease: &Lease,
        key: Uuid,
        result: &serde_json::Value,
        model_tokens: u64,
    ) -> Result<(), StoreError> {
        self.inner
            .lock()
            .await
            .complete_operation(lease, key, result, model_tokens)
            .await
    }

    async fn save(
        &self,
        lease: &Lease,
        expected: State,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<(), StoreError> {
        self.inner
            .lock()
            .await
            .save(lease, expected, task, policy, facts)
            .await
    }

    async fn release(&self, lease: &Lease) -> Result<(), StoreError> {
        self.inner.lock().await.release(lease).await
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum OperationLookup {
    New,
    Ambiguous,
    Completed(serde_json::Value),
}

pub trait TrustedPolicySource {
    fn load_policy(
        &self,
        task: &TaskRecord,
    ) -> impl Future<Output = Result<TrustedPolicy, ()>> + Send;
}

pub trait EvidenceSource {
    /// Must re-read trusted policy and GitHub state on every invocation.
    fn observe(
        &self,
        task: &TaskRecord,
        policy: &TrustedPolicy,
    ) -> impl Future<Output = Result<ObservedFacts, ()>> + Send;
}

pub trait StageRunner {
    /// Validate fixed provider and execution limits before claiming or resuming work.
    fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError>;
    fn agent_roles(&self) -> (Provider, Provider);

    /// A production implementation may invoke Codex CLI here. The engine never
    /// shells out itself and tests use an in-memory mock. Cancellation must stop
    /// the child process, and all writes must stay inside the task worktree.
    fn execute(
        &self,
        stage: Stage,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        budget: ExecutionBudget,
    ) -> impl Future<Output = Result<StageOutput, StageFailure>> + Send;

    /// Kill and wait for the child operation identified by its durable key.
    /// Success is the evidence required before the engine releases its lease.
    fn stop_and_verify(
        &self,
        lease: &Lease,
        operation_key: Uuid,
    ) -> impl Future<Output = Result<(), ()>> + Send;
}

pub struct Engine<S, P, E, R, V> {
    pub store: S,
    pub policies: P,
    pub evidence: E,
    pub runner: R,
    pub recovery: V,
    /// Only an in-memory MockGitHubAdapter can enable automatic merging.
    pub mock_github: Option<std::sync::Arc<std::sync::Mutex<MockGitHubAdapter>>>,
    pub lease_ttl: Duration,
}

impl<
    S: EngineStore,
    P: TrustedPolicySource,
    E: EvidenceSource,
    R: StageRunner,
    V: RecoveryVerifier + Sync,
> Engine<S, P, E, R, V>
{
    /// Claims a single queued task and advances it under the same lease until it
    /// completes in mock mode or reaches the human merge handoff. Recovery requires a
    /// separately verified supervisor-issued lease.
    pub async fn run_one(&self, task_id: Uuid, owner: &str) -> Result<StepResult, EngineError> {
        self.runner
            .validate_configuration()
            .map_err(|_| EngineError::InvalidConfiguration)?;
        let snapshot = self.store.get(task_id).await?;
        snapshot.validate().map_err(|_| EngineError::InvalidTask)?;
        if snapshot.state != State::Queued {
            return Err(EngineError::InvalidTask);
        }
        let policy = self
            .policies
            .load_policy(&snapshot)
            .await
            .map_err(|_| EngineError::PolicyUnavailable)?;
        validate_mock_repair_limit(&policy, self.mock_github.is_some())?;
        let facts = self
            .evidence
            .observe(&snapshot, &policy)
            .await
            .map_err(|_| EngineError::EvidenceUnavailable)?;
        if snapshot.state == State::Merging && facts.pr_merged {
            let mut completed = snapshot.clone();
            domain::transition(&mut completed, State::Completed, &policy, &facts)
                .map_err(EngineError::InvalidTransition)?;
        } else {
            verify_base(&snapshot, &policy, &facts)?;
        }
        let lease = self
            .store
            .claim(task_id, owner, self.lease_ttl, &policy, &facts)
            .await?;
        self.run_claimed(&lease).await
    }

    /// Explicitly resumes a persisted pause/block after fresh policy and
    /// GitHub evidence are checked by the store's fenced transition.
    pub async fn resume(&self, task_id: Uuid, owner: &str) -> Result<StepResult, EngineError> {
        self.runner
            .validate_configuration()
            .map_err(|_| EngineError::InvalidConfiguration)?;
        let task = self.store.get(task_id).await?;
        task.validate().map_err(|_| EngineError::InvalidTask)?;
        if !matches!(task.state, State::Paused | State::Blocked) {
            return Err(EngineError::InvalidTask);
        }
        let policy = self
            .policies
            .load_policy(&task)
            .await
            .map_err(|_| EngineError::PolicyUnavailable)?;
        validate_mock_repair_limit(&policy, self.mock_github.is_some())?;
        let facts = self
            .evidence
            .observe(&task, &policy)
            .await
            .map_err(|_| EngineError::EvidenceUnavailable)?;
        verify_base(&task, &policy, &facts)?;
        let lease = self
            .store
            .claim_resume(task_id, owner, self.lease_ttl, &policy, &facts)
            .await?;
        self.run_claimed(&lease).await
    }

    /// Rechecks a human-completed merge and records completion through the
    /// store's fenced Merging-to-Completed transaction.
    pub async fn complete_handoff(
        &self,
        task_id: Uuid,
        owner: &str,
    ) -> Result<StepResult, EngineError> {
        let task = self.store.get(task_id).await?;
        task.validate().map_err(|_| EngineError::InvalidTask)?;
        if !matches!(task.state, State::Completed | State::Merging) {
            return Err(EngineError::InvalidTask);
        }
        let policy = self
            .policies
            .load_policy(&task)
            .await
            .map_err(|_| EngineError::PolicyUnavailable)?;
        let facts = self
            .evidence
            .observe(&task, &policy)
            .await
            .map_err(|_| EngineError::EvidenceUnavailable)?;
        if task.state == State::Completed {
            domain::validate_completed(&task, &policy, &facts)
                .map_err(EngineError::InvalidTransition)?;
            return Ok(StepResult::Finished);
        }
        if !facts.pr_merged {
            return Ok(StepResult::WaitingForHuman);
        }
        let lease = self
            .store
            .claim_handoff(task_id, owner, self.lease_ttl, &policy, &facts)
            .await?;
        self.store.release(&lease).await?;
        Ok(StepResult::Finished)
    }

    /// Reacquires an expired task only after the supervisor independently
    /// proves that the previous process tree is stopped.
    pub async fn recover_and_run(
        &self,
        prior: &Lease,
        owner: &str,
    ) -> Result<StepResult, EngineError> {
        self.runner
            .validate_configuration()
            .map_err(|_| EngineError::InvalidConfiguration)?;
        let snapshot = self.store.get(prior.task_id).await?;
        snapshot.validate().map_err(|_| EngineError::InvalidTask)?;
        let policy = self
            .policies
            .load_policy(&snapshot)
            .await
            .map_err(|_| EngineError::PolicyUnavailable)?;
        validate_mock_repair_limit(&policy, self.mock_github.is_some())?;
        let facts = self
            .evidence
            .observe(&snapshot, &policy)
            .await
            .map_err(|_| EngineError::EvidenceUnavailable)?;
        if snapshot.state == State::Merging && facts.pr_merged {
            domain::validate_completed(&snapshot, &policy, &facts)
                .map_err(EngineError::InvalidTransition)?;
        } else {
            verify_base(&snapshot, &policy, &facts)?;
        }
        let lease = self
            .store
            .recover(
                prior.task_id,
                owner,
                self.lease_ttl,
                &self.recovery,
                &policy,
                &facts,
            )
            .await?;
        self.run_claimed(&lease).await
    }

    /// Runs an already held or supervisor-recovered lease without claiming a
    /// second task. Each durable transition is committed before the next stage.
    pub async fn run_claimed(&self, lease: &Lease) -> Result<StepResult, EngineError> {
        self.runner
            .validate_configuration()
            .map_err(|_| EngineError::InvalidConfiguration)?;
        loop {
            let task = self.store.load(lease).await?;
            task.validate().map_err(|_| EngineError::InvalidTask)?;
            let policy = self
                .policies
                .load_policy(&task)
                .await
                .map_err(|_| EngineError::PolicyUnavailable)?;
            validate_mock_repair_limit(&policy, self.mock_github.is_some())?;
            validate_task_agents(&task, self.runner.agent_roles(), self.mock_github.is_some())?;
            let before = self
                .evidence
                .observe(&task, &policy)
                .await
                .map_err(|_| EngineError::EvidenceUnavailable)?;
            validate_task_journal(&task, &policy, before.pr_merged)?;
            if task.state == State::Merging {
                if before.pr_merged {
                    if before.policy_base_ref != policy.base_ref
                        || before.policy_base_sha != policy.base_sha
                    {
                        return Err(EngineError::InvalidTransition(domain::Error::StaleBase));
                    }
                    if self.mock_github.is_some() {
                        validate_simulated_merge(&task, &policy, &before)?;
                    }
                    let mut candidate = task.clone();
                    domain::transition(&mut candidate, State::Completed, &policy, &before)
                        .map_err(EngineError::InvalidTransition)?;
                    self.store
                        .save(lease, task.state, &candidate, &policy, &before)
                        .await?;
                    self.store.release(lease).await?;
                    return Ok(StepResult::Finished);
                }
                if self.mock_github.is_none() {
                    self.store.release(lease).await?;
                    return Ok(StepResult::WaitingForHuman);
                }
            }
            if task.state == State::Completed {
                domain::validate_completed(&task, &policy, &before)
                    .map_err(EngineError::InvalidTransition)?;
                if self.mock_github.is_some() {
                    validate_simulated_merge(&task, &policy, &before)?;
                }
                self.store.release(lease).await?;
                return Ok(StepResult::Finished);
            }
            verify_base(&task, &policy, &before)?;
            if matches!(task.state, State::Blocked | State::Paused) {
                return Err(EngineError::InvalidTransition(
                    domain::Error::InvalidTransition,
                ));
            }
            let stage_and_next = if task.state == State::Merging {
                Some((Stage::Merge, State::Completed))
            } else {
                stage_for(task.state)
            };
            let Some((stage, next)) = stage_and_next else {
                return Err(EngineError::InvalidTask);
            };

            if task.attempts > policy.max_attempts
                || task.elapsed >= policy.max_runtime
                || task.model_tokens >= policy.max_model_tokens
            {
                let mut candidate = task.clone();
                domain::transition(&mut candidate, State::Paused, &policy, &before)
                    .map_err(EngineError::InvalidTransition)?;
                self.store
                    .save(lease, task.state, &candidate, &policy, &before)
                    .await?;
                self.store.release(lease).await?;
                return Ok(StepResult::Advanced(State::Paused));
            }
            let budget = ExecutionBudget {
                remaining_runtime: policy.max_runtime.saturating_sub(task.elapsed),
                remaining_model_tokens: policy.max_model_tokens - task.model_tokens,
            };
            let key = operation_key(
                Uuid::parse_str(&task.task_id).map_err(|_| EngineError::InvalidTask)?,
                task.attempts,
                task.state,
                stage,
            );
            if stage == Stage::Merge {
                validate_merge_preconditions(&task, &policy, &before)?;
                validate_task_journal(&task, &policy, false)?;
            }
            let hash = request_hash(&task, stage);
            let output = match self
                .store
                .prepare_operation(lease, key, stage_name(stage), &hash)
                .await?
            {
                OperationLookup::New => {
                    let execution = if stage == Stage::Merge {
                        self.execute_mock_merge(key, &task, &policy, &before)
                    } else {
                        self.execute_guarded(stage, &task, &policy, budget, lease)
                            .await
                    };
                    let output = match execution {
                        Ok(output) => output,
                        Err(failure) => {
                            return self
                                .stop_and_block(lease, key, &task, &policy, &before, Some(failure))
                                .await;
                        }
                    };
                    if !valid_stage_output(stage, &output) {
                        return self
                            .stop_and_block(
                                lease,
                                key,
                                &task,
                                &policy,
                                &before,
                                Some(StageFailure::InvalidOperationResult),
                            )
                            .await;
                    }
                    let value = serde_json::to_value(&output)
                        .map_err(|_| EngineError::InvalidOperationResult)?;
                    self.store
                        .complete_operation(lease, key, &value, output.model_tokens)
                        .await?;
                    output
                }
                OperationLookup::Completed(value) => match serde_json::from_value(value) {
                    Ok(output) => output,
                    Err(_) => {
                        return self
                            .stop_and_block(
                                lease,
                                key,
                                &task,
                                &policy,
                                &before,
                                Some(StageFailure::InvalidOperationResult),
                            )
                            .await;
                    }
                },
                OperationLookup::Ambiguous => {
                    return self
                        .stop_and_block(lease, key, &task, &policy, &before, None)
                        .await;
                }
            };

            if !valid_stage_output(stage, &output) {
                return self
                    .stop_and_block(
                        lease,
                        key,
                        &task,
                        &policy,
                        &before,
                        Some(StageFailure::InvalidOperationResult),
                    )
                    .await;
            }

            let current = self.store.load(lease).await?;
            current.validate().map_err(|_| EngineError::InvalidTask)?;
            if current.model_tokens > policy.max_model_tokens {
                let mut candidate = current.clone();
                domain::transition_from(&current, &mut candidate, State::Paused, &policy, &before)
                    .map_err(EngineError::InvalidTransition)?;
                self.store
                    .save(lease, current.state, &candidate, &policy, &before)
                    .await?;
                self.store.release(lease).await?;
                return Ok(StepResult::Advanced(State::Paused));
            }
            let mut candidate = current.clone();
            if let Some(assignee) = output.assignee {
                candidate.assignee = Some(assignee);
            }
            if let Some(implementer) = output.implementer {
                candidate.implementer = Some(implementer);
            }
            if let Some(reviewer) = output.reviewer {
                candidate.reviewer = Some(reviewer);
            }
            if let Some(session_id) = output.session_id {
                candidate.session_id = Some(session_id);
            }
            if let Some(journal) = output.mock_github_journal {
                validate_journal_extension(current.mock_github_journal.as_ref(), &journal)?;
                candidate.mock_github_journal = Some(journal);
            }
            if let Some(head) = output.head_sha {
                candidate.head_sha = Some(head);
            }
            if let Some(pr) = output.pull_request {
                candidate.pull_request = Some(pr);
            }
            candidate.validation_passed = output.validation_passed;
            let mut next = next;
            let needs_repair =
                matches!(stage, Stage::Validate | Stage::Review) && !output.validation_passed;
            if needs_repair {
                if task.attempts >= policy.max_attempts {
                    candidate = current.clone();
                    next = State::Paused;
                } else {
                    candidate.pull_request = None;
                    candidate.validation_passed = false;
                    candidate.attempts = candidate.attempts.saturating_add(1);
                    next = State::Repairing;
                }
            }
            let after = self
                .evidence
                .observe(&candidate, &policy)
                .await
                .map_err(|_| EngineError::EvidenceUnavailable)?;
            verify_base(&candidate, &policy, &after)?;
            if stage == Stage::Review
                && !needs_repair
                && (!after.reviewer_approved
                    || policy
                        .required_checks
                        .iter()
                        .any(|check| !after.checks_passed.contains(check)))
            {
                let mut paused = current.clone();
                domain::transition_from(&current, &mut paused, State::Paused, &policy, &after)
                    .map_err(EngineError::InvalidTransition)?;
                self.store
                    .save(lease, current.state, &paused, &policy, &after)
                    .await?;
                self.store.release(lease).await?;
                return Ok(StepResult::Advanced(State::Paused));
            }
            if stage == Stage::Merge {
                validate_task_journal(&candidate, &policy, after.pr_merged)?;
                if !after.pr_merged {
                    return Err(EngineError::InvalidTransition(
                        domain::Error::PullRequestMismatch,
                    ));
                }
                validate_simulated_merge(&candidate, &policy, &after)?;
            }
            domain::transition_from(&current, &mut candidate, next, &policy, &after)
                .map_err(EngineError::InvalidTransition)?;
            self.store
                .save(lease, current.state, &candidate, &policy, &after)
                .await?;
            if candidate.state == State::Merging && self.mock_github.is_none() {
                self.store.release(lease).await?;
                return Ok(StepResult::WaitingForHuman);
            }
            if candidate.state == State::Paused {
                self.store.release(lease).await?;
                return Ok(StepResult::Advanced(State::Paused));
            }
        }
    }

    async fn execute_guarded(
        &self,
        stage: Stage,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        budget: ExecutionBudget,
        lease: &Lease,
    ) -> Result<StageOutput, StageFailure> {
        let preflight = self
            .evidence
            .observe(task, policy)
            .await
            .map_err(|_| StageFailure::EvidenceUnavailable)?;
        verify_base(task, policy, &preflight).map_err(|_| StageFailure::InvalidInput)?;
        self.store
            .renew(lease, self.lease_ttl)
            .await
            .map_err(|_| StageFailure::LeaseUnavailable)?;
        let timeout = stage_timeout(stage, budget.remaining_runtime, self.mock_github.is_some());
        let budget = ExecutionBudget {
            remaining_runtime: timeout,
            ..budget
        };
        let future = self.runner.execute(stage, task, policy, budget);
        tokio::pin!(future);
        let heartbeat = (self.lease_ttl / 3).max(Duration::from_millis(250));
        let mut interval =
            tokio::time::interval_at(tokio::time::Instant::now() + heartbeat, heartbeat);
        let heartbeat_future = async {
            loop {
                interval.tick().await;
                if self.store.renew(lease, self.lease_ttl).await.is_err() {
                    return StageFailure::LeaseUnavailable;
                }
                let facts = match self.evidence.observe(task, policy).await {
                    Ok(facts) => facts,
                    Err(()) => return StageFailure::EvidenceUnavailable,
                };
                if verify_base(task, policy, &facts).is_err() {
                    return StageFailure::InvalidInput;
                }
            }
        };
        tokio::select! {
            result = tokio::time::timeout(timeout, &mut future) => {
                result.unwrap_or(Err(StageFailure::Timeout))
            },
            failure = heartbeat_future => Err(failure),
        }
    }

    fn execute_mock_merge(
        &self,
        key: Uuid,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<StageOutput, StageFailure> {
        validate_merge_preconditions(task, policy, facts)
            .map_err(|_| StageFailure::InvalidInput)?;
        validate_task_journal(task, policy, facts.pr_merged)
            .map_err(|_| StageFailure::InvalidOperationResult)?;
        let mut adapter = self
            .mock_github
            .as_ref()
            .ok_or(StageFailure::InvalidConfiguration)?
            .lock()
            .map_err(|_| StageFailure::Internal)?;
        let journal = task
            .mock_github_journal
            .as_ref()
            .map(|value| serde_json::from_value::<Vec<MockGitHubJournalEntry>>(value.clone()))
            .transpose()
            .map_err(|_| StageFailure::InvalidOperationResult)?
            .unwrap_or_default();
        adapter
            .restore_journal(&journal)
            .map_err(|_| StageFailure::InvalidOperationResult)?;
        let pull_number = task.pull_request.ok_or(StageFailure::InvalidInput)?;
        let head_sha = task.head_sha.as_deref().ok_or(StageFailure::InvalidInput)?;
        let result = adapter
            .merge(&key.to_string(), pull_number, head_sha, &policy.base_ref)
            .map_err(StageFailure::MockGitHub)?;
        if !matches!(result, MockGitHubOutput::SimulatedMerge { pull_number: merged, .. } if merged == pull_number)
        {
            return Err(StageFailure::InvalidOperationResult);
        }
        let mock_github_journal = serde_json::to_value(adapter.journal())
            .map_err(|_| StageFailure::InvalidOperationResult)?;
        Ok(StageOutput {
            assignee: None,
            implementer: None,
            reviewer: None,
            session_id: None,
            head_sha: None,
            pull_request: None,
            validation_passed: true,
            model_tokens: 0,
            mock_github_journal: Some(mock_github_journal),
            plan: None,
            code_change: None,
        })
    }

    async fn stop_and_block(
        &self,
        lease: &Lease,
        operation_key: Uuid,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
        failure: Option<StageFailure>,
    ) -> Result<StepResult, EngineError> {
        // A persistence failure must not skip the independent child-stop attempt.
        let stopped = self
            .runner
            .stop_and_verify(lease, operation_key)
            .await
            .is_ok();
        persist_blocked(&self.store, lease, task, policy, facts).await?;
        if stopped {
            self.store.release(lease).await?;
        }
        Ok(failure.map_or(
            StepResult::BlockedAmbiguousOperation,
            StepResult::BlockedStageFailure,
        ))
    }
}

fn validate_mock_repair_limit(policy: &TrustedPolicy, mock_mode: bool) -> Result<(), EngineError> {
    if mock_mode
        && policy.max_attempts
            != u32::from(AutonomyConfig::approved_mock_defaults().max_repair_attempts)
    {
        return Err(EngineError::InvalidConfiguration);
    }
    Ok(())
}

fn valid_stage_output(stage: Stage, output: &StageOutput) -> bool {
    match stage {
        Stage::Plan => {
            output.code_change.is_none()
                && output.plan.as_ref().is_some_and(|plan| {
                    !plan.requirements.is_empty()
                        && !plan.steps.is_empty()
                        && plan.requirements.len() <= 32
                        && plan.steps.len() <= 32
                        && plan.requirements.iter().all(|value| valid_summary(value))
                        && plan.steps.iter().all(|value| valid_summary(value))
                })
        }
        Stage::Implement => {
            output.plan.is_none()
                && output.code_change.as_ref().is_some_and(|change| {
                    valid_summary(&change.summary)
                        && !change.changed_files.is_empty()
                        && change.changed_files.len() <= 64
                        && change.changed_files.iter().all(|path| {
                            !path.is_empty()
                                && !path.contains('\\')
                                && !Path::new(path).is_absolute()
                                && Path::new(path)
                                    .components()
                                    .all(|component| matches!(component, Component::Normal(_)))
                        })
                        && mock_patch_digest(&change.summary, &change.changed_files)
                            .is_some_and(|digest| change.patch_digest == digest)
                })
        }
        Stage::Validate | Stage::Review | Stage::Merge => {
            output.plan.is_none() && output.code_change.is_none()
        }
    }
}

fn valid_summary(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 512
}

pub(crate) fn mock_patch_digest(summary: &str, changed_files: &[String]) -> Option<String> {
    let descriptor = serde_json::to_vec(&(summary, changed_files)).ok()?;
    let mut encoded = String::with_capacity(64);
    for byte in Sha3_256::digest(descriptor) {
        encoded.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        encoded.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    Some(encoded)
}

fn stage_timeout(stage: Stage, remaining: Duration, mock_mode: bool) -> Duration {
    if mock_mode && matches!(stage, Stage::Plan | Stage::Implement | Stage::Review) {
        remaining.min(Duration::from_secs(45 * 60))
    } else {
        remaining
    }
}

fn verify_base(
    task: &TaskRecord,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
) -> Result<(), EngineError> {
    if !facts.issue_open {
        return Err(EngineError::InvalidTransition(
            domain::Error::IssueUnavailable,
        ));
    }
    if task.base_sha != policy.base_sha
        || facts.base_sha != policy.base_sha
        || facts.policy_base_sha != policy.base_sha
        || facts.policy_base_ref != policy.base_ref
    {
        return Err(EngineError::InvalidTransition(domain::Error::StaleBase));
    }
    if let Some(head) = task.head_sha.as_deref()
        && facts.head_sha != head
    {
        return Err(EngineError::InvalidTransition(domain::Error::StaleHead));
    }
    Ok(())
}

async fn persist_blocked<S: EngineStore>(
    store: &S,
    lease: &Lease,
    task: &TaskRecord,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
) -> Result<(), EngineError> {
    let mut blocked = task.clone();
    domain::transition(&mut blocked, State::Blocked, policy, facts)
        .map_err(EngineError::InvalidTransition)?;
    store
        .save(lease, task.state, &blocked, policy, facts)
        .await?;
    Ok(())
}

fn stage_for(state: State) -> Option<(Stage, State)> {
    match state {
        State::Planning => Some((Stage::Plan, State::Implementing)),
        State::Implementing => Some((Stage::Implement, State::Validating)),
        State::Validating => Some((Stage::Validate, State::Reviewing)),
        State::Reviewing => Some((Stage::Review, State::Merging)),
        State::Repairing => Some((Stage::Implement, State::Validating)),
        _ => None,
    }
}

pub(crate) fn stage_name(stage: Stage) -> &'static str {
    match stage {
        Stage::Plan => "plan",
        Stage::Implement => "implement",
        Stage::Validate => "validate",
        Stage::Review => "review",
        Stage::Merge => "mock_merge",
    }
}

fn validate_journal_extension(
    current: Option<&serde_json::Value>,
    proposed: &serde_json::Value,
) -> Result<(), EngineError> {
    let current = current
        .and_then(serde_json::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let Some(proposed) = proposed.as_array() else {
        return Err(EngineError::InvalidOperationResult);
    };
    if proposed.len() > 64 || !proposed.starts_with(current) {
        return Err(EngineError::InvalidOperationResult);
    }
    Ok(())
}

fn validate_task_journal(
    task: &TaskRecord,
    policy: &TrustedPolicy,
    evidence_merged: bool,
) -> Result<(), EngineError> {
    let Some(value) = task.mock_github_journal.as_ref() else {
        return Ok(());
    };
    let task_id = Uuid::parse_str(&task.task_id).map_err(|_| EngineError::InvalidTask)?;
    let implementer = parse_provider(task.implementer.as_deref())?;
    let reviewer = parse_provider(task.reviewer.as_deref())?;
    if implementer != Provider::Codex || reviewer != Provider::Claude || task.session_id.is_none() {
        return Err(EngineError::InvalidOperationResult);
    }
    let entries: Vec<MockGitHubJournalEntry> =
        serde_json::from_value(value.clone()).map_err(|_| EngineError::InvalidOperationResult)?;
    let mock_policy = MockGitHubPolicy::with_agents(
        vec![policy.base_ref.clone()],
        policy.required_checks.clone(),
        implementer,
        reviewer,
    )
    .map_err(|_| EngineError::InvalidOperationResult)?;
    let adapter = MockGitHubAdapter::restore(mock_policy, &entries)
        .map_err(|_| EngineError::InvalidOperationResult)?;
    let mut previous_rank = None;
    let mut journal_validation = JournalValidation {
        task,
        policy,
        checks: std::collections::HashMap::new(),
        pull_number: None,
    };
    for entry in &entries {
        let (prefix, suffix) = entry
            .idempotency_key
            .split_once(':')
            .unwrap_or((&entry.idempotency_key, ""));
        let operation_id =
            Uuid::parse_str(prefix).map_err(|_| EngineError::InvalidOperationResult)?;
        let aligned = (0..=task.attempts).find_map(|attempt| {
            let stages = if attempt == 0 {
                [
                    (State::Implementing, Stage::Implement),
                    (State::Validating, Stage::Validate),
                    (State::Reviewing, Stage::Review),
                ]
            } else {
                [
                    (State::Repairing, Stage::Implement),
                    (State::Validating, Stage::Validate),
                    (State::Reviewing, Stage::Review),
                ]
            };
            stages.into_iter().find_map(|(state, stage)| {
                (operation_key(task_id, attempt, state, stage) == operation_id)
                    .then_some((attempt, stage))
            })
        });
        let merge_aligned = matches!(task.state, State::Merging | State::Completed)
            && evidence_merged
            && operation_key(task_id, task.attempts, State::Merging, Stage::Merge) == operation_id
            && suffix.is_empty();
        let Some((attempt, stage)) = aligned else {
            if !merge_aligned
                || !matches!(entry.request, MockGitHubRequest::Merge { .. })
                || !matches!(entry.result, Ok(MockGitHubOutput::SimulatedMerge { .. }))
            {
                return Err(EngineError::InvalidOperationResult);
            }
            validate_journal_merge_entry(entry, task, policy)?;
            continue;
        };
        if merge_aligned {
            return Err(EngineError::InvalidOperationResult);
        }
        let rank = journal_validation.validate_entry(entry, attempt, stage, suffix)?;
        if previous_rank.is_some_and(|prior| rank <= prior) {
            return Err(EngineError::InvalidOperationResult);
        }
        previous_rank = Some(rank);
    }
    if let Some(number) = task.pull_request {
        let pull = adapter
            .pull_request(number)
            .ok_or(EngineError::InvalidOperationResult)?;
        if Some(pull.head_sha.as_str()) != task.head_sha.as_deref()
            || pull.target != policy.base_ref
            || pull.merged != evidence_merged
        {
            return Err(EngineError::InvalidOperationResult);
        }
        if task.state == State::Completed && (!pull.merged || pull.merge_sha.is_none()) {
            return Err(EngineError::InvalidOperationResult);
        }
    }
    Ok(())
}

fn validate_task_agents(
    task: &TaskRecord,
    (implementer, reviewer): (Provider, Provider),
    mock_mode: bool,
) -> Result<(), EngineError> {
    let expected_implementer = provider_name(implementer);
    let expected_reviewer = provider_name(reviewer);
    let mismatch = task
        .implementer
        .as_deref()
        .is_some_and(|value| value != expected_implementer)
        || task
            .reviewer
            .as_deref()
            .is_some_and(|value| value != expected_reviewer);
    let missing = mock_mode
        && task.state != State::Queued
        && task.state != State::Planning
        && (task.implementer.is_none() || task.reviewer.is_none() || task.session_id.is_none());
    if implementer == reviewer || mismatch || missing {
        return Err(EngineError::InvalidConfiguration);
    }
    Ok(())
}

fn provider_name(provider: Provider) -> &'static str {
    match provider {
        Provider::Codex => "codex",
        Provider::Claude => "claude",
        Provider::DeepSeekHarness => "deepseek_harness",
    }
}

struct JournalValidation<'a> {
    task: &'a TaskRecord,
    policy: &'a TrustedPolicy,
    checks: std::collections::HashMap<(u32, String), bool>,
    pull_number: Option<u64>,
}

impl JournalValidation<'_> {
    fn validate_entry(
        &mut self,
        entry: &MockGitHubJournalEntry,
        attempt: u32,
        stage: Stage,
        suffix: &str,
    ) -> Result<(u32, u8, usize), EngineError> {
        let task = self.task;
        let policy = self.policy;
        let task_id = Uuid::parse_str(&task.task_id).map_err(|_| EngineError::InvalidTask)?;
        let branch = format!("orchestrator/{task_id}");
        let this_head = journal_head(attempt)?;
        let prior_head = if attempt == 0 {
            task.base_sha.as_str()
        } else {
            journal_head(attempt - 1)?
        };
        let invalid = || EngineError::InvalidOperationResult;
        let (stage_rank, operation_rank) = match (stage, suffix, &entry.request, &entry.result) {
            (
                Stage::Implement,
                "branch",
                MockGitHubRequest::CreateBranch {
                    branch: actual_branch,
                    base_sha,
                },
                Ok(MockGitHubOutput::BranchCreated {
                    branch: result_branch,
                    head_sha,
                }),
            ) if attempt == 0
                && actual_branch == &branch
                && base_sha == &task.base_sha
                && result_branch == &branch
                && head_sha == &task.base_sha =>
            {
                (0, 0)
            }
            (
                Stage::Implement,
                "push",
                MockGitHubRequest::CommitPush {
                    branch: actual_branch,
                    expected_head_sha,
                    new_head_sha,
                },
                Ok(MockGitHubOutput::Pushed {
                    branch: result_branch,
                    head_sha,
                }),
            ) if actual_branch == &branch
                && result_branch == &branch
                && expected_head_sha == prior_head
                && new_head_sha == this_head
                && head_sha == this_head =>
            {
                (0, 1)
            }
            (
                Stage::Validate,
                "pull",
                MockGitHubRequest::UpsertPullRequest {
                    branch: actual_branch,
                    target,
                    title,
                },
                Ok(MockGitHubOutput::PullRequest(pull)),
            ) if actual_branch == &branch
                && target == &policy.base_ref
                && title == &format!("Mock task {}", task.issue_number)
                && pull.branch == branch
                && pull.target == policy.base_ref
                && pull.title == *title
                && pull.head_sha == this_head
                && !pull.merged
                && pull.merge_sha.is_none()
                && *self.pull_number.get_or_insert(pull.number) == pull.number =>
            {
                (1, 0)
            }
            (
                Stage::Validate,
                check_suffix,
                MockGitHubRequest::SetCheck {
                    head_sha,
                    name,
                    passed,
                },
                Ok(MockGitHubOutput::CheckUpdated {
                    head_sha: result_head,
                    name: result_name,
                    passed: result_passed,
                }),
            ) if policy
                .required_checks
                .iter()
                .position(|check| check_suffix == format!("check-{check}"))
                .is_some_and(|index| {
                    name == &policy.required_checks[index]
                        && head_sha == this_head
                        && result_head == this_head
                        && result_name == name
                        && result_passed == passed
                        && self
                            .checks
                            .insert((attempt, name.clone()), *passed)
                            .is_none()
                }) =>
            {
                let index = policy
                    .required_checks
                    .iter()
                    .position(|check| check_suffix == format!("check-{check}"))
                    .ok_or_else(invalid)?;
                (1, index + 1)
            }
            (
                Stage::Validate,
                "read-checks",
                MockGitHubRequest::GetChecks { head_sha },
                Ok(MockGitHubOutput::CiResults {
                    head_sha: result_head,
                    checks: actual_checks,
                }),
            ) => {
                let expected_checks = policy
                    .required_checks
                    .iter()
                    .map(|name| {
                        self.checks
                            .get(&(attempt, name.clone()))
                            .copied()
                            .map(|passed| (name.clone(), passed))
                            .ok_or_else(invalid)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if head_sha != this_head
                    || result_head != this_head
                    || actual_checks != &expected_checks
                {
                    return Err(invalid());
                }
                (1, policy.required_checks.len() + 1)
            }
            (
                Stage::Review,
                "review",
                MockGitHubRequest::SetReview {
                    head_sha,
                    reviewer,
                    approved,
                },
                Ok(MockGitHubOutput::ReviewUpdated {
                    head_sha: result_head,
                    approved: result_approved,
                }),
            ) if head_sha == this_head
                && *reviewer == Provider::Claude
                && result_head == this_head
                && result_approved == approved =>
            {
                (2, 0)
            }
            _ => return Err(invalid()),
        };
        Ok((attempt, stage_rank, operation_rank))
    }
}

fn validate_journal_merge_entry(
    entry: &MockGitHubJournalEntry,
    task: &TaskRecord,
    policy: &TrustedPolicy,
) -> Result<(), EngineError> {
    let invalid = || EngineError::InvalidOperationResult;
    let head = task.head_sha.as_deref().ok_or_else(invalid)?;
    let number = task.pull_request.ok_or_else(invalid)?;
    if entry.request
        != (MockGitHubRequest::Merge {
            pull_number: number,
            expected_head_sha: head.to_owned(),
            target: policy.base_ref.clone(),
        })
        || !matches!(entry.result, Ok(MockGitHubOutput::SimulatedMerge { pull_number, .. }) if pull_number == number)
    {
        return Err(invalid());
    }
    Ok(())
}

fn journal_head(attempt: u32) -> Result<&'static str, EngineError> {
    match attempt {
        0 => Ok("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        1 => Ok("cccccccccccccccccccccccccccccccccccccccc"),
        2 => Ok("dddddddddddddddddddddddddddddddddddddddd"),
        3 => Ok("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        _ => Err(EngineError::InvalidOperationResult),
    }
}

fn validate_merge_preconditions(
    task: &TaskRecord,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
) -> Result<(), EngineError> {
    let head = task.head_sha.as_deref().ok_or(EngineError::InvalidTask)?;
    let pull = task.pull_request.ok_or(EngineError::InvalidTask)?;
    if task.state != State::Merging
        || task.attempts > policy.max_attempts
        || !task.validation_passed
        || policy.base_ref == "main"
        || facts.pr_merged
        || facts.head_sha != head
        || facts.validated_head_sha.as_deref() != Some(head)
        || facts.pr_head_sha.as_deref() != Some(head)
        || facts.pr_number != Some(pull)
        || facts.pr_base_ref.as_deref() != Some(policy.base_ref.as_str())
        || facts.pr_base_sha.as_deref() != Some(policy.base_sha.as_str())
        || !facts.reviewer_approved
        || policy
            .required_checks
            .iter()
            .any(|check| !facts.checks_passed.contains(check))
    {
        return Err(EngineError::InvalidTransition(
            domain::Error::InvalidTransition,
        ));
    }
    Ok(())
}

fn validate_simulated_merge(
    task: &TaskRecord,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
) -> Result<(), EngineError> {
    let value = task
        .mock_github_journal
        .as_ref()
        .ok_or(EngineError::InvalidOperationResult)?;
    validate_task_journal(task, policy, true)?;
    let entries: Vec<MockGitHubJournalEntry> =
        serde_json::from_value(value.clone()).map_err(|_| EngineError::InvalidOperationResult)?;
    let last = entries.last().ok_or(EngineError::InvalidOperationResult)?;
    let task_id = Uuid::parse_str(&task.task_id).map_err(|_| EngineError::InvalidTask)?;
    let expected_key = operation_key(task_id, task.attempts, State::Merging, Stage::Merge);
    let pull = task
        .pull_request
        .ok_or(EngineError::InvalidOperationResult)?;
    let head = task
        .head_sha
        .as_deref()
        .ok_or(EngineError::InvalidOperationResult)?;
    if last.idempotency_key != expected_key.to_string()
        || last.request
            != (MockGitHubRequest::Merge {
                pull_number: pull,
                expected_head_sha: head.to_owned(),
                target: policy.base_ref.clone(),
            })
        || !matches!(
            &last.result,
            Ok(MockGitHubOutput::SimulatedMerge {
                pull_number,
                merge_sha
            }) if *pull_number == pull
                && facts.merge_commit_sha.as_deref() == Some(merge_sha.as_str())
                && facts.base_contains_merge_commit
        )
    {
        return Err(EngineError::InvalidOperationResult);
    }
    Ok(())
}

fn parse_provider(value: Option<&str>) -> Result<Provider, EngineError> {
    match value {
        Some("codex") => Ok(Provider::Codex),
        Some("claude") => Ok(Provider::Claude),
        _ => Err(EngineError::InvalidOperationResult),
    }
}

pub(crate) fn operation_key(task_id: Uuid, attempt: u32, state: State, stage: Stage) -> Uuid {
    let mut hasher = Sha3_256::new();
    hasher.update(task_id.as_bytes());
    hasher.update(attempt.to_be_bytes());
    hasher.update(state_name(state).as_bytes());
    hasher.update(stage_name(stage).as_bytes());
    Uuid::from_bytes(hasher.finalize()[..16].try_into().unwrap_or([0; 16]))
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

pub(crate) fn request_hash(task: &TaskRecord, stage: Stage) -> [u8; 32] {
    let input = serde_json::json!({
        "task_id": task.task_id,
        "issue_number": task.issue_number,
        "state": state_name(task.state),
        "stage": stage_name(stage),
        "attempt": task.attempts,
        "base_sha": task.base_sha,
        "head_sha": task.head_sha,
    });
    Sha3_256::digest(serde_json::to_vec(&input).unwrap_or_default()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    type TestEngine = Engine<MockStore, MockPolicy, MockEvidence, MockRunner, MockRecovery>;

    #[derive(Clone)]
    struct MockStore(Arc<Mutex<MockDb>>);
    struct MockDb {
        task: TaskRecord,
        ops: HashMap<Uuid, OperationLookup>,
        executions: usize,
        saves: usize,
        validation_failures: usize,
        review_failures: usize,
        observed: Vec<(State, Option<String>, usize)>,
        stop_confirmed: bool,
        stop_attempts: usize,
        fail_save: bool,
        configuration_valid: bool,
        releases: usize,
    }

    impl EngineStore for MockStore {
        async fn get(&self, task_id: Uuid) -> Result<TaskRecord, StoreError> {
            let db = self.0.lock().map_err(|_| StoreError::InvalidRecord)?;
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
            let db = self.0.lock().map_err(|_| StoreError::InvalidRecord)?;
            if db.task.task_id != task_id.to_string() || db.task.state != State::Queued {
                return Err(StoreError::LeaseOccupied);
            }
            drop(db);
            let mut db = self.0.lock().map_err(|_| StoreError::InvalidRecord)?;
            let mut candidate = db.task.clone();
            domain::transition(&mut candidate, State::Planning, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?;
            db.task = candidate;
            Ok(Lease {
                task_id,
                owner: owner.into(),
                fencing_token: 1,
            })
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
            Err(StoreError::LeaseLost)
        }
        async fn claim_handoff(
            &self,
            task_id: Uuid,
            owner: &str,
            _: Duration,
            policy: &TrustedPolicy,
            facts: &ObservedFacts,
        ) -> Result<Lease, StoreError> {
            let mut db = self.0.lock().map_err(|_| StoreError::InvalidRecord)?;
            if db.task.task_id != task_id.to_string() {
                return Err(StoreError::TaskMissing);
            }
            let mut candidate = db.task.clone();
            domain::transition(&mut candidate, State::Completed, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?;
            db.task = candidate;
            Ok(Lease {
                task_id,
                owner: owner.into(),
                fencing_token: 2,
            })
        }
        async fn claim_resume(
            &self,
            task_id: Uuid,
            owner: &str,
            _: Duration,
            policy: &TrustedPolicy,
            facts: &ObservedFacts,
        ) -> Result<Lease, StoreError> {
            let mut db = self.0.lock().map_err(|_| StoreError::InvalidRecord)?;
            if db.task.task_id != task_id.to_string()
                || !matches!(db.task.state, State::Paused | State::Blocked)
            {
                return Err(StoreError::InvalidRecord);
            }
            let checkpoint = db.task.checkpoint.ok_or(StoreError::InvalidRecord)?;
            let mut candidate = db.task.clone();
            domain::transition(&mut candidate, checkpoint, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?;
            db.task = candidate;
            Ok(Lease {
                task_id,
                owner: owner.into(),
                fencing_token: 3,
            })
        }
        async fn renew(&self, _: &Lease, _: Duration) -> Result<(), StoreError> {
            Ok(())
        }
        async fn load(&self, _: &Lease) -> Result<TaskRecord, StoreError> {
            Ok(self
                .0
                .lock()
                .map_err(|_| StoreError::InvalidRecord)?
                .task
                .clone())
        }
        async fn prepare_operation(
            &self,
            _: &Lease,
            key: Uuid,
            _: &str,
            _: &[u8; 32],
        ) -> Result<OperationLookup, StoreError> {
            let mut db = self.0.lock().map_err(|_| StoreError::InvalidRecord)?;
            if let Some(value) = db.ops.get(&key) {
                return Ok(match value {
                    OperationLookup::New => OperationLookup::Ambiguous,
                    other => other.clone(),
                });
            }
            db.ops.insert(key, OperationLookup::Ambiguous);
            Ok(OperationLookup::New)
        }
        async fn complete_operation(
            &self,
            _: &Lease,
            key: Uuid,
            value: &serde_json::Value,
            model_tokens: u64,
        ) -> Result<(), StoreError> {
            let mut db = self.0.lock().map_err(|_| StoreError::InvalidRecord)?;
            db.task.model_tokens = db
                .task
                .model_tokens
                .checked_add(model_tokens)
                .ok_or(StoreError::InvalidRecord)?;
            db.ops
                .insert(key, OperationLookup::Completed(value.clone()));
            Ok(())
        }
        async fn save(
            &self,
            _: &Lease,
            expected: State,
            task: &TaskRecord,
            _: &TrustedPolicy,
            _: &ObservedFacts,
        ) -> Result<(), StoreError> {
            let mut db = self.0.lock().map_err(|_| StoreError::InvalidRecord)?;
            if db.fail_save {
                return Err(StoreError::InvalidRecord);
            }
            if db.task.state != expected {
                return Err(StoreError::InvalidRecord);
            }
            task.validate().map_err(|_| StoreError::InvalidRecord)?;
            db.task = task.clone();
            db.saves += 1;
            Ok(())
        }
        async fn release(&self, _: &Lease) -> Result<(), StoreError> {
            self.0
                .lock()
                .map_err(|_| StoreError::InvalidRecord)?
                .releases += 1;
            Ok(())
        }
    }

    #[derive(Clone)]
    struct MockPolicy(TrustedPolicy);
    impl TrustedPolicySource for MockPolicy {
        async fn load_policy(&self, _: &TaskRecord) -> Result<TrustedPolicy, ()> {
            Ok(self.0.clone())
        }
    }
    #[derive(Clone)]
    struct MockEvidence(Arc<Mutex<MockDb>>, Arc<Mutex<ObservedFacts>>);
    impl EvidenceSource for MockEvidence {
        async fn observe(&self, task: &TaskRecord, _: &TrustedPolicy) -> Result<ObservedFacts, ()> {
            let mut db = self.0.lock().map_err(|_| ())?;
            let executions = db.executions;
            db.observed
                .push((task.state, task.head_sha.clone(), executions));
            drop(db);
            Ok(self.1.lock().map_err(|_| ())?.clone())
        }
    }
    #[derive(Clone)]
    struct MockRunner(Arc<Mutex<MockDb>>);
    impl StageRunner for MockRunner {
        fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError> {
            if self
                .0
                .lock()
                .map_err(|_| crate::agent::ConfigError::ConcurrentTasks)?
                .configuration_valid
            {
                Ok(())
            } else {
                Err(crate::agent::ConfigError::ConcurrentTasks)
            }
        }

        fn agent_roles(&self) -> (Provider, Provider) {
            (Provider::Codex, Provider::Claude)
        }

        async fn execute(
            &self,
            stage: Stage,
            task: &TaskRecord,
            _: &TrustedPolicy,
            _: ExecutionBudget,
        ) -> Result<StageOutput, StageFailure> {
            let mut db = self.0.lock().map_err(|_| StageFailure::Internal)?;
            db.executions += 1;
            Ok(match stage {
                Stage::Plan => StageOutput {
                    assignee: Some("bot".into()),
                    implementer: Some("codex".into()),
                    reviewer: Some("claude".into()),
                    session_id: Some(task.task_id.clone()),
                    head_sha: None,
                    pull_request: None,
                    validation_passed: false,
                    model_tokens: 1,
                    mock_github_journal: None,
                    plan: Some(MockPlan {
                        requirements: vec!["complete the requested mock task".into()],
                        steps: vec!["implement".into(), "validate".into(), "review".into()],
                    }),
                    code_change: None,
                },
                Stage::Implement => StageOutput {
                    assignee: None,
                    implementer: None,
                    reviewer: None,
                    session_id: None,
                    head_sha: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()),
                    pull_request: None,
                    validation_passed: false,
                    model_tokens: 2,
                    mock_github_journal: None,
                    plan: None,
                    code_change: Some(MockCodeChange {
                        summary: "apply the deterministic mock change".into(),
                        changed_files: vec!["src/mock_generated.rs".into()],
                        patch_digest: mock_patch_digest(
                            "apply the deterministic mock change",
                            &["src/mock_generated.rs".into()],
                        )
                        .unwrap_or_default(),
                    }),
                },
                Stage::Validate => StageOutput {
                    assignee: None,
                    implementer: None,
                    reviewer: None,
                    session_id: None,
                    head_sha: None,
                    pull_request: Some(7),
                    validation_passed: if db.validation_failures > 0 {
                        db.validation_failures -= 1;
                        false
                    } else {
                        true
                    },
                    model_tokens: 1,
                    mock_github_journal: None,
                    plan: None,
                    code_change: None,
                },
                Stage::Review => StageOutput {
                    assignee: None,
                    implementer: None,
                    reviewer: None,
                    session_id: None,
                    head_sha: task.head_sha.clone(),
                    pull_request: task.pull_request,
                    validation_passed: if db.review_failures > 0 {
                        db.review_failures -= 1;
                        false
                    } else {
                        true
                    },
                    model_tokens: 1,
                    mock_github_journal: None,
                    plan: None,
                    code_change: None,
                },
                Stage::Merge => return Err(StageFailure::InvalidConfiguration),
            })
        }

        async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
            let mut db = self.0.lock().map_err(|_| ())?;
            db.stop_attempts += 1;
            if db.stop_confirmed { Ok(()) } else { Err(()) }
        }
    }

    struct MockRecovery;
    impl RecoveryVerifier for MockRecovery {
        fn verify_stopped(&self, _: Uuid, _: &str, _: i64) -> Option<serde_json::Value> {
            None
        }
    }

    fn fixture() -> (
        TestEngine,
        Arc<Mutex<MockDb>>,
        Uuid,
        Arc<Mutex<ObservedFacts>>,
    ) {
        let id = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        let base = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        let task = TaskRecord {
            task_id: id.to_string(),
            issue_number: 5,
            base_sha: base.clone(),
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
        let policy = TrustedPolicy {
            base_ref: "develop".into(),
            base_sha: base.clone(),
            allowed_assignee: "bot".into(),
            required_checks: vec!["ci".into()],
            max_attempts: 3,
            max_runtime: Duration::from_secs(600),
            max_model_tokens: 100,
        };
        let facts = ObservedFacts {
            policy_base_ref: "develop".into(),
            policy_base_sha: base.clone(),
            issue_open: true,
            base_sha: base,
            head_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            validated_head_sha: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()),
            pr_number: Some(7),
            pr_head_sha: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()),
            pr_base_ref: Some("develop".into()),
            pr_base_sha: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
            pr_merged: false,
            merge_commit_sha: None,
            base_contains_merge_commit: false,
            checks_passed: vec!["ci".into()],
            reviewer_approved: true,
            approved_assignee: "bot".into(),
        };
        let db = Arc::new(Mutex::new(MockDb {
            task,
            ops: HashMap::new(),
            executions: 0,
            saves: 0,
            validation_failures: 0,
            review_failures: 0,
            observed: Vec::new(),
            stop_confirmed: true,
            stop_attempts: 0,
            fail_save: false,
            configuration_valid: true,
            releases: 0,
        }));
        let observed = Arc::new(Mutex::new(facts));
        let engine = Engine {
            store: MockStore(db.clone()),
            policies: MockPolicy(policy),
            evidence: MockEvidence(db.clone(), observed.clone()),
            runner: MockRunner(db.clone()),
            recovery: MockRecovery,
            mock_github: None,
            lease_ttl: Duration::from_secs(30),
        };
        (engine, db, id, observed)
    }

    #[tokio::test]
    async fn operation_replay_never_executes_twice_and_ambiguous_work_blocks() {
        let (engine, db, id, _) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Planning;
            db.task.attempts = 1;
        }
        let key = operation_key(id, 1, State::Planning, Stage::Plan);
        {
            let mut db = db.lock().unwrap();
            db.stop_confirmed = false;
            db.ops.insert(key, OperationLookup::Ambiguous);
        }
        let lease = Lease {
            task_id: id,
            owner: "worker".into(),
            fencing_token: 1,
        };
        let result = engine.run_claimed(&lease).await.unwrap();
        assert_eq!(result, StepResult::BlockedAmbiguousOperation);
        let db = db.lock().unwrap();
        assert_eq!(db.executions, 0);
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.task.checkpoint, Some(State::Planning));
        assert_eq!(db.releases, 0);
    }

    #[tokio::test]
    async fn stop_is_attempted_even_when_blocked_state_cannot_be_saved() {
        let (engine, db, id, _) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Planning;
            db.task.attempts = 1;
            db.fail_save = true;
            let key = operation_key(id, 1, State::Planning, Stage::Plan);
            db.ops.insert(key, OperationLookup::Ambiguous);
        }
        let lease = Lease {
            task_id: id,
            owner: "worker".into(),
            fencing_token: 1,
        };

        assert!(matches!(
            engine.run_claimed(&lease).await,
            Err(EngineError::Store(StoreError::InvalidRecord))
        ));
        let db = db.lock().unwrap();
        assert_eq!(db.stop_attempts, 1);
        assert_eq!(db.releases, 0);
        assert_eq!(db.task.state, State::Planning);
    }

    #[tokio::test]
    async fn fresh_sha_mismatch_prevents_stage_execution() {
        let (engine, db, id, facts) = fixture();
        facts.lock().unwrap().base_sha = "cccccccccccccccccccccccccccccccccccccccc".into();
        assert!(matches!(
            engine.run_one(id, "worker").await,
            Err(EngineError::InvalidTransition(domain::Error::StaleBase))
        ));
        assert_eq!(db.lock().unwrap().executions, 0);
    }

    #[tokio::test]
    async fn invalid_agent_configuration_is_rejected_before_task_claim() {
        let (engine, db, id, _) = fixture();
        db.lock().unwrap().configuration_valid = false;

        assert!(matches!(
            engine.run_one(id, "worker").await,
            Err(EngineError::InvalidConfiguration)
        ));
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Queued);
        assert_eq!(db.executions, 0);
    }

    #[tokio::test]
    async fn mock_policy_cannot_raise_the_configured_repair_limit() {
        let (mut engine, db, id, _) = fixture();
        engine.policies.0.max_attempts = 4;
        engine.mock_github = Some(Arc::new(Mutex::new(MockGitHubAdapter::new(
            MockGitHubPolicy::with_agents(
                vec!["develop".into()],
                vec!["ci".into()],
                Provider::Codex,
                Provider::Claude,
            )
            .unwrap(),
        ))));

        assert!(matches!(
            engine.run_one(id, "worker").await,
            Err(EngineError::InvalidConfiguration)
        ));
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Queued);
        assert_eq!(db.executions, 0);
    }

    #[test]
    fn mock_agent_stages_are_capped_at_45_minutes() {
        let limit = Duration::from_secs(
            u64::from(AutonomyConfig::approved_mock_defaults().agent_timeout_minutes) * 60,
        );
        let long_budget = Duration::from_secs(60 * 60);

        assert_eq!(stage_timeout(Stage::Plan, long_budget, true), limit);
        assert_eq!(stage_timeout(Stage::Implement, long_budget, true), limit);
        assert_eq!(stage_timeout(Stage::Review, long_budget, true), limit);
        assert_eq!(
            stage_timeout(Stage::Validate, long_budget, true),
            long_budget
        );
        assert_eq!(stage_timeout(Stage::Plan, long_budget, false), long_budget);
    }

    #[tokio::test]
    async fn observed_merge_completes_without_invoking_a_merge_operation() {
        let (engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Merging;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        facts.lock().unwrap().pr_merged = true;
        facts.lock().unwrap().base_sha = "dddddddddddddddddddddddddddddddddddddddd".into();
        facts.lock().unwrap().merge_commit_sha =
            Some("cccccccccccccccccccccccccccccccccccccccc".into());
        facts.lock().unwrap().base_contains_merge_commit = true;
        let lease = Lease {
            task_id: id,
            owner: "worker".into(),
            fencing_token: 1,
        };
        assert_eq!(
            engine.run_claimed(&lease).await.unwrap(),
            StepResult::Finished
        );
        assert_eq!(db.lock().unwrap().task.state, State::Completed);
        assert_eq!(db.lock().unwrap().executions, 0);
    }

    #[tokio::test]
    async fn completed_database_row_requires_fresh_github_merge_evidence() {
        let (engine, db, id, _) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Completed;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        let lease = Lease {
            task_id: id,
            owner: "worker".into(),
            fencing_token: 1,
        };
        assert!(matches!(
            engine.run_claimed(&lease).await,
            Err(EngineError::InvalidTransition(_))
        ));
    }

    #[tokio::test]
    async fn runs_all_stages_under_one_lease_and_stops_at_human_merge() {
        let (engine, db, id, _) = fixture();
        let (first, second) = tokio::join!(
            engine.run_one(id, "worker-a"),
            engine.run_one(id, "worker-b")
        );
        assert!(
            matches!(
                (&first, &second),
                (Ok(StepResult::WaitingForHuman), Err(_))
                    | (Err(_), Ok(StepResult::WaitingForHuman))
            ),
            "first={first:?}, second={second:?}"
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Merging);
        assert_eq!(db.executions, 4);
        assert_eq!(db.task.model_tokens, 5);
        assert!(db.observed.iter().any(|(state, head, calls)| {
            *state == State::Implementing
                && head.as_deref() == Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                && *calls == 2
        }));
    }

    #[tokio::test]
    async fn completed_operation_reuses_checkpoint_after_crash_without_rerun() {
        let (engine, db, id, _) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Planning;
            db.task.attempts = 1;
            db.task.model_tokens = 1;
            let key = operation_key(id, 1, State::Planning, Stage::Plan);
            db.ops.insert(
                key,
                OperationLookup::Completed(
                    serde_json::to_value(StageOutput {
                        assignee: Some("bot".into()),
                        implementer: Some("codex".into()),
                        reviewer: Some("claude".into()),
                        session_id: Some(id.to_string()),
                        head_sha: None,
                        pull_request: None,
                        validation_passed: false,
                        model_tokens: 1,
                        mock_github_journal: None,
                        plan: Some(MockPlan {
                            requirements: vec!["complete the requested mock task".into()],
                            steps: vec!["implement".into(), "validate".into(), "review".into()],
                        }),
                        code_change: None,
                    })
                    .unwrap(),
                ),
            );
        }
        let lease = Lease {
            task_id: id,
            owner: "recovered-worker".into(),
            fencing_token: 2,
        };
        let result = engine.run_claimed(&lease).await;
        let db = db.lock().unwrap();
        assert_eq!(
            result.as_ref().ok(),
            Some(&StepResult::WaitingForHuman),
            "result={result:?}, state={:?}, calls={}",
            db.task.state,
            db.executions
        );
        assert_eq!(db.executions, 3);
    }

    #[tokio::test]
    async fn explicit_resume_reuses_completed_review_without_duplicate_execution_or_usage() {
        let (engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Reviewing;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        facts.lock().unwrap().reviewer_approved = false;
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1
                })
                .await
                .unwrap(),
            StepResult::Advanced(State::Paused)
        );
        {
            let mut facts = facts.lock().unwrap();
            facts.reviewer_approved = true;
        }
        assert_eq!(
            engine.resume(id, "resume-worker").await.unwrap(),
            StepResult::WaitingForHuman
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Merging);
        assert_eq!(db.task.model_tokens, 1);
        assert_eq!(db.executions, 1);
    }

    #[tokio::test]
    async fn failed_validation_enters_repairing_and_consumes_a_bounded_attempt() {
        let (engine, db, id, _) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Validating;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.validation_failures = 1;
        }
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1
                })
                .await
                .unwrap(),
            StepResult::WaitingForHuman
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Merging);
        assert_eq!(db.task.attempts, 2);
        assert_eq!(db.executions, 4);
    }

    #[tokio::test]
    async fn review_changes_are_repaired_and_revalidated() {
        let (engine, db, id, _) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Reviewing;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
            db.review_failures = 1;
        }
        let lease = Lease {
            task_id: id,
            owner: "worker".into(),
            fencing_token: 1,
        };
        assert_eq!(
            engine.run_claimed(&lease).await.unwrap(),
            StepResult::WaitingForHuman
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.attempts, 1);
        assert_eq!(db.executions, 4);
    }

    #[tokio::test]
    async fn exhausted_review_repairs_pause_without_discarding_the_checkpoint() {
        let (engine, db, id, _) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Reviewing;
            db.task.attempts = 3;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
            db.review_failures = 1;
        }
        let lease = Lease {
            task_id: id,
            owner: "worker".into(),
            fencing_token: 1,
        };
        assert_eq!(
            engine.run_claimed(&lease).await.unwrap(),
            StepResult::Advanced(State::Paused)
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.checkpoint, Some(State::Reviewing));
        assert_eq!(db.task.pull_request, Some(7));
        assert_eq!(db.task.attempts, 3);
    }

    #[test]
    fn task_journal_rejects_request_key_mismatch_and_foreign_branch_identity() {
        let (engine, db, _, _) = fixture();
        let task_id = Uuid::parse_str(&db.lock().unwrap().task.task_id).unwrap();
        let policy = engine.policies.0.clone();
        let task = {
            let mut task = db.lock().unwrap().task.clone();
            task.implementer = Some("codex".into());
            task.reviewer = Some("claude".into());
            task.session_id = Some("session-1".into());
            task
        };
        let branch = format!("orchestrator/{task_id}");
        let base_sha = task.base_sha.clone();
        let request = MockGitHubRequest::CreateBranch {
            branch: branch.clone(),
            base_sha: base_sha.clone(),
        };
        let result = Ok(MockGitHubOutput::BranchCreated {
            branch: branch.clone(),
            head_sha: base_sha.clone(),
        });
        let operation = operation_key(task_id, 0, State::Implementing, Stage::Implement);

        for (suffix, request, result) in [
            ("push", request.clone(), result.clone()),
            (
                "branch",
                MockGitHubRequest::CreateBranch {
                    branch: "orchestrator/foreign-task".into(),
                    base_sha: base_sha.clone(),
                },
                Ok(MockGitHubOutput::BranchCreated {
                    branch: "orchestrator/foreign-task".into(),
                    head_sha: base_sha.clone(),
                }),
            ),
        ] {
            let mut forged = task.clone();
            forged.mock_github_journal = Some(serde_json::json!([MockGitHubJournalEntry {
                idempotency_key: format!("{operation}:{suffix}"),
                request,
                result,
            }]));
            assert!(
                matches!(
                    validate_task_journal(&forged, &policy, false),
                    Err(EngineError::InvalidOperationResult)
                ),
                "a replayable journal must still match the task operation and task identity"
            );
        }
    }

    #[test]
    fn structured_plan_and_change_outputs_are_validated_before_persistence() {
        let plan = StageOutput {
            assignee: None,
            implementer: None,
            reviewer: None,
            session_id: None,
            head_sha: None,
            pull_request: None,
            validation_passed: false,
            model_tokens: 0,
            mock_github_journal: None,
            plan: Some(MockPlan {
                requirements: vec!["preserve the caller contract".into()],
                steps: vec!["implement".into()],
            }),
            code_change: None,
        };
        assert!(valid_stage_output(Stage::Plan, &plan));
        assert!(!valid_stage_output(Stage::Implement, &plan));

        let summary = "apply the mock change";
        let files = vec!["src/mock_generated.rs".to_owned()];
        let change = StageOutput {
            plan: None,
            code_change: Some(MockCodeChange {
                summary: summary.into(),
                changed_files: files.clone(),
                patch_digest: mock_patch_digest(summary, &files).unwrap(),
            }),
            ..plan.clone()
        };
        assert!(valid_stage_output(Stage::Implement, &change));

        let mut tampered = change.clone();
        tampered.code_change.as_mut().unwrap().patch_digest = "0".repeat(64);
        assert!(!valid_stage_output(Stage::Implement, &tampered));

        let unsafe_files = vec!["../outside.rs".to_owned()];
        let unsafe_change = StageOutput {
            code_change: Some(MockCodeChange {
                summary: summary.into(),
                changed_files: unsafe_files.clone(),
                patch_digest: mock_patch_digest(summary, &unsafe_files).unwrap(),
            }),
            ..change
        };
        assert!(!valid_stage_output(Stage::Implement, &unsafe_change));
    }

    #[derive(Clone)]
    struct TimeoutRunner {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        stops: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl StageRunner for TimeoutRunner {
        fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError> {
            Ok(())
        }

        fn agent_roles(&self) -> (Provider, Provider) {
            (Provider::Codex, Provider::Claude)
        }

        async fn execute(
            &self,
            _: Stage,
            _: &TaskRecord,
            _: &TrustedPolicy,
            _: ExecutionBudget,
        ) -> Result<StageOutput, StageFailure> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(1)).await;
            Err(StageFailure::InvalidInput)
        }

        async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
            self.stops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn agent_timeout_blocks_and_preserves_the_checkpoint_without_reexecution() {
        let (engine, db, task_id, _) = fixture();
        let runner = TimeoutRunner {
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            stops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let mut policy = engine.policies.0.clone();
        policy.max_runtime = Duration::from_millis(10);
        let engine = Engine {
            store: engine.store,
            policies: MockPolicy(policy),
            evidence: engine.evidence,
            runner: runner.clone(),
            recovery: engine.recovery,
            mock_github: None,
            lease_ttl: engine.lease_ttl,
        };

        assert_eq!(
            engine.run_one(task_id, "worker").await.unwrap(),
            StepResult::BlockedStageFailure(StageFailure::Timeout)
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.task.checkpoint, Some(State::Planning));
        assert!(db.task.head_sha.is_none());
        assert_eq!(db.ops.len(), 1);
        assert!(matches!(
            db.ops.values().next(),
            Some(OperationLookup::Ambiguous)
        ));
        assert_eq!(runner.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(runner.stops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    struct InvalidOutputRunner;

    impl StageRunner for InvalidOutputRunner {
        fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError> {
            Ok(())
        }

        fn agent_roles(&self) -> (Provider, Provider) {
            (Provider::Codex, Provider::Claude)
        }

        async fn execute(
            &self,
            _: Stage,
            _: &TaskRecord,
            _: &TrustedPolicy,
            _: ExecutionBudget,
        ) -> Result<StageOutput, StageFailure> {
            Ok(StageOutput {
                assignee: Some("bot".into()),
                implementer: Some("codex".into()),
                reviewer: Some("claude".into()),
                session_id: Some("invalid-plan-output".into()),
                head_sha: None,
                pull_request: None,
                validation_passed: false,
                model_tokens: 1,
                mock_github_journal: None,
                plan: None,
                code_change: None,
            })
        }

        async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn invalid_stage_output_is_blocked_with_a_structured_reason() {
        let (engine, db, task_id, _) = fixture();
        let engine = Engine {
            store: engine.store,
            policies: engine.policies,
            evidence: engine.evidence,
            runner: InvalidOutputRunner,
            recovery: engine.recovery,
            mock_github: None,
            lease_ttl: engine.lease_ttl,
        };

        assert_eq!(
            engine.run_one(task_id, "worker").await.unwrap(),
            StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.task.checkpoint, Some(State::Planning));
    }
}

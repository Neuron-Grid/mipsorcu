//! One-step-at-a-time orchestration. External work is injectable and operation
//! records make an interrupted side effect fail closed on the next invocation.

use std::{future::Future, time::Duration};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

use crate::{
    domain::{self, ObservedFacts, State, TaskRecord, TrustedPolicy},
    postgres::{Lease, OperationStatus, RecoveryVerifier, StoreError, TaskStore},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Plan,
    Implement,
    Validate,
    Review,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StageOutput {
    pub assignee: Option<String>,
    pub head_sha: Option<String>,
    pub pull_request: Option<u64>,
    pub validation_passed: bool,
    pub model_tokens: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ExecutionBudget {
    pub remaining_runtime: Duration,
    pub remaining_model_tokens: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepResult {
    Advanced(State),
    WaitingForHuman,
    BlockedAmbiguousOperation,
    Finished,
}

#[derive(Debug)]
pub enum EngineError {
    Store(StoreError),
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
    /// A production implementation may invoke Codex CLI here. The engine never
    /// shells out itself and tests use an in-memory mock. Cancellation must stop
    /// the child process, and all writes must stay inside the task worktree.
    fn execute(
        &self,
        stage: Stage,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        budget: ExecutionBudget,
    ) -> impl Future<Output = Result<StageOutput, ()>> + Send;

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
    /// reaches the human merge handoff. Active-task crash recovery requires a
    /// separately verified supervisor-issued lease.
    pub async fn run_one(&self, task_id: Uuid, owner: &str) -> Result<StepResult, EngineError> {
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
            .claim(task_id, owner, self.lease_ttl, &policy, &facts)
            .await?;
        self.run_claimed(&lease).await
    }

    /// Explicitly resumes a persisted pause/block after fresh policy and
    /// GitHub evidence are checked by the store's fenced transition.
    pub async fn resume(&self, task_id: Uuid, owner: &str) -> Result<StepResult, EngineError> {
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
        let snapshot = self.store.get(prior.task_id).await?;
        snapshot.validate().map_err(|_| EngineError::InvalidTask)?;
        let policy = self
            .policies
            .load_policy(&snapshot)
            .await
            .map_err(|_| EngineError::PolicyUnavailable)?;
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
        loop {
            let task = self.store.load(lease).await?;
            task.validate().map_err(|_| EngineError::InvalidTask)?;
            let policy = self
                .policies
                .load_policy(&task)
                .await
                .map_err(|_| EngineError::PolicyUnavailable)?;
            let before = self
                .evidence
                .observe(&task, &policy)
                .await
                .map_err(|_| EngineError::EvidenceUnavailable)?;
            if task.state == State::Merging {
                if !before.pr_merged {
                    self.store.release(lease).await?;
                    return Ok(StepResult::WaitingForHuman);
                }
                if before.policy_base_ref != policy.base_ref
                    || before.policy_base_sha != policy.base_sha
                {
                    return Err(EngineError::InvalidTransition(domain::Error::StaleBase));
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
            if task.state == State::Completed {
                domain::validate_completed(&task, &policy, &before)
                    .map_err(EngineError::InvalidTransition)?;
                self.store.release(lease).await?;
                return Ok(StepResult::Finished);
            }
            verify_base(&task, &policy, &before)?;
            if matches!(task.state, State::Blocked | State::Paused) {
                return Err(EngineError::InvalidTransition(
                    domain::Error::InvalidTransition,
                ));
            }
            let Some((stage, next)) = stage_for(task.state) else {
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
            let hash = request_hash(&task, stage);
            let output = match self
                .store
                .prepare_operation(lease, key, stage_name(stage), &hash)
                .await?
            {
                OperationLookup::New => {
                    let output = match self
                        .execute_guarded(stage, &task, &policy, budget, lease)
                        .await
                    {
                        Ok(output) => output,
                        Err(()) => {
                            return self
                                .stop_and_block(lease, key, &task, &policy, &before)
                                .await;
                        }
                    };
                    let value = serde_json::to_value(&output)
                        .map_err(|_| EngineError::InvalidOperationResult)?;
                    self.store
                        .complete_operation(lease, key, &value, output.model_tokens)
                        .await?;
                    output
                }
                OperationLookup::Completed(value) => serde_json::from_value(value)
                    .map_err(|_| EngineError::InvalidOperationResult)?,
                OperationLookup::Ambiguous => {
                    return self
                        .stop_and_block(lease, key, &task, &policy, &before)
                        .await;
                }
            };

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
                candidate.pull_request = None;
                candidate.validation_passed = false;
                if task.attempts >= policy.max_attempts {
                    next = State::Paused;
                } else {
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
            domain::transition_from(&current, &mut candidate, next, &policy, &after)
                .map_err(EngineError::InvalidTransition)?;
            self.store
                .save(lease, current.state, &candidate, &policy, &after)
                .await?;
            if candidate.state == State::Merging {
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
    ) -> Result<StageOutput, ()> {
        let preflight = self.evidence.observe(task, policy).await?;
        verify_base(task, policy, &preflight).map_err(|_| ())?;
        self.store
            .renew(lease, self.lease_ttl)
            .await
            .map_err(|_| ())?;
        let future = self.runner.execute(stage, task, policy, budget);
        tokio::pin!(future);
        let heartbeat = (self.lease_ttl / 3).max(Duration::from_millis(250));
        let mut interval =
            tokio::time::interval_at(tokio::time::Instant::now() + heartbeat, heartbeat);
        tokio::select! {
            result = tokio::time::timeout(budget.remaining_runtime, &mut future) => result.map_err(|_| ())?,
            _ = async {
                loop {
                    interval.tick().await;
                    self.store.renew(lease, self.lease_ttl).await.map_err(|_| ())?;
                    let facts = self.evidence.observe(task, policy).await?;
                    verify_base(task, policy, &facts).map_err(|_| ())?;
                }
                #[allow(unreachable_code)]
                Ok::<(), ()>(())
            } => Err(()),
        }
    }

    async fn stop_and_block(
        &self,
        lease: &Lease,
        operation_key: Uuid,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
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
        Ok(StepResult::BlockedAmbiguousOperation)
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

fn stage_name(stage: Stage) -> &'static str {
    match stage {
        Stage::Plan => "plan",
        Stage::Implement => "implement",
        Stage::Validate => "validate",
        Stage::Review => "review",
    }
}

fn operation_key(task_id: Uuid, attempt: u32, state: State, stage: Stage) -> Uuid {
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

fn request_hash(task: &TaskRecord, stage: Stage) -> [u8; 32] {
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
        observed: Vec<(State, Option<String>, usize)>,
        stop_confirmed: bool,
        stop_attempts: usize,
        fail_save: bool,
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
            candidate.attempts += 1;
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
        async fn execute(
            &self,
            stage: Stage,
            task: &TaskRecord,
            _: &TrustedPolicy,
            _: ExecutionBudget,
        ) -> Result<StageOutput, ()> {
            let mut db = self.0.lock().map_err(|_| ())?;
            db.executions += 1;
            Ok(match stage {
                Stage::Plan => StageOutput {
                    assignee: Some("bot".into()),
                    head_sha: None,
                    pull_request: None,
                    validation_passed: false,
                    model_tokens: 1,
                },
                Stage::Implement => StageOutput {
                    assignee: None,
                    head_sha: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()),
                    pull_request: None,
                    validation_passed: false,
                    model_tokens: 2,
                },
                Stage::Validate => StageOutput {
                    assignee: None,
                    head_sha: None,
                    pull_request: Some(7),
                    validation_passed: if db.validation_failures > 0 {
                        db.validation_failures -= 1;
                        false
                    } else {
                        true
                    },
                    model_tokens: 1,
                },
                Stage::Review => StageOutput {
                    assignee: None,
                    head_sha: task.head_sha.clone(),
                    pull_request: task.pull_request,
                    validation_passed: true,
                    model_tokens: 1,
                },
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
            head_sha: None,
            state: State::Queued,
            attempts: 0,
            assignee: None,
            validation_passed: false,
            pull_request: None,
            checkpoint: None,
            elapsed: Duration::ZERO,
            model_tokens: 0,
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
            observed: Vec::new(),
            stop_confirmed: true,
            stop_attempts: 0,
            fail_save: false,
            releases: 0,
        }));
        let observed = Arc::new(Mutex::new(facts));
        let engine = Engine {
            store: MockStore(db.clone()),
            policies: MockPolicy(policy),
            evidence: MockEvidence(db.clone(), observed.clone()),
            runner: MockRunner(db.clone()),
            recovery: MockRecovery,
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
                        head_sha: None,
                        pull_request: None,
                        validation_passed: false,
                        model_tokens: 1,
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
}

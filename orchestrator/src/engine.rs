//! One-step-at-a-time orchestration. External work is injectable and operation
//! records make an interrupted side effect fail closed on the next invocation.

use std::{
    fmt,
    future::Future,
    io::{self, Write},
    path::{Component, Path},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

use crate::{
    agent::{AutonomyConfig, Cancellation, Failure, Provider},
    domain::{self, ObservedFacts, State, TaskRecord, TrustedPolicy},
    mock_github::{
        MockGitHubAdapter, MockGitHubError, MockGitHubJournalEntry, MockGitHubOutput,
        MockGitHubPolicy, MockGitHubRequest,
    },
    policy::PolicyBundle,
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

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct MockPlan {
    pub requirements: Vec<String>,
    pub steps: Vec<String>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct MockCodeChange {
    pub summary: String,
    pub changed_files: Vec<String>,
    /// SHA3-256 over the deterministic mock patch descriptor, separate from Git's head SHA.
    pub patch_digest: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct StageOutput {
    pub assignee: Option<String>,
    pub implementer: Option<String>,
    pub reviewer: Option<String>,
    pub session_id: Option<String>,
    pub head_sha: Option<String>,
    pub pull_request: Option<u64>,
    pub validation_passed: bool,
    #[serde(default)]
    pub local_validation_passed: Option<bool>,
    pub model_tokens: u64,
    pub mock_github_journal: Option<serde_json::Value>,
    #[serde(default)]
    pub plan: Option<MockPlan>,
    #[serde(default)]
    pub code_change: Option<MockCodeChange>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedStageResultV1 {
    result_type: String,
    format_version: u8,
    stage: Stage,
    metadata: PersistedStageMetadataV1,
    model_tokens: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedStageMetadataV1 {
    assignee: Option<String>,
    implementer: Option<String>,
    reviewer: Option<String>,
    session_id: Option<String>,
    head_sha: Option<String>,
    pull_request: Option<u64>,
    validation_passed: bool,
    local_validation_passed: Option<bool>,
}

struct AppliedStageOutput {
    assignee: Option<String>,
    implementer: Option<String>,
    reviewer: Option<String>,
    session_id: Option<String>,
    head_sha: Option<String>,
    pull_request: Option<u64>,
    validation_passed: bool,
    local_validation_passed: Option<bool>,
    model_tokens: u64,
    mock_github_journal: Option<serde_json::Value>,
}

impl From<StageOutput> for AppliedStageOutput {
    fn from(output: StageOutput) -> Self {
        Self {
            assignee: output.assignee,
            implementer: output.implementer,
            reviewer: output.reviewer,
            session_id: output.session_id,
            head_sha: output.head_sha,
            pull_request: output.pull_request,
            validation_passed: output.validation_passed,
            local_validation_passed: output.local_validation_passed,
            model_tokens: output.model_tokens,
            mock_github_journal: output.mock_github_journal,
        }
    }
}

impl From<PersistedStageResultV1> for AppliedStageOutput {
    fn from(result: PersistedStageResultV1) -> Self {
        Self {
            assignee: result.metadata.assignee,
            implementer: result.metadata.implementer,
            reviewer: result.metadata.reviewer,
            session_id: result.metadata.session_id,
            head_sha: result.metadata.head_sha,
            pull_request: result.metadata.pull_request,
            validation_passed: result.metadata.validation_passed,
            local_validation_passed: result.metadata.local_validation_passed,
            model_tokens: result.model_tokens,
            mock_github_journal: None,
        }
    }
}

/// Encodes only the fields needed to resume an operation. The trusted engine
/// applies task and provider policy checks before persisting this value.
/// Session IDs are UUID correlation IDs for the currently supported Codex,
/// Claude, and supervisor-generated sessions; unverified provider formats fail closed.
pub fn persisted_stage_result_v1(
    stage: Stage,
    output: &StageOutput,
) -> Result<serde_json::Value, StageFailure> {
    if !valid_stage_output(stage, output)
        || output
            .session_id
            .as_deref()
            .is_some_and(|id| !is_canonical_uuid(id))
        || output.mock_github_journal.is_some()
    {
        return Err(StageFailure::InvalidOperationResult);
    }
    let result = PersistedStageResultV1 {
        result_type: "stage_result".into(),
        format_version: 1,
        stage,
        metadata: PersistedStageMetadataV1 {
            assignee: output.assignee.clone(),
            implementer: output.implementer.clone(),
            reviewer: output.reviewer.clone(),
            session_id: output.session_id.clone(),
            head_sha: output.head_sha.clone(),
            pull_request: output.pull_request,
            validation_passed: output.validation_passed,
            local_validation_passed: output.local_validation_passed,
        },
        model_tokens: output.model_tokens,
    };
    serde_json::to_value(result).map_err(|_| StageFailure::InvalidOperationResult)
}

fn is_canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| uuid.to_string() == value)
}

impl fmt::Debug for MockPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MockPlan([REDACTED])")
    }
}

impl fmt::Debug for MockCodeChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MockCodeChange([REDACTED])")
    }
}

impl fmt::Debug for StageOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StageOutput([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ExecutionBudget {
    pub remaining_runtime: Duration,
    pub remaining_model_tokens: u64,
}

/// An independent supervisor proof for a repair operation.
#[derive(Clone, Eq, PartialEq)]
pub enum RepairProof {
    Start,
    Completed {
        head_sha: String,
        pull_request: Option<u64>,
        result_digest: [u8; 32],
        total_model_tokens: u64,
    },
}

const MAX_REPAIR_RESULT_BYTES: usize = 1024 * 1024;

struct BoundedJsonCount(usize);

impl Write for BoundedJsonCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_REPAIR_RESULT_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "result too large"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Hashes the complete JSON value for a supervisor receipt, without logging it.
/// Objects are recursively sorted by key and serialized as compact serde_json;
/// this is a versioned application encoding, not a general JSON canonicalization.
/// A trusted supervisor must derive its receipt independently of the task DB.
pub fn repair_result_digest(result: &serde_json::Value) -> Option<[u8; 32]> {
    if !result.is_object() {
        return None;
    }
    serde_json::to_writer(&mut BoundedJsonCount(0), result).ok()?;
    let mut canonical = result.clone();
    canonical.sort_all_objects();
    let bytes = serde_json::to_vec(&canonical).ok()?;
    let mut digest = Sha3_256::new();
    digest.update(b"mipsorcu.repair.result.v1\0");
    digest.update(bytes);
    Some(digest.finalize().into())
}

impl fmt::Debug for RepairProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => f.write_str("Start"),
            Self::Completed { .. } => f.write_str("Completed([REDACTED])"),
        }
    }
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
    /// Release only an expired BLOCKED lease after independent stop verification.
    fn release_expired_blocked_lease(
        &self,
        _prior: &Lease,
        _verifier: &dyn RecoveryVerifier,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        async { Err(StoreError::RecoveryRejected) }
    }
    /// Takes a fenced lease for Merging/Completed handoff work without changing
    /// task state. A merged Merging row may be dry-run validated before leasing.
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
    /// Renews only for the bounded, read-only verification after a human merge.
    /// Implementations must not make this lease valid for work or task writes.
    fn renew_handoff_verification(
        &self,
        lease: &Lease,
        ttl: Duration,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let _ = (lease, ttl, task, policy, facts);
        async { Err(StoreError::RecoveryRejected) }
    }
    fn work_deadline_expired(
        &self,
        lease: &Lease,
        task: &TaskRecord,
        policy: &TrustedPolicy,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        let _ = (lease, task, policy);
        async { Err(StoreError::RecoveryRejected) }
    }
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
    /// Persists only Merging -> Completed after independent merged evidence.
    fn save_handoff_completed(
        &self,
        lease: &Lease,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let _ = (lease, task, policy, facts);
        async { Err(StoreError::RecoveryRejected) }
    }
    /// Creates or reads the one task-scoped post-merge Issue-close intent.
    /// The returned database marker is never permission to send a write.
    fn prepare_issue_close(
        &self,
        _lease: &Lease,
        _policy: &TrustedPolicy,
        _facts: &ObservedFacts,
    ) -> impl Future<Output = Result<Option<OperationLookup>, StoreError>> + Send {
        async { Err(StoreError::RecoveryRejected) }
    }
    /// Reconciles only fresh remote evidence against an existing close intent.
    fn reconcile_issue_close(
        &self,
        _lease: &Lease,
        _policy: &TrustedPolicy,
        _facts: &ObservedFacts,
    ) -> impl Future<Output = Result<OperationLookup, StoreError>> + Send {
        async { Err(StoreError::RecoveryRejected) }
    }
    fn release(&self, lease: &Lease) -> impl Future<Output = Result<(), StoreError>> + Send;
}

mod issue_close_controller_sealed {
    pub trait Sealed {}
}

/// Crate-internal host-side writer for the single post-merge Issue-close attempt.
/// Implementations must independently verify the live fence and worker lifecycle,
/// recheck remote identity before the PATCH, and initiate at most one send. Dropping
/// this future must not initiate a later send; an already-started HTTP request may
/// still be processed remotely and is treated as ambiguous until fresh evidence is
/// reconciled. Results are accepted only after that reconciliation.
pub trait IssueCloseController: issue_close_controller_sealed::Sealed {
    fn close_issue_once(
        &self,
        _lease: &Lease,
        _task: &TaskRecord,
        _policy: &TrustedPolicy,
        _facts: &ObservedFacts,
        _operation_id: Uuid,
    ) -> impl Future<Output = Result<(), ()>> + Send {
        async { Err(()) }
    }
}

struct RejectIssueCloseController;

impl issue_close_controller_sealed::Sealed for RejectIssueCloseController {}

impl IssueCloseController for RejectIssueCloseController {}

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

    async fn release_expired_blocked_lease(
        &self,
        prior: &Lease,
        verifier: &dyn RecoveryVerifier,
    ) -> Result<(), StoreError> {
        self.inner
            .lock()
            .await
            .release_expired_blocked_lease(prior, verifier)
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

    async fn renew_handoff_verification(
        &self,
        lease: &Lease,
        ttl: Duration,
        _: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<(), StoreError> {
        self.inner
            .lock()
            .await
            .renew_handoff_verification(lease, ttl, policy, facts)
            .await
    }

    async fn work_deadline_expired(
        &self,
        lease: &Lease,
        _: &TaskRecord,
        _: &TrustedPolicy,
    ) -> Result<bool, StoreError> {
        self.inner.lock().await.work_deadline_expired(lease).await
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
            OperationStatus::Completed {
                result,
                fencing_token,
            } => OperationLookup::Completed {
                result,
                fencing_token,
            },
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

    async fn save_handoff_completed(
        &self,
        lease: &Lease,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<(), StoreError> {
        self.inner
            .lock()
            .await
            .save_handoff_completed(lease, task, policy, facts)
            .await
    }

    async fn prepare_issue_close(
        &self,
        lease: &Lease,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<Option<OperationLookup>, StoreError> {
        self.inner
            .lock()
            .await
            .prepare_issue_close(lease, policy, facts)
            .await
            .map(|status| status.map(operation_status_to_lookup))
    }

    async fn reconcile_issue_close(
        &self,
        lease: &Lease,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
    ) -> Result<OperationLookup, StoreError> {
        self.inner
            .lock()
            .await
            .reconcile_issue_close(lease, policy, facts)
            .await
            .map(operation_status_to_lookup)
    }

    async fn release(&self, lease: &Lease) -> Result<(), StoreError> {
        self.inner.lock().await.release(lease).await
    }
}

fn operation_status_to_lookup(status: OperationStatus) -> OperationLookup {
    match status {
        OperationStatus::NewlyPrepared => OperationLookup::New,
        OperationStatus::Ambiguous => OperationLookup::Ambiguous,
        OperationStatus::Completed {
            result,
            fencing_token,
        } => OperationLookup::Completed {
            result,
            fencing_token,
        },
    }
}

#[derive(Clone, PartialEq)]
pub enum OperationLookup {
    New,
    Ambiguous,
    Completed {
        result: serde_json::Value,
        fencing_token: i64,
    },
}

impl fmt::Debug for OperationLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::New => f.write_str("New"),
            Self::Ambiguous => f.write_str("Ambiguous"),
            Self::Completed { .. } => f.write_str("Completed([REDACTED])"),
        }
    }
}

pub trait TrustedPolicySource {
    fn load_policy(
        &self,
        task: &TaskRecord,
    ) -> impl Future<Output = Result<TrustedPolicy, ()>> + Send;
}

/// The caller must load this bundle from operator-controlled configuration,
/// never from a task or the task database.
impl TrustedPolicySource for PolicyBundle {
    async fn load_policy(&self, _: &TaskRecord) -> Result<TrustedPolicy, ()> {
        Ok(self.task_policy().clone())
    }
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

    /// An explicit declaration, not proof that a child process has stopped.
    fn supports_cancellation(&self) -> bool {
        false
    }

    /// A production implementation may invoke Codex CLI here. The engine never
    /// shells out itself and tests use an in-memory mock. All writes must stay
    /// inside the task worktree. The returned future can be dropped without the
    /// engine calling `stop_and_verify`, including when its caller is cancelled.
    /// A real runner must arrange independent cancellation and retain control of
    /// the entire child process tree until the supervisor confirms it has stopped.
    /// Returning success requires that no process from the stage remains active.
    fn execute(
        &self,
        lease: &Lease,
        operation_key: Uuid,
        stage: Stage,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        budget: ExecutionBudget,
    ) -> impl Future<Output = Result<StageOutput, StageFailure>> + Send;

    /// The token signals cancellation, not proof that the process tree stopped.
    /// A real runner must forward it to an independently owned supervisor that
    /// outlives this future. The default refuses to execute.
    #[allow(clippy::too_many_arguments)]
    fn execute_with_cancellation(
        &self,
        _lease: &Lease,
        _operation_key: Uuid,
        _stage: Stage,
        _task: &TaskRecord,
        _policy: &TrustedPolicy,
        _budget: ExecutionBudget,
        _cancellation: Cancellation,
    ) -> impl Future<Output = Result<StageOutput, StageFailure>> + Send {
        async { Err(StageFailure::InvalidConfiguration) }
    }

    /// Independently measures local validation for the task's current head.
    ///
    /// A trusted implementation must check the current task, lease, operation key, and head,
    /// and measure the local result without relying on database values or `StageOutput`. It must
    /// use bounded local checks only: no LLM or paid external call. The engine applies the task
    /// budget, timeout, lease heartbeat, and cancellation boundary to this future. A production
    /// runner must not trust stage output or database fields as evidence. This method is called
    /// before every review, merge, or completion authority decision and after a Validate result.
    /// The default rejects callers that cannot provide that proof.
    fn verify_local_validation(
        &self,
        _lease: &Lease,
        _operation_key: Uuid,
        _task: &TaskRecord,
        _policy: &TrustedPolicy,
    ) -> impl Future<Output = Result<bool, ()>> + Send {
        async { Err(()) }
    }

    /// Independently proves whether a repair may start or has already completed.
    ///
    /// This is a read-only bounded local verification contract: it must not run
    /// an LLM, write files, or perform external changes. Implementations must
    /// verify the fenced lease and operation key as well as independently
    /// establish the repair reason and any unconsumed review findings before
    /// returning `Start`. `Completed` requires an independent receipt binding
    /// task, attempt, operation key, request, fencing generation, head, pull request,
    /// complete result digest, and post-operation token usage. The receipt must
    /// not be derived from the task database. The supplied facts are freshly
    /// observed outside the task row; runners must validate them against their
    /// independent local context. A runner may authorize a restart only when it
    /// can independently recover the required proof; absence of that proof must
    /// fail closed.
    /// Review prose must remain private to the runner and must not be returned
    /// in `StageOutput`, logged, or persisted. The engine applies timeout,
    /// lease-renewal, evidence-freshness, and cancellation boundaries. The
    /// default rejects runners that cannot provide this independent proof.
    fn verify_repair_context(
        &self,
        _lease: &Lease,
        _operation_key: Uuid,
        _task: &TaskRecord,
        _policy: &TrustedPolicy,
        _facts: &ObservedFacts,
    ) -> impl Future<Output = Result<RepairProof, ()>> + Send {
        async { Err(()) }
    }

    /// Independently verifies a completed non-Mock operation using a durable
    /// supervisor receipt outside the task database.
    ///
    /// The receipt must bind task, attempt, operation, stage, request hash,
    /// original and current fencing generations, result digest, and actual
    /// cumulative model-token usage. Implementations are bounded and read-only:
    /// they must not call an LLM, spawn processes or detached tasks, or perform
    /// external writes. Dropping the future must cancel all verification work.
    /// They must compare
    /// the receipt with trusted supervisor state and the supplied fresh facts,
    /// never derive it from the task database. `request_hash` covers only task
    /// metadata; implementations must independently bind the complete prompt,
    /// model, billing, sandbox, policy fingerprint, and other execution inputs
    /// from trusted supervisor state. Missing or mismatched evidence fails
    /// closed. The default rejects every completed non-Mock replay.
    #[allow(clippy::too_many_arguments)]
    fn verify_completed_operation(
        &self,
        _lease: &Lease,
        _task: &TaskRecord,
        _stage: Stage,
        _operation_key: Uuid,
        _request_hash: [u8; 32],
        _original_fencing_token: i64,
        _result_digest: [u8; 32],
        _cumulative_model_tokens: u64,
        _facts: &ObservedFacts,
    ) -> impl Future<Output = Result<(), ()>> + Send {
        async { Err(()) }
    }

    /// Kill and wait for the child operation identified by its durable key.
    /// Success is the evidence required before the engine releases its lease.
    /// The engine limits this wait and can drop the future; implementations must
    /// retain independent stop and recovery control when cancellation occurs.
    fn stop_and_verify(
        &self,
        lease: &Lease,
        operation_key: Uuid,
    ) -> impl Future<Output = Result<(), ()>> + Send;
}

struct CancelStageOnDrop(Option<Cancellation>);

impl Drop for CancelStageOnDrop {
    fn drop(&mut self) {
        if let Some(cancellation) = &self.0 {
            cancellation.cancel();
        }
    }
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
    S: EngineStore + Sync,
    P: TrustedPolicySource,
    E: EvidenceSource,
    R: StageRunner,
    V: RecoveryVerifier + Sync,
> Engine<S, P, E, R, V>
{
    fn validate_runner(&self) -> Result<(), EngineError> {
        self.runner
            .validate_configuration()
            .map_err(|_| EngineError::InvalidConfiguration)?;
        if !self.runner.supports_cancellation() {
            return Err(EngineError::InvalidConfiguration);
        }
        let settings = AutonomyConfig::approved_mock_defaults();
        if self.runner.agent_roles() != (settings.implementer, settings.reviewer) {
            return Err(EngineError::InvalidConfiguration);
        }
        Ok(())
    }

    async fn observe_handoff_evidence(
        &self,
        task: &TaskRecord,
        policy: &TrustedPolicy,
    ) -> Result<ObservedFacts, ()> {
        let timeout = Duration::from_secs(5).min(self.lease_ttl / 2);
        tokio::time::timeout(timeout, self.evidence.observe(task, policy))
            .await
            .map_err(|_| ())?
    }

    /// Claims a single queued task and advances it under the same lease until it
    /// completes in mock mode or reaches the human merge handoff. Recovery requires a
    /// separately verified supervisor-issued lease.
    pub async fn run_one(&self, task_id: Uuid, owner: &str) -> Result<StepResult, EngineError> {
        self.validate_runner()?;
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
        validate_execution_policy(&policy)?;
        let facts = self
            .evidence
            .observe(&snapshot, &policy)
            .await
            .map_err(|_| EngineError::EvidenceUnavailable)?;
        verify_base(&snapshot, &policy, &facts)?;
        let lease = self
            .store
            .claim(task_id, owner, self.lease_ttl, &policy, &facts)
            .await?;
        self.run_claimed(&lease).await
    }

    /// Explicitly resumes a persisted pause/block after fresh policy and
    /// GitHub evidence are checked by the store's fenced transition.
    pub async fn resume(&self, task_id: Uuid, owner: &str) -> Result<StepResult, EngineError> {
        self.validate_runner()?;
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
        validate_execution_policy(&policy)?;
        let facts = self
            .evidence
            .observe(&task, &policy)
            .await
            .map_err(|_| EngineError::EvidenceUnavailable)?;
        if task.checkpoint == Some(State::Merging) && facts.pr_merged {
            validate_merged_resume(&task, &policy, &facts)?;
        } else {
            verify_base(&task, &policy, &facts)?;
        }
        let lease = self
            .store
            .claim_resume(task_id, owner, self.lease_ttl, &policy, &facts)
            .await?;
        self.run_claimed(&lease).await
    }

    /// Rechecks a human-completed merge under a lease before recording completion.
    pub async fn complete_handoff(
        &self,
        task_id: Uuid,
        owner: &str,
    ) -> Result<StepResult, EngineError> {
        self.complete_handoff_inner(task_id, owner, None::<&RejectIssueCloseController>)
            .await
    }

    /// Rechecks a merge and permits one explicit post-merge Issue-close attempt
    /// through a trusted host controller. The normal handoff path remains read-only.
    pub async fn complete_handoff_with_issue_close<C: IssueCloseController>(
        &self,
        task_id: Uuid,
        owner: &str,
        controller: &C,
    ) -> Result<StepResult, EngineError> {
        self.complete_handoff_inner(task_id, owner, Some(controller))
            .await
    }

    async fn complete_handoff_inner<C: IssueCloseController>(
        &self,
        task_id: Uuid,
        owner: &str,
        controller: Option<&C>,
    ) -> Result<StepResult, EngineError> {
        self.validate_runner()?;
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
        validate_execution_policy(&policy)?;
        let facts = self
            .observe_handoff_evidence(&task, &policy)
            .await
            .map_err(|_| EngineError::EvidenceUnavailable)?;
        if task.state == State::Completed {
            domain::validate_completed(&task, &policy, &facts)
                .map_err(EngineError::InvalidTransition)?;
        } else if facts.pr_merged {
            let mut completed = task.clone();
            domain::transition_from(&task, &mut completed, State::Completed, &policy, &facts)
                .map_err(EngineError::InvalidTransition)?;
        } else {
            verify_base(&task, &policy, &facts)?;
        }
        let lease = self
            .store
            .claim_handoff(task_id, owner, self.lease_ttl, &policy, &facts)
            .await?;
        self.run_claimed_inner(&lease, controller).await
    }

    /// Releases an expired BLOCKED lease after independent stop verification.
    /// The task remains blocked and unresolved operations are never re-executed.
    pub async fn release_expired_blocked_lease(&self, prior: &Lease) -> Result<(), EngineError> {
        self.store
            .release_expired_blocked_lease(prior, &self.recovery)
            .await?;
        Ok(())
    }

    /// Reacquires an expired task only after the supervisor independently
    /// proves that the previous process tree is stopped.
    pub async fn recover_and_run(
        &self,
        prior: &Lease,
        owner: &str,
    ) -> Result<StepResult, EngineError> {
        self.validate_runner()?;
        let snapshot = self.store.get(prior.task_id).await?;
        snapshot.validate().map_err(|_| EngineError::InvalidTask)?;
        let policy = self
            .policies
            .load_policy(&snapshot)
            .await
            .map_err(|_| EngineError::PolicyUnavailable)?;
        validate_execution_policy(&policy)?;
        let facts = self
            .evidence
            .observe(&snapshot, &policy)
            .await
            .map_err(|_| EngineError::EvidenceUnavailable)?;
        if snapshot.state == State::Merging && facts.pr_merged {
            let mut completed = snapshot.clone();
            domain::transition_from(&snapshot, &mut completed, State::Completed, &policy, &facts)
                .map_err(EngineError::InvalidTransition)?;
        } else if snapshot.state == State::Completed {
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
        self.run_claimed_inner(lease, None::<&RejectIssueCloseController>)
            .await
    }

    async fn run_claimed_inner<C: IssueCloseController>(
        &self,
        lease: &Lease,
        issue_close_controller: Option<&C>,
    ) -> Result<StepResult, EngineError> {
        self.validate_runner()?;
        loop {
            let task = self.store.load(lease).await?;
            task.validate().map_err(|_| EngineError::InvalidTask)?;
            let policy = self
                .policies
                .load_policy(&task)
                .await
                .map_err(|_| EngineError::PolicyUnavailable)?;
            validate_execution_policy(&policy)?;
            validate_task_agents(&task, self.runner.agent_roles(), self.mock_github.is_some())?;
            let mut before = if self.mock_github.is_none()
                && matches!(task.state, State::Merging | State::Completed)
            {
                self.observe_handoff_evidence(&task, &policy).await
            } else {
                self.evidence.observe(&task, &policy).await
            }
            .map_err(|_| EngineError::EvidenceUnavailable)?;
            validate_task_journal(&task, &policy, before.pr_merged)?;
            if self.mock_github.is_none()
                && task.state == State::Merging
                && !before.pr_merged
                && (task.elapsed >= policy.max_runtime
                    || self
                        .store
                        .work_deadline_expired(lease, &task, &policy)
                        .await?)
            {
                validate_authority_evidence(&task, &policy, &before)?;
                verify_base(&task, &policy, &before)?;
                validate_merge_preconditions(&task, &policy, &before)?;
                self.store.release(lease).await?;
                return Ok(StepResult::WaitingForHuman);
            }
            let local_validation = if self.mock_github.is_none()
                && matches!(
                    task.state,
                    State::Reviewing | State::Merging | State::Completed
                ) {
                validate_authority_evidence(&task, &policy, &before)?;
                let handoff_verification =
                    before.pr_merged && matches!(task.state, State::Merging | State::Completed);
                let (verified, latest) = match self
                    .verify_state_local_validation(
                        lease,
                        &task,
                        &policy,
                        before.clone(),
                        handoff_verification,
                    )
                    .await
                {
                    Ok(result) => result,
                    Err(_)
                        if task.state == State::Completed
                            || (task.state == State::Merging && before.pr_merged) =>
                    {
                        let task_id =
                            Uuid::parse_str(&task.task_id).map_err(|_| EngineError::InvalidTask)?;
                        let key = operation_key(
                            task_id,
                            task.attempts,
                            State::Validating,
                            Stage::Validate,
                        );
                        let stopped = self.stop_and_verify_guarded(lease, key).await;
                        if stopped {
                            self.store.release(lease).await?;
                        }
                        return Err(EngineError::InvalidOperationResult);
                    }
                    Err(failure) => {
                        let task_id =
                            Uuid::parse_str(&task.task_id).map_err(|_| EngineError::InvalidTask)?;
                        let key = operation_key(
                            task_id,
                            task.attempts,
                            State::Validating,
                            Stage::Validate,
                        );
                        return self
                            .stop_and_block(lease, key, &task, &policy, &before, Some(failure))
                            .await;
                    }
                };
                before = latest;
                Some(verified)
            } else {
                None
            };
            if task.state == State::Merging {
                if local_validation == Some(false) {
                    let task_id =
                        Uuid::parse_str(&task.task_id).map_err(|_| EngineError::InvalidTask)?;
                    let key =
                        operation_key(task_id, task.attempts, State::Validating, Stage::Validate);
                    if before.pr_merged {
                        let stopped = self.stop_and_verify_guarded(lease, key).await;
                        if stopped {
                            self.store.release(lease).await?;
                        }
                        return Err(EngineError::InvalidOperationResult);
                    }
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
                if before.pr_merged {
                    if before.policy_base_ref != policy.base_ref
                        || before.policy_base_sha != policy.base_sha
                    {
                        return Err(EngineError::InvalidTransition(domain::Error::StaleBase));
                    }
                    if self.mock_github.is_some() {
                        validate_simulated_merge(&task, &policy, &before)?;
                    } else if local_validation != Some(true) {
                        return Err(EngineError::InvalidOperationResult);
                    } else if issue_close_controller.is_some() || !before.issue_open {
                        let prepared = self
                            .store
                            .prepare_issue_close(lease, &policy, &before)
                            .await?;
                        match &prepared {
                            None if !before.issue_open => {}
                            None => return Err(EngineError::InvalidOperationResult),
                            Some(OperationLookup::New)
                                if before.issue_open && issue_close_controller.is_some() =>
                            {
                                if let Some(controller) = issue_close_controller {
                                    let task_id = Uuid::parse_str(&task.task_id)
                                        .map_err(|_| EngineError::InvalidTask)?;
                                    let operation_id =
                                        crate::postgres::issue_close_operation_key(task_id);
                                    let timeout = Duration::from_secs(5).min(self.lease_ttl / 2);
                                    let _ = tokio::time::timeout(
                                        timeout,
                                        controller.close_issue_once(
                                            lease,
                                            &task,
                                            &policy,
                                            &before,
                                            operation_id,
                                        ),
                                    )
                                    .await;
                                }
                            }
                            Some(OperationLookup::New)
                            | Some(OperationLookup::Ambiguous)
                            | Some(OperationLookup::Completed { .. }) => {}
                        }
                        if prepared.is_some() {
                            // A durable intent may outlive a successful remote write.
                            // Always observe again before reconciling it, even when this
                            // invocation starts with the Issue already closed.
                            let latest = self
                                .observe_handoff_evidence(&task, &policy)
                                .await
                                .map_err(|_| EngineError::EvidenceUnavailable)?;
                            validate_authority_evidence(&task, &policy, &latest)?;
                            let reconciled = self
                                .store
                                .reconcile_issue_close(lease, &policy, &latest)
                                .await?;
                            match reconciled {
                                OperationLookup::Completed { result, .. }
                                    if result
                                        == serde_json::json!({
                                            "issue_closed_observed": true
                                        })
                                        && !latest.issue_open =>
                                {
                                    before = latest;
                                }
                                OperationLookup::New
                                | OperationLookup::Ambiguous
                                | OperationLookup::Completed { .. } => {
                                    self.store.release(lease).await?;
                                    return Ok(StepResult::WaitingForHuman);
                                }
                            }
                        } else {
                            let latest = self
                                .observe_handoff_evidence(&task, &policy)
                                .await
                                .map_err(|_| EngineError::EvidenceUnavailable)?;
                            validate_authority_evidence(&task, &policy, &latest)?;
                            if latest.issue_open {
                                self.store.release(lease).await?;
                                return Ok(StepResult::WaitingForHuman);
                            }
                            before = latest;
                        }
                    } else if before.issue_open {
                        self.store.release(lease).await?;
                        return Ok(StepResult::WaitingForHuman);
                    }
                    let mut candidate = task.clone();
                    domain::transition(&mut candidate, State::Completed, &policy, &before)
                        .map_err(EngineError::InvalidTransition)?;
                    if self.mock_github.is_some() {
                        self.store
                            .save(lease, State::Merging, &candidate, &policy, &before)
                            .await?;
                    } else {
                        self.store
                            .save_handoff_completed(lease, &candidate, &policy, &before)
                            .await?;
                    }
                    self.store.release(lease).await?;
                    return Ok(StepResult::Finished);
                }
                if self.mock_github.is_none() {
                    validate_merge_preconditions(&task, &policy, &before)?;
                    if local_validation != Some(true) {
                        return Err(EngineError::InvalidOperationResult);
                    }
                    self.store.release(lease).await?;
                    return Ok(StepResult::WaitingForHuman);
                }
            }
            if task.state == State::Completed {
                domain::validate_completed(&task, &policy, &before)
                    .map_err(EngineError::InvalidTransition)?;
                if self.mock_github.is_some() {
                    validate_simulated_merge(&task, &policy, &before)?;
                } else if local_validation != Some(true) {
                    return Err(EngineError::InvalidOperationResult);
                }
                self.store.release(lease).await?;
                return Ok(StepResult::Finished);
            }
            verify_base(&task, &policy, &before)?;
            if task.state == State::Reviewing
                && (local_validation == Some(false)
                    || before
                        .ci
                        .as_ref()
                        .is_some_and(|ci| ci.status == domain::CiStatus::Failed))
            {
                let mut candidate = task.clone();
                let next = if task.attempts >= policy.max_attempts {
                    State::Paused
                } else {
                    candidate.attempts = candidate.attempts.saturating_add(1);
                    candidate.validation_passed = false;
                    State::Repairing
                };
                domain::transition_from(&task, &mut candidate, next, &policy, &before)
                    .map_err(EngineError::InvalidTransition)?;
                self.store
                    .save(lease, task.state, &candidate, &policy, &before)
                    .await?;
                if next == State::Paused {
                    self.store.release(lease).await?;
                    return Ok(StepResult::WaitingForHuman);
                }
                continue;
            }
            if task.state == State::Reviewing
                && !before
                    .ci
                    .as_ref()
                    .is_some_and(|ci| ci.status == domain::CiStatus::Passed)
            {
                let mut candidate = task.clone();
                domain::transition_from(&task, &mut candidate, State::Paused, &policy, &before)
                    .map_err(EngineError::InvalidTransition)?;
                self.store
                    .save(lease, task.state, &candidate, &policy, &before)
                    .await?;
                self.store.release(lease).await?;
                return Ok(StepResult::WaitingForHuman);
            }
            if task.state == State::Reviewing {
                domain::require_review_evidence(&task, &policy, &before)
                    .map_err(EngineError::InvalidTransition)?;
            }
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
            let repair_proof = if stage == Stage::Implement
                && task.state == State::Repairing
                && self.mock_github.is_none()
            {
                match self
                    .verify_repair_context_guarded(lease, key, &task, &policy, budget)
                    .await
                {
                    Ok(proof) => Some(proof),
                    Err(failure) => {
                        return self
                            .stop_and_block(lease, key, &task, &policy, &before, Some(failure))
                            .await;
                    }
                }
            } else {
                None
            };
            let hash = request_hash(&task, stage);
            let output: AppliedStageOutput = match self
                .store
                .prepare_operation(lease, key, stage_name(stage), &hash)
                .await?
            {
                OperationLookup::New => {
                    if matches!(repair_proof.as_ref(), Some(RepairProof::Completed { .. })) {
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
                    let execution = if stage == Stage::Merge {
                        self.execute_mock_merge(key, &task, &policy, &before)
                    } else {
                        self.execute_guarded(stage, key, &task, &policy, budget, lease)
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
                    if !valid_stage_output_for_task(
                        stage,
                        &output,
                        &task,
                        &policy,
                        self.runner.agent_roles(),
                        self.mock_github.is_some(),
                    ) || !operation_usage_fits(&task, &output)
                        || !valid_output_journal_extension(&task, &output)
                        || (self.mock_github.is_none() && output.mock_github_journal.is_some())
                        || (self.mock_github.is_none()
                            && output
                                .session_id
                                .as_deref()
                                .is_some_and(|id| !is_canonical_uuid(id)))
                    {
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
                    let (value, applied_output) = if self.mock_github.is_some() {
                        (
                            serde_json::to_value(&output)
                                .map_err(|_| EngineError::InvalidOperationResult)?,
                            AppliedStageOutput::from(output),
                        )
                    } else {
                        let value = match persisted_stage_result_v1(stage, &output) {
                            Ok(value) => value,
                            Err(failure) => {
                                return self
                                    .stop_and_block(
                                        lease,
                                        key,
                                        &task,
                                        &policy,
                                        &before,
                                        Some(failure),
                                    )
                                    .await;
                            }
                        };
                        let persisted: PersistedStageResultV1 =
                            serde_json::from_value(value.clone())
                                .map_err(|_| EngineError::InvalidOperationResult)?;
                        if !valid_persisted_stage_result_for_task(
                            stage,
                            &persisted,
                            &task,
                            &policy,
                            self.runner.agent_roles(),
                        ) {
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
                        (value, AppliedStageOutput::from(persisted))
                    };
                    self.store
                        .complete_operation(lease, key, &value, applied_output.model_tokens)
                        .await?;
                    applied_output
                }
                OperationLookup::Completed {
                    result: value,
                    fencing_token: original_fencing_token,
                } => {
                    if self.mock_github.is_none() {
                        let Some(result_digest) = repair_result_digest(&value) else {
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
                        };
                        if let Err(failure) = self
                            .verify_completed_operation_guarded(
                                lease,
                                key,
                                stage,
                                hash,
                                original_fencing_token,
                                result_digest,
                                task.model_tokens,
                                &task,
                                &policy,
                                &before,
                                budget,
                            )
                            .await
                        {
                            return self
                                .stop_and_block(lease, key, &task, &policy, &before, Some(failure))
                                .await;
                        }
                    }
                    let digest_matches = match &repair_proof {
                        Some(RepairProof::Completed { result_digest, .. }) => {
                            repair_result_digest(&value) == Some(*result_digest)
                        }
                        _ => true,
                    };
                    if !digest_matches {
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
                    let result = if value.get("result_type").is_some()
                        || value.get("format_version").is_some()
                        || value.get("stage").is_some()
                    {
                        if self.mock_github.is_some() || repair_result_digest(&value).is_none() {
                            None
                        } else {
                            serde_json::from_value::<PersistedStageResultV1>(value)
                                .ok()
                                .filter(|result| {
                                    valid_persisted_stage_result_for_task(
                                        stage,
                                        result,
                                        &task,
                                        &policy,
                                        self.runner.agent_roles(),
                                    ) && repair_proof_matches(
                                        &repair_proof,
                                        &task,
                                        result.metadata.head_sha.as_ref(),
                                        result.metadata.pull_request,
                                    )
                                })
                                .map(AppliedStageOutput::from)
                        }
                    } else {
                        serde_json::from_value::<StageOutput>(value)
                            .ok()
                            .filter(|output| {
                                valid_stage_output_for_task(
                                    stage,
                                    output,
                                    &task,
                                    &policy,
                                    self.runner.agent_roles(),
                                    self.mock_github.is_some(),
                                ) && (self.mock_github.is_some()
                                    || output.mock_github_journal.is_none())
                                    && valid_output_journal_extension(&task, output)
                                    && repair_proof_matches(
                                        &repair_proof,
                                        &task,
                                        output.head_sha.as_ref(),
                                        output.pull_request,
                                    )
                            })
                            .map(AppliedStageOutput::from)
                    };
                    match result {
                        Some(output) => output,
                        None => {
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
                    }
                }
                OperationLookup::Ambiguous => {
                    return self
                        .stop_and_block(lease, key, &task, &policy, &before, None)
                        .await;
                }
            };

            let local_validation_result = if stage == Stage::Validate && self.mock_github.is_none()
            {
                let verified = self
                    .verify_local_validation_guarded(lease, key, &task, &policy, budget, false)
                    .await;
                let stored = local_validation_passed(
                    output.local_validation_passed,
                    output.validation_passed,
                );
                match verified {
                    Ok(verified) if verified == stored => verified,
                    other => {
                        let failure = other.err().unwrap_or(StageFailure::InvalidOperationResult);
                        return self
                            .stop_and_block(lease, key, &task, &policy, &before, Some(failure))
                            .await;
                    }
                }
            } else {
                local_validation_passed(output.local_validation_passed, output.validation_passed)
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
            let after = self
                .evidence
                .observe(&candidate, &policy)
                .await
                .map_err(|_| EngineError::EvidenceUnavailable)?;
            verify_base(&candidate, &policy, &after)?;
            if stage == Stage::Validate {
                candidate.validation_passed = local_validation_result
                    && after
                        .ci
                        .as_ref()
                        .is_some_and(|ci| ci.status == domain::CiStatus::Passed);
            }
            let ci_pending_or_unknown = !after.ci.as_ref().is_some_and(|ci| {
                matches!(
                    ci.status,
                    domain::CiStatus::Passed | domain::CiStatus::Failed
                )
            });
            if matches!(stage, Stage::Validate | Stage::Review)
                && ci_pending_or_unknown
                && (stage == Stage::Validate && local_validation_result
                    || stage == Stage::Review && output.validation_passed)
            {
                candidate.validation_passed = if stage == Stage::Validate {
                    false
                } else {
                    current.validation_passed
                };
                domain::transition_from(&current, &mut candidate, State::Paused, &policy, &after)
                    .map_err(EngineError::InvalidTransition)?;
                self.store
                    .save(lease, current.state, &candidate, &policy, &after)
                    .await?;
                self.store.release(lease).await?;
                return Ok(StepResult::WaitingForHuman);
            }
            let ci_failed = matches!(stage, Stage::Validate | Stage::Review)
                && after
                    .ci
                    .as_ref()
                    .is_some_and(|ci| ci.status == domain::CiStatus::Failed);
            let needs_repair = (stage == Stage::Validate
                && (ci_failed || !local_validation_result))
                || (stage == Stage::Review && (ci_failed || !output.validation_passed));
            if needs_repair {
                if task.attempts >= policy.max_attempts {
                    candidate = current.clone();
                    next = State::Paused;
                } else {
                    candidate.validation_passed = false;
                    candidate.attempts = candidate.attempts.saturating_add(1);
                    next = State::Repairing;
                }
            }
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
        operation_key: Uuid,
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
        if stage == Stage::Review {
            domain::require_review_evidence(task, policy, &preflight)
                .map_err(|_| StageFailure::InvalidInput)?;
        }
        self.store
            .renew(lease, self.lease_ttl)
            .await
            .map_err(|_| StageFailure::LeaseUnavailable)?;
        let timeout = stage_timeout(stage, budget.remaining_runtime);
        let budget = ExecutionBudget {
            remaining_runtime: timeout,
            ..budget
        };
        let cancellation = Cancellation::default();
        let cancel_before_start = CancelStageOnDrop(Some(cancellation.clone()));
        let future = self.runner.execute_with_cancellation(
            lease,
            operation_key,
            stage,
            task,
            policy,
            budget,
            cancellation,
        );
        tokio::pin!(future);
        let mut cancel_on_drop = cancel_before_start;
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
                if stage == Stage::Review
                    && domain::require_review_evidence(task, policy, &facts).is_err()
                {
                    return StageFailure::InvalidInput;
                }
            }
        };
        let result = tokio::select! {
            result = tokio::time::timeout(timeout, &mut future) => {
                result.unwrap_or(Err(StageFailure::Timeout))
            },
            failure = heartbeat_future => Err(failure),
        };
        if result.is_ok() {
            cancel_on_drop.0 = None;
        }
        result
    }

    async fn verify_repair_context_guarded(
        &self,
        lease: &Lease,
        repair_operation_key: Uuid,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        budget: ExecutionBudget,
    ) -> Result<RepairProof, StageFailure> {
        let task_id = Uuid::parse_str(&task.task_id).map_err(|_| StageFailure::InvalidInput)?;
        task.head_sha.as_deref().ok_or(StageFailure::InvalidInput)?;
        if lease.task_id != task_id
            || lease.fencing_token <= 0
            || task.state != State::Repairing
            || task.checkpoint.is_some()
            || repair_operation_key
                != operation_key(task_id, task.attempts, State::Repairing, Stage::Implement)
        {
            return Err(StageFailure::InvalidInput);
        }
        let preflight = self
            .evidence
            .observe(task, policy)
            .await
            .map_err(|_| StageFailure::EvidenceUnavailable)?;
        validate_repair_evidence(task, policy, &preflight)?;
        self.store
            .renew(lease, self.lease_ttl)
            .await
            .map_err(|_| StageFailure::LeaseUnavailable)?;
        let timeout = stage_timeout(Stage::Implement, budget.remaining_runtime);
        if timeout.is_zero() {
            return Err(StageFailure::Timeout);
        }
        let future = self.runner.verify_repair_context(
            lease,
            repair_operation_key,
            task,
            policy,
            &preflight,
        );
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
                if validate_repair_evidence(task, policy, &facts).is_err() {
                    return StageFailure::InvalidInput;
                }
            }
        };
        let proof = tokio::select! {
            result = tokio::time::timeout(timeout, &mut future) => {
                match result {
                    Ok(Ok(proof)) => proof,
                    Ok(Err(())) => return Err(StageFailure::InvalidOperationResult),
                    Err(_) => return Err(StageFailure::Timeout),
                }
            },
            failure = heartbeat_future => return Err(failure),
        };
        let latest = self
            .evidence
            .observe(task, policy)
            .await
            .map_err(|_| StageFailure::EvidenceUnavailable)?;
        validate_repair_evidence(task, policy, &latest)?;
        Ok(proof)
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_completed_operation_guarded(
        &self,
        lease: &Lease,
        key: Uuid,
        stage: Stage,
        hash: [u8; 32],
        original_fencing_token: i64,
        digest: [u8; 32],
        cumulative_model_tokens: u64,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        facts: &ObservedFacts,
        budget: ExecutionBudget,
    ) -> Result<(), StageFailure> {
        let task_id = Uuid::parse_str(&task.task_id).map_err(|_| StageFailure::InvalidInput)?;
        if lease.task_id != task_id
            || lease.fencing_token <= 0
            || key != operation_key(task_id, task.attempts, task.state, stage)
            || hash != request_hash(task, stage)
            || original_fencing_token <= 0
            || original_fencing_token > lease.fencing_token
            || cumulative_model_tokens != task.model_tokens
            || i64::try_from(cumulative_model_tokens).is_err()
        {
            return Err(StageFailure::InvalidInput);
        }
        validate_authority_evidence(task, policy, facts).map_err(|_| StageFailure::InvalidInput)?;
        self.store
            .renew(lease, self.lease_ttl)
            .await
            .map_err(|_| StageFailure::LeaseUnavailable)?;
        let timeout = stage_timeout(stage, budget.remaining_runtime);
        if timeout.is_zero() {
            return Err(StageFailure::Timeout);
        }
        let future = self.runner.verify_completed_operation(
            lease,
            task,
            stage,
            key,
            hash,
            original_fencing_token,
            digest,
            cumulative_model_tokens,
            facts,
        );
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
                let fresh = match self.evidence.observe(task, policy).await {
                    Ok(facts) => facts,
                    Err(()) => return StageFailure::EvidenceUnavailable,
                };
                if validate_authority_evidence(task, policy, &fresh).is_err() {
                    return StageFailure::InvalidInput;
                }
            }
        };
        tokio::select! {
            result = tokio::time::timeout(timeout, &mut future) => match result {
                Ok(Ok(())) => {}
                Ok(Err(())) => return Err(StageFailure::InvalidOperationResult),
                Err(_) => return Err(StageFailure::Timeout),
            },
            failure = heartbeat_future => return Err(failure),
        }
        let latest = self
            .evidence
            .observe(task, policy)
            .await
            .map_err(|_| StageFailure::EvidenceUnavailable)?;
        validate_authority_evidence(task, policy, &latest)
            .map_err(|_| StageFailure::InvalidInput)?;
        Ok(())
    }

    async fn verify_state_local_validation(
        &self,
        lease: &Lease,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        initial: ObservedFacts,
        handoff_verification: bool,
    ) -> Result<(bool, ObservedFacts), StageFailure> {
        validate_authority_evidence(task, policy, &initial)
            .map_err(stage_failure_from_engine_error)?;
        let task_id = Uuid::parse_str(&task.task_id).map_err(|_| StageFailure::InvalidInput)?;
        let operation_key =
            operation_key(task_id, task.attempts, State::Validating, Stage::Validate);
        let budget = ExecutionBudget {
            remaining_runtime: if handoff_verification {
                Duration::from_secs(5).min(self.lease_ttl / 2)
            } else {
                policy.max_runtime.saturating_sub(task.elapsed)
            },
            remaining_model_tokens: policy.max_model_tokens.saturating_sub(task.model_tokens),
        };
        let verified = self
            .verify_local_validation_guarded(
                lease,
                operation_key,
                task,
                policy,
                budget,
                handoff_verification,
            )
            .await?;
        let latest = if handoff_verification {
            self.observe_handoff_evidence(task, policy).await
        } else {
            self.evidence.observe(task, policy).await
        }
        .map_err(|_| StageFailure::EvidenceUnavailable)?;
        validate_authority_evidence(task, policy, &latest)
            .map_err(stage_failure_from_engine_error)?;
        Ok((verified, latest))
    }

    async fn verify_local_validation_guarded(
        &self,
        lease: &Lease,
        operation_key: Uuid,
        task: &TaskRecord,
        policy: &TrustedPolicy,
        budget: ExecutionBudget,
        handoff_verification: bool,
    ) -> Result<bool, StageFailure> {
        let preflight = if handoff_verification {
            self.observe_handoff_evidence(task, policy).await
        } else {
            self.evidence.observe(task, policy).await
        }
        .map_err(|_| StageFailure::EvidenceUnavailable)?;
        validate_authority_evidence(task, policy, &preflight)
            .map_err(|_| StageFailure::InvalidInput)?;
        let renew = if handoff_verification {
            self.store
                .renew_handoff_verification(lease, self.lease_ttl, task, policy, &preflight)
                .await
        } else {
            self.store.renew(lease, self.lease_ttl).await
        };
        renew.map_err(|_| StageFailure::LeaseUnavailable)?;
        let timeout = stage_timeout(Stage::Validate, budget.remaining_runtime);
        if timeout.is_zero() {
            return Err(StageFailure::Timeout);
        }
        let future = self
            .runner
            .verify_local_validation(lease, operation_key, task, policy);
        tokio::pin!(future);
        let heartbeat = (self.lease_ttl / 3).max(Duration::from_millis(250));
        let mut interval =
            tokio::time::interval_at(tokio::time::Instant::now() + heartbeat, heartbeat);
        let heartbeat_future = async {
            loop {
                interval.tick().await;
                let facts = match if handoff_verification {
                    self.observe_handoff_evidence(task, policy).await
                } else {
                    self.evidence.observe(task, policy).await
                } {
                    Ok(facts) => facts,
                    Err(()) => return StageFailure::EvidenceUnavailable,
                };
                if validate_authority_evidence(task, policy, &facts).is_err() {
                    return StageFailure::InvalidInput;
                }
                let renewed = if handoff_verification {
                    self.store
                        .renew_handoff_verification(lease, self.lease_ttl, task, policy, &facts)
                        .await
                } else {
                    self.store.renew(lease, self.lease_ttl).await
                };
                if renewed.is_err() {
                    return StageFailure::LeaseUnavailable;
                }
            }
        };
        tokio::select! {
            result = tokio::time::timeout(timeout, &mut future) => {
                match result {
                    Ok(Ok(verified)) => Ok(verified),
                    Ok(Err(())) => Err(StageFailure::InvalidOperationResult),
                    Err(_) => Err(StageFailure::Timeout),
                }
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
            local_validation_passed: None,
            model_tokens: 0,
            mock_github_journal: Some(mock_github_journal),
            plan: None,
            code_change: None,
        })
    }

    async fn stop_and_verify_guarded(&self, lease: &Lease, operation_key: Uuid) -> bool {
        let timeout = (self.lease_ttl / 2).min(Duration::from_secs(10));
        matches!(
            tokio::time::timeout(timeout, self.runner.stop_and_verify(lease, operation_key)).await,
            Ok(Ok(()))
        )
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
        let stopped = self.stop_and_verify_guarded(lease, operation_key).await;
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

fn validate_execution_policy(policy: &TrustedPolicy) -> Result<(), EngineError> {
    if policy.base_ref != "develop"
        || policy.max_attempts
            != u32::from(AutonomyConfig::approved_mock_defaults().max_repair_attempts)
    {
        return Err(EngineError::InvalidConfiguration);
    }
    Ok(())
}

fn repair_proof_matches(
    proof: &Option<RepairProof>,
    task: &TaskRecord,
    candidate_head_sha: Option<&String>,
    candidate_pull_request: Option<u64>,
) -> bool {
    match proof {
        None => true,
        Some(RepairProof::Start) => false,
        Some(RepairProof::Completed {
            head_sha,
            pull_request,
            total_model_tokens,
            ..
        }) => {
            valid_git_sha(head_sha)
                && candidate_head_sha.or(task.head_sha.as_ref()) == Some(head_sha)
                && candidate_pull_request.or(task.pull_request) == *pull_request
                && task.model_tokens == *total_model_tokens
        }
    }
}

fn validate_repair_evidence(
    task: &TaskRecord,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
) -> Result<(), StageFailure> {
    verify_base(task, policy, facts).map_err(|_| StageFailure::InvalidInput)?;
    if task.pull_request.is_some()
        && (task.pull_request != facts.pr_number
            || task.head_sha.as_deref() != Some(facts.head_sha.as_str())
            || task.head_sha.as_deref() != facts.pr_head_sha.as_deref()
            || facts.pr_base_ref.as_deref() != Some(policy.base_ref.as_str())
            || facts.pr_base_sha.as_deref() != Some(policy.base_sha.as_str())
            || facts.pr_merged)
    {
        return Err(StageFailure::InvalidInput);
    }
    if let Some(ci) = facts.ci.as_ref()
        && (task.pull_request != Some(ci.pull_request)
            || task.head_sha.as_deref() != Some(ci.head_sha.as_str())
            || facts.head_sha != ci.head_sha
            || facts.pr_number != Some(ci.pull_request)
            || facts.pr_head_sha.as_deref() != Some(ci.head_sha.as_str()))
    {
        return Err(StageFailure::InvalidInput);
    }
    Ok(())
}

fn valid_stage_output(stage: Stage, output: &StageOutput) -> bool {
    let valid_assignee = output
        .assignee
        .as_deref()
        .is_none_or(|value| !value.trim().is_empty() && value.chars().count() <= 255);
    let valid_metadata = [
        output.implementer.as_deref(),
        output.reviewer.as_deref(),
        output.session_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    .all(|value| !value.trim().is_empty() && value.len() <= 255);
    let valid_head = output.head_sha.as_deref().is_none_or(valid_git_sha);
    let valid_pull_request = output
        .pull_request
        .is_none_or(|number| number > 0 && i64::try_from(number).is_ok());
    if !valid_assignee
        || !valid_metadata
        || !valid_head
        || !valid_pull_request
        || i64::try_from(output.model_tokens).is_err()
        || (stage != Stage::Validate && output.local_validation_passed.is_some())
        || (matches!(stage, Stage::Plan | Stage::Implement) && output.validation_passed)
        || (stage == Stage::Merge && !output.validation_passed)
    {
        return false;
    }
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

fn valid_stage_output_for_task(
    stage: Stage,
    output: &StageOutput,
    task: &TaskRecord,
    policy: &TrustedPolicy,
    (implementer, reviewer): (Provider, Provider),
    mock_mode: bool,
) -> bool {
    if !valid_stage_output(stage, output) {
        return false;
    }

    valid_stage_metadata_for_task(
        stage,
        output.assignee.as_ref(),
        output.implementer.as_ref(),
        output.reviewer.as_ref(),
        output.session_id.as_ref(),
        output.head_sha.as_ref(),
        output.pull_request,
        task,
        policy,
        (implementer, reviewer),
        mock_mode,
    )
}

fn valid_persisted_stage_result_for_task(
    stage: Stage,
    result: &PersistedStageResultV1,
    task: &TaskRecord,
    policy: &TrustedPolicy,
    roles: (Provider, Provider),
) -> bool {
    result.result_type == "stage_result"
        && result.format_version == 1
        && result.stage == stage
        && result
            .metadata
            .session_id
            .as_deref()
            .is_none_or(is_canonical_uuid)
        && result
            .metadata
            .assignee
            .as_deref()
            .is_none_or(|value| !value.trim().is_empty() && value.chars().count() <= 255)
        && [
            result.metadata.implementer.as_deref(),
            result.metadata.reviewer.as_deref(),
            result.metadata.session_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        .all(|value| !value.trim().is_empty() && value.len() <= 255)
        && result
            .metadata
            .head_sha
            .as_deref()
            .is_none_or(valid_git_sha)
        && result
            .metadata
            .pull_request
            .is_none_or(|number| number > 0 && i64::try_from(number).is_ok())
        && i64::try_from(result.model_tokens).is_ok()
        && !(stage != Stage::Validate && result.metadata.local_validation_passed.is_some())
        && !(matches!(stage, Stage::Plan | Stage::Implement) && result.metadata.validation_passed)
        && !(stage == Stage::Merge && !result.metadata.validation_passed)
        && (stage != Stage::Plan
            || (result
                .metadata
                .implementer
                .as_deref()
                .or(task.implementer.as_deref())
                == Some(provider_name(roles.0))
                && result
                    .metadata
                    .reviewer
                    .as_deref()
                    .or(task.reviewer.as_deref())
                    == Some(provider_name(roles.1))
                && result
                    .metadata
                    .session_id
                    .as_deref()
                    .or(task.session_id.as_deref())
                    .is_some_and(is_canonical_uuid)))
        && valid_stage_metadata_for_task(
            stage,
            result.metadata.assignee.as_ref(),
            result.metadata.implementer.as_ref(),
            result.metadata.reviewer.as_ref(),
            result.metadata.session_id.as_ref(),
            result.metadata.head_sha.as_ref(),
            result.metadata.pull_request,
            task,
            policy,
            roles,
            false,
        )
}

#[allow(clippy::too_many_arguments)]
fn valid_stage_metadata_for_task(
    stage: Stage,
    assignee: Option<&String>,
    output_implementer: Option<&String>,
    output_reviewer: Option<&String>,
    output_session_id: Option<&String>,
    output_head_sha: Option<&String>,
    output_pull_request: Option<u64>,
    task: &TaskRecord,
    policy: &TrustedPolicy,
    (implementer, reviewer): (Provider, Provider),
    mock_mode: bool,
) -> bool {
    let metadata_unchanged = if stage == Stage::Plan {
        let not_replacing = |value: Option<&String>, current: Option<&String>| {
            current.is_none_or(|current| value.is_none_or(|value| value == current))
        };
        not_replacing(output_implementer, task.implementer.as_ref())
            && not_replacing(output_reviewer, task.reviewer.as_ref())
            && not_replacing(output_session_id, task.session_id.as_ref())
            && output_implementer.is_none_or(|value| value == provider_name(implementer))
            && output_reviewer.is_none_or(|value| value == provider_name(reviewer))
    } else {
        let unchanged = |value: Option<&String>, current: Option<&String>| {
            value.is_none_or(|value| current == Some(value))
        };
        unchanged(assignee, task.assignee.as_ref())
            && unchanged(output_implementer, task.implementer.as_ref())
            && unchanged(output_reviewer, task.reviewer.as_ref())
            && unchanged(output_session_id, task.session_id.as_ref())
    };
    if !metadata_unchanged {
        return false;
    }

    let resulting_assignee = assignee.or(task.assignee.as_ref());
    if stage == Stage::Plan
        && resulting_assignee.map(String::as_str) != Some(policy.allowed_assignee.as_str())
    {
        return false;
    }
    if mock_mode
        && stage == Stage::Plan
        && (output_implementer.or(task.implementer.as_ref()).is_none()
            || output_reviewer.or(task.reviewer.as_ref()).is_none()
            || output_session_id.or(task.session_id.as_ref()).is_none())
    {
        return false;
    }

    let resulting_head = output_head_sha.or(task.head_sha.as_ref());
    if stage == Stage::Implement && resulting_head.is_none() {
        return false;
    }
    if stage != Stage::Implement
        && output_head_sha.is_some_and(|head| task.head_sha.as_ref() != Some(head))
    {
        return false;
    }

    let pull_request_may_be_added = matches!(stage, Stage::Implement | Stage::Validate);
    if !pull_request_may_be_added
        && output_pull_request.is_some_and(|number| task.pull_request != Some(number))
    {
        return false;
    }
    if pull_request_may_be_added
        && task
            .pull_request
            .is_some_and(|current| output_pull_request.is_some_and(|number| number != current))
    {
        return false;
    }
    true
}

fn operation_usage_fits(task: &TaskRecord, output: &StageOutput) -> bool {
    task.model_tokens
        .checked_add(output.model_tokens)
        .and_then(|tokens| i64::try_from(tokens).ok())
        .is_some()
}

fn valid_git_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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

fn stage_timeout(stage: Stage, remaining: Duration) -> Duration {
    if matches!(stage, Stage::Plan | Stage::Implement | Stage::Review) {
        let minutes = AutonomyConfig::approved_mock_defaults().agent_timeout_minutes;
        remaining.min(Duration::from_secs(u64::from(minutes) * 60))
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

fn validate_authority_evidence(
    task: &TaskRecord,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
) -> Result<(), EngineError> {
    match task.state {
        State::Reviewing => {
            verify_base(task, policy, facts)?;
            let head = task.head_sha.as_deref().ok_or(EngineError::InvalidTask)?;
            if task.pull_request.is_none()
                || task.pull_request != facts.pr_number
                || facts.pr_head_sha.as_deref() != Some(head)
                || facts.pr_base_ref.as_deref() != Some(policy.base_ref.as_str())
                || facts.pr_base_sha.as_deref() != Some(policy.base_sha.as_str())
                || facts.pr_merged
            {
                return Err(EngineError::InvalidTransition(
                    domain::Error::PullRequestMismatch,
                ));
            }
            if facts
                .ci
                .as_ref()
                .is_some_and(|ci| ci.head_sha != head || Some(ci.pull_request) != task.pull_request)
            {
                return Err(EngineError::InvalidTransition(domain::Error::StaleHead));
            }
            if facts
                .ci
                .as_ref()
                .is_some_and(|ci| ci.status == domain::CiStatus::Passed)
            {
                domain::require_review_evidence(task, policy, facts)
                    .map_err(EngineError::InvalidTransition)?;
            }
            Ok(())
        }
        State::Merging if facts.pr_merged => {
            let mut completed = task.clone();
            domain::transition_from(task, &mut completed, State::Completed, policy, facts)
                .map_err(EngineError::InvalidTransition)
        }
        State::Merging => {
            verify_base(task, policy, facts)?;
            domain::require_review_evidence(task, policy, facts)
                .map_err(EngineError::InvalidTransition)?;
            validate_merge_preconditions(task, policy, facts)
        }
        State::Completed => {
            domain::validate_completed(task, policy, facts).map_err(EngineError::InvalidTransition)
        }
        _ => verify_base(task, policy, facts),
    }
}

fn validate_merged_resume(
    task: &TaskRecord,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
) -> Result<(), EngineError> {
    if !matches!(task.state, State::Paused | State::Blocked)
        || task.checkpoint != Some(State::Merging)
        || !facts.pr_merged
    {
        return Err(EngineError::InvalidTask);
    }
    let mut merging = task.clone();
    merging.state = State::Merging;
    merging.checkpoint = None;
    merging.validate().map_err(|_| EngineError::InvalidTask)?;
    let mut completed = merging.clone();
    domain::transition_from(&merging, &mut completed, State::Completed, policy, facts)
        .map_err(EngineError::InvalidTransition)
}

fn stage_failure_from_engine_error(error: EngineError) -> StageFailure {
    match error {
        EngineError::EvidenceUnavailable => StageFailure::EvidenceUnavailable,
        EngineError::Store(_) => StageFailure::LeaseUnavailable,
        EngineError::InvalidOperationResult => StageFailure::InvalidOperationResult,
        EngineError::InvalidTransition(_) | EngineError::InvalidTask => StageFailure::InvalidInput,
        EngineError::InvalidConfiguration | EngineError::PolicyUnavailable => {
            StageFailure::InvalidConfiguration
        }
    }
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

fn local_validation_passed(local: Option<bool>, validation: bool) -> bool {
    local.unwrap_or(validation)
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

fn valid_output_journal_extension(task: &TaskRecord, output: &StageOutput) -> bool {
    if task
        .mock_github_journal
        .as_ref()
        .is_some_and(|journal| !crate::postgres::valid_mock_journal(journal))
    {
        return false;
    }
    output.mock_github_journal.as_ref().is_none_or(|proposed| {
        crate::postgres::valid_mock_journal(proposed)
            && validate_journal_extension(task.mock_github_journal.as_ref(), proposed).is_ok()
    })
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
    let settings = AutonomyConfig::approved_mock_defaults();
    if (implementer, reviewer) != (settings.implementer, settings.reviewer) || mismatch || missing {
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

/// Computes the deterministic task-metadata binding used by the operation ledger.
///
/// This hash covers only the task ID, issue number, state, stage, attempt,
/// base SHA, and head SHA. It does not bind the prompt, model, billing route,
/// sandbox, policy fingerprint, or other execution settings, and must not be
/// treated as a hash of the complete request. A trusted supervisor may include
/// it in an independent receipt, but must separately verify the complete
/// execution configuration and inputs against its own trusted record. No
/// prompt, secret, or stage output is included here.
pub fn request_hash(task: &TaskRecord, stage: Stage) -> [u8; 32] {
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
        sync::{Arc, Mutex, atomic::Ordering},
    };

    // These in-memory test runners own no external process tree.
    macro_rules! in_memory_cancellation {
        () => {
            fn supports_cancellation(&self) -> bool {
                true
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
        };
    }

    type TestEngine = Engine<MockStore, MockPolicy, MockEvidence, MockRunner, MockRecovery>;

    #[derive(Clone)]
    struct MockStore(Arc<Mutex<MockDb>>);
    struct DefaultHandoffStore;

    impl EngineStore for DefaultHandoffStore {
        async fn get(&self, _: Uuid) -> Result<TaskRecord, StoreError> {
            Err(StoreError::TaskMissing)
        }
        async fn claim(
            &self,
            _: Uuid,
            _: &str,
            _: Duration,
            _: &TrustedPolicy,
            _: &ObservedFacts,
        ) -> Result<Lease, StoreError> {
            Err(StoreError::RecoveryRejected)
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
            _: Uuid,
            _: &str,
            _: Duration,
            _: &TrustedPolicy,
            _: &ObservedFacts,
        ) -> Result<Lease, StoreError> {
            Err(StoreError::RecoveryRejected)
        }
        async fn claim_resume(
            &self,
            _: Uuid,
            _: &str,
            _: Duration,
            _: &TrustedPolicy,
            _: &ObservedFacts,
        ) -> Result<Lease, StoreError> {
            Err(StoreError::RecoveryRejected)
        }
        async fn renew(&self, _: &Lease, _: Duration) -> Result<(), StoreError> {
            Ok(())
        }
        async fn load(&self, _: &Lease) -> Result<TaskRecord, StoreError> {
            Err(StoreError::TaskMissing)
        }
        async fn prepare_operation(
            &self,
            _: &Lease,
            _: Uuid,
            _: &str,
            _: &[u8; 32],
        ) -> Result<OperationLookup, StoreError> {
            Err(StoreError::RecoveryRejected)
        }
        async fn complete_operation(
            &self,
            _: &Lease,
            _: Uuid,
            _: &serde_json::Value,
            _: u64,
        ) -> Result<(), StoreError> {
            Err(StoreError::RecoveryRejected)
        }
        async fn save(
            &self,
            _: &Lease,
            _: State,
            _: &TaskRecord,
            _: &TrustedPolicy,
            _: &ObservedFacts,
        ) -> Result<(), StoreError> {
            Ok(())
        }
        async fn release(&self, _: &Lease) -> Result<(), StoreError> {
            Ok(())
        }
    }

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
        stopped_operation_keys: Vec<Uuid>,
        fail_save: bool,
        configuration_valid: bool,
        roles: (Provider, Provider),
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
            let db = self.0.lock().map_err(|_| StoreError::InvalidRecord)?;
            if db.task.task_id != task_id.to_string() {
                return Err(StoreError::TaskMissing);
            }
            match db.task.state {
                State::Merging if facts.pr_merged => {
                    let mut candidate = db.task.clone();
                    domain::transition_from(
                        &db.task,
                        &mut candidate,
                        State::Completed,
                        policy,
                        facts,
                    )
                    .map_err(|_| StoreError::InvalidRecord)?;
                }
                State::Merging => {}
                State::Completed => domain::validate_completed(&db.task, policy, facts)
                    .map_err(|_| StoreError::InvalidRecord)?,
                _ => return Err(StoreError::InvalidRecord),
            }
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
            if checkpoint == State::Merging && facts.pr_merged {
                validate_merged_resume(&candidate, policy, facts)
                    .map_err(|_| StoreError::InvalidRecord)?;
                candidate.state = State::Merging;
                candidate.checkpoint = None;
                candidate
                    .validate()
                    .map_err(|_| StoreError::InvalidRecord)?;
            } else {
                domain::transition(&mut candidate, checkpoint, policy, facts)
                    .map_err(|_| StoreError::InvalidRecord)?;
            }
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
        async fn renew_handoff_verification(
            &self,
            lease: &Lease,
            _: Duration,
            _: &TaskRecord,
            policy: &TrustedPolicy,
            facts: &ObservedFacts,
        ) -> Result<(), StoreError> {
            let db = self.0.lock().map_err(|_| StoreError::InvalidRecord)?;
            if db.task.task_id != lease.task_id.to_string() {
                return Err(StoreError::TaskMissing);
            }
            match db.task.state {
                State::Merging => {
                    let mut completed = db.task.clone();
                    domain::transition_from(
                        &db.task,
                        &mut completed,
                        State::Completed,
                        policy,
                        facts,
                    )
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
            lease: &Lease,
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
            db.ops.insert(
                key,
                OperationLookup::Completed {
                    result: value.clone(),
                    fencing_token: lease.fencing_token,
                },
            );
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
            let mut db = self.0.lock().map_err(|_| StoreError::InvalidRecord)?;
            if db.task.task_id != lease.task_id.to_string() || db.task.state != State::Merging {
                return Err(StoreError::LeaseLost);
            }
            if db.fail_save {
                return Err(StoreError::InvalidRecord);
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
            db.task = persisted;
            db.saves += 1;
            Ok(())
        }
        async fn prepare_issue_close(
            &self,
            lease: &Lease,
            policy: &TrustedPolicy,
            facts: &ObservedFacts,
        ) -> Result<Option<OperationLookup>, StoreError> {
            if !facts.pr_merged {
                return Err(StoreError::InvalidRecord);
            }
            let mut db = self.0.lock().map_err(|_| StoreError::InvalidRecord)?;
            if db.task.task_id != lease.task_id.to_string() || db.task.state != State::Merging {
                return Err(StoreError::LeaseLost);
            }
            let mut completed = db.task.clone();
            domain::transition_from(&db.task, &mut completed, State::Completed, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?;
            let key = crate::postgres::issue_close_operation_key(lease.task_id);
            if let Some(status) = db.ops.get(&key) {
                return Ok(Some(match status {
                    OperationLookup::New => OperationLookup::Ambiguous,
                    other => other.clone(),
                }));
            }
            if !facts.issue_open {
                return Ok(None);
            }
            db.ops.insert(key, OperationLookup::Ambiguous);
            Ok(Some(OperationLookup::New))
        }
        async fn reconcile_issue_close(
            &self,
            lease: &Lease,
            policy: &TrustedPolicy,
            facts: &ObservedFacts,
        ) -> Result<OperationLookup, StoreError> {
            if !facts.pr_merged {
                return Err(StoreError::InvalidRecord);
            }
            let mut db = self.0.lock().map_err(|_| StoreError::InvalidRecord)?;
            if db.task.task_id != lease.task_id.to_string() || db.task.state != State::Merging {
                return Err(StoreError::LeaseLost);
            }
            let mut completed = db.task.clone();
            domain::transition_from(&db.task, &mut completed, State::Completed, policy, facts)
                .map_err(|_| StoreError::InvalidRecord)?;
            let key = crate::postgres::issue_close_operation_key(lease.task_id);
            let status = db.ops.get(&key).ok_or(StoreError::OperationConflict)?;
            if let OperationLookup::Completed { result, .. } = status {
                if result != &serde_json::json!({"issue_closed_observed": true}) {
                    return Err(StoreError::InvalidRecord);
                }
                return if facts.issue_open {
                    Ok(OperationLookup::Ambiguous)
                } else {
                    Ok(status.clone())
                };
            }
            if facts.issue_open {
                return Ok(OperationLookup::Ambiguous);
            }
            let result = serde_json::json!({"issue_closed_observed": true});
            let completed = OperationLookup::Completed {
                result,
                fencing_token: lease.fencing_token,
            };
            db.ops.insert(key, completed.clone());
            Ok(completed)
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
    struct MockIssueCloseController {
        facts: Arc<Mutex<ObservedFacts>>,
        sends: Arc<Mutex<Vec<Uuid>>>,
        response_lost: bool,
    }

    impl issue_close_controller_sealed::Sealed for MockIssueCloseController {}

    impl IssueCloseController for MockIssueCloseController {
        async fn close_issue_once(
            &self,
            lease: &Lease,
            task: &TaskRecord,
            policy: &TrustedPolicy,
            facts: &ObservedFacts,
            operation_id: Uuid,
        ) -> Result<(), ()> {
            if task.state != State::Merging
                || lease.task_id.to_string() != task.task_id
                || lease.fencing_token <= 0
                || policy.base_ref != "develop"
                || !facts.pr_merged
                || !facts.issue_open
                || operation_id != crate::postgres::issue_close_operation_key(lease.task_id)
            {
                return Err(());
            }
            self.sends.lock().map_err(|_| ())?.push(operation_id);
            self.facts.lock().map_err(|_| ())?.issue_open = false;
            if self.response_lost { Err(()) } else { Ok(()) }
        }
    }

    #[derive(Clone)]
    struct MockRunner {
        db: Arc<Mutex<MockDb>>,
        verified_local_validation: Option<bool>,
        fail_local_validation_attempt: Option<u32>,
        verification_calls: Arc<Mutex<Vec<ValidationVerificationCall>>>,
        repair_proof_fixture: Arc<Mutex<RepairProofFixture>>,
        repair_verification_calls: Arc<Mutex<Vec<RepairVerificationCall>>>,
        repair_verifier_delay: Arc<Mutex<Option<Duration>>>,
        completed_proofs: Arc<Mutex<Vec<CompletedOperationProofFixture>>>,
        completed_verifier_delay: Arc<Mutex<Option<Duration>>>,
        completed_verifier_dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    struct CompletedVerifierDropGuard(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for CompletedVerifierDropGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[derive(Clone)]
    struct CompletedOperationProofFixture {
        task_id: Uuid,
        attempt: u32,
        stage: Stage,
        operation_key: Uuid,
        request_hash: [u8; 32],
        original_fencing_token: i64,
        current_fencing_token: i64,
        result_digest: [u8; 32],
        cumulative_model_tokens: u64,
        facts_digest: [u8; 32],
    }

    struct ValidationVerificationCall {
        task_id: Uuid,
        operation_key: Uuid,
        head_sha: String,
        fencing_token: i64,
    }
    struct RepairVerificationCall {
        task_id: Uuid,
        operation_key: Uuid,
        head_sha: String,
        attempt: u32,
        fencing_token: i64,
    }
    #[derive(Clone)]
    enum RepairProofFixture {
        AcceptCurrent,
        Missing,
        Completed {
            head_sha: String,
            pull_request: Option<u64>,
            result_digest: [u8; 32],
            total_model_tokens: u64,
        },
        Expected {
            task_id: Uuid,
            head_sha: String,
            attempt: u32,
        },
    }
    impl StageRunner for MockRunner {
        in_memory_cancellation!();
        fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError> {
            if self
                .db
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
            self.db.lock().unwrap().roles
        }

        async fn execute(
            &self,
            lease: &Lease,
            _: Uuid,
            stage: Stage,
            task: &TaskRecord,
            _: &TrustedPolicy,
            _: ExecutionBudget,
        ) -> Result<StageOutput, StageFailure> {
            if lease.task_id
                != task
                    .task_id
                    .parse::<Uuid>()
                    .map_err(|_| StageFailure::InvalidInput)?
                || lease.fencing_token <= 0
            {
                return Err(StageFailure::InvalidInput);
            }
            let mut db = self.db.lock().map_err(|_| StageFailure::Internal)?;
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
                    local_validation_passed: None,
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
                    local_validation_passed: None,
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
                    local_validation_passed: None,
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
                    local_validation_passed: None,
                    model_tokens: 1,
                    mock_github_journal: None,
                    plan: None,
                    code_change: None,
                },
                Stage::Merge => return Err(StageFailure::InvalidConfiguration),
            })
        }

        async fn verify_local_validation(
            &self,
            lease: &Lease,
            key: Uuid,
            task: &TaskRecord,
            _: &TrustedPolicy,
        ) -> Result<bool, ()> {
            let task_id = task.task_id.parse::<Uuid>().map_err(|_| ())?;
            if lease.task_id != task_id
                || lease.fencing_token <= 0
                || key != operation_key(task_id, task.attempts, State::Validating, Stage::Validate)
                || !matches!(
                    task.state,
                    State::Validating | State::Reviewing | State::Merging | State::Completed
                )
                || task.head_sha.as_deref() != Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            {
                return Err(());
            }
            self.verification_calls
                .lock()
                .map_err(|_| ())?
                .push(ValidationVerificationCall {
                    task_id: lease.task_id,
                    operation_key: key,
                    head_sha: task.head_sha.clone().ok_or(())?,
                    fencing_token: lease.fencing_token,
                });
            if self.fail_local_validation_attempt == Some(task.attempts) {
                Ok(false)
            } else {
                self.verified_local_validation.ok_or(())
            }
        }

        fn verify_completed_operation(
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
        ) -> impl Future<Output = Result<(), ()>> + Send {
            let receipt = self.completed_proofs.lock().ok().and_then(|mut proofs| {
                let position = proofs.iter().position(|proof| {
                    proof.task_id == lease.task_id
                        && proof.current_fencing_token == lease.fencing_token
                        && proof.stage == stage
                })?;
                Some(proofs.remove(position))
            });
            let valid = receipt.is_some_and(|proof| {
                task.task_id.parse::<Uuid>().ok() == Some(proof.task_id)
                    && lease.task_id == proof.task_id
                    && task.attempts == proof.attempt
                    && stage == proof.stage
                    && operation_key == proof.operation_key
                    && request_hash == proof.request_hash
                    && original_fencing_token == proof.original_fencing_token
                    && lease.fencing_token == proof.current_fencing_token
                    && original_fencing_token <= lease.fencing_token
                    && result_digest == proof.result_digest
                    && cumulative_model_tokens == proof.cumulative_model_tokens
                    && facts_digest_for_test(facts) == proof.facts_digest
            });
            let delay = self.completed_verifier_delay.lock().ok().and_then(|v| *v);
            let drop_guard = CompletedVerifierDropGuard(self.completed_verifier_dropped.clone());
            async move {
                let _drop_guard = drop_guard;
                if let Some(delay) = delay {
                    tokio::time::sleep(delay).await;
                }
                if valid { Ok(()) } else { Err(()) }
            }
        }

        async fn verify_repair_context(
            &self,
            lease: &Lease,
            key: Uuid,
            task: &TaskRecord,
            _: &TrustedPolicy,
            facts: &ObservedFacts,
        ) -> Result<RepairProof, ()> {
            let task_id = task.task_id.parse::<Uuid>().map_err(|_| ())?;
            let head_sha = task.head_sha.clone().ok_or(())?;
            if lease.task_id != task_id
                || lease.fencing_token <= 0
                || task.state != State::Repairing
                || key != operation_key(task_id, task.attempts, State::Repairing, Stage::Implement)
                || !facts.issue_open
                || facts.ci.as_ref().is_some_and(|ci| {
                    ci.head_sha != head_sha
                        || task.pull_request.is_some_and(|pr| ci.pull_request != pr)
                })
            {
                return Err(());
            }
            self.repair_verification_calls
                .lock()
                .map_err(|_| ())?
                .push(RepairVerificationCall {
                    task_id,
                    operation_key: key,
                    head_sha: head_sha.clone(),
                    attempt: task.attempts,
                    fencing_token: lease.fencing_token,
                });
            let delay = *self.repair_verifier_delay.lock().map_err(|_| ())?;
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            let proof = self.repair_proof_fixture.lock().map_err(|_| ())?.clone();
            match proof {
                RepairProofFixture::AcceptCurrent => Ok(RepairProof::Start),
                RepairProofFixture::Missing => Err(()),
                RepairProofFixture::Completed {
                    head_sha,
                    pull_request,
                    result_digest,
                    total_model_tokens,
                } => Ok(RepairProof::Completed {
                    head_sha,
                    pull_request,
                    result_digest,
                    total_model_tokens,
                }),
                RepairProofFixture::Expected {
                    task_id: expected_task_id,
                    head_sha: expected_head_sha,
                    attempt: expected_attempt,
                } => {
                    if expected_task_id == task_id
                        && expected_head_sha == head_sha
                        && expected_attempt == task.attempts
                    {
                        Ok(RepairProof::Start)
                    } else {
                        Err(())
                    }
                }
            }
        }

        async fn stop_and_verify(&self, _: &Lease, key: Uuid) -> Result<(), ()> {
            let mut db = self.db.lock().map_err(|_| ())?;
            db.stop_attempts += 1;
            db.stopped_operation_keys.push(key);
            if db.stop_confirmed { Ok(()) } else { Err(()) }
        }
    }

    struct MockRecovery;
    impl RecoveryVerifier for MockRecovery {
        fn verify_stopped(&self, _: Uuid, _: &str, _: i64) -> Option<serde_json::Value> {
            None
        }
    }

    fn test_task(id: Uuid) -> TaskRecord {
        let base = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
        TaskRecord {
            task_id: id.to_string(),
            issue_number: 5,
            base_sha: base,
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
        }
    }

    fn fixture() -> (
        TestEngine,
        Arc<Mutex<MockDb>>,
        Uuid,
        Arc<Mutex<ObservedFacts>>,
    ) {
        let id = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap();
        let task = test_task(id);
        let base = task.base_sha.clone();
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
            ci: Some(domain::CiObservation {
                head_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                pull_request: 7,
                status: domain::CiStatus::Passed,
            }),
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
            stopped_operation_keys: Vec::new(),
            fail_save: false,
            configuration_valid: true,
            roles: (Provider::Codex, Provider::Claude),
            releases: 0,
        }));
        let observed = Arc::new(Mutex::new(facts));
        let engine = Engine {
            store: MockStore(db.clone()),
            policies: MockPolicy(policy),
            evidence: MockEvidence(db.clone(), observed.clone()),
            runner: MockRunner {
                db: db.clone(),
                verified_local_validation: Some(true),
                fail_local_validation_attempt: None,
                verification_calls: Arc::new(Mutex::new(Vec::new())),
                repair_proof_fixture: Arc::new(Mutex::new(RepairProofFixture::AcceptCurrent)),
                repair_verification_calls: Arc::new(Mutex::new(Vec::new())),
                repair_verifier_delay: Arc::new(Mutex::new(None)),
                completed_proofs: Arc::new(Mutex::new(Vec::new())),
                completed_verifier_delay: Arc::new(Mutex::new(None)),
                completed_verifier_dropped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
            recovery: MockRecovery,
            mock_github: None,
            lease_ttl: Duration::from_secs(30),
        };
        (engine, db, id, observed)
    }

    struct UnsupportedRunner {
        declares_support: bool,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl StageRunner for UnsupportedRunner {
        fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError> {
            Ok(())
        }
        fn agent_roles(&self) -> (Provider, Provider) {
            (Provider::Codex, Provider::Claude)
        }
        fn supports_cancellation(&self) -> bool {
            self.declares_support
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
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(StageFailure::Internal)
        }
        async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn unsupported_cancellation_is_rejected_before_claim_or_execution() {
        let (engine, db, task_id, _) = fixture();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let engine = Engine {
            store: engine.store,
            policies: engine.policies,
            evidence: engine.evidence,
            runner: UnsupportedRunner {
                declares_support: false,
                calls: calls.clone(),
            },
            recovery: engine.recovery,
            mock_github: None,
            lease_ttl: engine.lease_ttl,
        };
        let prior = Lease {
            task_id,
            owner: "old-worker".into(),
            fencing_token: 1,
        };
        assert!(matches!(
            engine.run_one(task_id, "worker").await,
            Err(EngineError::InvalidConfiguration)
        ));
        assert!(matches!(
            engine.resume(task_id, "worker").await,
            Err(EngineError::InvalidConfiguration)
        ));
        assert!(matches!(
            engine.complete_handoff(task_id, "worker").await,
            Err(EngineError::InvalidConfiguration)
        ));
        assert!(matches!(
            engine.recover_and_run(&prior, "worker").await,
            Err(EngineError::InvalidConfiguration)
        ));
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Queued);
        assert!(db.ops.is_empty());
        assert_eq!(db.releases, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn declaration_without_cancellation_override_never_runs_stage() {
        let (engine, db, task_id, _) = fixture();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let engine = Engine {
            store: engine.store,
            policies: engine.policies,
            evidence: engine.evidence,
            runner: UnsupportedRunner {
                declares_support: true,
                calls: calls.clone(),
            },
            recovery: engine.recovery,
            mock_github: None,
            lease_ttl: engine.lease_ttl,
        };
        assert_eq!(
            engine.run_one(task_id, "worker").await.unwrap(),
            StepResult::BlockedStageFailure(StageFailure::InvalidConfiguration)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(db.lock().unwrap().task.state, State::Blocked);
    }

    fn facts_digest_for_test(facts: &ObservedFacts) -> [u8; 32] {
        let input = serde_json::json!({
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
            "merge_commit_sha": facts.merge_commit_sha,
            "base_contains_merge_commit": facts.base_contains_merge_commit,
            "checks_passed": facts.checks_passed,
            "reviewer_approved": facts.reviewer_approved,
            "approved_assignee": facts.approved_assignee,
            "ci": facts.ci.as_ref().map(|ci| serde_json::json!({
                "head_sha": ci.head_sha,
                "pull_request": ci.pull_request,
                "status": match ci.status {
                    domain::CiStatus::Pending => "pending",
                    domain::CiStatus::Passed => "passed",
                    domain::CiStatus::Failed => "failed",
                    domain::CiStatus::Unknown => "unknown",
                },
            })),
        });
        Sha3_256::digest(serde_json::to_vec(&input).unwrap_or_default()).into()
    }

    fn register_completed_proof(
        runner: &MockRunner,
        task: &TaskRecord,
        stage: Stage,
        result: &serde_json::Value,
        original_fencing_token: i64,
        current_fencing_token: i64,
        facts: &ObservedFacts,
    ) {
        let task_id = Uuid::parse_str(&task.task_id).unwrap();
        runner
            .completed_proofs
            .lock()
            .unwrap()
            .push(CompletedOperationProofFixture {
                task_id,
                attempt: task.attempts,
                stage,
                operation_key: operation_key(task_id, task.attempts, task.state, stage),
                request_hash: request_hash(task, stage),
                original_fencing_token,
                current_fencing_token,
                result_digest: repair_result_digest(result).unwrap(),
                cumulative_model_tokens: task.model_tokens,
                facts_digest: facts_digest_for_test(facts),
            });
    }

    fn expected_completed_validation_task(id: Uuid) -> TaskRecord {
        let mut task = test_task(id);
        task.state = State::Validating;
        task.attempts = 1;
        task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
        task.pull_request = Some(7);
        task.model_tokens = 1;
        task
    }

    fn completed_validation_result(local_result: bool) -> serde_json::Value {
        serde_json::to_value(StageOutput {
            assignee: None,
            implementer: None,
            reviewer: None,
            session_id: None,
            head_sha: None,
            pull_request: Some(7),
            validation_passed: local_result,
            local_validation_passed: Some(local_result),
            model_tokens: 1,
            mock_github_journal: None,
            plan: None,
            code_change: None,
        })
        .unwrap()
    }

    struct SensitivePersistRunner {
        stages: Arc<Mutex<Vec<Stage>>>,
        supervisor: MockRunner,
    }

    impl StageRunner for SensitivePersistRunner {
        in_memory_cancellation!();
        fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError> {
            Ok(())
        }

        fn agent_roles(&self) -> (Provider, Provider) {
            (Provider::Codex, Provider::Claude)
        }

        async fn execute(
            &self,
            _: &Lease,
            _: Uuid,
            stage: Stage,
            task: &TaskRecord,
            _: &TrustedPolicy,
            _: ExecutionBudget,
        ) -> Result<StageOutput, StageFailure> {
            self.stages
                .lock()
                .map_err(|_| StageFailure::Internal)?
                .push(stage);
            if stage != Stage::Plan {
                return Err(StageFailure::Agent(Failure::Unavailable));
            }
            Ok(StageOutput {
                assignee: Some("bot".into()),
                implementer: Some("codex".into()),
                reviewer: Some("claude".into()),
                session_id: Some(task.task_id.clone()),
                head_sha: None,
                pull_request: None,
                validation_passed: false,
                local_validation_passed: None,
                model_tokens: 3,
                mock_github_journal: None,
                plan: Some(MockPlan {
                    requirements: vec!["sk-live-sensitive-canary".into()],
                    steps: vec!["/private/workspace/secret-project/implementation.rs".into()],
                }),
                code_change: None,
            })
        }

        fn verify_completed_operation(
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
        ) -> impl Future<Output = Result<(), ()>> + Send {
            self.supervisor.verify_completed_operation(
                lease,
                task,
                stage,
                operation_key,
                request_hash,
                original_fencing_token,
                result_digest,
                cumulative_model_tokens,
                facts,
            )
        }

        async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
            Ok(())
        }
    }

    fn store_completed_validation(db: &Arc<Mutex<MockDb>>, id: Uuid, local_result: bool) -> Uuid {
        let mut db = db.lock().unwrap();
        db.task.state = State::Validating;
        db.task.attempts = 1;
        db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
        db.task.pull_request = Some(7);
        db.task.validation_passed = false;
        db.task.model_tokens = 1;
        let key = operation_key(id, 1, State::Validating, Stage::Validate);
        db.ops.insert(
            key,
            OperationLookup::Completed {
                result: completed_validation_result(local_result),
                fencing_token: 1,
            },
        );
        key
    }

    #[tokio::test]
    async fn forged_completed_validation_success_is_denied_without_trusted_verifier() {
        let (mut engine, db, id, facts) = fixture();
        engine.runner.verified_local_validation = None;
        let key = store_completed_validation(&db, id, true);
        register_completed_proof(
            &engine.runner,
            &expected_completed_validation_task(id),
            Stage::Validate,
            &completed_validation_result(true),
            1,
            1,
            &facts.lock().unwrap(),
        );
        let result = engine
            .run_claimed(&Lease {
                task_id: id,
                owner: "worker".into(),
                fencing_token: 1,
            })
            .await
            .unwrap();

        assert_eq!(
            result,
            StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.task.checkpoint, Some(State::Validating));
        assert_eq!(db.executions, 0);
        assert!(db.ops.contains_key(&key));
        assert_eq!(engine.runner.verification_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn forged_completed_validation_failure_cannot_trigger_repair() {
        let (mut engine, db, id, facts) = fixture();
        store_completed_validation(&db, id, false);
        engine.runner.verified_local_validation = Some(true);
        register_completed_proof(
            &engine.runner,
            &expected_completed_validation_task(id),
            Stage::Validate,
            &completed_validation_result(false),
            1,
            1,
            &facts.lock().unwrap(),
        );
        let result = engine
            .run_claimed(&Lease {
                task_id: id,
                owner: "worker".into(),
                fencing_token: 1,
            })
            .await
            .unwrap();

        assert_eq!(
            result,
            StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.task.attempts, 1);
        assert_eq!(db.executions, 0);
        assert_eq!(engine.runner.verification_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn completed_validation_verifier_timeout_is_reported_and_blocks() {
        struct SlowVerifier(MockRunner);

        impl StageRunner for SlowVerifier {
            in_memory_cancellation!();
            fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError> {
                self.0.validate_configuration()
            }

            fn agent_roles(&self) -> (Provider, Provider) {
                self.0.agent_roles()
            }

            async fn execute(
                &self,
                lease: &Lease,
                operation_key: Uuid,
                stage: Stage,
                task: &TaskRecord,
                policy: &TrustedPolicy,
                budget: ExecutionBudget,
            ) -> Result<StageOutput, StageFailure> {
                self.0
                    .execute(lease, operation_key, stage, task, policy, budget)
                    .await
            }

            async fn verify_local_validation(
                &self,
                _: &Lease,
                _: Uuid,
                _: &TaskRecord,
                _: &TrustedPolicy,
            ) -> Result<bool, ()> {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(true)
            }

            fn verify_completed_operation(
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
            ) -> impl Future<Output = Result<(), ()>> + Send {
                self.0.verify_completed_operation(
                    lease,
                    task,
                    stage,
                    operation_key,
                    request_hash,
                    original_fencing_token,
                    result_digest,
                    cumulative_model_tokens,
                    facts,
                )
            }

            async fn stop_and_verify(&self, lease: &Lease, key: Uuid) -> Result<(), ()> {
                self.0.stop_and_verify(lease, key).await
            }
        }

        let (engine, db, id, facts) = fixture();
        store_completed_validation(&db, id, true);
        let expected_task = expected_completed_validation_task(id);
        register_completed_proof(
            &engine.runner,
            &expected_task,
            Stage::Validate,
            &completed_validation_result(true),
            1,
            1,
            &facts.lock().unwrap(),
        );
        let mut policy = engine.policies.0.clone();
        policy.max_runtime = Duration::from_millis(10);
        let engine = Engine {
            store: engine.store,
            policies: MockPolicy(policy),
            evidence: engine.evidence,
            runner: SlowVerifier(engine.runner),
            recovery: engine.recovery,
            mock_github: None,
            lease_ttl: engine.lease_ttl,
        };
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await
                .unwrap(),
            StepResult::BlockedStageFailure(StageFailure::Timeout)
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.executions, 0);
        assert_eq!(db.stop_attempts, 1);
    }

    #[tokio::test]
    async fn verified_completed_validation_resumes_after_fresh_ci_pass_without_reexecution() {
        let (mut engine, db, id, facts) = fixture();
        let key = store_completed_validation(&db, id, true);
        engine.runner.verified_local_validation = Some(true);
        facts.lock().unwrap().ci.as_mut().unwrap().status = domain::CiStatus::Pending;
        let expected_task = expected_completed_validation_task(id);
        let pending_facts = facts.lock().unwrap().clone();
        register_completed_proof(
            &engine.runner,
            &expected_task,
            Stage::Validate,
            &completed_validation_result(true),
            1,
            1,
            &pending_facts,
        );
        let first_lease = Lease {
            task_id: id,
            owner: "worker".into(),
            fencing_token: 1,
        };

        assert_eq!(
            engine.run_claimed(&first_lease).await.unwrap(),
            StepResult::WaitingForHuman
        );
        {
            let db = db.lock().unwrap();
            assert_eq!(db.task.state, State::Paused);
            assert_eq!(db.task.checkpoint, Some(State::Validating));
            assert_eq!(db.executions, 0);
        }

        facts.lock().unwrap().ci.as_mut().unwrap().status = domain::CiStatus::Passed;
        let observed = facts.lock().unwrap().clone();
        let resumed_lease = engine
            .store
            .claim_resume(
                id,
                "worker",
                engine.lease_ttl,
                &engine.policies.0,
                &observed,
            )
            .await
            .unwrap();
        register_completed_proof(
            &engine.runner,
            &expected_task,
            Stage::Validate,
            &completed_validation_result(true),
            1,
            resumed_lease.fencing_token,
            &observed,
        );
        assert_eq!(
            engine.run_claimed(&resumed_lease).await.unwrap(),
            StepResult::WaitingForHuman
        );

        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Merging);
        assert_eq!(db.executions, 1, "only the Review stage ran after resume");
        assert!(matches!(
            db.ops.get(&key),
            Some(OperationLookup::Completed { .. })
        ));
        let calls = engine.runner.verification_calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert!(calls.iter().all(|call| {
            call.task_id == id
                && call.operation_key == key
                && call.head_sha == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }));
        assert_ne!(
            calls[0].fencing_token, calls[1].fencing_token,
            "resumption uses a new lease fence"
        );
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
    async fn wrong_agent_roles_are_rejected_before_task_claim() {
        for roles in [
            (Provider::DeepSeekHarness, Provider::Claude),
            (Provider::Codex, Provider::DeepSeekHarness),
            (Provider::Codex, Provider::Codex),
        ] {
            let (engine, db, id, _) = fixture();
            db.lock().unwrap().roles = roles;
            assert!(matches!(
                engine.run_one(id, "worker").await,
                Err(EngineError::InvalidConfiguration)
            ));
            let db = db.lock().unwrap();
            assert_eq!(db.task.state, State::Queued);
            assert_eq!(db.executions, 0);
            assert_eq!(db.saves, 0);
        }
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

    #[tokio::test]
    async fn non_mock_policy_is_checked_before_claim_or_execution() {
        for (branch, attempts) in [("main", 3), ("release", 3), ("develop", 4)] {
            let (mut engine, db, id, _) = fixture();
            engine.policies.0.base_ref = branch.into();
            engine.policies.0.max_attempts = attempts;
            assert!(matches!(
                engine.run_one(id, "worker").await,
                Err(EngineError::InvalidConfiguration)
            ));
            let db = db.lock().unwrap();
            assert_eq!(db.task.state, State::Queued);
            assert_eq!(db.executions, 0);
            assert_eq!(db.saves, 0);
        }
    }

    #[tokio::test]
    async fn invalid_policy_is_rejected_on_resume_recovery_and_handoff() {
        let (mut engine, db, id, _) = fixture();
        engine.policies.0.base_ref = "main".into();
        let lease = Lease {
            task_id: id,
            owner: "worker".into(),
            fencing_token: 1,
        };
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Blocked;
            db.task.checkpoint = Some(State::Planning);
        }
        assert!(matches!(
            engine.resume(id, "worker").await,
            Err(EngineError::InvalidConfiguration)
        ));
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Planning;
            db.task.checkpoint = None;
        }
        assert!(matches!(
            engine.recover_and_run(&lease, "worker").await,
            Err(EngineError::InvalidConfiguration)
        ));
        assert!(matches!(
            engine.run_claimed(&lease).await,
            Err(EngineError::InvalidConfiguration)
        ));
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Merging;
            db.task.head_sha = Some("b".repeat(40));
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        assert!(matches!(
            engine.complete_handoff(id, "worker").await,
            Err(EngineError::InvalidConfiguration)
        ));
        let db = db.lock().unwrap();
        assert_eq!(db.executions, 0);
        assert_eq!(db.saves, 0);
        assert!(db.ops.is_empty());
    }

    #[test]
    fn agent_stages_are_capped_at_45_minutes() {
        let limit = Duration::from_secs(
            u64::from(AutonomyConfig::approved_mock_defaults().agent_timeout_minutes) * 60,
        );
        let long_budget = Duration::from_secs(60 * 60);

        assert_eq!(stage_timeout(Stage::Plan, long_budget), limit);
        assert_eq!(stage_timeout(Stage::Implement, long_budget), limit);
        assert_eq!(stage_timeout(Stage::Review, long_budget), limit);
        assert_eq!(stage_timeout(Stage::Validate, long_budget), long_budget);
        assert_eq!(stage_timeout(Stage::Merge, long_budget), long_budget);
        assert_eq!(
            stage_timeout(Stage::Plan, Duration::from_secs(5)),
            Duration::from_secs(5)
        );
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
        facts.lock().unwrap().issue_open = false;
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
    async fn merged_task_waits_for_issue_close_before_completion() {
        let (engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Merging;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        {
            let mut facts = facts.lock().unwrap();
            facts.pr_merged = true;
            facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
            facts.base_contains_merge_commit = true;
        }
        assert_eq!(
            engine.complete_handoff(id, "handoff-worker").await.unwrap(),
            StepResult::WaitingForHuman
        );
        assert_eq!(db.lock().unwrap().task.state, State::Merging);
        facts.lock().unwrap().issue_open = false;
        assert_eq!(
            engine.complete_handoff(id, "handoff-worker").await.unwrap(),
            StepResult::Finished
        );
        assert_eq!(db.lock().unwrap().task.state, State::Completed);
        assert_eq!(db.lock().unwrap().executions, 0);
    }

    #[tokio::test]
    async fn issue_close_response_loss_is_reconciled_from_fresh_closed_evidence() {
        let (engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Merging;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        {
            let mut facts = facts.lock().unwrap();
            facts.pr_merged = true;
            facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
            facts.base_contains_merge_commit = true;
        }
        let sends = Arc::new(Mutex::new(Vec::new()));
        let controller = MockIssueCloseController {
            facts: facts.clone(),
            sends: sends.clone(),
            response_lost: true,
        };

        assert_eq!(
            engine
                .complete_handoff_with_issue_close(id, "handoff-worker", &controller)
                .await
                .unwrap(),
            StepResult::Finished
        );
        assert_eq!(db.lock().unwrap().task.state, State::Completed);
        assert_eq!(db.lock().unwrap().executions, 0);
        assert_eq!(
            *sends.lock().unwrap(),
            vec![crate::postgres::issue_close_operation_key(id)]
        );
    }

    const ISSUE_CLOSE_CRASH_DATABASE: &str = "orchestrator_test_engine_issue_close_crash";
    const ISSUE_CLOSE_CRASH_PHASE: &str = "MIPSORCU_ISSUE_CLOSE_CRASH_PHASE";
    const ISSUE_CLOSE_CRASH_API_ROOT: &str = "MIPSORCU_ISSUE_CLOSE_CRASH_API_ROOT";
    const ISSUE_CLOSE_CRASH_MARKER: &str = "MIPSORCU_ISSUE_CLOSE_CRASH_MARKER";
    const ISSUE_CLOSE_CRASH_TASK_ID: Uuid = Uuid::from_u128(0x20261123000100000000000000000001);
    const ISSUE_CLOSE_CRASH_OWNER: &str = "issue-close-crash-child";
    const ISSUE_CLOSE_CRASH_BASE_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ISSUE_CLOSE_CRASH_HEAD_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ISSUE_CLOSE_CRASH_MERGE_SHA: &str = "cccccccccccccccccccccccccccccccccccccccc";

    #[derive(Clone)]
    struct IssueCloseCrashPolicy;

    impl TrustedPolicySource for IssueCloseCrashPolicy {
        async fn load_policy(&self, _: &TaskRecord) -> Result<TrustedPolicy, ()> {
            Ok(TrustedPolicy {
                base_ref: "develop".to_owned(),
                base_sha: ISSUE_CLOSE_CRASH_BASE_SHA.to_owned(),
                allowed_assignee: "worker".to_owned(),
                required_checks: vec!["ci".to_owned()],
                max_attempts: 3,
                max_runtime: Duration::from_secs(60),
                max_model_tokens: 100,
            })
        }
    }

    #[derive(Clone)]
    struct IssueCloseCrashEvidence(Arc<std::sync::atomic::AtomicBool>);

    impl EvidenceSource for IssueCloseCrashEvidence {
        async fn observe(&self, _: &TaskRecord, _: &TrustedPolicy) -> Result<ObservedFacts, ()> {
            Ok(issue_close_crash_facts(
                !self.0.load(Ordering::SeqCst),
                true,
            ))
        }
    }

    struct IssueCloseCrashRunner;

    impl StageRunner for IssueCloseCrashRunner {
        fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError> {
            Ok(())
        }

        fn agent_roles(&self) -> (Provider, Provider) {
            (Provider::Codex, Provider::Claude)
        }

        fn supports_cancellation(&self) -> bool {
            true
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
            Err(StageFailure::InvalidConfiguration)
        }

        async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
            Ok(())
        }

        async fn verify_local_validation(
            &self,
            lease: &Lease,
            key: Uuid,
            task: &TaskRecord,
            _: &TrustedPolicy,
        ) -> Result<bool, ()> {
            let task_id = task.task_id.parse::<Uuid>().map_err(|_| ())?;
            if lease.task_id != task_id
                || lease.fencing_token <= 0
                || key != operation_key(task_id, task.attempts, State::Validating, Stage::Validate)
                || task.head_sha.as_deref() != Some(ISSUE_CLOSE_CRASH_HEAD_SHA)
            {
                return Err(());
            }
            Ok(true)
        }
    }

    struct IssueCloseCrashRecovery;

    impl RecoveryVerifier for IssueCloseCrashRecovery {
        fn verify_stopped(
            &self,
            task_id: Uuid,
            old_owner: &str,
            expired_fencing_token: i64,
        ) -> Option<serde_json::Value> {
            (task_id == ISSUE_CLOSE_CRASH_TASK_ID
                && old_owner == ISSUE_CLOSE_CRASH_OWNER
                && expired_fencing_token > 0)
                .then(|| serde_json::json!({"parent_confirmed_child_sigkill": true}))
        }
    }

    struct IssueCloseCrashController;

    impl issue_close_controller_sealed::Sealed for IssueCloseCrashController {}

    impl IssueCloseController for IssueCloseCrashController {
        async fn close_issue_once(
            &self,
            lease: &Lease,
            task: &TaskRecord,
            policy: &TrustedPolicy,
            facts: &ObservedFacts,
            operation_id: Uuid,
        ) -> Result<(), ()> {
            use std::{fs::OpenOptions, io::Write};

            if std::env::var(ISSUE_CLOSE_CRASH_PHASE).as_deref() != Ok("post")
                || task.state != State::Merging
                || lease.task_id != ISSUE_CLOSE_CRASH_TASK_ID
                || lease.owner != ISSUE_CLOSE_CRASH_OWNER
                || lease.fencing_token <= 0
                || task.issue_number != 17
                || policy.base_ref != "develop"
                || !facts.pr_merged
                || !facts.issue_open
                || operation_id != crate::postgres::issue_close_operation_key(lease.task_id)
            {
                return Err(());
            }

            let database_url = issue_close_crash_database_url().map_err(|_| ())?;
            let (client, connection) =
                tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
                    .await
                    .map_err(|_| ())?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let live_intent: bool = client
                .query_one(
                    "SELECT count(*) = 1 FROM orchestrator.task_operations o \
                     JOIN orchestrator.tasks t ON t.id=o.task_id \
                     JOIN orchestrator.execution_lease l ON l.task_id=t.id AND l.fencing_token=o.fencing_token \
                     WHERE o.operation_key=$1 AND o.task_id=$2 AND o.fencing_token=$3 \
                       AND o.result IS NULL AND o.operation='github_issue_close' \
                       AND t.status::text='merging' AND t.issue_number=17 AND t.repository='org/repo' \
                       AND l.owner=$4 AND l.expires_at > clock_timestamp()",
                    &[
                        &operation_id,
                        &lease.task_id,
                        &lease.fencing_token,
                        &lease.owner,
                    ],
                )
                .await
                .map_err(|_| ())?
                .get(0);
            if !live_intent {
                return Err(());
            }

            let api_root = std::env::var(ISSUE_CLOSE_CRASH_API_ROOT).map_err(|_| ())?;
            let root = reqwest::Url::parse(&api_root).map_err(|_| ())?;
            if root.scheme() != "http"
                || root.host_str() != Some("127.0.0.1")
                || root.port().is_none_or(|port| port == 0)
                || !root.username().is_empty()
                || root.password().is_some()
                || root.path() != "/"
                || root.query().is_some()
                || root.fragment().is_some()
            {
                return Err(());
            }
            let response = reqwest::Client::new()
                .patch(format!("{api_root}repos/org/repo/issues/17"))
                .bearer_auth("synthetic-test-token")
                .json(&serde_json::json!({"state": "closed"}))
                .send()
                .await
                .map_err(|_| ())?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(());
            }
            let body: serde_json::Value = response.json().await.map_err(|_| ())?;
            if body != serde_json::json!({"number": 17, "state": "closed"}) {
                return Err(());
            }

            let marker =
                std::path::PathBuf::from(std::env::var(ISSUE_CLOSE_CRASH_MARKER).map_err(|_| ())?);
            let marker_name = marker.file_name().and_then(|name| name.to_str());
            if marker.parent() != Some(std::path::Path::new("/tmp"))
                || !marker_name
                    .and_then(|name| name.strip_prefix("mipsorcu-issue-close-crash-"))
                    .and_then(|name| name.strip_suffix(".ready"))
                    .is_some_and(|id| Uuid::parse_str(id).is_ok())
            {
                return Err(());
            }
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(marker)
                .map_err(|_| ())?
                .write_all(b"remote close response received")
                .map_err(|_| ())?;
            std::future::pending::<()>().await;
            Ok(())
        }
    }

    fn issue_close_crash_facts(issue_open: bool, merged: bool) -> ObservedFacts {
        ObservedFacts {
            policy_base_ref: "develop".to_owned(),
            policy_base_sha: ISSUE_CLOSE_CRASH_BASE_SHA.to_owned(),
            issue_open,
            base_sha: ISSUE_CLOSE_CRASH_BASE_SHA.to_owned(),
            head_sha: ISSUE_CLOSE_CRASH_HEAD_SHA.to_owned(),
            validated_head_sha: Some(ISSUE_CLOSE_CRASH_HEAD_SHA.to_owned()),
            pr_number: Some(42),
            pr_head_sha: Some(ISSUE_CLOSE_CRASH_HEAD_SHA.to_owned()),
            pr_base_ref: Some("develop".to_owned()),
            pr_base_sha: Some(ISSUE_CLOSE_CRASH_BASE_SHA.to_owned()),
            pr_merged: merged,
            checks_passed: vec!["ci".to_owned()],
            reviewer_approved: true,
            approved_assignee: "worker".to_owned(),
            merge_commit_sha: merged.then(|| ISSUE_CLOSE_CRASH_MERGE_SHA.to_owned()),
            base_contains_merge_commit: merged,
            ci: Some(domain::CiObservation {
                head_sha: ISSUE_CLOSE_CRASH_HEAD_SHA.to_owned(),
                pull_request: 42,
                status: domain::CiStatus::Passed,
            }),
        }
    }

    fn require_issue_close_crash_network_isolation() -> Result<(), ()> {
        #[cfg(target_os = "linux")]
        {
            let interfaces = std::fs::read_dir("/sys/class/net").map_err(|_| ())?;
            let mut names = interfaces
                .map(|entry| {
                    entry
                        .map_err(|_| ())
                        .and_then(|entry| entry.file_name().into_string().map_err(|_| ()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            names.sort();
            if names != ["lo"] {
                return Err(());
            }

            let routes = std::fs::read_to_string("/proc/net/route").map_err(|_| ())?;
            if routes.lines().count() != 1 {
                return Err(());
            }
            let ipv6_routes = std::fs::read_to_string("/proc/net/ipv6_route").map_err(|_| ())?;
            if ipv6_routes
                .lines()
                .any(|route| route.split_whitespace().last() != Some("lo"))
            {
                return Err(());
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(())
        }
    }

    fn issue_close_crash_database_url() -> Result<String, ()> {
        require_issue_close_crash_network_isolation()?;
        let database_url =
            std::env::var("MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL").map_err(|_| ())?;
        let config: tokio_postgres::Config = database_url.parse().map_err(|_| ())?;
        if !matches!(config.get_hosts(), [tokio_postgres::config::Host::Tcp(host)] if host == "127.0.0.1")
            || !config.get_hostaddrs().is_empty()
            || config.get_ports() != [5432]
            || config.get_dbname() != Some(ISSUE_CLOSE_CRASH_DATABASE)
            || config.get_user() != Some("orchestrator_test")
        {
            return Err(());
        }
        Ok(database_url)
    }

    type IssueCloseCrashEngine = Engine<
        PostgresEngineStore,
        IssueCloseCrashPolicy,
        IssueCloseCrashEvidence,
        IssueCloseCrashRunner,
        IssueCloseCrashRecovery,
    >;

    async fn issue_close_crash_engine(
        database_url: &str,
        closed: Arc<std::sync::atomic::AtomicBool>,
        lease_ttl: Duration,
    ) -> IssueCloseCrashEngine {
        IssueCloseCrashEngine {
            store: PostgresEngineStore::new(
                TaskStore::connect(database_url)
                    .await
                    .expect("connect dedicated disposable Issue-close test database"),
            ),
            policies: IssueCloseCrashPolicy,
            evidence: IssueCloseCrashEvidence(closed),
            runner: IssueCloseCrashRunner,
            recovery: IssueCloseCrashRecovery,
            mock_github: None,
            lease_ttl,
        }
    }

    #[cfg(unix)]
    struct IssueCloseCrashChild(std::process::Child);

    #[cfg(unix)]
    impl Drop for IssueCloseCrashChild {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    #[cfg(unix)]
    struct IssueCloseCrashFakeGitHub {
        address: String,
        closed: Arc<std::sync::atomic::AtomicBool>,
        patches: Arc<std::sync::atomic::AtomicUsize>,
        worker: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(unix)]
    impl IssueCloseCrashFakeGitHub {
        fn start() -> Self {
            use std::{
                io::{Read, Write},
                net::TcpListener,
                sync::atomic::AtomicUsize,
            };

            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind fake GitHub loopback");
            let address = format!(
                "http://{}/",
                listener.local_addr().expect("read fake address")
            );
            let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let patches = Arc::new(AtomicUsize::new(0));
            let worker_closed = Arc::clone(&closed);
            let worker_patches = Arc::clone(&patches);
            let worker = std::thread::spawn(move || {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                let mut header_end = None;
                let mut content_length = None;
                while let Ok(size) = stream.read(&mut chunk) {
                    if size == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..size]);
                    if header_end.is_none() {
                        header_end = request
                            .windows(4)
                            .position(|window| window == b"\r\n\r\n")
                            .map(|index| index + 4);
                        if let Some(end) = header_end {
                            let headers =
                                String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                            content_length = headers.lines().find_map(|line| {
                                line.strip_prefix("content-length:")?
                                    .trim()
                                    .parse::<usize>()
                                    .ok()
                            });
                        }
                    }
                    if header_end.zip(content_length).is_some_and(|(end, length)| {
                        end.checked_add(length)
                            .is_some_and(|total| request.len() >= total)
                    }) {
                        break;
                    }
                    if request.len() > 16 * 1024 {
                        break;
                    }
                }

                let valid = header_end.zip(content_length).is_some_and(|(end, length)| {
                    let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                    let body = request
                        .get(end..)
                        .and_then(|tail| tail.get(..length))
                        .unwrap_or_default();
                    let parsed_body: Result<serde_json::Value, _> = serde_json::from_slice(body);
                    headers.starts_with("patch /repos/org/repo/issues/17 http/1.1\r\n")
                        && headers
                            .lines()
                            .any(|line| line == "authorization: bearer synthetic-test-token")
                        && parsed_body
                            .is_ok_and(|value| value == serde_json::json!({"state": "closed"}))
                });
                let (status, body) = if valid {
                    worker_patches.fetch_add(1, Ordering::SeqCst);
                    worker_closed.store(true, Ordering::SeqCst);
                    ("200 OK", r#"{"number":17,"state":"closed"}"#)
                } else {
                    ("400 Bad Request", "{}")
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            });
            Self {
                address,
                closed,
                patches,
                worker: Some(worker),
            }
        }

        fn stop_and_join(&mut self) {
            if let Some(worker) = self.worker.take() {
                worker.join().expect("fake GitHub server thread");
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires the disposable network-none PostgreSQL runner"]
    async fn postgres_issue_close_child_crash_recovers_without_replay() {
        use std::{
            fs,
            os::unix::process::ExitStatusExt,
            process::{Command, Stdio},
            sync::atomic::Ordering,
        };

        let database_url = issue_close_crash_database_url()
            .expect("only the dedicated loopback PostgreSQL runner is accepted");
        if std::env::var(ISSUE_CLOSE_CRASH_PHASE).as_deref() == Ok("post") {
            let api_root = std::env::var(ISSUE_CLOSE_CRASH_API_ROOT)
                .expect("parent supplies only its fake loopback API root");
            let parsed_root = reqwest::Url::parse(&api_root).expect("parse fake API root");
            assert!(
                parsed_root.scheme() == "http"
                    && parsed_root.host_str() == Some("127.0.0.1")
                    && parsed_root.port().is_some_and(|port| port != 0)
                    && parsed_root.username().is_empty()
                    && parsed_root.password().is_none()
                    && parsed_root.path() == "/"
                    && parsed_root.query().is_none()
                    && parsed_root.fragment().is_none(),
                "test child may contact only the parent fake loopback API"
            );
            let marker = std::path::PathBuf::from(
                std::env::var(ISSUE_CLOSE_CRASH_MARKER)
                    .expect("parent supplies child synchronization marker"),
            );
            let marker_name = marker.file_name().and_then(|name| name.to_str());
            assert!(
                marker.parent() == Some(std::path::Path::new("/tmp"))
                    && marker_name
                        .and_then(|name| name.strip_prefix("mipsorcu-issue-close-crash-"))
                        .and_then(|name| name.strip_suffix(".ready"))
                        .is_some_and(|id| Uuid::parse_str(id).is_ok()),
                "child marker must be a uniquely named temporary file"
            );
            let engine = issue_close_crash_engine(
                &database_url,
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
                Duration::from_secs(30),
            )
            .await;
            let outcome = engine
                .complete_handoff_with_issue_close(
                    ISSUE_CLOSE_CRASH_TASK_ID,
                    ISSUE_CLOSE_CRASH_OWNER,
                    &IssueCloseCrashController,
                )
                .await;
            let code = match outcome {
                Ok(_) => 20,
                Err(EngineError::Store(StoreError::InvalidRecord)) => 21,
                Err(EngineError::Store(StoreError::LeaseLost)) => 22,
                Err(EngineError::Store(_)) => 23,
                Err(EngineError::InvalidConfiguration) => 24,
                Err(EngineError::PolicyUnavailable) => 25,
                Err(EngineError::EvidenceUnavailable) => 26,
                Err(EngineError::InvalidTask) => 27,
                Err(EngineError::InvalidOperationResult) => 28,
                Err(EngineError::InvalidTransition(_)) => 29,
            };
            std::process::exit(code);
        }

        let config: tokio_postgres::Config =
            database_url.parse().expect("parse isolated PostgreSQL URL");
        let (bootstrap, connection) = config
            .connect(tokio_postgres::NoTls)
            .await
            .expect("connect dedicated disposable PostgreSQL database");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let dedicated_role: bool = bootstrap
            .query_one(
                "SELECT rolname = 'orchestrator_test' AND NOT rolsuper \
                 FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .expect("inspect test role")
            .get(0);
        assert!(dedicated_role);
        let existing_objects: i64 = bootstrap
            .query_one(
                "SELECT count(*) FROM pg_namespace \
                 WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'public') \
                   AND nspname NOT LIKE 'pg_toast%'",
                &[],
            )
            .await
            .expect("inspect database before migration")
            .get(0);
        assert_eq!(existing_objects, 0);
        for migration in [
            include_str!("../migrations/0001_orchestrator.sql"),
            include_str!("../migrations/0002_execution_metadata.sql"),
            include_str!("../migrations/0003_mock_runtime_fingerprint.sql"),
        ] {
            bootstrap
                .batch_execute(migration)
                .await
                .expect("migrate only the empty dedicated test database");
        }

        let mut task_store = TaskStore::connect(&database_url)
            .await
            .expect("connect isolated Issue-close task store");
        task_store
            .create(&crate::postgres::NewTask {
                task_id: ISSUE_CLOSE_CRASH_TASK_ID,
                repository: "org/repo".to_owned(),
                issue_number: 17,
                base_sha: ISSUE_CLOSE_CRASH_BASE_SHA.to_owned(),
                max_attempts: 3,
                execution_timeout: Duration::from_secs(60),
                model_budget: 100,
                idempotency_key: Uuid::from_u128(0x20261123000100000000000000000002),
            })
            .await
            .expect("create disposable Merging task fixture");
        let seed_policy = IssueCloseCrashPolicy
            .load_policy(&task_store.get(ISSUE_CLOSE_CRASH_TASK_ID).await.unwrap())
            .await
            .expect("load fixture policy");
        let seed_lease = task_store
            .claim(
                ISSUE_CLOSE_CRASH_TASK_ID,
                "issue-close-crash-seed",
                Duration::from_secs(30),
                &seed_policy,
                &issue_close_crash_facts(true, false),
            )
            .await
            .expect("claim queued task before constructing Merging fixture");
        bootstrap
            .execute(
                "UPDATE orchestrator.tasks SET status='blocked', head_sha=$2, pr_number=42, \
                 validation_result=$3, checkpoint=jsonb_build_object('state','planning'), \
                 resume_state='planning', issue_assignee='worker', implementer='codex', \
                 reviewer='claude', session_id='issue-close-crash-fixture' WHERE id=$1",
                &[
                    &ISSUE_CLOSE_CRASH_TASK_ID,
                    &ISSUE_CLOSE_CRASH_HEAD_SHA,
                    &serde_json::json!({
                        "passed": true,
                        "ci_observation": {
                            "head_sha": ISSUE_CLOSE_CRASH_HEAD_SHA,
                            "pull_request": 42,
                            "status": "passed"
                        }
                    }),
                ],
            )
            .await
            .expect("stage a valid task row before the Merging fixture");
        task_store
            .release(&seed_lease)
            .await
            .expect("release fixture seed lease");
        bootstrap
            .execute(
                "UPDATE orchestrator.tasks SET status='merging', checkpoint=NULL, resume_state=NULL WHERE id=$1",
                &[&ISSUE_CLOSE_CRASH_TASK_ID],
            )
            .await
            .expect("place disposable task at the human-merge handoff");
        drop(task_store);

        let mut server = IssueCloseCrashFakeGitHub::start();
        let marker = std::env::temp_dir().join(format!(
            "mipsorcu-issue-close-crash-{}.ready",
            Uuid::new_v4()
        ));
        let child_process = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "engine::tests::postgres_issue_close_child_crash_recovers_without_replay",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", "/tmp")
            .env("MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL", &database_url)
            .env(ISSUE_CLOSE_CRASH_PHASE, "post")
            .env(ISSUE_CLOSE_CRASH_API_ROOT, &server.address)
            .env(ISSUE_CLOSE_CRASH_MARKER, &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn only the synthetic Issue-close child");
        let mut child = IssueCloseCrashChild(child_process);
        tokio::time::timeout(Duration::from_secs(15), async {
            while !marker.exists() {
                if let Some(status) = child.0.try_wait().expect("poll test child") {
                    panic!("ISSUE_CLOSE_CHILD_STATUS={}", status.code().unwrap_or(0));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("child must report the successful fake Issue-close response within the bound");
        assert!(
            child
                .0
                .try_wait()
                .expect("confirm child remains alive")
                .is_none()
        );
        assert!(server.closed.load(Ordering::SeqCst));
        assert_eq!(server.patches.load(Ordering::SeqCst), 1);

        let (observer, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
            .await
            .expect("open independent Issue-close recovery observer");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let persisted = observer
            .query_one(
                "SELECT o.operation_key, o.fencing_token, o.result, t.status::text, \
                        l.owner, l.expires_at > clock_timestamp() \
                 FROM orchestrator.task_operations o \
                 JOIN orchestrator.tasks t ON t.id=o.task_id \
                 JOIN orchestrator.execution_lease l ON l.task_id=t.id AND l.fencing_token=o.fencing_token \
                 WHERE o.task_id=$1 AND o.operation='github_issue_close'",
                &[&ISSUE_CLOSE_CRASH_TASK_ID],
            )
            .await
            .expect("read child durable Issue-close intent and lease");
        let operation_key: Uuid = persisted.get(0);
        let fencing_token: i64 = persisted.get(1);
        let result: Option<serde_json::Value> = persisted.get(2);
        assert_eq!(result, None);
        assert_eq!(persisted.get::<_, String>(3), "merging");
        assert_eq!(persisted.get::<_, String>(4), ISSUE_CLOSE_CRASH_OWNER);
        assert!(persisted.get::<_, bool>(5));
        assert_eq!(
            operation_key,
            crate::postgres::issue_close_operation_key(ISSUE_CLOSE_CRASH_TASK_ID)
        );

        child
            .0
            .kill()
            .expect("SIGKILL only the spawned Issue-close child");
        let child_status = child.0.wait().expect("wait for killed Issue-close child");
        assert_eq!(child_status.signal(), Some(9));
        drop(child);
        fs::remove_file(&marker).expect("remove child synchronization marker");
        server.stop_and_join();

        let expired_rows = observer
            .execute(
                "UPDATE orchestrator.execution_lease \
                 SET expires_at=clock_timestamp() - interval '1 second' \
                 WHERE singleton AND task_id=$1 AND owner=$2 AND fencing_token=$3 \
                   AND expires_at > clock_timestamp()",
                &[
                    &ISSUE_CLOSE_CRASH_TASK_ID,
                    &ISSUE_CLOSE_CRASH_OWNER,
                    &fencing_token,
                ],
            )
            .await
            .expect("expire only the killed child lease in the disposable test database");
        assert_eq!(expired_rows, 1);

        let prior = Lease {
            task_id: ISSUE_CLOSE_CRASH_TASK_ID,
            owner: ISSUE_CLOSE_CRASH_OWNER.to_owned(),
            fencing_token,
        };
        let engine = issue_close_crash_engine(
            &database_url,
            Arc::clone(&server.closed),
            Duration::from_secs(30),
        )
        .await;
        assert_eq!(
            engine
                .recover_and_run(&prior, "issue-close-crash-recovery")
                .await
                .expect("recover and reconcile closed Issue evidence"),
            StepResult::Finished
        );
        assert!(server.closed.load(Ordering::SeqCst));
        assert_eq!(server.patches.load(Ordering::SeqCst), 1);

        let recovered = observer
            .query_one(
                "SELECT t.status::text, o.result, o.fencing_token, l.task_id, l.fencing_token \
                 FROM orchestrator.tasks t \
                 JOIN orchestrator.task_operations o ON o.task_id=t.id \
                 CROSS JOIN orchestrator.execution_lease l \
                 WHERE t.id=$1 AND o.operation_key=$2",
                &[&ISSUE_CLOSE_CRASH_TASK_ID, &operation_key],
            )
            .await
            .expect("inspect reconciled handoff after recovery");
        assert_eq!(recovered.get::<_, String>(0), "completed");
        assert_eq!(
            recovered.get::<_, Option<serde_json::Value>>(1),
            Some(serde_json::json!({"issue_closed_observed": true}))
        );
        assert_eq!(recovered.get::<_, i64>(2), fencing_token);
        assert_eq!(recovered.get::<_, Option<Uuid>>(3), None);
        assert!(recovered.get::<_, i64>(4) > fencing_token);
    }

    #[tokio::test]
    async fn ambiguous_issue_close_is_never_replayed_and_closed_recovery_reconciles() {
        let (engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Merging;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
            db.ops.insert(
                crate::postgres::issue_close_operation_key(id),
                OperationLookup::Ambiguous,
            );
        }
        {
            let mut facts = facts.lock().unwrap();
            facts.pr_merged = true;
            facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
            facts.base_contains_merge_commit = true;
        }
        let sends = Arc::new(Mutex::new(Vec::new()));
        let controller = MockIssueCloseController {
            facts: facts.clone(),
            sends: sends.clone(),
            response_lost: false,
        };

        assert_eq!(
            engine
                .complete_handoff_with_issue_close(id, "handoff-worker", &controller)
                .await
                .unwrap(),
            StepResult::WaitingForHuman
        );
        assert!(sends.lock().unwrap().is_empty());
        assert_eq!(db.lock().unwrap().task.state, State::Merging);

        facts.lock().unwrap().issue_open = false;
        assert_eq!(
            engine
                .complete_handoff_with_issue_close(id, "handoff-worker", &controller)
                .await
                .unwrap(),
            StepResult::Finished
        );
        assert!(sends.lock().unwrap().is_empty());
        assert_eq!(db.lock().unwrap().task.state, State::Completed);
    }

    #[tokio::test]
    async fn settled_issue_close_marker_is_rechecked_before_handoff_completion() {
        let (engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Merging;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
            db.ops.insert(
                crate::postgres::issue_close_operation_key(id),
                OperationLookup::Completed {
                    result: serde_json::json!({"issue_closed_observed": true}),
                    fencing_token: 1,
                },
            );
        }
        {
            let mut facts = facts.lock().unwrap();
            facts.pr_merged = true;
            facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
            facts.base_contains_merge_commit = true;
        }
        let sends = Arc::new(Mutex::new(Vec::new()));
        let controller = MockIssueCloseController {
            facts: facts.clone(),
            sends: sends.clone(),
            response_lost: false,
        };

        // A reopened Issue invalidates the settled marker and keeps the task in Merging.
        assert_eq!(
            engine
                .complete_handoff_with_issue_close(id, "handoff-worker", &controller)
                .await
                .unwrap(),
            StepResult::WaitingForHuman
        );
        assert!(sends.lock().unwrap().is_empty());
        assert_eq!(db.lock().unwrap().task.state, State::Merging);

        facts.lock().unwrap().issue_open = false;
        assert_eq!(
            engine
                .complete_handoff_with_issue_close(id, "handoff-worker", &controller)
                .await
                .unwrap(),
            StepResult::Finished
        );
        assert!(sends.lock().unwrap().is_empty());
        assert_eq!(db.lock().unwrap().task.state, State::Completed);
    }

    #[tokio::test]
    async fn missing_controller_and_failed_local_proof_never_create_close_intent() {
        let (mut engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Merging;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        {
            let mut facts = facts.lock().unwrap();
            facts.pr_merged = true;
            facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
            facts.base_contains_merge_commit = true;
        }
        let sends = Arc::new(Mutex::new(Vec::new()));
        let controller = MockIssueCloseController {
            facts: facts.clone(),
            sends: sends.clone(),
            response_lost: false,
        };

        assert_eq!(
            engine.complete_handoff(id, "handoff-worker").await.unwrap(),
            StepResult::WaitingForHuman
        );
        assert!(db.lock().unwrap().ops.is_empty());

        engine.runner.verified_local_validation = Some(false);
        assert!(
            engine
                .complete_handoff_with_issue_close(id, "handoff-worker", &controller)
                .await
                .is_err()
        );
        assert!(db.lock().unwrap().ops.is_empty());
        assert!(sends.lock().unwrap().is_empty());
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
    async fn forged_reviewing_merging_and_completed_rows_need_independent_local_proof() {
        for state in [State::Reviewing, State::Merging, State::Completed] {
            let (mut engine, db, id, facts) = fixture();
            engine.runner.verified_local_validation = None;
            {
                let mut db = db.lock().unwrap();
                db.task.state = state;
                db.task.attempts = 1;
                db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
                db.task.pull_request = Some(7);
                db.task.validation_passed = true;
            }
            if state == State::Completed {
                let mut facts = facts.lock().unwrap();
                facts.pr_merged = true;
                facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
                facts.base_contains_merge_commit = true;
            }
            let result = engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await;
            if state == State::Completed {
                assert!(matches!(result, Err(EngineError::InvalidOperationResult)));
                assert_eq!(db.lock().unwrap().task.state, State::Completed);
            } else {
                assert_eq!(
                    result.unwrap(),
                    StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
                );
                assert_eq!(db.lock().unwrap().task.state, State::Blocked);
                assert_eq!(db.lock().unwrap().task.checkpoint, Some(state));
            }
            assert_eq!(db.lock().unwrap().executions, 0);
        }
    }

    #[tokio::test]
    async fn independent_local_proof_allows_real_handoff_without_persisting_completion_early() {
        let (mut engine, db, id, _) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Merging;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        engine.runner.verified_local_validation = Some(true);
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await
                .unwrap(),
            StepResult::WaitingForHuman
        );
        assert_eq!(db.lock().unwrap().task.state, State::Merging);
        assert_eq!(engine.runner.verification_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn false_local_proof_in_merging_blocks_and_stops_before_release() {
        for stop_confirmed in [true, false] {
            let (mut engine, db, id, _) = fixture();
            {
                let mut db = db.lock().unwrap();
                db.task.state = State::Merging;
                db.task.attempts = 1;
                db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
                db.task.pull_request = Some(7);
                db.task.validation_passed = true;
                db.stop_confirmed = stop_confirmed;
            }
            engine.runner.verified_local_validation = Some(false);
            assert_eq!(
                engine
                    .run_claimed(&Lease {
                        task_id: id,
                        owner: "worker".into(),
                        fencing_token: 1,
                    })
                    .await
                    .unwrap(),
                StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
            );
            let expected_key = operation_key(id, 1, State::Validating, Stage::Validate);
            let db = db.lock().unwrap();
            assert_eq!(db.task.state, State::Blocked);
            assert_eq!(db.task.checkpoint, Some(State::Merging));
            assert_eq!(db.stop_attempts, 1);
            assert_eq!(db.stopped_operation_keys, vec![expected_key]);
            assert_eq!(db.releases, usize::from(stop_confirmed));
        }
    }

    #[tokio::test]
    async fn merged_merging_verification_failure_stops_without_blocking_or_completing() {
        for verifier_result in [Some(false), None] {
            for stop_confirmed in [true, false] {
                let (mut engine, db, id, facts) = fixture();
                {
                    let mut db = db.lock().unwrap();
                    db.task.state = State::Merging;
                    db.task.attempts = 1;
                    db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
                    db.task.pull_request = Some(7);
                    db.task.validation_passed = true;
                    if verifier_result.is_none() {
                        db.task.elapsed = Duration::from_secs(600);
                    }
                    db.stop_confirmed = stop_confirmed;
                }
                {
                    let mut facts = facts.lock().unwrap();
                    facts.issue_open = false;
                    facts.pr_merged = true;
                    facts.merge_commit_sha =
                        Some("cccccccccccccccccccccccccccccccccccccccc".into());
                    facts.base_contains_merge_commit = true;
                }
                engine.runner.verified_local_validation = verifier_result;

                assert!(matches!(
                    engine
                        .run_claimed(&Lease {
                            task_id: id,
                            owner: "worker".into(),
                            fencing_token: 1,
                        })
                        .await,
                    Err(EngineError::InvalidOperationResult)
                ));
                let expected_key = operation_key(id, 1, State::Validating, Stage::Validate);
                let db = db.lock().unwrap();
                assert_eq!(db.task.state, State::Merging);
                assert_eq!(db.task.checkpoint, None);
                assert_eq!(db.stop_attempts, 1);
                assert_eq!(db.stopped_operation_keys, vec![expected_key]);
                assert_eq!(db.releases, usize::from(stop_confirmed));
            }
        }
    }

    #[tokio::test]
    async fn complete_handoff_records_completed_only_after_lease_bound_local_proof() {
        let (mut engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Merging;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
            db.task.elapsed = Duration::from_secs(600);
        }
        {
            let mut facts = facts.lock().unwrap();
            facts.pr_merged = true;
            facts.issue_open = false;
            facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
            facts.base_contains_merge_commit = true;
        }
        engine.runner.verified_local_validation = Some(true);
        assert_eq!(
            engine.complete_handoff(id, "handoff-worker").await.unwrap(),
            StepResult::Finished
        );
        assert_eq!(db.lock().unwrap().task.state, State::Completed);
        assert_eq!(engine.runner.verification_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn store_without_handoff_methods_rejects_renewal_deadline_check_and_completion() {
        let (engine, db, id, facts) = fixture();
        let store = DefaultHandoffStore;
        let lease = Lease {
            task_id: id,
            owner: "worker".into(),
            fencing_token: 1,
        };
        let task = db.lock().unwrap().task.clone();
        let policy = &engine.policies.0;
        let facts = facts.lock().unwrap().clone();
        let mut completed = task.clone();
        completed.state = State::Completed;

        assert!(matches!(
            store
                .renew_handoff_verification(&lease, Duration::from_secs(1), &task, policy, &facts,)
                .await,
            Err(StoreError::RecoveryRejected)
        ));
        assert!(matches!(
            store.work_deadline_expired(&lease, &task, policy).await,
            Err(StoreError::RecoveryRejected)
        ));
        assert!(matches!(
            store
                .save_handoff_completed(&lease, &completed, policy, &facts)
                .await,
            Err(StoreError::RecoveryRejected)
        ));
    }

    #[tokio::test]
    async fn expired_unmerged_handoff_waits_without_running_local_work() {
        let (engine, db, id, _) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Merging;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
            db.task.elapsed = Duration::from_secs(600);
        }
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await
                .unwrap(),
            StepResult::WaitingForHuman
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Merging);
        assert_eq!(db.executions, 0);
        assert!(engine.runner.verification_calls.lock().unwrap().is_empty());
        assert_eq!(db.releases, 1);
    }

    #[tokio::test]
    async fn complete_handoff_does_not_persist_completed_without_local_proof() {
        let (mut engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Merging;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        {
            let mut facts = facts.lock().unwrap();
            facts.pr_merged = true;
            facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
            facts.base_contains_merge_commit = true;
        }
        engine.runner.verified_local_validation = None;
        assert!(matches!(
            engine.complete_handoff(id, "handoff-worker").await,
            Err(EngineError::InvalidOperationResult)
        ));
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Merging);
        assert_eq!(db.task.checkpoint, None);
        assert_eq!(db.stop_attempts, 1);
        assert_eq!(db.releases, 1);
    }

    #[tokio::test]
    async fn completed_verifier_failure_releases_only_after_validate_operation_stops() {
        for stop_confirmed in [true, false] {
            let (mut engine, db, id, facts) = fixture();
            {
                let mut db = db.lock().unwrap();
                db.task.state = State::Completed;
                db.task.attempts = 1;
                db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
                db.task.pull_request = Some(7);
                db.task.validation_passed = true;
                db.stop_confirmed = stop_confirmed;
            }
            {
                let mut facts = facts.lock().unwrap();
                facts.pr_merged = true;
                facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
                facts.base_contains_merge_commit = true;
            }
            engine.runner.verified_local_validation = None;
            assert!(matches!(
                engine
                    .run_claimed(&Lease {
                        task_id: id,
                        owner: "worker".into(),
                        fencing_token: 1,
                    })
                    .await,
                Err(EngineError::InvalidOperationResult)
            ));
            let expected_key = operation_key(id, 1, State::Validating, Stage::Validate);
            let db = db.lock().unwrap();
            assert_eq!(db.task.state, State::Completed);
            assert_eq!(db.stop_attempts, 1);
            assert_eq!(db.stopped_operation_keys, vec![expected_key]);
            assert_eq!(db.releases, usize::from(stop_confirmed));
        }
    }

    #[tokio::test]
    async fn operator_policy_bundle_drives_engine_and_rejects_a_changed_task_base() {
        let policy_path =
            std::env::temp_dir().join(format!("mipsorcu-engine-policy-{}.json", Uuid::new_v4()));
        let policy_json = r#"{
            "version": 1,
            "repository": "org/repo",
            "base_branch": "develop",
            "base_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "head_repository": "org/repo",
            "head_ref_prefix": "orchestrator",
            "pull_author": "bot",
            "allowed_assignee": "bot",
            "required_checks": [{"name": "ci", "app_id": 4}],
            "minimum_approvals": 1,
            "validation_check": "ci",
            "limits": {"max_attempts": 3, "max_runtime_seconds": 600, "max_model_tokens": 100}
        }"#;
        std::fs::write(&policy_path, policy_json).unwrap();
        let bundle = PolicyBundle::load(&policy_path).unwrap();
        std::fs::remove_file(&policy_path).unwrap();

        let use_bundle = |engine: TestEngine| Engine {
            store: engine.store,
            policies: bundle.clone(),
            evidence: engine.evidence,
            runner: engine.runner,
            recovery: engine.recovery,
            mock_github: engine.mock_github,
            lease_ttl: engine.lease_ttl,
        };
        let (engine, db, id, _) = fixture();
        let engine = use_bundle(engine);
        assert_eq!(
            engine.run_one(id, "worker").await.unwrap(),
            StepResult::WaitingForHuman
        );
        assert_eq!(db.lock().unwrap().task.state, State::Merging);

        let (engine, db, id, _) = fixture();
        db.lock().unwrap().task.base_sha = "cccccccccccccccccccccccccccccccccccccccc".into();
        let engine = use_bundle(engine);
        assert!(matches!(
            engine.run_one(id, "worker").await,
            Err(EngineError::InvalidTransition(domain::Error::StaleBase))
        ));
        let db = db.lock().unwrap();
        assert_eq!(db.executions, 0);
        assert!(db.ops.is_empty());
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
        let (engine, db, id, facts) = fixture();
        let output = StageOutput {
            assignee: Some("bot".into()),
            implementer: Some("codex".into()),
            reviewer: Some("claude".into()),
            session_id: Some(id.to_string()),
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
        };
        let result_value = serde_json::to_value(&output).unwrap();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Planning;
            db.task.attempts = 1;
            db.task.model_tokens = 1;
            let key = operation_key(id, 1, State::Planning, Stage::Plan);
            db.ops.insert(
                key,
                OperationLookup::Completed {
                    result: result_value.clone(),
                    fencing_token: 1,
                },
            );
        }
        let lease = Lease {
            task_id: id,
            owner: "recovered-worker".into(),
            fencing_token: 2,
        };
        let mut expected_task = test_task(id);
        expected_task.state = State::Planning;
        expected_task.attempts = 1;
        expected_task.model_tokens = 1;
        register_completed_proof(
            &engine.runner,
            &expected_task,
            Stage::Plan,
            &result_value,
            1,
            lease.fencing_token,
            &facts.lock().unwrap(),
        );
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
    async fn nonmock_runner_persists_only_allowlisted_stage_metadata() {
        let (engine, db, id, _) = fixture();
        let stages = Arc::new(Mutex::new(Vec::new()));
        let engine = Engine {
            store: engine.store,
            policies: engine.policies,
            evidence: engine.evidence,
            runner: SensitivePersistRunner {
                stages: stages.clone(),
                supervisor: engine.runner.clone(),
            },
            recovery: engine.recovery,
            mock_github: None,
            lease_ttl: engine.lease_ttl,
        };

        assert_eq!(
            engine.run_one(id, "worker").await.unwrap(),
            StepResult::BlockedStageFailure(StageFailure::Agent(Failure::Unavailable))
        );
        let key = operation_key(id, 0, State::Planning, Stage::Plan);
        let db = db.lock().unwrap();
        let Some(OperationLookup::Completed { result, .. }) = db.ops.get(&key) else {
            panic!("the completed plan operation must be retained");
        };
        let serialized = serde_json::to_string(result).unwrap();
        assert!(result.get("plan").is_none());
        assert!(result.get("code_change").is_none());
        assert_eq!(result["result_type"], "stage_result");
        assert_eq!(result["format_version"], 1);
        assert_eq!(result["stage"], "plan");
        assert_eq!(result["metadata"]["session_id"], id.to_string());
        assert_eq!(result["model_tokens"], 3);
        assert!(!serialized.contains("sk-live-sensitive-canary"));
        assert!(!serialized.contains("/private/workspace/secret-project/implementation.rs"));
        assert_eq!(*stages.lock().unwrap(), vec![Stage::Plan, Stage::Implement]);
    }

    #[tokio::test]
    async fn mock_runner_keeps_the_existing_stage_output_persistence_format() {
        let (engine, db, id, _) = fixture();
        let stages = Arc::new(Mutex::new(Vec::new()));
        let engine = Engine {
            store: engine.store,
            policies: engine.policies,
            evidence: engine.evidence,
            runner: SensitivePersistRunner {
                stages: stages.clone(),
                supervisor: engine.runner.clone(),
            },
            recovery: engine.recovery,
            mock_github: Some(Arc::new(Mutex::new(MockGitHubAdapter::new(
                MockGitHubPolicy::with_agents(
                    vec!["develop".into()],
                    vec!["ci".into()],
                    Provider::Codex,
                    Provider::Claude,
                )
                .unwrap(),
            )))),
            lease_ttl: engine.lease_ttl,
        };
        assert_eq!(
            engine.run_one(id, "worker").await.unwrap(),
            StepResult::BlockedStageFailure(StageFailure::Agent(Failure::Unavailable))
        );
        let key = operation_key(id, 0, State::Planning, Stage::Plan);
        let db = db.lock().unwrap();
        let Some(OperationLookup::Completed { result, .. }) = db.ops.get(&key) else {
            panic!("the completed mock plan operation must be retained");
        };
        assert!(result.get("result_type").is_none());
        assert!(result.get("format_version").is_none());
        assert!(result.get("plan").is_some());
        assert!(result.get("code_change").is_some());
        assert!(result.get("mock_github_journal").is_some());
        assert!(serde_json::from_value::<StageOutput>(result.clone()).is_ok());
        assert_eq!(*stages.lock().unwrap(), vec![Stage::Plan, Stage::Implement]);
    }

    #[tokio::test]
    async fn persisted_stage_receipt_replays_without_reexecuting_its_stage() {
        let (engine, db, id, facts) = fixture();
        let output = StageOutput {
            assignee: Some("bot".into()),
            implementer: Some("codex".into()),
            reviewer: Some("claude".into()),
            session_id: Some(id.to_string()),
            head_sha: None,
            pull_request: None,
            validation_passed: false,
            local_validation_passed: None,
            model_tokens: 3,
            mock_github_journal: None,
            plan: Some(MockPlan {
                requirements: vec!["private plan text".into()],
                steps: vec!["/private/source/path".into()],
            }),
            code_change: None,
        };
        let receipt = persisted_stage_result_v1(Stage::Plan, &output).unwrap();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Planning;
            db.task.model_tokens = 3;
            let key = operation_key(id, 0, State::Planning, Stage::Plan);
            db.ops.insert(
                key,
                OperationLookup::Completed {
                    result: receipt.clone(),
                    fencing_token: 1,
                },
            );
        }
        let mut expected_task = test_task(id);
        expected_task.state = State::Planning;
        expected_task.model_tokens = 3;
        register_completed_proof(
            &engine.runner,
            &expected_task,
            Stage::Plan,
            &receipt,
            1,
            1,
            &facts.lock().unwrap(),
        );
        let stages = Arc::new(Mutex::new(Vec::new()));
        let engine = Engine {
            store: engine.store,
            policies: engine.policies,
            evidence: engine.evidence,
            runner: SensitivePersistRunner {
                stages: stages.clone(),
                supervisor: engine.runner.clone(),
            },
            recovery: engine.recovery,
            mock_github: None,
            lease_ttl: engine.lease_ttl,
        };
        let result = engine
            .run_claimed(&Lease {
                task_id: id,
                owner: "worker".into(),
                fencing_token: 1,
            })
            .await
            .unwrap();
        assert_eq!(
            result,
            StepResult::BlockedStageFailure(StageFailure::Agent(Failure::Unavailable))
        );
        assert_eq!(*stages.lock().unwrap(), vec![Stage::Implement]);
        let db = db.lock().unwrap();
        assert_eq!(
            db.task.model_tokens, 3,
            "receipt replay must not recount usage"
        );
        let expected_session_id = id.to_string();
        assert_eq!(
            db.task.session_id.as_deref(),
            Some(expected_session_id.as_str())
        );
    }

    #[tokio::test]
    async fn completed_replay_rejects_missing_or_forged_independent_receipts() {
        for mismatch in 0..8 {
            let (engine, db, id, facts) = fixture();
            let result = completed_validation_result(true);
            store_completed_validation(&db, id, true);
            let expected_task = expected_completed_validation_task(id);
            register_completed_proof(
                &engine.runner,
                &expected_task,
                Stage::Validate,
                &result,
                1,
                1,
                &facts.lock().unwrap(),
            );
            if mismatch < 7 {
                let mut proofs = engine.runner.completed_proofs.lock().unwrap();
                let proof = proofs.first_mut().unwrap();
                match mismatch {
                    0 => proof.task_id = Uuid::new_v4(),
                    1 => proof.operation_key = Uuid::new_v4(),
                    2 => proof.request_hash[0] ^= 1,
                    3 => proof.result_digest[0] ^= 1,
                    4 => proof.cumulative_model_tokens += 1,
                    5 => proof.facts_digest[0] ^= 1,
                    _ => proof.original_fencing_token = 2,
                }
            } else {
                engine.runner.completed_proofs.lock().unwrap().clear();
            }
            let result = engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await
                .unwrap();
            assert_eq!(
                result,
                StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult),
                "mismatch={mismatch}"
            );
            let db = db.lock().unwrap();
            assert_eq!(db.task.state, State::Blocked, "mismatch={mismatch}");
            assert_eq!(db.executions, 0, "mismatch={mismatch}");
        }
    }

    #[tokio::test]
    async fn completed_replay_timeout_drops_verifier_and_never_reexecutes() {
        let (mut engine, db, id, facts) = fixture();
        store_completed_validation(&db, id, true);
        register_completed_proof(
            &engine.runner,
            &expected_completed_validation_task(id),
            Stage::Validate,
            &completed_validation_result(true),
            1,
            1,
            &facts.lock().unwrap(),
        );
        engine.policies.0.max_runtime = Duration::from_millis(5);
        *engine.runner.completed_verifier_delay.lock().unwrap() = Some(Duration::from_secs(1));
        let result = engine
            .run_claimed(&Lease {
                task_id: id,
                owner: "worker".into(),
                fencing_token: 1,
            })
            .await
            .unwrap();
        assert_eq!(
            result,
            StepResult::BlockedStageFailure(StageFailure::Timeout)
        );
        assert!(
            engine
                .runner
                .completed_verifier_dropped
                .load(Ordering::SeqCst)
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.task.checkpoint, Some(State::Validating));
        assert_eq!(db.executions, 0);
        assert_eq!(db.stop_attempts, 1);
    }

    #[tokio::test]
    async fn completed_replay_rejects_original_fence_newer_than_current_lease() {
        let (engine, db, id, _) = fixture();
        store_completed_validation(&db, id, true);
        let key = operation_key(id, 1, State::Validating, Stage::Validate);
        if let Some(OperationLookup::Completed { fencing_token, .. }) =
            db.lock().unwrap().ops.get_mut(&key)
        {
            *fencing_token = 2;
        } else {
            panic!("completed fixture must exist");
        }
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await
                .unwrap(),
            StepResult::BlockedStageFailure(StageFailure::InvalidInput)
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.executions, 0);
    }

    #[tokio::test]
    async fn malformed_versioned_receipts_fail_closed_without_legacy_fallback() {
        for mutation in 0..5 {
            let (engine, db, id, _) = fixture();
            let output = StageOutput {
                assignee: Some("bot".into()),
                implementer: Some("codex".into()),
                reviewer: Some("claude".into()),
                session_id: Some(id.to_string()),
                head_sha: None,
                pull_request: None,
                validation_passed: false,
                local_validation_passed: None,
                model_tokens: 1,
                mock_github_journal: None,
                plan: Some(MockPlan {
                    requirements: vec!["valid plan".into()],
                    steps: vec!["implement".into()],
                }),
                code_change: None,
            };
            let mut receipt = persisted_stage_result_v1(Stage::Plan, &output).unwrap();
            match mutation {
                0 => receipt["unexpected"] = serde_json::json!("untrusted"),
                1 => receipt["format_version"] = serde_json::json!(2),
                2 => {
                    receipt.as_object_mut().unwrap().remove("format_version");
                }
                3 => receipt["stage"] = serde_json::json!("review"),
                _ => {
                    let object = receipt.as_object_mut().unwrap();
                    object.remove("result_type");
                    object.remove("format_version");
                    object.remove("stage");
                }
            }
            {
                let mut db = db.lock().unwrap();
                db.task.state = State::Planning;
                db.task.model_tokens = 1;
                let key = operation_key(id, 0, State::Planning, Stage::Plan);
                db.ops.insert(
                    key,
                    OperationLookup::Completed {
                        result: receipt,
                        fencing_token: 1,
                    },
                );
            }
            let stages = Arc::new(Mutex::new(Vec::new()));
            let engine = Engine {
                store: engine.store,
                policies: engine.policies,
                evidence: engine.evidence,
                runner: SensitivePersistRunner {
                    stages: stages.clone(),
                    supervisor: engine.runner.clone(),
                },
                recovery: engine.recovery,
                mock_github: None,
                lease_ttl: engine.lease_ttl,
            };
            assert_eq!(
                engine
                    .run_claimed(&Lease {
                        task_id: id,
                        owner: "worker".into(),
                        fencing_token: 1,
                    })
                    .await
                    .unwrap(),
                StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
            );
            assert!(stages.lock().unwrap().is_empty());
            assert_eq!(db.lock().unwrap().task.state, State::Blocked);
        }
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
        let mut expected_task = expected_completed_validation_task(id);
        expected_task.state = State::Reviewing;
        expected_task.validation_passed = true;
        let review = StageOutput {
            assignee: None,
            implementer: None,
            reviewer: None,
            session_id: None,
            head_sha: expected_task.head_sha.clone(),
            pull_request: Some(7),
            validation_passed: true,
            local_validation_passed: None,
            model_tokens: 1,
            mock_github_journal: None,
            plan: None,
            code_change: None,
        };
        let receipt = persisted_stage_result_v1(Stage::Review, &review).unwrap();
        register_completed_proof(
            &engine.runner,
            &expected_task,
            Stage::Review,
            &receipt,
            1,
            3,
            &facts.lock().unwrap(),
        );
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
        let (mut engine, db, id, _) = fixture();
        engine.runner.fail_local_validation_attempt = Some(1);
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
        let calls = engine.runner.repair_verification_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].task_id, id);
        assert_eq!(
            calls[0].head_sha,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(calls[0].attempt, 2);
        assert_eq!(
            calls[0].operation_key,
            operation_key(id, 2, State::Repairing, Stage::Implement)
        );
        assert_eq!(calls[0].fencing_token, 1);
    }

    fn set_repairing_task(db: &Arc<Mutex<MockDb>>) {
        let mut db = db.lock().unwrap();
        db.task.state = State::Repairing;
        db.task.attempts = 1;
        db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
        db.task.pull_request = Some(7);
        db.task.validation_passed = false;
    }

    fn expected_repair_task(id: Uuid) -> TaskRecord {
        let mut task = test_task(id);
        task.state = State::Repairing;
        task.attempts = 1;
        task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
        task.pull_request = Some(7);
        task.model_tokens = 5;
        task
    }

    fn completed_repair_output() -> StageOutput {
        let files = vec!["src/mock_generated.rs".to_owned()];
        let summary = "apply the deterministic mock change";
        StageOutput {
            assignee: None,
            implementer: None,
            reviewer: None,
            session_id: None,
            head_sha: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()),
            pull_request: Some(7),
            validation_passed: false,
            local_validation_passed: None,
            model_tokens: 2,
            mock_github_journal: None,
            plan: None,
            code_change: Some(MockCodeChange {
                summary: summary.into(),
                patch_digest: mock_patch_digest(summary, &files).unwrap(),
                changed_files: files,
            }),
        }
    }

    fn seed_completed_repair(db: &Arc<Mutex<MockDb>>, id: Uuid) -> Uuid {
        let key = operation_key(id, 1, State::Repairing, Stage::Implement);
        let mut db = db.lock().unwrap();
        db.task.model_tokens = 5;
        db.ops.insert(
            key,
            OperationLookup::Completed {
                result: serde_json::to_value(completed_repair_output()).unwrap(),
                fencing_token: 1,
            },
        );
        key
    }

    fn completion_proof_fixture(head_sha: &str, pull_request: Option<u64>) -> RepairProofFixture {
        let output = serde_json::to_value(completed_repair_output()).unwrap();
        RepairProofFixture::Completed {
            head_sha: head_sha.into(),
            pull_request,
            result_digest: repair_result_digest(&output).unwrap(),
            total_model_tokens: 5,
        }
    }

    #[tokio::test]
    async fn independently_proven_completed_repair_replays_without_executing_or_recounting() {
        let (engine, db, id, facts) = fixture();
        set_repairing_task(&db);
        let key = seed_completed_repair(&db, id);
        let expected_task = expected_repair_task(id);
        let output = serde_json::to_value(completed_repair_output()).unwrap();
        register_completed_proof(
            &engine.runner,
            &expected_task,
            Stage::Implement,
            &output,
            1,
            1,
            &facts.lock().unwrap(),
        );
        *engine.runner.repair_proof_fixture.lock().unwrap() =
            completion_proof_fixture("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Some(7));
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await
                .unwrap(),
            StepResult::WaitingForHuman
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Merging);
        assert_eq!(db.executions, 2, "only validation and review execute");
        assert_eq!(db.task.model_tokens, 7, "replayed usage is not added twice");
        assert!(matches!(
            db.ops.get(&key),
            Some(OperationLookup::Completed { .. })
        ));
    }

    #[tokio::test]
    async fn independently_proven_v1_repair_digest_covers_the_persisted_receipt() {
        let (engine, db, id, facts) = fixture();
        set_repairing_task(&db);
        let output = completed_repair_output();
        let receipt = persisted_stage_result_v1(Stage::Implement, &output).unwrap();
        let digest = repair_result_digest(&receipt).unwrap();
        let key = operation_key(id, 1, State::Repairing, Stage::Implement);
        {
            let mut db = db.lock().unwrap();
            db.task.model_tokens = 5;
            db.ops.insert(
                key,
                OperationLookup::Completed {
                    result: receipt.clone(),
                    fencing_token: 1,
                },
            );
        }
        let expected_task = expected_repair_task(id);
        register_completed_proof(
            &engine.runner,
            &expected_task,
            Stage::Implement,
            &receipt,
            1,
            1,
            &facts.lock().unwrap(),
        );
        *engine.runner.repair_proof_fixture.lock().unwrap() = RepairProofFixture::Completed {
            head_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            pull_request: Some(7),
            result_digest: digest,
            total_model_tokens: 5,
        };
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await
                .unwrap(),
            StepResult::WaitingForHuman
        );
        assert!(matches!(
            db.lock().unwrap().ops.get(&key),
            Some(OperationLookup::Completed { result: value, .. }) if value == &receipt
        ));
    }

    #[tokio::test]
    async fn v1_repair_proof_rejects_a_changed_persisted_receipt() {
        let (engine, db, id, facts) = fixture();
        set_repairing_task(&db);
        let receipt =
            persisted_stage_result_v1(Stage::Implement, &completed_repair_output()).unwrap();
        let digest = repair_result_digest(&receipt).unwrap();
        let expected_task = expected_repair_task(id);
        register_completed_proof(
            &engine.runner,
            &expected_task,
            Stage::Implement,
            &receipt,
            1,
            1,
            &facts.lock().unwrap(),
        );
        let mut changed = receipt;
        changed["metadata"]["validation_passed"] = serde_json::json!(true);
        let key = operation_key(id, 1, State::Repairing, Stage::Implement);
        {
            let mut db = db.lock().unwrap();
            db.task.model_tokens = 5;
            db.ops.insert(
                key,
                OperationLookup::Completed {
                    result: changed,
                    fencing_token: 1,
                },
            );
        }
        *engine.runner.repair_proof_fixture.lock().unwrap() = RepairProofFixture::Completed {
            head_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            pull_request: Some(7),
            result_digest: digest,
            total_model_tokens: 5,
        };
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await
                .unwrap(),
            StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
        );
        assert_eq!(db.lock().unwrap().task.state, State::Blocked);
    }

    #[tokio::test]
    async fn completed_repair_needs_matching_independent_proof() {
        for proof in [
            RepairProofFixture::AcceptCurrent,
            RepairProofFixture::Missing,
            completion_proof_fixture("cccccccccccccccccccccccccccccccccccccccc", Some(7)),
            completion_proof_fixture("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Some(8)),
        ] {
            let (engine, db, id, facts) = fixture();
            set_repairing_task(&db);
            seed_completed_repair(&db, id);
            let expected_task = expected_repair_task(id);
            let output = serde_json::to_value(completed_repair_output()).unwrap();
            register_completed_proof(
                &engine.runner,
                &expected_task,
                Stage::Implement,
                &output,
                1,
                1,
                &facts.lock().unwrap(),
            );
            *engine.runner.repair_proof_fixture.lock().unwrap() = proof;
            assert_eq!(
                engine
                    .run_claimed(&Lease {
                        task_id: id,
                        owner: "worker".into(),
                        fencing_token: 1,
                    })
                    .await
                    .unwrap(),
                StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
            );
            let db = db.lock().unwrap();
            assert_eq!(db.task.state, State::Blocked);
            assert_eq!(db.executions, 0);
        }
    }

    #[tokio::test]
    async fn completed_repair_rejects_changed_result_or_usage() {
        for corruption in 0..4 {
            let (engine, db, id, facts) = fixture();
            set_repairing_task(&db);
            let key = seed_completed_repair(&db, id);
            let expected_task = expected_repair_task(id);
            let output = serde_json::to_value(completed_repair_output()).unwrap();
            register_completed_proof(
                &engine.runner,
                &expected_task,
                Stage::Implement,
                &output,
                1,
                1,
                &facts.lock().unwrap(),
            );
            *engine.runner.repair_proof_fixture.lock().unwrap() =
                completion_proof_fixture("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Some(7));
            {
                let mut db = db.lock().unwrap();
                if corruption == 3 {
                    db.task.model_tokens = 6;
                } else if let Some(OperationLookup::Completed { result: value, .. }) =
                    db.ops.get_mut(&key)
                {
                    match corruption {
                        0 => value["model_tokens"] = serde_json::json!(3),
                        1 => value["unexpected"] = serde_json::json!("untrusted"),
                        _ => {
                            let files = vec!["src/mock_generated.rs".to_owned()];
                            let summary = "a different valid change";
                            value["code_change"]["summary"] = serde_json::json!(summary);
                            value["code_change"]["patch_digest"] =
                                serde_json::json!(mock_patch_digest(summary, &files).unwrap());
                        }
                    }
                } else {
                    panic!("completed fixture must exist");
                }
            }
            assert_eq!(
                engine
                    .run_claimed(&Lease {
                        task_id: id,
                        owner: "worker".into(),
                        fencing_token: 1,
                    })
                    .await
                    .unwrap(),
                StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
            );
            let db = db.lock().unwrap();
            assert_eq!(db.task.state, State::Blocked);
            assert_eq!(db.executions, 0);
        }
    }

    #[test]
    fn repair_result_digest_is_bounded_and_independent_of_object_key_order() {
        let first: serde_json::Value =
            serde_json::from_str(r#"{"z":{"b":2,"a":1},"a":true}"#).unwrap();
        let second: serde_json::Value =
            serde_json::from_str(r#"{"a":true,"z":{"a":1,"b":2}}"#).unwrap();
        assert_eq!(repair_result_digest(&first), repair_result_digest(&second));
        assert_ne!(
            repair_result_digest(&first),
            repair_result_digest(&serde_json::json!({"a": true, "z": {"a": 1, "b": 3}}))
        );
        assert!(repair_result_digest(&serde_json::json!([])).is_none());
        assert!(
            repair_result_digest(
                &serde_json::json!({"value": "x".repeat(MAX_REPAIR_RESULT_BYTES)})
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn completion_proof_without_durable_result_never_starts_a_new_repair() {
        let (engine, db, id, _) = fixture();
        set_repairing_task(&db);
        *engine.runner.repair_proof_fixture.lock().unwrap() =
            completion_proof_fixture("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Some(7));
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await
                .unwrap(),
            StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.executions, 0);
        assert!(
            db.ops
                .values()
                .all(|operation| matches!(operation, OperationLookup::Ambiguous))
        );
    }

    #[tokio::test]
    async fn completion_proof_never_reexecutes_an_ambiguous_repair() {
        let (engine, db, id, _) = fixture();
        set_repairing_task(&db);
        let key = operation_key(id, 1, State::Repairing, Stage::Implement);
        db.lock()
            .unwrap()
            .ops
            .insert(key, OperationLookup::Ambiguous);
        *engine.runner.repair_proof_fixture.lock().unwrap() =
            completion_proof_fixture("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Some(7));
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await
                .unwrap(),
            StepResult::BlockedAmbiguousOperation
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.executions, 0);
        assert!(matches!(db.ops.get(&key), Some(OperationLookup::Ambiguous)));
    }

    async fn assert_repair_gate_blocks_without_operation(
        engine: TestEngine,
        db: Arc<Mutex<MockDb>>,
        id: Uuid,
        failure: StageFailure,
    ) {
        let result = engine
            .run_claimed(&Lease {
                task_id: id,
                owner: "worker".into(),
                fencing_token: 1,
            })
            .await
            .unwrap();
        assert_eq!(result, StepResult::BlockedStageFailure(failure));
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.task.checkpoint, Some(State::Repairing));
        assert!(db.ops.is_empty(), "repair operation must not be prepared");
        assert_eq!(db.executions, 0, "repair implementation must not execute");
        assert_eq!(db.stop_attempts, 1);
        assert_eq!(
            db.releases, 1,
            "lease releases only after stop confirmation"
        );
    }

    #[tokio::test]
    async fn restarted_repair_without_independent_feedback_proof_is_blocked() {
        let (engine, db, id, _) = fixture();
        set_repairing_task(&db);
        *engine.runner.repair_proof_fixture.lock().unwrap() = RepairProofFixture::Missing;
        assert_repair_gate_blocks_without_operation(
            engine,
            db,
            id,
            StageFailure::InvalidOperationResult,
        )
        .await;
    }

    #[tokio::test]
    async fn repair_with_stale_head_or_attempt_proof_is_blocked_before_prepare() {
        for stale_proof in [
            RepairProofFixture::Expected {
                task_id: Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
                head_sha: "cccccccccccccccccccccccccccccccccccccccc".into(),
                attempt: 1,
            },
            RepairProofFixture::Expected {
                task_id: Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
                head_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                attempt: 0,
            },
        ] {
            let (engine, db, id, _) = fixture();
            set_repairing_task(&db);
            *engine.runner.repair_proof_fixture.lock().unwrap() = stale_proof;
            assert_repair_gate_blocks_without_operation(
                engine,
                db,
                id,
                StageFailure::InvalidOperationResult,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn repair_verifier_timeout_stops_before_prepare_and_releases_only_when_stopped() {
        let (mut engine, db, id, _) = fixture();
        set_repairing_task(&db);
        engine.policies.0.max_runtime = Duration::from_millis(2);
        *engine.runner.repair_verifier_delay.lock().unwrap() = Some(Duration::from_millis(30));
        assert_repair_gate_blocks_without_operation(engine, db, id, StageFailure::Timeout).await;
    }

    #[tokio::test]
    async fn repair_verifier_stop_failure_keeps_lease_and_never_prepares_operation() {
        let (engine, db, id, _) = fixture();
        set_repairing_task(&db);
        *engine.runner.repair_proof_fixture.lock().unwrap() = RepairProofFixture::Missing;
        db.lock().unwrap().stop_confirmed = false;
        let result = engine
            .run_claimed(&Lease {
                task_id: id,
                owner: "worker".into(),
                fencing_token: 1,
            })
            .await
            .unwrap();
        assert_eq!(
            result,
            StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.task.checkpoint, Some(State::Repairing));
        assert!(db.ops.is_empty());
        assert_eq!(db.executions, 0);
        assert_eq!(db.stop_attempts, 1);
        assert_eq!(
            db.releases, 0,
            "lease remains held when stop is unconfirmed"
        );
    }

    #[tokio::test]
    async fn pending_ci_pauses_without_spending_attempt_and_resumes_from_fresh_evidence() {
        let (mut engine, db, id, facts) = fixture();
        engine.runner.verified_local_validation = Some(true);
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Validating;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
        }
        facts.lock().unwrap().ci.as_mut().unwrap().status = domain::CiStatus::Pending;
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await
                .unwrap(),
            StepResult::WaitingForHuman
        );
        {
            let db = db.lock().unwrap();
            assert_eq!(db.task.state, State::Paused);
            assert_eq!(db.task.checkpoint, Some(State::Validating));
            assert_eq!(db.task.attempts, 1);
            assert_eq!(db.task.pull_request, Some(7));
            assert_eq!(db.executions, 1);
        }

        facts.lock().unwrap().ci.as_mut().unwrap().status = domain::CiStatus::Passed;
        let validation = StageOutput {
            assignee: None,
            implementer: None,
            reviewer: None,
            session_id: None,
            head_sha: None,
            pull_request: Some(7),
            validation_passed: true,
            local_validation_passed: None,
            model_tokens: 1,
            mock_github_journal: None,
            plan: None,
            code_change: None,
        };
        let receipt = persisted_stage_result_v1(Stage::Validate, &validation).unwrap();
        register_completed_proof(
            &engine.runner,
            &expected_completed_validation_task(id),
            Stage::Validate,
            &receipt,
            1,
            3,
            &facts.lock().unwrap(),
        );
        assert_eq!(
            engine.resume(id, "resume-worker").await.unwrap(),
            StepResult::WaitingForHuman
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Merging);
        assert_eq!(db.task.attempts, 1);
        assert_eq!(
            db.executions, 2,
            "the cached validate operation must not rerun"
        );
    }

    #[tokio::test]
    async fn pending_ci_during_review_resumes_without_replaying_review() {
        let (engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Reviewing;
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        facts.lock().unwrap().ci.as_mut().unwrap().status = domain::CiStatus::Pending;
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await
                .unwrap(),
            StepResult::WaitingForHuman
        );
        {
            let db = db.lock().unwrap();
            assert_eq!(db.task.state, State::Paused);
            assert_eq!(db.task.checkpoint, Some(State::Reviewing));
            assert_eq!(db.task.attempts, 1);
            assert_eq!(
                db.executions, 0,
                "review must not start while CI is pending"
            );
        }

        facts.lock().unwrap().ci.as_mut().unwrap().status = domain::CiStatus::Passed;
        assert_eq!(
            engine.resume(id, "resume-worker").await.unwrap(),
            StepResult::WaitingForHuman
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Merging);
        assert_eq!(db.task.attempts, 1);
        assert_eq!(db.executions, 1, "review should run only after CI passes");
    }

    #[tokio::test]
    async fn merged_merging_checkpoint_resumes_after_issue_closes() {
        let (mut engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Paused;
            db.task.checkpoint = Some(State::Merging);
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        {
            let mut facts = facts.lock().unwrap();
            facts.issue_open = false;
            facts.pr_merged = true;
            facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
            facts.base_contains_merge_commit = true;
        }
        engine.runner.verified_local_validation = Some(true);

        assert_eq!(
            engine.resume(id, "resume-worker").await.unwrap(),
            StepResult::Finished
        );
        assert_eq!(db.lock().unwrap().task.state, State::Completed);
        assert_eq!(engine.runner.verification_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn closed_issue_does_not_allow_resume_of_unmerged_merging_checkpoint() {
        let (engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Paused;
            db.task.checkpoint = Some(State::Merging);
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        facts.lock().unwrap().issue_open = false;

        assert!(matches!(
            engine.resume(id, "resume-worker").await,
            Err(EngineError::InvalidTransition(
                domain::Error::IssueUnavailable
            ))
        ));
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Paused);
        assert_eq!(db.task.checkpoint, Some(State::Merging));
        assert_eq!(db.releases, 0);
    }

    #[tokio::test]
    async fn merged_merging_checkpoint_still_rejects_stale_head() {
        let (engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Paused;
            db.task.checkpoint = Some(State::Merging);
            db.task.attempts = 1;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        {
            let mut facts = facts.lock().unwrap();
            facts.issue_open = false;
            facts.pr_merged = true;
            facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".into());
            facts.base_contains_merge_commit = true;
            facts.head_sha = "dddddddddddddddddddddddddddddddddddddddd".into();
            facts.pr_head_sha = Some(facts.head_sha.clone());
            let stale_head = facts.head_sha.clone();
            if let Some(ci) = facts.ci.as_mut() {
                ci.head_sha = stale_head;
            }
        }

        assert!(matches!(
            engine.resume(id, "resume-worker").await,
            Err(EngineError::InvalidTransition(domain::Error::StaleHead))
        ));
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Paused);
        assert_eq!(db.task.checkpoint, Some(State::Merging));
        assert_eq!(db.releases, 0);
    }

    #[tokio::test]
    async fn review_does_not_start_with_ci_for_a_different_head() {
        let (engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Reviewing;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        facts.lock().unwrap().ci.as_mut().unwrap().head_sha = "c".repeat(40);
        let result = engine
            .run_claimed(&Lease {
                task_id: id,
                owner: "worker".into(),
                fencing_token: 1,
            })
            .await;
        assert!(matches!(
            result,
            Err(EngineError::InvalidTransition(domain::Error::StaleHead))
        ));
        assert_eq!(db.lock().unwrap().executions, 0);
    }

    #[tokio::test]
    async fn review_rechecks_ci_identity_immediately_before_starting() {
        struct ChangingEvidence {
            calls: std::sync::atomic::AtomicUsize,
            facts: ObservedFacts,
        }

        impl EvidenceSource for ChangingEvidence {
            async fn observe(
                &self,
                _: &TaskRecord,
                _: &TrustedPolicy,
            ) -> Result<ObservedFacts, ()> {
                let mut facts = self.facts.clone();
                if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
                    facts.ci.as_mut().unwrap().head_sha = "c".repeat(40);
                }
                Ok(facts)
            }
        }

        let (engine, db, id, facts) = fixture();
        {
            let mut db = db.lock().unwrap();
            db.task.state = State::Reviewing;
            db.task.head_sha = Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
            db.task.pull_request = Some(7);
            db.task.validation_passed = true;
        }
        let evidence = ChangingEvidence {
            calls: std::sync::atomic::AtomicUsize::new(0),
            facts: facts.lock().unwrap().clone(),
        };
        let engine = Engine {
            store: engine.store,
            policies: engine.policies,
            evidence,
            runner: engine.runner,
            recovery: engine.recovery,
            mock_github: engine.mock_github,
            lease_ttl: engine.lease_ttl,
        };
        assert_eq!(
            engine
                .run_claimed(&Lease {
                    task_id: id,
                    owner: "worker".into(),
                    fencing_token: 1,
                })
                .await
                .unwrap(),
            StepResult::BlockedStageFailure(StageFailure::InvalidInput)
        );
        assert_eq!(db.lock().unwrap().executions, 0);
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
        drop(db);
        let calls = engine.runner.repair_verification_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].task_id, id);
        assert_eq!(
            calls[0].head_sha,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(calls[0].attempt, 1);
        assert_eq!(
            calls[0].operation_key,
            operation_key(id, 1, State::Repairing, Stage::Implement)
        );
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
            local_validation_passed: None,
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
        let mut invalid_plan_status = plan.clone();
        invalid_plan_status.local_validation_passed = Some(true);
        assert!(!valid_stage_output(Stage::Plan, &invalid_plan_status));
        assert!(!local_validation_passed(Some(false), true));
        assert!(local_validation_passed(Some(true), false));
        assert!(!local_validation_passed(None, false));

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

    #[test]
    fn operation_usage_validation_rejects_only_database_integer_overflow() {
        let (engine, db, _, _) = fixture();
        let task = db.lock().unwrap().task.clone();
        let output = StageOutput {
            assignee: None,
            implementer: None,
            reviewer: None,
            session_id: None,
            head_sha: None,
            pull_request: None,
            validation_passed: false,
            local_validation_passed: None,
            model_tokens: 1,
            mock_github_journal: None,
            plan: Some(MockPlan {
                requirements: vec!["valid plan requirement".into()],
                steps: vec!["valid plan step".into()],
            }),
            code_change: None,
        };
        assert!(operation_usage_fits(&task, &output));
        let mut over_budget = output.clone();
        over_budget.model_tokens = 101;
        assert!(operation_usage_fits(&task, &over_budget));

        let mut at_database_limit = task;
        at_database_limit.model_tokens = i64::MAX as u64;
        assert!(!operation_usage_fits(&at_database_limit, &output));

        let mut above_limit_output = output;
        above_limit_output.model_tokens = i64::MAX as u64 + 1;
        assert!(!valid_stage_output(Stage::Plan, &above_limit_output));
        assert_eq!(engine.policies.0.max_model_tokens, 100);
    }

    #[derive(Clone)]
    struct TimeoutRunner {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        stops: Arc<std::sync::atomic::AtomicUsize>,
        executed: Arc<Mutex<Option<(Uuid, Uuid, i64)>>>,
        stopped: Arc<Mutex<Option<(Uuid, Uuid, i64)>>>,
        cancellation: Arc<Mutex<Option<Cancellation>>>,
        dropped_after_cancel: Arc<std::sync::atomic::AtomicBool>,
        stop_saw_cancel: Arc<std::sync::atomic::AtomicBool>,
        hang_stop: bool,
        succeed: bool,
    }

    impl TimeoutRunner {
        fn new(hang_stop: bool, succeed: bool) -> Self {
            Self {
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                stops: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                executed: Arc::new(Mutex::new(None)),
                stopped: Arc::new(Mutex::new(None)),
                cancellation: Arc::new(Mutex::new(None)),
                dropped_after_cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                stop_saw_cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                hang_stop,
                succeed,
            }
        }
    }

    struct ObserveCancellationOnDrop {
        cancellation: Cancellation,
        observed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for ObserveCancellationOnDrop {
        fn drop(&mut self) {
            self.observed.store(
                self.cancellation.cancelled(),
                std::sync::atomic::Ordering::SeqCst,
            );
        }
    }

    impl StageRunner for TimeoutRunner {
        fn supports_cancellation(&self) -> bool {
            true
        }
        fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError> {
            Ok(())
        }

        fn agent_roles(&self) -> (Provider, Provider) {
            (Provider::Codex, Provider::Claude)
        }

        async fn execute(
            &self,
            lease: &Lease,
            operation_key: Uuid,
            _: Stage,
            _: &TaskRecord,
            _: &TrustedPolicy,
            _: ExecutionBudget,
        ) -> Result<StageOutput, StageFailure> {
            *self.executed.lock().map_err(|_| StageFailure::Internal)? =
                Some((lease.task_id, operation_key, lease.fencing_token));
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.succeed {
                return Ok(StageOutput {
                    assignee: None,
                    implementer: None,
                    reviewer: None,
                    session_id: None,
                    head_sha: None,
                    pull_request: None,
                    validation_passed: false,
                    local_validation_passed: None,
                    model_tokens: 0,
                    mock_github_journal: None,
                    plan: None,
                    code_change: None,
                });
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            Err(StageFailure::InvalidInput)
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
            let _observe = ObserveCancellationOnDrop {
                cancellation: cancellation.clone(),
                observed: self.dropped_after_cancel.clone(),
            };
            *self
                .cancellation
                .lock()
                .map_err(|_| StageFailure::Internal)? = Some(cancellation);
            self.execute(lease, operation_key, stage, task, policy, budget)
                .await
        }

        async fn stop_and_verify(&self, lease: &Lease, operation_key: Uuid) -> Result<(), ()> {
            let cancelled = self
                .cancellation
                .lock()
                .map_err(|_| ())?
                .as_ref()
                .is_some_and(Cancellation::cancelled);
            self.stop_saw_cancel
                .store(cancelled, std::sync::atomic::Ordering::SeqCst);
            *self.stopped.lock().map_err(|_| ())? =
                Some((lease.task_id, operation_key, lease.fencing_token));
            self.stops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.hang_stop {
                std::future::pending::<()>().await;
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn agent_timeout_blocks_and_preserves_the_checkpoint_without_reexecution() {
        let (engine, db, task_id, _) = fixture();
        let runner = TimeoutRunner::new(false, false);
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
        assert!(
            runner
                .stop_saw_cancel
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        assert!(
            runner
                .dropped_after_cancel
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        assert!(
            runner
                .cancellation
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .cancelled()
        );
        let executed = *runner.executed.lock().unwrap();
        let stopped = *runner.stopped.lock().unwrap();
        assert_eq!(executed, stopped);
        let (executed_task, operation_key, fencing_token) = executed.unwrap();
        assert_eq!(executed_task, task_id);
        assert!(fencing_token > 0);
        assert!(db.ops.contains_key(&operation_key));
    }

    #[tokio::test]
    async fn stop_timeout_blocks_without_releasing_the_lease() {
        let (engine, db, task_id, _) = fixture();
        let runner = TimeoutRunner::new(true, false);
        let mut policy = engine.policies.0.clone();
        policy.max_runtime = Duration::from_millis(10);
        let engine = Engine {
            store: engine.store,
            policies: MockPolicy(policy),
            evidence: engine.evidence,
            runner: runner.clone(),
            recovery: engine.recovery,
            mock_github: None,
            lease_ttl: Duration::from_millis(80),
        };
        let result =
            tokio::time::timeout(Duration::from_secs(2), engine.run_one(task_id, "worker"))
                .await
                .expect("stop verification must not wait indefinitely")
                .unwrap();
        assert_eq!(
            result,
            StepResult::BlockedStageFailure(StageFailure::Timeout)
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.releases, 0);
        assert_eq!(runner.stops.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(matches!(
            db.ops.values().next(),
            Some(OperationLookup::Ambiguous)
        ));
    }

    #[tokio::test]
    async fn aborting_engine_keeps_operation_ambiguous_and_does_not_release_lease() {
        let (engine, db, task_id, _) = fixture();
        let runner = TimeoutRunner::new(false, false);
        let engine = Engine {
            store: engine.store,
            policies: engine.policies,
            evidence: engine.evidence,
            runner: runner.clone(),
            recovery: engine.recovery,
            mock_github: None,
            lease_ttl: engine.lease_ttl,
        };
        let task = tokio::spawn(async move { engine.run_one(task_id, "worker").await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while runner.calls.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stage must start before abort");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Planning);
        assert_eq!(db.releases, 0);
        assert_eq!(runner.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(runner.stops.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(
            runner
                .dropped_after_cancel
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        assert!(
            runner
                .cancellation
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .cancelled()
        );
        assert!(matches!(
            db.ops.values().next(),
            Some(OperationLookup::Ambiguous)
        ));
    }

    #[tokio::test]
    async fn completed_stage_does_not_receive_a_cancellation_signal() {
        let (engine, db, task_id, _) = fixture();
        let task = db.lock().unwrap().task.clone();
        let runner = TimeoutRunner::new(false, true);
        let engine = Engine {
            store: engine.store,
            policies: engine.policies,
            evidence: engine.evidence,
            runner: runner.clone(),
            recovery: engine.recovery,
            mock_github: None,
            lease_ttl: engine.lease_ttl,
        };
        let lease = Lease {
            task_id,
            owner: "worker".into(),
            fencing_token: 1,
        };
        let budget = ExecutionBudget {
            remaining_runtime: Duration::from_secs(5),
            remaining_model_tokens: 100,
        };
        assert!(
            engine
                .execute_guarded(
                    Stage::Plan,
                    Uuid::new_v4(),
                    &task,
                    &engine.policies.0,
                    budget,
                    &lease
                )
                .await
                .is_ok()
        );
        assert!(
            !runner
                .cancellation
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .cancelled()
        );
    }

    struct InvalidOutputRunner {
        inject_journal: bool,
    }

    impl StageRunner for InvalidOutputRunner {
        in_memory_cancellation!();
        fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError> {
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
            Ok(StageOutput {
                assignee: Some("bot".into()),
                implementer: Some("codex".into()),
                reviewer: Some("claude".into()),
                session_id: Some("invalid-plan-output".into()),
                head_sha: None,
                pull_request: None,
                validation_passed: false,
                local_validation_passed: None,
                model_tokens: 1,
                mock_github_journal: self
                    .inject_journal
                    .then(|| serde_json::json!({"untrusted": "sensitive-placeholder"})),
                plan: self.inject_journal.then(|| MockPlan {
                    requirements: vec!["test requirement".into()],
                    steps: vec!["test step".into()],
                }),
                code_change: None,
            })
        }

        async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum InvalidPlanField {
        EmptyAssignee,
        EmptyImplementer,
        LongReviewer,
        EmptySession,
        MalformedHead,
        ZeroPullRequest,
        WrongAssignee,
        WrongImplementer,
        MalformedJournal,
    }

    struct InvalidPlanRunner {
        field: InvalidPlanField,
        calls: Arc<std::sync::atomic::AtomicUsize>,
        stops: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl StageRunner for InvalidPlanRunner {
        in_memory_cancellation!();
        fn validate_configuration(&self) -> Result<(), crate::agent::ConfigError> {
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
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut output = StageOutput {
                assignee: Some("bot".into()),
                implementer: Some("codex".into()),
                reviewer: Some("claude".into()),
                session_id: Some("session-1".into()),
                head_sha: None,
                pull_request: None,
                validation_passed: false,
                local_validation_passed: None,
                model_tokens: 1,
                mock_github_journal: None,
                plan: Some(MockPlan {
                    requirements: vec!["valid plan requirement".into()],
                    steps: vec!["valid plan step".into()],
                }),
                code_change: None,
            };
            match self.field {
                InvalidPlanField::EmptyAssignee => output.assignee = Some(" \t".into()),
                InvalidPlanField::EmptyImplementer => output.implementer = Some(String::new()),
                InvalidPlanField::LongReviewer => output.reviewer = Some("r".repeat(256)),
                InvalidPlanField::EmptySession => output.session_id = Some(" ".into()),
                InvalidPlanField::MalformedHead => output.head_sha = Some("not-a-sha".into()),
                InvalidPlanField::ZeroPullRequest => output.pull_request = Some(0),
                InvalidPlanField::WrongAssignee => output.assignee = Some("another-worker".into()),
                InvalidPlanField::WrongImplementer => {
                    output.implementer = Some("deepseek_harness".into());
                }
                InvalidPlanField::MalformedJournal => {
                    output.mock_github_journal = Some(serde_json::json!({"invalid": "shape"}));
                }
            }
            Ok(output)
        }

        async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
            self.stops.fetch_add(1, Ordering::SeqCst);
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
            runner: InvalidOutputRunner {
                inject_journal: false,
            },
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

    #[tokio::test]
    async fn invalid_identity_and_db_fields_are_rejected_before_new_operation_completion() {
        let fields = [
            InvalidPlanField::EmptyAssignee,
            InvalidPlanField::EmptyImplementer,
            InvalidPlanField::LongReviewer,
            InvalidPlanField::EmptySession,
            InvalidPlanField::MalformedHead,
            InvalidPlanField::ZeroPullRequest,
            InvalidPlanField::WrongAssignee,
            InvalidPlanField::WrongImplementer,
            InvalidPlanField::MalformedJournal,
        ];
        for mock_mode in [false, true] {
            for field in fields {
                let (mut engine, db, task_id, _) = fixture();
                if mock_mode {
                    engine.mock_github = Some(Arc::new(Mutex::new(MockGitHubAdapter::new(
                        MockGitHubPolicy::with_agents(
                            vec!["develop".into()],
                            vec!["ci".into()],
                            Provider::Codex,
                            Provider::Claude,
                        )
                        .unwrap(),
                    ))));
                }
                let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let stops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let engine = Engine {
                    store: engine.store,
                    policies: engine.policies,
                    evidence: engine.evidence,
                    runner: InvalidPlanRunner {
                        field,
                        calls: calls.clone(),
                        stops: stops.clone(),
                    },
                    recovery: engine.recovery,
                    mock_github: engine.mock_github,
                    lease_ttl: engine.lease_ttl,
                };

                assert_eq!(
                    engine.run_one(task_id, "worker").await.unwrap(),
                    StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
                );
                let db = db.lock().unwrap();
                assert_eq!(db.task.state, State::Blocked);
                assert_eq!(db.task.checkpoint, Some(State::Planning));
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert_eq!(stops.load(Ordering::SeqCst), 1);
                assert!(
                    db.ops.values().all(|operation| {
                        !matches!(operation, OperationLookup::Completed { .. })
                    })
                );
            }
        }
    }

    #[tokio::test]
    async fn invalid_completed_plan_replay_blocks_without_reexecution() {
        let (engine, db, task_id, _) = fixture();
        let output = StageOutput {
            assignee: Some("bot".into()),
            implementer: Some("invalid-provider".into()),
            reviewer: Some("claude".into()),
            session_id: Some("session-1".into()),
            head_sha: None,
            pull_request: None,
            validation_passed: false,
            local_validation_passed: None,
            model_tokens: 1,
            mock_github_journal: None,
            plan: Some(MockPlan {
                requirements: vec!["valid plan requirement".into()],
                steps: vec!["valid plan step".into()],
            }),
            code_change: None,
        };
        let key = operation_key(task_id, 0, State::Planning, Stage::Plan);
        db.lock().unwrap().ops.insert(
            key,
            OperationLookup::Completed {
                result: serde_json::to_value(output).unwrap(),
                fencing_token: 1,
            },
        );
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let engine = Engine {
            store: engine.store,
            policies: engine.policies,
            evidence: engine.evidence,
            runner: InvalidPlanRunner {
                field: InvalidPlanField::WrongImplementer,
                calls: calls.clone(),
                stops: stops.clone(),
            },
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
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(matches!(
            db.ops.get(&key),
            Some(OperationLookup::Completed { .. })
        ));
    }

    #[tokio::test]
    async fn malformed_mock_journal_completed_replay_blocks_without_reexecution() {
        let (mut engine, db, task_id, _) = fixture();
        engine.mock_github = Some(Arc::new(Mutex::new(MockGitHubAdapter::new(
            MockGitHubPolicy::with_agents(
                vec!["develop".into()],
                vec!["ci".into()],
                Provider::Codex,
                Provider::Claude,
            )
            .unwrap(),
        ))));
        let output = StageOutput {
            assignee: Some("bot".into()),
            implementer: Some("codex".into()),
            reviewer: Some("claude".into()),
            session_id: Some("session-1".into()),
            head_sha: None,
            pull_request: None,
            validation_passed: false,
            local_validation_passed: None,
            model_tokens: 1,
            mock_github_journal: Some(serde_json::json!({"invalid": "shape"})),
            plan: Some(MockPlan {
                requirements: vec!["valid plan requirement".into()],
                steps: vec!["valid plan step".into()],
            }),
            code_change: None,
        };
        let key = operation_key(task_id, 0, State::Planning, Stage::Plan);
        db.lock().unwrap().ops.insert(
            key,
            OperationLookup::Completed {
                result: serde_json::to_value(output).unwrap(),
                fencing_token: 1,
            },
        );
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let engine = Engine {
            store: engine.store,
            policies: engine.policies,
            evidence: engine.evidence,
            runner: InvalidPlanRunner {
                field: InvalidPlanField::MalformedJournal,
                calls: calls.clone(),
                stops: stops.clone(),
            },
            recovery: engine.recovery,
            mock_github: engine.mock_github,
            lease_ttl: engine.lease_ttl,
        };

        assert_eq!(
            engine.run_one(task_id, "worker").await.unwrap(),
            StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        assert!(matches!(
            db.ops.get(&key),
            Some(OperationLookup::Completed { .. })
        ));
    }

    #[tokio::test]
    async fn real_runner_cannot_persist_mock_journal_in_operation_result() {
        let (engine, db, task_id, _) = fixture();
        let engine = Engine {
            store: engine.store,
            policies: engine.policies,
            evidence: engine.evidence,
            runner: InvalidOutputRunner {
                inject_journal: true,
            },
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
        assert!(db.task.mock_github_journal.is_none());
        assert!(
            db.ops
                .values()
                .all(|operation| !matches!(operation, OperationLookup::Completed { .. }))
        );
    }

    #[tokio::test]
    async fn real_runner_rejects_replayed_operation_with_mock_journal() {
        let (engine, db, task_id, _) = fixture();
        let key = operation_key(task_id, 0, State::Planning, Stage::Plan);
        let output = StageOutput {
            assignee: Some("bot".into()),
            implementer: Some("codex".into()),
            reviewer: Some("claude".into()),
            session_id: Some(task_id.to_string()),
            head_sha: None,
            pull_request: None,
            validation_passed: false,
            local_validation_passed: None,
            model_tokens: 0,
            mock_github_journal: Some(serde_json::json!({"untrusted": "placeholder"})),
            plan: Some(MockPlan {
                requirements: vec!["test requirement".into()],
                steps: vec!["test step".into()],
            }),
            code_change: None,
        };
        db.lock().unwrap().ops.insert(
            key,
            OperationLookup::Completed {
                result: serde_json::to_value(output).unwrap(),
                fencing_token: 1,
            },
        );
        assert_eq!(
            engine.run_one(task_id, "worker").await.unwrap(),
            StepResult::BlockedStageFailure(StageFailure::InvalidOperationResult)
        );
        let db = db.lock().unwrap();
        assert_eq!(db.task.state, State::Blocked);
        assert_eq!(db.executions, 0);
        assert!(db.task.mock_github_journal.is_none());
    }

    #[test]
    fn debug_redacts_stage_output_and_operation_result() {
        let marker = "sensitive-placeholder";
        let plan = MockPlan {
            requirements: vec![marker.into()],
            steps: vec![marker.into()],
        };
        let change = MockCodeChange {
            summary: marker.into(),
            changed_files: vec![marker.into()],
            patch_digest: marker.into(),
        };
        let output = StageOutput {
            assignee: Some(marker.into()),
            implementer: None,
            reviewer: None,
            session_id: Some(marker.into()),
            head_sha: None,
            pull_request: None,
            validation_passed: false,
            local_validation_passed: None,
            model_tokens: 0,
            mock_github_journal: Some(serde_json::json!({"value": marker})),
            plan: Some(plan.clone()),
            code_change: Some(change.clone()),
        };
        let operation = OperationLookup::Completed {
            result: serde_json::json!({"value": marker}),
            fencing_token: 1,
        };
        let proof = RepairProof::Completed {
            head_sha: marker.into(),
            pull_request: None,
            result_digest: [0; 32],
            total_model_tokens: 0,
        };
        let (_, db, _, _) = fixture();
        let mut task = db.lock().unwrap().task.clone();
        task.session_id = Some(marker.into());
        task.mock_github_journal = Some(serde_json::json!([{ "value": marker }]));
        let pull = crate::mock_github::MockPullRequest {
            number: 1,
            branch: marker.into(),
            target: marker.into(),
            title: marker.into(),
            head_sha: marker.into(),
            merged: false,
            merge_sha: None,
        };
        let request = MockGitHubRequest::UpsertPullRequest {
            branch: marker.into(),
            target: marker.into(),
            title: marker.into(),
        };
        let result = MockGitHubOutput::PullRequest(pull.clone());
        let entry = MockGitHubJournalEntry {
            idempotency_key: marker.into(),
            request: request.clone(),
            result: Ok(result.clone()),
        };
        for text in [
            format!("{plan:?}"),
            format!("{change:?}"),
            format!("{output:?}"),
            format!("{operation:?}"),
            format!("{proof:?}"),
            format!("{task:?}"),
            format!("{pull:?}"),
            format!("{request:?}"),
            format!("{result:?}"),
            format!("{entry:?}"),
        ] {
            assert!(!text.contains(marker));
            assert!(text.contains("[REDACTED]"));
        }
    }
}

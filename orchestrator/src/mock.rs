//! Local-only demonstration of the real engine with in-memory adapters.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use serde_json::Value;
use uuid::Uuid;

use crate::{
    domain::{self, ObservedFacts, State, TaskRecord, TrustedPolicy},
    engine::{
        Engine, EngineError, EngineStore, EvidenceSource, ExecutionBudget, OperationLookup, Stage,
        StageOutput, StageRunner, StepResult, TrustedPolicySource,
    },
    postgres::{Lease, RecoveryVerifier, StoreError},
};

const TASK_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BASE_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HEAD_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
        _: Uuid,
        _: &str,
        _: Duration,
        _: &TrustedPolicy,
        _: &ObservedFacts,
    ) -> Result<Lease, StoreError> {
        Err(StoreError::HumanActionPending)
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
            Some(OperationLookup::Completed(value)) => {
                Ok(OperationLookup::Completed(value.clone()))
            }
            Some(_) => Ok(OperationLookup::Ambiguous),
            None => {
                db.operations.insert(key, OperationLookup::New);
                Ok(OperationLookup::New)
            }
        }
    }

    async fn complete_operation(
        &self,
        _: &Lease,
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
        db.operations
            .insert(key, OperationLookup::Completed(result.clone()));
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
    async fn observe(&self, _: &TaskRecord, _: &TrustedPolicy) -> Result<ObservedFacts, ()> {
        Ok(self.0.clone())
    }
}

#[derive(Clone)]
struct MemoryRunner(Arc<Mutex<MemoryDb>>);

impl StageRunner for MemoryRunner {
    async fn execute(
        &self,
        stage: Stage,
        _: &TaskRecord,
        _: &TrustedPolicy,
        _: ExecutionBudget,
    ) -> Result<StageOutput, ()> {
        let mut db = self.0.lock().map_err(|_| ())?;
        db.stage_executions += 1;
        if stage == Stage::Plan {
            db.plan_executions += 1;
        }
        Ok(match stage {
            Stage::Plan => StageOutput {
                assignee: Some("mock-worker".into()),
                head_sha: None,
                pull_request: None,
                validation_passed: false,
                model_tokens: 1,
            },
            Stage::Implement => StageOutput {
                assignee: None,
                head_sha: Some(HEAD_SHA.into()),
                pull_request: None,
                validation_passed: false,
                model_tokens: 1,
            },
            Stage::Validate => StageOutput {
                assignee: None,
                head_sha: None,
                pull_request: Some(7),
                validation_passed: true,
                model_tokens: 1,
            },
            Stage::Review => StageOutput {
                assignee: None,
                head_sha: Some(HEAD_SHA.into()),
                pull_request: Some(7),
                validation_passed: true,
                model_tokens: 1,
            },
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
        validated_head_sha: Some(HEAD_SHA.into()),
        pr_number: Some(7),
        pr_head_sha: Some(HEAD_SHA.into()),
        pr_base_ref: Some(policy.base_ref.clone()),
        pr_base_sha: Some(policy.base_sha.clone()),
        pr_merged: false,
        checks_passed: vec!["mock-check".into()],
        reviewer_approved: true,
        approved_assignee: policy.allowed_assignee.clone(),
        merge_commit_sha: None,
        base_contains_merge_commit: false,
    };
    let task = TaskRecord {
        task_id: task_id.to_string(),
        issue_number: 1,
        base_sha: BASE_SHA.into(),
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
    let db = Arc::new(Mutex::new(MemoryDb {
        task,
        operations: HashMap::new(),
        stage_executions: 0,
        plan_executions: 0,
        fail_next_save: true,
        fencing_token: 0,
    }));
    let policy = Arc::new(Mutex::new(policy));
    let engine = Engine {
        store: MemoryStore(db.clone()),
        policies: MemoryPolicy(policy.clone()),
        evidence: MemoryEvidence(facts),
        runner: MemoryRunner(db.clone()),
        recovery: NoRecovery,
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
        .map_err(|_| "mock engine replay failed".to_owned())?;
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
        .map_err(|_| "mock engine resume failed".to_owned())?;
    if resumed != StepResult::WaitingForHuman {
        return Err("mock engine did not stop at the human merge handoff".into());
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
    println!(
        "mock engine resumed: state={:?}, stage executions={executions}",
        final_task.state
    );
    println!("simulation only: no PostgreSQL, GitHub, Git, filesystem write, or model was used");
    Ok(())
}

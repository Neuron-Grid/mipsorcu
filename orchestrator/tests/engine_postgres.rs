use std::{
    env,
    net::IpAddr,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use mipsorcu_orchestrator::{
    domain::{ObservedFacts, State, TaskRecord, TrustedPolicy},
    engine::{
        Engine, EngineError, EngineStore, EvidenceSource, ExecutionBudget, OperationLookup,
        PostgresEngineStore, Stage, StageOutput, StageRunner, TrustedPolicySource,
    },
    postgres::{Lease, NewTask, RecoveryVerifier, StoreError, TaskStore},
};
use tokio_postgres::{Config, NoTls, config::Host};
use uuid::Uuid;

const TEST_DATABASE_URL: &str = "MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL";
const BASE_SHA: &str = "0123456789012345678901234567890123456789";
const STALE_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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

#[derive(Clone, Default)]
struct Runner(Arc<AtomicUsize>);
impl StageRunner for Runner {
    async fn execute(
        &self,
        _: Stage,
        _: &TaskRecord,
        _: &TrustedPolicy,
        _: ExecutionBudget,
    ) -> Result<StageOutput, ()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(())
    }

    async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
        Ok(())
    }
}

struct Supervisor;
impl RecoveryVerifier for Supervisor {
    fn verify_stopped(&self, _: Uuid, _: &str, _: i64) -> Option<serde_json::Value> {
        Some(serde_json::json!({"stopped": true}))
    }
}

struct FailAfterPrepare {
    inner: PostgresEngineStore,
    fired: std::sync::atomic::AtomicBool,
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
        if prepared == OperationLookup::New && !self.fired.swap(true, Ordering::SeqCst) {
            return Err(StoreError::LeaseLost);
        }
        Ok(prepared)
    }

    async fn complete_operation(
        &self,
        lease: &Lease,
        key: Uuid,
        result: &serde_json::Value,
        model_tokens: u64,
    ) -> Result<(), StoreError> {
        self.inner
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
        self.inner.save(lease, expected, task, policy, facts).await
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
        base_ref: "main".into(),
        base_sha: BASE_SHA.into(),
        allowed_assignee: "worker".into(),
        required_checks: vec!["ci".into()],
        max_attempts: 3,
        max_runtime: Duration::from_secs(600),
        max_model_tokens: 100,
    };
    let evidence = ObservedFacts {
        policy_base_ref: "main".into(),
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
        policy_base_ref: "main".into(),
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
        },
        policies: Policy(engine.policies.0.clone()),
        evidence: Evidence(valid_facts.clone()),
        runner: Runner(runner.clone()),
        recovery: Supervisor,
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
        evidence: Evidence(valid_facts),
        runner: Runner(runner.clone()),
        recovery: Supervisor,
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

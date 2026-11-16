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
    agent::{Failure, Provider},
    domain::{ObservedFacts, State, TaskRecord, TrustedPolicy},
    engine::{
        Engine, EngineError, EngineStore, EvidenceSource, ExecutionBudget, OperationLookup,
        PostgresEngineStore, Stage, StageFailure, StageOutput, StageRunner, TrustedPolicySource,
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
    fn validate_configuration(&self) -> Result<(), mipsorcu_orchestrator::agent::ConfigError> {
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
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(StageFailure::Agent(Failure::Unavailable))
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
    failure_point: FailurePoint,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FailurePoint {
    AfterPrepare,
    AfterComplete,
}

#[derive(Clone, Default)]
struct RestoreRunner {
    plan_calls: Arc<AtomicUsize>,
    implement_calls: Arc<AtomicUsize>,
}

#[derive(Clone, Default)]
struct WaitingRunner {
    entered: Arc<AtomicUsize>,
    active: Arc<AtomicBool>,
    stop_calls: Arc<AtomicUsize>,
}

struct ActiveStageGuard(Arc<AtomicBool>);

impl Drop for ActiveStageGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl StageRunner for WaitingRunner {
    fn validate_configuration(&self) -> Result<(), mipsorcu_orchestrator::agent::ConfigError> {
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
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.active.store(true, Ordering::SeqCst);
        let _guard = ActiveStageGuard(self.active.clone());
        std::future::pending().await
    }

    async fn stop_and_verify(&self, _: &Lease, _: Uuid) -> Result<(), ()> {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl StageRunner for RestoreRunner {
    fn validate_configuration(&self) -> Result<(), mipsorcu_orchestrator::agent::ConfigError> {
        Ok(())
    }

    fn agent_roles(&self) -> (Provider, Provider) {
        (Provider::Codex, Provider::Claude)
    }

    async fn execute(
        &self,
        stage: Stage,
        _: &TaskRecord,
        _: &TrustedPolicy,
        _: ExecutionBudget,
    ) -> Result<StageOutput, StageFailure> {
        match stage {
            Stage::Plan => {
                self.plan_calls.fetch_add(1, Ordering::SeqCst);
                Ok(StageOutput {
                    assignee: Some("worker".into()),
                    implementer: Some("codex".into()),
                    reviewer: Some("claude".into()),
                    session_id: Some("session-persisted-plan".into()),
                    head_sha: None,
                    pull_request: None,
                    validation_passed: false,
                    model_tokens: 5,
                    mock_github_journal: None,
                    plan: Some(mipsorcu_orchestrator::engine::MockPlan {
                        requirements: vec!["persist operation output".into()],
                        steps: vec!["execute".into(), "resume".into()],
                    }),
                    code_change: None,
                })
            }
            Stage::Implement => {
                self.implement_calls.fetch_add(1, Ordering::SeqCst);
                Err(StageFailure::Agent(Failure::Unavailable))
            }
            _ => Err(StageFailure::InvalidConfiguration),
        }
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

    async fn complete_operation(
        &self,
        lease: &Lease,
        key: Uuid,
        result: &serde_json::Value,
        model_tokens: u64,
    ) -> Result<(), StoreError> {
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
        evidence: Evidence(valid_facts),
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

    let replay_facts = ObservedFacts {
        policy_base_ref: "main".into(),
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
        Some("session-persisted-plan")
    );
    assert_eq!(restored_task.model_tokens, 5);
    assert_eq!(restore_runner.plan_calls.load(Ordering::SeqCst), 1);
    assert_eq!(restore_runner.implement_calls.load(Ordering::SeqCst), 1);

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
        base_ref: "main".into(),
        base_sha: BASE_SHA.into(),
        allowed_assignee: "worker-connection-loss".into(),
        required_checks: vec!["ci".into()],
        max_attempts: 3,
        max_runtime: Duration::from_secs(600),
        max_model_tokens: 100,
    };
    let connection_loss_facts = ObservedFacts {
        policy_base_ref: "main".into(),
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

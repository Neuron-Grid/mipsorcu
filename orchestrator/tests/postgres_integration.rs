use std::{env, time::Duration};

use mipsorcu_orchestrator::{
    domain::{self, ObservedFacts, State, TaskRecord, TrustedPolicy},
    mock_github::{MockGitHubAdapter, MockGitHubPolicy, MockGitHubRequest},
    postgres::{
        Lease, NewTask, OperationStatus, RecoveryVerifier, StoreError, TaskStore,
        issue_close_operation_key,
    },
};
use tokio_postgres::NoTls;
use uuid::Uuid;

const TEST_DATABASE_URL: &str = "MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL";
const BASE_SHA: &str = "0123456789012345678901234567890123456789";
const MAX_OPERATION_RESULT_BYTES: usize = 8 * 1024 * 1024;
const CRASH_FIXTURE_TASK_ID: Uuid = Uuid::from_u128(0x20261121000100000000000000000001);
const CRASH_FIXTURE_IDEMPOTENCY_KEY: Uuid = Uuid::from_u128(0x20261121000100000000000000000002);
const CRASH_FIXTURE_OPERATION_KEY: Uuid = Uuid::from_u128(0x20261121000100000000000000000003);
const CRASH_FIXTURE_WORKER: &str = "postgres-crash-seed-worker";
const CRASH_FIXTURE_OPERATION: &str = "create_pull_request";
const CRASH_FIXTURE_REQUEST_HASH: [u8; 32] = [0x42; 32];

#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL database; run before postgres_server_crash_recover"]
async fn postgres_server_crash_seed() {
    let database_url = env::var(TEST_DATABASE_URL).unwrap_or_else(|_| {
        panic!("set {TEST_DATABASE_URL} to a fresh local orchestrator_test_* database")
    });
    assert_isolated_loopback_database(&database_url);

    let (bootstrap, connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("connect to isolated disposable database");
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
        .expect("inspect test database schemas")
        .get(0);
    let public_objects: i64 = bootstrap
        .query_one("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','v','m','S','f','p')", &[])
        .await
        .expect("inspect public schema")
        .get(0);
    assert_eq!(
        (orchestrator_schema, public_objects),
        (0, 0),
        "refusing to mutate a database with an existing orchestrator schema or public objects"
    );
    bootstrap
        .batch_execute(include_str!("../migrations/0001_orchestrator.sql"))
        .await
        .expect("apply orchestrator migration to throwaway database");
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

    let (policy, facts) = crash_fixture_policy_and_facts();
    let mut task = new_task(9091, CRASH_FIXTURE_IDEMPOTENCY_KEY);
    task.task_id = CRASH_FIXTURE_TASK_ID;
    let mut store = TaskStore::connect(&database_url)
        .await
        .expect("connect disposable test store");
    assert_eq!(
        store
            .create(&task)
            .await
            .expect("create fixed crash fixture"),
        CRASH_FIXTURE_TASK_ID
    );
    let lease = store
        .claim(
            CRASH_FIXTURE_TASK_ID,
            CRASH_FIXTURE_WORKER,
            Duration::from_secs(3),
            &policy,
            &facts,
        )
        .await
        .expect("claim task before simulated PostgreSQL crash");
    assert_eq!(
        store
            .prepare_operation(
                &lease,
                CRASH_FIXTURE_OPERATION_KEY,
                CRASH_FIXTURE_OPERATION,
                &CRASH_FIXTURE_REQUEST_HASH,
            )
            .await
            .expect("commit operation intent before simulated crash"),
        OperationStatus::NewlyPrepared
    );
    let persisted = bootstrap
        .query_one(
            "SELECT t.status::text, o.result, l.fencing_token FROM orchestrator.tasks t JOIN orchestrator.task_operations o ON o.task_id=t.id JOIN orchestrator.execution_lease l ON l.task_id=t.id WHERE t.id=$1 AND o.operation_key=$2",
            &[&CRASH_FIXTURE_TASK_ID, &CRASH_FIXTURE_OPERATION_KEY],
        )
        .await
        .expect("inspect durable seed rows");
    assert_eq!(persisted.get::<_, String>(0), "planning");
    assert_eq!(
        persisted.get::<_, Option<serde_json::Value>>(1),
        None,
        "external operation remains unresolved"
    );
    assert_eq!(persisted.get::<_, i64>(2), lease.fencing_token);
    drop(store);
}

#[tokio::test]
#[ignore = "requires the same disposable PostgreSQL volume after postgres_server_crash_seed and server restart"]
async fn postgres_server_crash_recover() {
    let database_url = env::var(TEST_DATABASE_URL).unwrap_or_else(|_| {
        panic!("set {TEST_DATABASE_URL} to the restarted local orchestrator_test_* database")
    });
    assert_isolated_loopback_database(&database_url);

    let (bootstrap, connection) = tokio_postgres::connect(&database_url, NoTls)
        .await
        .expect("connect to the same disposable database after restart");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let (policy, facts) = crash_fixture_policy_and_facts();
    let mut store = TaskStore::connect(&database_url)
        .await
        .expect("connect fresh worker after PostgreSQL restart");
    let snapshot = store
        .get(CRASH_FIXTURE_TASK_ID)
        .await
        .expect("read task committed before PostgreSQL crash");
    assert_eq!(snapshot.state, State::Planning);
    let persisted = bootstrap
        .query_one(
            "SELECT o.operation, o.result, octet_length(o.request_hash) FROM orchestrator.task_operations o WHERE o.task_id=$1 AND o.operation_key=$2",
            &[&CRASH_FIXTURE_TASK_ID, &CRASH_FIXTURE_OPERATION_KEY],
        )
        .await
        .expect("read unresolved operation committed before PostgreSQL crash");
    assert_eq!(persisted.get::<_, String>(0), CRASH_FIXTURE_OPERATION);
    assert_eq!(
        persisted.get::<_, Option<serde_json::Value>>(1),
        None,
        "restarted server preserves ambiguity"
    );
    assert_eq!(persisted.get::<_, i32>(2), 32);

    let old_lease = bootstrap
        .query_one(
            "SELECT owner, fencing_token, expires_at <= clock_timestamp() FROM orchestrator.execution_lease WHERE singleton AND task_id=$1",
            &[&CRASH_FIXTURE_TASK_ID],
        )
        .await
        .expect("read expired lease committed before PostgreSQL crash");
    let old_owner: String = old_lease.get(0);
    let old_fencing_token: i64 = old_lease.get(1);
    assert_eq!(old_owner, CRASH_FIXTURE_WORKER);
    let mut expired = old_lease.get::<_, bool>(2);
    for _ in 0..40 {
        if expired {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        expired = bootstrap
            .query_one(
                "SELECT expires_at <= clock_timestamp() FROM orchestrator.execution_lease WHERE singleton AND task_id=$1",
                &[&CRASH_FIXTURE_TASK_ID],
            )
            .await
            .expect("wait for seeded lease expiry")
            .get(0);
    }
    assert!(expired, "seeded lease must expire before recovery");
    let verifier = MockRecoveryVerifier {
        task_id: CRASH_FIXTURE_TASK_ID,
        owner: old_owner,
        fencing_token: old_fencing_token,
    };
    let recovered = store
        .recover(
            CRASH_FIXTURE_TASK_ID,
            "postgres-crash-recovery-worker",
            Duration::from_secs(30),
            &verifier,
            &policy,
            &facts,
        )
        .await
        .expect("recover expired lease after independent test stop confirmation");
    assert!(recovered.fencing_token > old_fencing_token);
    assert!(
        matches!(
            store
                .renew(
                    &Lease {
                        task_id: CRASH_FIXTURE_TASK_ID,
                        owner: CRASH_FIXTURE_WORKER.to_owned(),
                        fencing_token: old_fencing_token,
                    },
                    Duration::from_secs(5),
                )
                .await,
            Err(StoreError::LeaseLost)
        ),
        "the pre-crash fencing generation must stay rejected"
    );
    assert_eq!(
        store
            .prepare_operation(
                &recovered,
                CRASH_FIXTURE_OPERATION_KEY,
                CRASH_FIXTURE_OPERATION,
                &CRASH_FIXTURE_REQUEST_HASH,
            )
            .await
            .expect("inspect the operation after PostgreSQL crash recovery"),
        OperationStatus::Ambiguous,
        "a prepared external operation must never be repeated after restart"
    );
}

#[tokio::test]
#[ignore = "requires a fresh local orchestrator_test_* PostgreSQL database"]
async fn postgres_claim_idempotency_expiry_fencing_and_recovery() {
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
        .expect("inspect test database schemas")
        .get(0);
    let public_objects: i64 = bootstrap
        .query_one("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','v','m','S','f','p')", &[])
        .await.expect("inspect public schema").get(0);
    assert_eq!(
        (orchestrator_schema, public_objects),
        (0, 0),
        "refusing to mutate a database with an existing orchestrator schema or public objects"
    );
    bootstrap
        .batch_execute(include_str!("../migrations/0001_orchestrator.sql"))
        .await
        .expect("apply orchestrator migration to throwaway database");
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

    let policy = TrustedPolicy {
        base_ref: "main".to_owned(),
        base_sha: BASE_SHA.to_owned(),
        allowed_assignee: "worker-a".to_owned(),
        required_checks: vec!["ci".to_owned()],
        max_attempts: 4,
        max_runtime: Duration::from_secs(600),
        max_model_tokens: 100_000,
    };
    let facts = ObservedFacts {
        policy_base_ref: "main".to_owned(),
        policy_base_sha: BASE_SHA.to_owned(),
        issue_open: true,
        base_sha: BASE_SHA.to_owned(),
        ..ObservedFacts::default()
    };
    let idem = Uuid::new_v4();
    let task_a = new_task(101, idem);
    let worker_label = format!("mipsorcu-test-{}", Uuid::new_v4().simple());
    let worker_url = format!("{database_url}?application_name={worker_label}");
    let mut left = TaskStore::connect(&worker_url)
        .await
        .expect("connect first worker");
    let mut right = TaskStore::connect(&worker_url)
        .await
        .expect("connect competing worker");

    let mut fractional_timeout = new_task(107, Uuid::new_v4());
    fractional_timeout.execution_timeout = Duration::from_millis(1_500);
    assert!(matches!(
        left.create(&fractional_timeout).await,
        Err(StoreError::InvalidInput)
    ));
    assert_eq!(
        left.create(&task_a).await.expect("create task"),
        task_a.task_id
    );
    assert_eq!(
        right
            .create(&task_a)
            .await
            .expect("idempotent create replay"),
        task_a.task_id
    );
    let task_a_fingerprint = "a".repeat(64);
    left.bind_mock_runtime_config(task_a.task_id, &task_a_fingerprint)
        .await
        .expect("bind mock runtime fingerprint while queued");
    right
        .bind_mock_runtime_config(task_a.task_id, &task_a_fingerprint)
        .await
        .expect("accept matching fingerprint replay");
    assert_eq!(
        left.get(task_a.task_id)
            .await
            .expect("read persisted mock runtime fingerprint")
            .mock_runtime_fingerprint
            .as_deref(),
        Some(task_a_fingerprint.as_str())
    );
    assert!(matches!(
        left.bind_mock_runtime_config(task_a.task_id, "invalid")
            .await,
        Err(StoreError::InvalidInput)
    ));
    assert!(matches!(
        right
            .bind_mock_runtime_config(task_a.task_id, &"b".repeat(64))
            .await,
        Err(StoreError::OperationConflict)
    ));
    let mut changed_timeout_replay = task_a.clone();
    changed_timeout_replay.execution_timeout = Duration::from_secs(601);
    assert!(matches!(
        right.create(&changed_timeout_replay).await,
        Err(StoreError::OperationConflict)
    ));
    let mut conflicting_replay = task_a.clone();
    conflicting_replay.task_id = Uuid::new_v4();
    conflicting_replay.issue_number = 103;
    assert!(matches!(
        right.create(&conflicting_replay).await,
        Err(StoreError::OperationConflict)
    ));
    let task_b = new_task(102, Uuid::new_v4());
    left.create(&task_b).await.expect("create competing task");
    let task_b_fingerprint = "c".repeat(64);
    left.bind_mock_runtime_config(task_b.task_id, &task_b_fingerprint)
        .await
        .expect("bind second task mock runtime before claim");
    let mut queued_timeout_task = new_task(106, Uuid::new_v4());
    queued_timeout_task.execution_timeout = Duration::from_secs(1);
    left.create(&queued_timeout_task)
        .await
        .expect("create task with short execution timeout");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let queued_deadline_is_unset: bool = bootstrap
        .query_one(
            "SELECT execution_deadline IS NULL AND execution_started_at IS NULL FROM orchestrator.tasks WHERE id = $1",
            &[&queued_timeout_task.task_id],
        )
        .await
        .expect("inspect queued task execution clock")
        .get(0);
    assert!(queued_deadline_is_unset);
    assert_eq!(
        left.get(queued_timeout_task.task_id)
            .await
            .expect("read task before first claim")
            .elapsed,
        Duration::ZERO,
        "queued time must not count toward execution runtime"
    );
    let queued_timeout_lease = left
        .claim(
            queued_timeout_task.task_id,
            "worker-a",
            Duration::from_secs(5),
            &policy,
            &facts,
        )
        .await
        .expect("queue wait must not consume execution timeout");
    let queued_timeout_paused = transition_task(
        &mut left,
        &queued_timeout_lease,
        &policy,
        &facts,
        State::Paused,
        |task| task.checkpoint = Some(State::Planning),
    )
    .await;
    assert_eq!(queued_timeout_paused.state, State::Paused);
    left.release(&queued_timeout_lease)
        .await
        .expect("release queued timeout test task");

    let (left_result, right_result) = tokio::join!(
        left.claim(
            task_a.task_id,
            "worker-process-a",
            Duration::from_secs(1),
            &policy,
            &facts
        ),
        right.claim(
            task_a.task_id,
            "worker-process-b",
            Duration::from_secs(1),
            &policy,
            &facts
        ),
    );
    let lease = match (left_result, right_result) {
        (Ok(lease), Err(StoreError::LeaseOccupied))
        | (Err(StoreError::LeaseOccupied), Ok(lease)) => lease,
        outcomes => panic!("expected exactly one successful competing claim: {outcomes:?}"),
    };
    assert!(matches!(
        right
            .claim(
                task_b.task_id,
                "worker-process-b",
                Duration::from_secs(1),
                &policy,
                &facts
            )
            .await,
        Err(StoreError::LeaseOccupied)
    ));
    left.bind_mock_runtime_config(task_a.task_id, &task_a_fingerprint)
        .await
        .expect("accept matching fingerprint after task claim");
    assert_eq!(
        left.get(task_a.task_id)
            .await
            .expect("read initial repair count")
            .attempts,
        0,
        "claiming a task does not consume a repair"
    );
    let identity_row = bootstrap
        .query_one(
            "SELECT assigned_worker, issue_assignee FROM orchestrator.tasks WHERE id=$1",
            &[&task_a.task_id],
        )
        .await
        .expect("read separate execution and issue identities");
    let identities: (String, Option<String>) = (identity_row.get(0), identity_row.get(1));
    assert_eq!(identities, (lease.owner.clone(), None));
    assert_eq!(
        left.get(task_a.task_id)
            .await
            .expect("read preserved issue assignee")
            .assignee
            .as_deref(),
        None
    );
    let operation_key = Uuid::new_v4();
    let request_hash = [7u8; 32];
    assert_eq!(
        left.prepare_operation(&lease, operation_key, "create_pull_request", &request_hash)
            .await
            .expect("prepare external operation"),
        OperationStatus::NewlyPrepared,
    );
    assert_eq!(
        left.prepare_operation(&lease, operation_key, "create_pull_request", &request_hash)
            .await
            .expect("idempotent operation replay"),
        OperationStatus::Ambiguous,
    );
    assert!(matches!(
        left.prepare_operation(&lease, operation_key, "create_pull_request", &[8u8; 32])
            .await,
        Err(StoreError::OperationConflict)
    ));
    let usage_operation_key = Uuid::new_v4();
    let usage_result = serde_json::json!({"model_tokens": 17, "stage": "plan"});
    left.prepare_operation(&lease, usage_operation_key, "plan", &request_hash)
        .await
        .expect("prepare usage-accounted operation");
    left.complete_operation(&lease, usage_operation_key, &usage_result, 17)
        .await
        .expect("persist result and invocation usage atomically");
    assert_eq!(
        left.get(task_a.task_id)
            .await
            .expect("read usage")
            .model_tokens,
        17
    );

    // Results near the storage limit remain replayable. The SQL-side JSONB
    // text length check is authoritative because its formatting differs from serde_json.
    left.renew(&lease, Duration::from_secs(30))
        .await
        .expect("keep the lease live while testing large results");
    let boundary_key = Uuid::new_v4();
    let boundary_hash = [9u8; 32];
    left.prepare_operation(&lease, boundary_key, "boundary", &boundary_hash)
        .await
        .expect("prepare result below storage limit");
    let boundary_result = serde_json::json!({
        "padding": "x".repeat(MAX_OPERATION_RESULT_BYTES - 32)
    });
    left.complete_operation(&lease, boundary_key, &boundary_result, 1)
        .await
        .expect("persist result below storage limit");
    assert_eq!(
        left.prepare_operation(&lease, boundary_key, "boundary", &boundary_hash)
            .await
            .expect("replay result below storage limit"),
        OperationStatus::Completed {
            result: boundary_result,
            fencing_token: lease.fencing_token,
        },
    );

    let oversized_input_key = Uuid::new_v4();
    let oversized_input_hash = [10u8; 32];
    left.prepare_operation(
        &lease,
        oversized_input_key,
        "oversized_input",
        &oversized_input_hash,
    )
    .await
    .expect("prepare operation for oversized input check");
    let oversized_input = serde_json::json!({
        "padding": "x".repeat(MAX_OPERATION_RESULT_BYTES + 128)
    });
    assert!(matches!(
        left.complete_operation(&lease, oversized_input_key, &oversized_input, 23)
            .await,
        Err(StoreError::InvalidInput)
    ));
    assert_eq!(
        left.get(task_a.task_id)
            .await
            .expect("read usage after rejecting oversized result")
            .model_tokens,
        18,
        "rejected results must not add model usage"
    );
    assert_eq!(
        left.prepare_operation(
            &lease,
            oversized_input_key,
            "oversized_input",
            &oversized_input_hash,
        )
        .await
        .expect("inspect operation after rejecting oversized result"),
        OperationStatus::Ambiguous,
        "rejected result leaves the operation uncompleted"
    );

    let oversized_stored_key = Uuid::new_v4();
    let oversized_stored_hash = [11u8; 32];
    let oversized_stored_fingerprint: String = bootstrap
        .query_one(
            "INSERT INTO orchestrator.task_operations(operation_key,task_id,fencing_token,operation,request_hash,result) VALUES($1,$2,$3,$4,$5,jsonb_build_object('padding', repeat('x',$6))) RETURNING md5(result::text)",
            &[&oversized_stored_key, &task_a.task_id, &lease.fencing_token, &"legacy_oversized", &&oversized_stored_hash[..], &i32::try_from(MAX_OPERATION_RESULT_BYTES + 128).expect("test result size fits PostgreSQL integer")],
        )
        .await
        .expect("seed oversized legacy result in isolated test database")
        .get(0);
    assert!(matches!(
        left.prepare_operation(
            &lease,
            oversized_stored_key,
            "legacy_oversized",
            &oversized_stored_hash,
        )
        .await,
        Err(StoreError::InvalidRecord)
    ));
    let stored_size_row = bootstrap
        .query_one(
            "SELECT octet_length(o.result::text), t.model_usage, md5(o.result::text) FROM orchestrator.task_operations o JOIN orchestrator.tasks t ON t.id=o.task_id WHERE o.operation_key=$1",
            &[&oversized_stored_key],
        )
        .await
        .expect("inspect oversized legacy result without returning its JSON");
    assert!(stored_size_row.get::<_, i32>(0) as usize > MAX_OPERATION_RESULT_BYTES);
    assert_eq!(stored_size_row.get::<_, i64>(1), 18);
    assert_eq!(
        stored_size_row.get::<_, String>(2),
        oversized_stored_fingerprint,
        "rejecting a large legacy result must preserve its stored row"
    );
    assert_eq!(
        left.prepare_operation(&lease, usage_operation_key, "plan", &request_hash)
            .await
            .expect("read completed operation replay"),
        OperationStatus::Completed {
            result: usage_result.clone(),
            fencing_token: lease.fencing_token,
        },
    );
    assert!(matches!(
        left.complete_operation(&lease, usage_operation_key, &usage_result, 17)
            .await,
        Err(StoreError::OperationConflict)
    ));
    assert_eq!(
        left.get(task_a.task_id)
            .await
            .expect("usage remains exact once")
            .model_tokens,
        18
    );

    left.renew(&lease, Duration::from_secs(1))
        .await
        .expect("restore the short lease for the expiry test");
    let bystander = TaskStore::connect(&database_url)
        .await
        .expect("connect an unrelated observer");
    let terminated = bootstrap
        .query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND usename = current_user AND application_name = $1 AND pid <> pg_backend_pid()",
            &[&worker_label],
        )
        .await
        .expect("disconnect workers from the isolated test database");
    assert_eq!(
        terminated.len(),
        2,
        "both worker connections must be tested"
    );
    assert!(terminated.iter().all(|row| row.get::<_, bool>(0)));
    assert!(matches!(
        left.get(task_a.task_id).await,
        Err(StoreError::Database(_))
    ));
    assert!(matches!(
        right.get(task_a.task_id).await,
        Err(StoreError::Database(_))
    ));
    assert_eq!(
        bystander
            .get(task_a.task_id)
            .await
            .expect("unrelated connection remains active")
            .state,
        State::Planning
    );
    drop(bystander);

    drop(left);
    drop(right);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let mut restarted = TaskStore::connect(&database_url)
        .await
        .expect("connect restarted worker");
    assert!(matches!(
        restarted
            .claim(
                task_b.task_id,
                "worker-b",
                Duration::from_secs(5),
                &policy,
                &facts
            )
            .await,
        Err(StoreError::LeaseOccupied)
    ));
    assert!(matches!(
        restarted.renew(&lease, Duration::from_secs(5)).await,
        Err(StoreError::LeaseLost)
    ));
    let snapshot = restarted
        .get(task_a.task_id)
        .await
        .expect("read persisted task after restart");
    assert_eq!(snapshot.state, State::Planning);
    assert!(
        matches!(
            restarted
                .save(&lease, State::Planning, &snapshot, &policy, &facts)
                .await,
            Err(StoreError::LeaseLost)
        ),
        "an expired fencing token must not update persisted task state"
    );

    let verifier = MockRecoveryVerifier {
        task_id: task_a.task_id,
        owner: lease.owner.clone(),
        fencing_token: lease.fencing_token,
    };
    assert!(
        matches!(
            restarted
                .release_expired_blocked_lease(&lease, &verifier)
                .await,
            Err(StoreError::InvalidRecord)
        ),
        "an expired non-BLOCKED task must remain on the normal recovery path"
    );
    let recovered = restarted
        .recover(
            task_a.task_id,
            "worker-b",
            Duration::from_secs(5),
            &verifier,
            &policy,
            &facts,
        )
        .await
        .expect("recover expired execution after supervisor confirmation");
    assert!(recovered.fencing_token > lease.fencing_token);
    assert_eq!(
        restarted
            .prepare_operation(&recovered, usage_operation_key, "plan", &request_hash)
            .await
            .expect("replay completed operation under a new lease"),
        OperationStatus::Completed {
            result: usage_result.clone(),
            fencing_token: lease.fencing_token,
        },
        "completed operation replay must retain the original fence"
    );
    let recovery_evidence: serde_json::Value = bootstrap
        .query_one(
            "SELECT evidence FROM orchestrator.recovery_confirmations WHERE task_id = $1 AND expired_fencing_token = $2 AND confirmed_by = $3",
            &[&task_a.task_id, &lease.fencing_token, &lease.owner],
        )
        .await
        .expect("read sanitized recovery evidence")
        .get(0);
    assert_eq!(
        recovery_evidence,
        serde_json::json!({"supervisor_verified_worker_tree_stopped": true}),
        "verifier details are discarded before writing the recovery row"
    );
    assert!(matches!(
        restarted.renew(&lease, Duration::from_secs(5)).await,
        Err(StoreError::LeaseLost)
    ));
    let recovered_snapshot = restarted
        .get(task_a.task_id)
        .await
        .expect("read task with new fencing generation");
    assert!(
        matches!(
            restarted
                .save(
                    &lease,
                    State::Planning,
                    &recovered_snapshot,
                    &policy,
                    &facts
                )
                .await,
            Err(StoreError::LeaseLost)
        ),
        "the previous fencing generation must stay unable to update after recovery"
    );
    assert_eq!(
        restarted
            .prepare_operation(
                &recovered,
                operation_key,
                "create_pull_request",
                &request_hash
            )
            .await
            .expect("inspect operation after crash recovery"),
        OperationStatus::Ambiguous,
        "a prepared external effect must be reconciled, never repeated after a crash",
    );

    bootstrap
        .execute(
            "UPDATE orchestrator.tasks SET execution_deadline = clock_timestamp() - interval '1 second' WHERE id = $1",
            &[&task_a.task_id],
        )
        .await
        .expect("expire the active task deadline");
    assert!(matches!(
        restarted.renew(&recovered, Duration::from_secs(5)).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        restarted
            .prepare_operation(
                &recovered,
                Uuid::new_v4(),
                "must_not_run_after_deadline",
                &request_hash,
            )
            .await,
        Err(StoreError::InvalidRecord)
    ));

    let failed = transition_task(
        &mut restarted,
        &recovered,
        &policy,
        &facts,
        State::Failed,
        |_| {},
    )
    .await;
    assert_eq!(failed.state, State::Failed);
    restarted
        .release(&recovered)
        .await
        .expect("release stopped failed task");

    let task_c = new_task(103, Uuid::new_v4());
    restarted
        .create(&task_c)
        .await
        .expect("create blocked lease test task");
    let blocked_lease = restarted
        .claim(
            task_c.task_id,
            "blocked-worker",
            Duration::from_secs(1),
            &policy,
            &facts,
        )
        .await
        .expect("claim task for blocked lease test");
    let unresolved_key = Uuid::new_v4();
    let unresolved_hash = [7_u8; 32];
    assert_eq!(
        restarted
            .prepare_operation(
                &blocked_lease,
                unresolved_key,
                "external_write",
                &unresolved_hash
            )
            .await
            .expect("prepare ambiguous operation before stop"),
        OperationStatus::NewlyPrepared
    );
    let blocked = transition_task(
        &mut restarted,
        &blocked_lease,
        &policy,
        &facts,
        State::Blocked,
        |_| {},
    )
    .await;
    assert_eq!(blocked.checkpoint, Some(State::Planning));
    let live_verifier = MockRecoveryVerifier {
        task_id: task_c.task_id,
        owner: blocked_lease.owner.clone(),
        fencing_token: blocked_lease.fencing_token,
    };
    assert!(
        matches!(
            restarted
                .release_expired_blocked_lease(&blocked_lease, &live_verifier)
                .await,
            Err(StoreError::LeaseLost)
        ),
        "a live lease cannot be released even with a stop proof"
    );
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let mut wrong_owner_lease = blocked_lease.clone();
    wrong_owner_lease.owner.push_str("-stale");
    assert!(
        matches!(
            restarted
                .release_expired_blocked_lease(&wrong_owner_lease, &live_verifier)
                .await,
            Err(StoreError::LeaseLost)
        ),
        "the caller must present the exact prior owner"
    );
    let mut wrong_fence_lease = blocked_lease.clone();
    wrong_fence_lease.fencing_token += 1;
    assert!(
        matches!(
            restarted
                .release_expired_blocked_lease(&wrong_fence_lease, &live_verifier)
                .await,
            Err(StoreError::LeaseLost)
        ),
        "the caller must present the exact prior fencing generation"
    );

    let rejecting_verifier = MockRecoveryVerifier {
        task_id: task_c.task_id,
        owner: blocked_lease.owner.clone(),
        fencing_token: blocked_lease.fencing_token + 1,
    };
    assert!(matches!(
        restarted
            .release_expired_blocked_lease(&blocked_lease, &rejecting_verifier)
            .await,
        Err(StoreError::RecoveryRejected)
    ));
    let rejected_confirmation_count: i64 = bootstrap
        .query_one(
            "SELECT count(*) FROM orchestrator.recovery_confirmations WHERE task_id=$1 AND expired_fencing_token=$2",
            &[&task_c.task_id, &blocked_lease.fencing_token],
        )
        .await
        .expect("inspect rejected recovery attempt")
        .get(0);
    assert_eq!(
        rejected_confirmation_count, 0,
        "failed verification must not write confirmation evidence"
    );
    assert!(matches!(
        restarted
            .claim(
                task_b.task_id,
                "must-remain-blocked",
                Duration::from_secs(5),
                &policy,
                &facts
            )
            .await,
        Err(StoreError::LeaseOccupied)
    ));

    let stopped_verifier = MockRecoveryVerifier {
        task_id: task_c.task_id,
        owner: blocked_lease.owner.clone(),
        fencing_token: blocked_lease.fencing_token,
    };
    restarted
        .release_expired_blocked_lease(&blocked_lease, &stopped_verifier)
        .await
        .expect("release only the expired lease after independent stop proof");
    let blocked_after_release = restarted
        .get(task_c.task_id)
        .await
        .expect("read unchanged blocked task");
    assert_eq!(blocked_after_release.state, State::Blocked);
    assert_eq!(blocked_after_release.checkpoint, Some(State::Planning));
    let sanitized_confirmation: serde_json::Value = bootstrap
        .query_one(
            "SELECT evidence FROM orchestrator.recovery_confirmations WHERE task_id=$1 AND expired_fencing_token=$2 AND confirmed_by=$3",
            &[&task_c.task_id, &blocked_lease.fencing_token, &blocked_lease.owner],
        )
        .await
        .expect("inspect successful stop confirmation")
        .get(0);
    assert_eq!(
        sanitized_confirmation,
        serde_json::json!({"supervisor_verified_worker_tree_stopped": true}),
        "only the fixed stop-proof marker is persisted"
    );
    let operation_after_release = bootstrap
        .query_one(
            "SELECT result FROM orchestrator.task_operations WHERE operation_key=$1 AND task_id=$2",
            &[&unresolved_key, &task_c.task_id],
        )
        .await
        .expect("inspect unresolved operation after lease release");
    let operation_result: Option<serde_json::Value> = operation_after_release.get(0);
    assert_eq!(
        operation_result, None,
        "release must not resolve or replay an ambiguous operation"
    );
    let resumed_blocked_lease = restarted
        .claim_resume(
            task_c.task_id,
            "recovery-worker",
            Duration::from_secs(1),
            &policy,
            &facts,
        )
        .await
        .expect("resume the blocked task only through the normal evidence-checked path");
    assert_eq!(
        restarted
            .prepare_operation(
                &resumed_blocked_lease,
                unresolved_key,
                "external_write",
                &unresolved_hash,
            )
            .await
            .expect("inspect unresolved operation after resume"),
        OperationStatus::Ambiguous,
        "resuming the checkpoint must not replay an operation with an unknown outcome"
    );
    let reblocked = transition_task(
        &mut restarted,
        &resumed_blocked_lease,
        &policy,
        &facts,
        State::Blocked,
        |_| {},
    )
    .await;
    assert_eq!(reblocked.checkpoint, Some(State::Planning));
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let resumed_stopped_verifier = MockRecoveryVerifier {
        task_id: task_c.task_id,
        owner: resumed_blocked_lease.owner.clone(),
        fencing_token: resumed_blocked_lease.fencing_token,
    };
    restarted
        .release_expired_blocked_lease(&resumed_blocked_lease, &resumed_stopped_verifier)
        .await
        .expect("release the second expired BLOCKED lease after stop proof");
    let still_blocked = restarted
        .get(task_c.task_id)
        .await
        .expect("read BLOCKED task after the second lease release");
    assert_eq!(still_blocked.state, State::Blocked);
    assert_eq!(still_blocked.checkpoint, Some(State::Planning));
    let task_b_lease = restarted
        .claim(
            task_b.task_id,
            "worker-process-b",
            Duration::from_secs(10),
            &policy,
            &facts,
        )
        .await
        .expect("claim task after blocked lease release");
    assert!(
        task_b_lease.fencing_token > blocked_lease.fencing_token,
        "the next claim must advance beyond the released fencing generation"
    );
    assert!(matches!(
        restarted
            .bind_mock_runtime_config(task_b.task_id, &"d".repeat(64))
            .await,
        Err(StoreError::OperationConflict)
    ));
    let resume_operation = Uuid::new_v4();
    let mut mock_github = MockGitHubAdapter::new(
        MockGitHubPolicy::new(vec!["develop".into()], vec!["ci".into()])
            .expect("valid mock GitHub policy"),
    );
    mock_github
        .execute(
            "session-51-branch",
            MockGitHubRequest::CreateBranch {
                branch: "task-51".into(),
                base_sha: BASE_SHA.into(),
            },
        )
        .expect("create deterministic mock branch");
    let persisted_journal =
        serde_json::to_value(mock_github.journal()).expect("serialize deterministic mock journal");
    let resume_facts = ObservedFacts {
        approved_assignee: "worker-a".into(),
        ..facts.clone()
    };
    let implementing = transition_task(
        &mut restarted,
        &task_b_lease,
        &policy,
        &resume_facts,
        State::Implementing,
        |task| {
            task.assignee = Some("worker-a".into());
            task.implementer = Some("codex".into());
            task.reviewer = Some("claude".into());
            task.session_id = Some("session-51".into());
            task.mock_github_journal = Some(persisted_journal.clone());
        },
    )
    .await;
    assert_eq!(implementing.state, State::Implementing);
    restarted
        .prepare_operation(
            &task_b_lease,
            resume_operation,
            "open_pull_request",
            &request_hash,
        )
        .await
        .expect("persist operation before pause");
    let paused = transition_task(
        &mut restarted,
        &task_b_lease,
        &policy,
        &resume_facts,
        State::Paused,
        |task| task.checkpoint = Some(State::Implementing),
    )
    .await;
    assert_eq!(paused.checkpoint, Some(State::Implementing));
    restarted
        .release(&task_b_lease)
        .await
        .expect("release paused task");
    bootstrap
        .execute(
            "UPDATE orchestrator.tasks SET validation_result=$2 WHERE id=$1",
            &[
                &task_b.task_id,
                &serde_json::json!({
                    "passed": false,
                    "ci_observation": {
                        "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "pull_request": 99,
                        "status": "passed"
                    }
                }),
            ],
        )
        .await
        .expect("seed a historical CI snapshot in the isolated database");
    let resumed_lease = restarted
        .claim_resume(
            task_b.task_id,
            "worker-b",
            Duration::from_secs(10),
            &policy,
            &resume_facts,
        )
        .await
        .expect("resume same persisted task after fresh checks");
    let resumed = restarted
        .get(task_b.task_id)
        .await
        .expect("load resumed task");
    assert_eq!(resumed.state, State::Implementing);
    assert_eq!(
        resumed.attempts, paused.attempts,
        "resume does not consume another attempt"
    );
    assert_eq!(resumed.checkpoint, None);
    assert_eq!(resumed.implementer.as_deref(), Some("codex"));
    assert_eq!(resumed.reviewer.as_deref(), Some("claude"));
    assert_eq!(resumed.session_id.as_deref(), Some("session-51"));
    assert_eq!(resumed.mock_github_journal, Some(persisted_journal));
    assert_eq!(
        restarted
            .get_ci_observation(task_b.task_id)
            .await
            .expect("read CI snapshot after resume with no CI evidence"),
        Some(domain::CiObservation {
            head_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            pull_request: 99,
            status: domain::CiStatus::Passed,
        }),
        "resume preserves historical CI metadata when fresh facts contain no CI observation"
    );
    assert_eq!(
        resumed.mock_runtime_fingerprint.as_deref(),
        Some(task_b_fingerprint.as_str())
    );
    assert!(matches!(
        restarted.renew(&task_b_lease, Duration::from_secs(2)).await,
        Err(StoreError::LeaseLost)
    ));
    assert_eq!(
        restarted
            .prepare_operation(
                &resumed_lease,
                resume_operation,
                "open_pull_request",
                &request_hash
            )
            .await
            .expect("inspect interrupted operation after resume"),
        OperationStatus::Ambiguous,
    );

    let handoff_facts =
        advance_to_merging(&mut restarted, &resumed_lease, &policy, facts.clone(), 51).await;
    assert_eq!(
        restarted
            .get_ci_observation(task_b.task_id)
            .await
            .expect("read CI snapshot persisted by TaskStore::save"),
        Some(domain::CiObservation {
            head_sha: "abcdefabcdefabcdefabcdefabcdefabcdefabcd".into(),
            pull_request: 51,
            status: domain::CiStatus::Passed,
        })
    );
    let task_identities = bootstrap
        .query_one(
            "SELECT assigned_worker, issue_assignee FROM orchestrator.tasks WHERE id=$1",
            &[&task_b.task_id],
        )
        .await
        .expect("read current worker and issue assignee after resume");
    let task_identities: (String, Option<String>) =
        (task_identities.get(0), task_identities.get(1));
    assert_eq!(
        task_identities,
        ("worker-b".into(), Some("worker-a".into()))
    );
    let merging = restarted
        .get(task_b.task_id)
        .await
        .expect("load human handoff");
    assert_eq!(merging.state, State::Merging);
    restarted
        .release(&resumed_lease)
        .await
        .expect("release merge handoff");
    let pending_lease = restarted
        .claim_handoff(
            task_b.task_id,
            "worker-c",
            Duration::from_secs(5),
            &policy,
            &handoff_facts,
        )
        .await
        .expect("claim the unmerged handoff only for verification");
    assert_eq!(
        restarted
            .get(task_b.task_id)
            .await
            .expect("handoff remains durable")
            .state,
        State::Merging
    );
    let mut premature = merging.clone();
    assert!(domain::transition(&mut premature, State::Completed, &policy, &handoff_facts).is_err());
    restarted
        .release(&pending_lease)
        .await
        .expect("release the unmerged handoff");
    let merged_facts = merged_closed_issue_facts(handoff_facts);
    let mut no_fresh_ci = merged_facts.clone();
    no_fresh_ci.ci = None;
    assert!(
        matches!(
            restarted
                .claim_handoff(
                    task_b.task_id,
                    "worker-c",
                    Duration::from_secs(5),
                    &policy,
                    &no_fresh_ci
                )
                .await,
            Err(StoreError::InvalidRecord)
        ),
        "a persisted passed snapshot cannot substitute for fresh CI evidence"
    );
    let mut missing_ancestry = merged_facts.clone();
    missing_ancestry.base_contains_merge_commit = false;
    assert!(
        matches!(
            restarted
                .claim_handoff(
                    task_b.task_id,
                    "worker-c",
                    Duration::from_secs(5),
                    &policy,
                    &missing_ancestry
                )
                .await,
            Err(StoreError::InvalidRecord)
        ),
        "a merged flag without proof that the current base contains its merge commit is insufficient"
    );
    let completion_lease = restarted
        .claim_handoff(
            task_b.task_id,
            "worker-c",
            Duration::from_secs(5),
            &policy,
            &merged_facts,
        )
        .await
        .expect("claim after fresh merge and ancestry evidence");
    let handoff = restarted
        .get(task_b.task_id)
        .await
        .expect("read claimed handoff");
    assert_eq!(handoff.state, State::Merging);
    let mut completed_handoff = handoff.clone();
    domain::transition(
        &mut completed_handoff,
        State::Completed,
        &policy,
        &merged_facts,
    )
    .expect("verify merge evidence before completion");
    restarted
        .save(
            &completion_lease,
            State::Merging,
            &completed_handoff,
            &policy,
            &merged_facts,
        )
        .await
        .expect("persist verified completion under the lease");
    let completed_handoff = restarted
        .get(task_b.task_id)
        .await
        .expect("read persisted completion");
    assert_eq!(completed_handoff.state, State::Completed);
    assert_eq!(
        completed_handoff.base_sha, BASE_SHA,
        "persist the original trusted base snapshot"
    );
    restarted
        .release(&completion_lease)
        .await
        .expect("release completed handoff");

    let task_c = new_task(104, Uuid::new_v4());
    restarted
        .create(&task_c)
        .await
        .expect("create expired merge task");
    let mut close_policy = policy.clone();
    close_policy.base_ref = "develop".to_owned();
    let mut close_facts = facts.clone();
    close_facts.policy_base_ref = close_policy.base_ref.clone();
    close_facts.policy_base_sha = close_policy.base_sha.clone();
    let merge_lease = restarted
        .claim(
            task_c.task_id,
            "worker-a",
            Duration::from_secs(10),
            &close_policy,
            &close_facts,
        )
        .await
        .expect("claim task for expired merge recovery");
    assert!(matches!(
        restarted
            .bind_mock_runtime_config(task_c.task_id, &"e".repeat(64))
            .await,
        Err(StoreError::OperationConflict)
    ));
    let merge_facts =
        advance_to_merging(&mut restarted, &merge_lease, &close_policy, close_facts, 52).await;
    let closed_merged_facts = merged_closed_issue_facts(merge_facts.clone());
    assert_eq!(
        restarted
            .prepare_issue_close(&merge_lease, &close_policy, &closed_merged_facts)
            .await
            .expect("closed Issue without an intent needs no close write"),
        None
    );
    let mut merged_open_facts = closed_merged_facts.clone();
    merged_open_facts.issue_open = true;
    assert_eq!(
        restarted
            .prepare_issue_close(&merge_lease, &close_policy, &merged_open_facts)
            .await
            .expect("prepare the one close attempt under the original active fence"),
        Some(OperationStatus::NewlyPrepared)
    );
    let close_key = issue_close_operation_key(task_c.task_id);
    assert!(matches!(
        restarted
            .prepare_operation(&merge_lease, close_key, "github_issue_close", &[9; 32])
            .await,
        Err(StoreError::InvalidInput)
    ));
    assert!(matches!(
        restarted
            .complete_operation(
                &merge_lease,
                close_key,
                &serde_json::json!({"issue_closed_observed": true}),
                0,
            )
            .await,
        Err(StoreError::OperationConflict)
    ));
    bootstrap
        .execute(
            "UPDATE orchestrator.execution_lease SET expires_at=clock_timestamp() - interval '1 second' WHERE singleton AND task_id=$1 AND owner=$2 AND fencing_token=$3",
            &[&task_c.task_id, &merge_lease.owner, &merge_lease.fencing_token],
        )
        .await
        .expect("expire the original fenced lease after preparing the close intent");
    bootstrap
        .execute(
            "UPDATE orchestrator.tasks SET execution_deadline=clock_timestamp() - interval '1 second' WHERE id=$1",
            &[&task_c.task_id],
        )
        .await
        .expect("expire task work after preparing the close intent");
    let merge_verifier = MockRecoveryVerifier {
        task_id: task_c.task_id,
        owner: "worker-a".to_owned(),
        fencing_token: merge_lease.fencing_token,
    };
    let mut missing_merge_ancestry = closed_merged_facts.clone();
    missing_merge_ancestry.base_contains_merge_commit = false;
    assert!(
        matches!(
            restarted
                .recover(
                    task_c.task_id,
                    "worker-b",
                    Duration::from_secs(5),
                    &merge_verifier,
                    &close_policy,
                    &missing_merge_ancestry,
                )
                .await,
            Err(StoreError::InvalidRecord)
        ),
        "expired merged work is not complete until the current base contains the merge commit"
    );
    let finalized = restarted
        .recover(
            task_c.task_id,
            "worker-b",
            Duration::from_secs(5),
            &merge_verifier,
            &close_policy,
            &closed_merged_facts,
        )
        .await
        .expect("reacquire expired merged handoff despite the closed issue");
    assert!(finalized.fencing_token > merge_lease.fencing_token);
    assert_eq!(
        restarted
            .get(task_c.task_id)
            .await
            .expect("read recovered merge")
            .state,
        State::Merging
    );
    let current = restarted
        .get(task_c.task_id)
        .await
        .expect("read recovered handoff");
    let mut completed = current.clone();
    domain::transition(
        &mut completed,
        State::Completed,
        &close_policy,
        &closed_merged_facts,
    )
    .expect("verify recovered merge evidence");
    bootstrap.execute(
        "UPDATE orchestrator.tasks SET execution_started_at=NULL, execution_deadline=NULL WHERE id=$1",
        &[&task_c.task_id],
    ).await.expect("simulate a missing work deadline");
    assert!(matches!(
        restarted.work_deadline_expired(&finalized).await,
        Err(StoreError::InvalidRecord)
    ));
    bootstrap.execute(
        "UPDATE orchestrator.tasks SET execution_started_at=clock_timestamp() - interval '2 seconds', execution_deadline=clock_timestamp() - interval '1 second' WHERE id=$1",
        &[&task_c.task_id],
    ).await.expect("expire work deadline before handoff verification");
    assert!(matches!(
        restarted
            .prepare_issue_close(&merge_lease, &close_policy, &merged_open_facts)
            .await,
        Err(StoreError::LeaseLost)
    ));
    assert_eq!(
        restarted
            .prepare_issue_close(&finalized, &close_policy, &merged_open_facts)
            .await
            .expect("prepared close remains ambiguous after restart"),
        Some(OperationStatus::Ambiguous)
    );
    let mut advanced_base_facts = merged_open_facts.clone();
    advanced_base_facts.base_sha = "e".repeat(40);
    advanced_base_facts.pr_base_sha = Some("e".repeat(40));
    assert_eq!(
        restarted
            .prepare_issue_close(&finalized, &close_policy, &advanced_base_facts)
            .await
            .expect("a later base tip does not change the original merge identity"),
        Some(OperationStatus::Ambiguous)
    );
    let mut changed_merge_identity = merged_open_facts.clone();
    changed_merge_identity.merge_commit_sha = Some("f".repeat(40));
    assert!(matches!(
        restarted
            .prepare_issue_close(&finalized, &close_policy, &changed_merge_identity)
            .await,
        Err(StoreError::OperationConflict)
    ));
    assert_eq!(
        restarted
            .reconcile_issue_close(&finalized, &close_policy, &merged_open_facts)
            .await
            .expect("open Issue evidence cannot settle the ambiguous close"),
        OperationStatus::Ambiguous
    );
    assert!(matches!(
        restarted
            .reconcile_issue_close(&merge_lease, &close_policy, &closed_merged_facts)
            .await,
        Err(StoreError::LeaseLost)
    ));
    assert_eq!(
        restarted
            .reconcile_issue_close(&finalized, &close_policy, &closed_merged_facts)
            .await
            .expect("fresh closed Issue evidence settles the ambiguous close"),
        OperationStatus::Completed {
            result: serde_json::json!({"issue_closed_observed": true}),
            fencing_token: merge_lease.fencing_token,
        }
    );
    assert!(matches!(
        restarted
            .prepare_issue_close(&finalized, &close_policy, &changed_merge_identity)
            .await,
        Err(StoreError::OperationConflict)
    ));
    assert_eq!(
        restarted
            .prepare_issue_close(&finalized, &close_policy, &merged_open_facts)
            .await
            .expect("reopened Issue cannot be reported as closed"),
        Some(OperationStatus::Ambiguous)
    );
    assert_eq!(
        restarted
            .reconcile_issue_close(&finalized, &close_policy, &merged_open_facts)
            .await
            .expect("fresh open evidence does not replay a prior close observation as success"),
        OperationStatus::Ambiguous
    );
    assert_eq!(
        restarted
            .prepare_issue_close(&finalized, &close_policy, &closed_merged_facts)
            .await
            .expect("closed observation replays without authorizing a second write"),
        Some(OperationStatus::Completed {
            result: serde_json::json!({"issue_closed_observed": true}),
            fencing_token: merge_lease.fencing_token,
        })
    );
    assert_eq!(
        restarted
            .reconcile_issue_close(&finalized, &close_policy, &closed_merged_facts)
            .await
            .expect("reconciliation replays its stored closed observation after a crash"),
        OperationStatus::Completed {
            result: serde_json::json!({"issue_closed_observed": true}),
            fencing_token: merge_lease.fencing_token,
        }
    );
    bootstrap
        .execute(
            "UPDATE orchestrator.task_operations SET result=$2 WHERE operation_key=$1",
            &[&close_key, &serde_json::json!({"issue_closed": true})],
        )
        .await
        .expect("corrupt only the disposable close result fixture");
    assert!(matches!(
        restarted
            .reconcile_issue_close(&finalized, &close_policy, &closed_merged_facts)
            .await,
        Err(StoreError::InvalidRecord)
    ));
    let mut stale_head = closed_merged_facts.clone();
    stale_head.head_sha = "f".repeat(40);
    assert!(matches!(
        restarted
            .reconcile_issue_close(&finalized, &close_policy, &stale_head)
            .await,
        Err(StoreError::InvalidRecord)
    ));
    assert!(matches!(
        restarted
            .renew_handoff_verification(
                &merge_lease,
                Duration::from_secs(5),
                &close_policy,
                &closed_merged_facts,
            )
            .await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        restarted
            .save_handoff_completed(
                &merge_lease,
                &completed,
                &close_policy,
                &closed_merged_facts
            )
            .await,
        Err(StoreError::LeaseLost)
    ));
    let mut open_merged_facts = closed_merged_facts.clone();
    open_merged_facts.issue_open = true;
    assert!(matches!(
        restarted
            .save_handoff_completed(&finalized, &completed, &close_policy, &open_merged_facts)
            .await,
        Err(StoreError::InvalidRecord)
    ));
    assert!(matches!(
        restarted.renew(&finalized, Duration::from_secs(5)).await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        restarted
            .renew_handoff_verification(
                &finalized,
                Duration::from_secs(5),
                &close_policy,
                &missing_merge_ancestry,
            )
            .await,
        Err(StoreError::InvalidRecord)
    ));
    restarted
        .renew_handoff_verification(
            &finalized,
            Duration::from_secs(5),
            &close_policy,
            &closed_merged_facts,
        )
        .await
        .expect("renew only for independently validated merged handoff evidence");
    assert!(matches!(
        restarted
            .prepare_operation(&finalized, Uuid::new_v4(), "plan", &[7; 32],)
            .await,
        Err(StoreError::InvalidRecord)
    ));
    assert!(matches!(
        restarted
            .save(
                &finalized,
                State::Merging,
                &completed,
                &close_policy,
                &closed_merged_facts,
            )
            .await,
        Err(StoreError::InvalidRecord)
    ));
    restarted
        .save_handoff_completed(&finalized, &completed, &close_policy, &closed_merged_facts)
        .await
        .expect("persist only the verified terminal handoff after the work deadline");
    assert_eq!(
        restarted
            .get(task_c.task_id)
            .await
            .expect("read completion")
            .state,
        State::Completed
    );
    assert!(matches!(
        restarted.renew(&merge_lease, Duration::from_secs(5)).await,
        Err(StoreError::LeaseLost)
    ));
    restarted
        .release(&finalized)
        .await
        .expect("release recovered completed task");

    let task_d = new_task(105, Uuid::new_v4());
    restarted
        .create(&task_d)
        .await
        .expect("create model budget boundary task");
    let budget_lease = restarted
        .claim(
            task_d.task_id,
            "worker-a",
            Duration::from_secs(10),
            &policy,
            &facts,
        )
        .await
        .expect("claim model budget boundary task");
    let repair_facts = ObservedFacts {
        approved_assignee: "worker-a".into(),
        ..facts.clone()
    };
    transition_task(
        &mut restarted,
        &budget_lease,
        &policy,
        &repair_facts,
        State::Implementing,
        |task| task.assignee = Some("worker-a".into()),
    )
    .await;
    let repaired = transition_task(
        &mut restarted,
        &budget_lease,
        &policy,
        &repair_facts,
        State::Repairing,
        |task| task.attempts += 1,
    )
    .await;
    assert_eq!(
        repaired.attempts, 1,
        "repairing increments the repair counter"
    );
    assert_eq!(
        restarted
            .get(task_d.task_id)
            .await
            .expect("read persisted repair count")
            .attempts,
        1,
        "the repair count survives a database reload"
    );
    let overage_key = Uuid::new_v4();
    let overage_result = serde_json::json!({"model_tokens": 100_001, "stage": "plan"});
    restarted
        .prepare_operation(&budget_lease, overage_key, "plan", &request_hash)
        .await
        .expect("prepare over-budget model invocation");
    restarted
        .complete_operation(&budget_lease, overage_key, &overage_result, 100_001)
        .await
        .expect("record full over-budget invocation before the engine stops");
    assert_eq!(
        restarted
            .get(task_d.task_id)
            .await
            .expect("read persisted overage")
            .model_tokens,
        100_001,
        "the single call that crosses the budget is retained in usage"
    );
    assert_eq!(
        restarted
            .prepare_operation(&budget_lease, overage_key, "plan", &request_hash)
            .await
            .expect("read over-budget completed operation"),
        OperationStatus::Completed {
            result: overage_result,
            fencing_token: budget_lease.fencing_token,
        },
    );
    assert_eq!(
        restarted
            .get(task_d.task_id)
            .await
            .expect("verify overage was not counted twice")
            .model_tokens,
        100_001
    );
    let current = restarted
        .get(task_d.task_id)
        .await
        .expect("read repair task");
    let mut pause_candidate = current.clone();
    domain::transition_from(
        &current,
        &mut pause_candidate,
        State::Paused,
        &policy,
        &repair_facts,
    )
    .expect("construct a valid pause before corrupting the record");
    bootstrap
        .execute(
            "UPDATE orchestrator.tasks SET validation_result=$2 WHERE id=$1",
            &[
                &task_d.task_id,
                &serde_json::json!({
                    "passed": false,
                    "ci_observation": {
                        "head_sha": "abcdefabcdefabcdefabcdefabcdefabcdefabcd",
                        "pull_request": 105,
                        "status": "passed",
                        "raw_log": "must not be exposed"
                    }
                }),
            ],
        )
        .await
        .expect("seed malformed CI metadata in the isolated database");
    assert!(
        matches!(
            restarted.get_ci_observation(task_d.task_id).await,
            Err(StoreError::InvalidRecord)
        ),
        "unknown fields are rejected without returning raw JSON"
    );
    assert!(matches!(
        restarted
            .save(
                &budget_lease,
                State::Repairing,
                &pause_candidate,
                &policy,
                &repair_facts
            )
            .await,
        Err(StoreError::InvalidRecord)
    ));
    let oversized_validation = serde_json::json!({"passed": false, "opaque": "x".repeat(17_000)});
    bootstrap
        .execute(
            "UPDATE orchestrator.tasks SET validation_result=$2 WHERE id=$1",
            &[&task_d.task_id, &oversized_validation],
        )
        .await
        .expect("seed oversized metadata in the isolated database");
    assert!(
        matches!(
            restarted.get_ci_observation(task_d.task_id).await,
            Err(StoreError::InvalidRecord)
        ),
        "oversized metadata is rejected before decoding JSONB into the application"
    );
    assert!(matches!(
        restarted
            .save(
                &budget_lease,
                State::Repairing,
                &pause_candidate,
                &policy,
                &repair_facts
            )
            .await,
        Err(StoreError::InvalidRecord)
    ));
    bootstrap
        .execute(
            "UPDATE orchestrator.tasks SET validation_result=$2 WHERE id=$1",
            &[&task_d.task_id, &serde_json::json!({"passed": false})],
        )
        .await
        .expect("restore the isolated fixture after corruption checks");
    let mut mismatched_ci = repair_facts.clone();
    mismatched_ci.ci = Some(domain::CiObservation {
        head_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        pull_request: 105,
        status: domain::CiStatus::Passed,
    });
    let mut mismatched_candidate = restarted
        .get(task_d.task_id)
        .await
        .expect("load task before rejecting mismatched CI");
    mismatched_candidate.state = State::Paused;
    mismatched_candidate.checkpoint = Some(State::Repairing);
    assert!(
        matches!(
            restarted
                .save(
                    &budget_lease,
                    State::Repairing,
                    &mismatched_candidate,
                    &policy,
                    &mismatched_ci,
                )
                .await,
            Err(StoreError::InvalidRecord)
        ),
        "CI evidence for another head or PR fails closed before persistence"
    );
    let paused_overage = transition_task(
        &mut restarted,
        &budget_lease,
        &policy,
        &repair_facts,
        State::Paused,
        |task| task.checkpoint = Some(State::Repairing),
    )
    .await;
    assert_eq!(paused_overage.model_tokens, 100_001);
    restarted
        .release(&budget_lease)
        .await
        .expect("release over-budget paused task");

    let mut mock_github = MockGitHubAdapter::new(
        MockGitHubPolicy::new(vec!["develop".into()], vec!["ci".into()])
            .expect("valid mock GitHub policy"),
    );
    mock_github
        .execute(
            "strict-journal-branch",
            MockGitHubRequest::CreateBranch {
                branch: "strict-journal-work".into(),
                base_sha: BASE_SHA.into(),
            },
        )
        .expect("create mock journal entry");
    let mut unknown_journal = serde_json::to_value(mock_github.journal())
        .expect("serialize mock journal for isolated recovery check");
    unknown_journal[0]["unexpected"] = serde_json::json!("opaque");
    bootstrap
        .execute(
            "UPDATE orchestrator.tasks SET mock_github_journal=$2 WHERE id=$1",
            &[&task_d.task_id, &unknown_journal],
        )
        .await
        .expect("seed an unknown journal field in the isolated database");
    assert!(matches!(
        restarted.get(task_d.task_id).await,
        Err(StoreError::InvalidRecord)
    ));
    let persisted_unknown_journal: serde_json::Value = bootstrap
        .query_one(
            "SELECT mock_github_journal FROM orchestrator.tasks WHERE id=$1",
            &[&task_d.task_id],
        )
        .await
        .expect("read seeded journal after recovery rejection")
        .get(0);
    assert_eq!(
        persisted_unknown_journal, unknown_journal,
        "recovery rejects malformed journal without deleting or rewriting it"
    );
}

async fn transition_task(
    store: &mut TaskStore,
    lease: &Lease,
    policy: &TrustedPolicy,
    facts: &ObservedFacts,
    to: State,
    mutate: impl FnOnce(&mut TaskRecord),
) -> TaskRecord {
    let current = store
        .get(lease.task_id)
        .await
        .expect("load task before transition");
    let mut proposed = current.clone();
    proposed.state = to;
    mutate(&mut proposed);
    domain::transition_from(&current, &mut proposed, to, policy, facts).unwrap_or_else(|error| {
        panic!(
            "construct state transition from fresh evidence: {:?} -> {:?}, repairs={}, assignee={:?}, head={:?}, PR={:?}, validation={}, checkpoint={:?}: {error:?}",
            current.state,
            to,
            current.attempts,
            current.assignee,
            current.head_sha,
            current.pull_request,
            current.validation_passed,
            current.checkpoint,
        )
    });
    store
        .save(lease, current.state, &proposed, policy, facts)
        .await
        .expect("persist state transition with current lease");
    proposed
}

async fn advance_to_merging(
    store: &mut TaskStore,
    lease: &Lease,
    policy: &TrustedPolicy,
    mut facts: ObservedFacts,
    pull_request: u64,
) -> ObservedFacts {
    facts.approved_assignee = "worker-a".to_owned();
    let current = store
        .get(lease.task_id)
        .await
        .expect("read task before preparing merge stages");
    if current.state == State::Planning {
        transition_task(store, lease, policy, &facts, State::Implementing, |task| {
            task.assignee = Some("worker-a".to_owned());
        })
        .await;
    } else {
        assert_eq!(current.state, State::Implementing);
        assert_eq!(current.assignee.as_deref(), Some("worker-a"));
    }

    let head_sha = "abcdefabcdefabcdefabcdefabcdefabcdefabcd";
    facts.head_sha = head_sha.to_owned();
    transition_task(store, lease, policy, &facts, State::Validating, |task| {
        task.head_sha = Some(head_sha.to_owned());
    })
    .await;

    facts.validated_head_sha = Some(head_sha.to_owned());
    facts.pr_number = Some(pull_request);
    facts.pr_head_sha = Some(head_sha.to_owned());
    facts.pr_base_ref = Some(policy.base_ref.clone());
    facts.pr_base_sha = Some(BASE_SHA.to_owned());
    facts.ci = Some(domain::CiObservation {
        head_sha: head_sha.to_owned(),
        pull_request,
        status: domain::CiStatus::Passed,
    });
    transition_task(store, lease, policy, &facts, State::Reviewing, |task| {
        task.pull_request = Some(pull_request);
        task.validation_passed = true;
    })
    .await;

    facts.checks_passed = vec!["ci".to_owned()];
    facts.reviewer_approved = true;
    transition_task(store, lease, policy, &facts, State::Merging, |_| {}).await;
    facts
}

fn merged_closed_issue_facts(mut facts: ObservedFacts) -> ObservedFacts {
    facts.issue_open = false;
    facts.pr_merged = true;
    facts.base_sha = "dddddddddddddddddddddddddddddddddddddddd".to_owned();
    facts.merge_commit_sha = Some("cccccccccccccccccccccccccccccccccccccccc".to_owned());
    facts.base_contains_merge_commit = true;
    facts
}

struct MockRecoveryVerifier {
    task_id: Uuid,
    owner: String,
    fencing_token: i64,
}

impl RecoveryVerifier for MockRecoveryVerifier {
    fn verify_stopped(
        &self,
        task_id: Uuid,
        old_owner: &str,
        expired_fencing_token: i64,
    ) -> Option<serde_json::Value> {
        (task_id == self.task_id
            && old_owner == self.owner
            && expired_fencing_token == self.fencing_token)
            .then(|| serde_json::json!({"test_verifier_detail": "discard this value"}))
    }
}

fn new_task(issue_number: i64, idempotency_key: Uuid) -> NewTask {
    NewTask {
        task_id: Uuid::new_v4(),
        repository: "owner/repo".to_owned(),
        issue_number,
        base_sha: BASE_SHA.to_owned(),
        max_attempts: 4,
        execution_timeout: Duration::from_secs(600),
        model_budget: 100_000,
        idempotency_key,
    }
}

fn crash_fixture_policy_and_facts() -> (TrustedPolicy, ObservedFacts) {
    let policy = TrustedPolicy {
        base_ref: "main".to_owned(),
        base_sha: BASE_SHA.to_owned(),
        allowed_assignee: "worker-a".to_owned(),
        required_checks: vec!["ci".to_owned()],
        max_attempts: 4,
        max_runtime: Duration::from_secs(600),
        max_model_tokens: 100_000,
    };
    let facts = ObservedFacts {
        policy_base_ref: "main".to_owned(),
        policy_base_sha: BASE_SHA.to_owned(),
        issue_open: true,
        base_sha: BASE_SHA.to_owned(),
        ..ObservedFacts::default()
    };
    (policy, facts)
}

fn assert_isolated_loopback_database(url: &str) {
    let Some(rest) = url
        .strip_prefix("postgres://")
        .or_else(|| url.strip_prefix("postgresql://"))
    else {
        panic!("{TEST_DATABASE_URL} must use a postgres:// or postgresql:// URL");
    };
    assert!(
        !rest.contains(['?', '#']),
        "query and fragment are not allowed in test URL"
    );
    let (authority, database) = rest
        .split_once('/')
        .expect("test URL must include a database name");
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    assert!(
        is_loopback_host(host_port),
        "integration tests require a loopback PostgreSQL host"
    );
    assert!(
        database.starts_with("orchestrator_test_") && !database.contains('%'),
        "integration tests require a dedicated orchestrator_test_* database"
    );
}

fn is_loopback_host(host_port: &str) -> bool {
    ["localhost", "127.0.0.1", "[::1]"].iter().any(|host| {
        host_port == *host
            || host_port
                .strip_prefix(&format!("{host}:"))
                .and_then(|port| port.parse::<u16>().ok())
                .is_some_and(|port| port != 0)
    })
}

use std::{env, time::Duration};

use mipsorcu_orchestrator::{
    domain::{self, ObservedFacts, State, TaskRecord, TrustedPolicy},
    mock_github::{MockGitHubAdapter, MockGitHubPolicy, MockGitHubRequest},
    postgres::{Lease, NewTask, OperationStatus, RecoveryVerifier, StoreError, TaskStore},
};
use tokio_postgres::NoTls;
use uuid::Uuid;

const TEST_DATABASE_URL: &str = "MIPSORCU_ORCHESTRATOR_TEST_DATABASE_URL";
const BASE_SHA: &str = "0123456789012345678901234567890123456789";

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
    let mut left = TaskStore::connect(&database_url)
        .await
        .expect("connect first worker");
    let mut right = TaskStore::connect(&database_url)
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
    assert_eq!(
        left.prepare_operation(&lease, usage_operation_key, "plan", &request_hash)
            .await
            .expect("read completed operation replay"),
        OperationStatus::Completed(usage_result.clone()),
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
        17
    );

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

    let task_b_lease = restarted
        .claim(
            task_b.task_id,
            "worker-process-b",
            Duration::from_secs(10),
            &policy,
            &facts,
        )
        .await
        .expect("claim task for checkpoint resume");
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
    assert!(
        matches!(
            restarted
                .claim_handoff(
                    task_b.task_id,
                    "worker-c",
                    Duration::from_secs(5),
                    &policy,
                    &handoff_facts
                )
                .await,
            Err(StoreError::HumanActionPending)
        ),
        "an unmerged PR must remain a human handoff"
    );
    assert_eq!(
        restarted
            .get(task_b.task_id)
            .await
            .expect("handoff remains durable")
            .state,
        State::Merging
    );
    let merged_facts = merged_closed_issue_facts(handoff_facts);
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
        .expect("complete only after fresh merge and ancestry evidence");
    let completed_handoff = restarted
        .get(task_b.task_id)
        .await
        .expect("read completed handoff");
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
    let merge_lease = restarted
        .claim(
            task_c.task_id,
            "worker-a",
            Duration::from_secs(1),
            &policy,
            &facts,
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
        advance_to_merging(&mut restarted, &merge_lease, &policy, facts.clone(), 52).await;
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let closed_merged_facts = merged_closed_issue_facts(merge_facts);
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
                    &policy,
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
            &policy,
            &closed_merged_facts,
        )
        .await
        .expect("expired merged handoff completes despite the closed issue");
    assert!(finalized.fencing_token > merge_lease.fencing_token);
    assert_eq!(
        restarted
            .get(task_c.task_id)
            .await
            .expect("read recovered merge")
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
        OperationStatus::Completed(overage_result),
    );
    assert_eq!(
        restarted
            .get(task_d.task_id)
            .await
            .expect("verify overage was not counted twice")
            .model_tokens,
        100_001
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
    facts.pr_base_ref = Some("main".to_owned());
    facts.pr_base_sha = Some(BASE_SHA.to_owned());
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
            .then(|| serde_json::json!({"worker_stopped": true, "descendants_stopped": true}))
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

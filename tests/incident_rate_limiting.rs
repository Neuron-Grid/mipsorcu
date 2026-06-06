use std::sync::{Arc, Mutex};
use std::time::Duration;

use mipsorcu::{
    AuditAction, AuditAppendError, AuditEvent, AuditEventAppender, AuditRecorder, ComponentName,
    DummyNotificationSink, FailingNotificationSink, IncidentCategory, IncidentDispatchOutcome,
    IncidentDispatcher, IncidentId, IncidentNotification, IncidentNotifier, IncidentRetryPolicy,
    IncidentSeverity, IncidentSummary, LocalAuditFallbackStore, SourceEventAt,
};

#[derive(Clone, Default)]
struct RecordingAuditAppender {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl RecordingAuditAppender {
    fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl AuditEventAppender for RecordingAuditAppender {
    async fn append_audit_event<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> Result<(), AuditAppendError> {
        let mut guard =
            self.events
                .lock()
                .map_err(|_| AuditAppendError::ExternalDependencyFailed {
                    code: "test_lock_poisoned",
                })?;
        guard.push(event.clone());
        Ok(())
    }
}

fn timestamp(value: &str) -> SourceEventAt {
    SourceEventAt::parse(value).expect("test timestamp must be valid")
}

fn notification(incident_id: &str, severity: IncidentSeverity) -> IncidentNotification {
    notification_for(
        incident_id,
        IncidentCategory::SchedulerFailure,
        severity,
        vec![ComponentName::scheduler()],
        "scheduler job failed three consecutive times",
    )
}

fn notification_for(
    incident_id: &str,
    category: IncidentCategory,
    severity: IncidentSeverity,
    affected_components: Vec<ComponentName>,
    summary: &str,
) -> IncidentNotification {
    IncidentNotification::new(
        IncidentId::parse(incident_id).unwrap(),
        timestamp("2026-06-01T02:00:00Z"),
        category,
        severity,
        IncidentSummary::new(summary).unwrap(),
        affected_components,
        timestamp("2026-06-01T02:00:00Z"),
    )
    .unwrap()
}

fn dispatcher<N>(
    sink: Arc<N>,
    appender: RecordingAuditAppender,
    window: Duration,
) -> IncidentDispatcher<N, RecordingAuditAppender>
where
    N: IncidentNotifier,
{
    let fallback_path = std::env::temp_dir().join(format!(
        "mipsorcu-incident-rate-limit-{}.jsonl",
        std::process::id()
    ));
    let audit_recorder = Arc::new(AuditRecorder::new(
        appender,
        LocalAuditFallbackStore::new(fallback_path),
    ));
    IncidentDispatcher::new(sink, audit_recorder)
        .with_rate_limit_window(window)
        .with_retry_policy(IncidentRetryPolicy {
            max_attempts: 1,
            initial_backoff: Duration::ZERO,
            max_total_backoff: Duration::ZERO,
        })
}

#[tokio::test]
async fn non_critical_incidents_are_rate_limited_and_audited() {
    let sink = Arc::new(DummyNotificationSink::new());
    let appender = RecordingAuditAppender::default();
    let dispatcher = dispatcher(sink.clone(), appender.clone(), Duration::from_secs(300));

    let first = notification(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        IncidentSeverity::High,
    );
    let second = notification(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        IncidentSeverity::High,
    );

    assert_eq!(
        dispatcher.dispatch(first).await,
        IncidentDispatchOutcome::Sent
    );
    assert_eq!(
        dispatcher.dispatch(second).await,
        IncidentDispatchOutcome::Suppressed
    );

    assert_eq!(sink.notification_count(), 1);
    let actions = appender
        .events()
        .into_iter()
        .map(|event| event.action())
        .collect::<Vec<_>>();
    assert_eq!(
        actions,
        vec![
            AuditAction::IncidentNotificationSent,
            AuditAction::IncidentNotificationSuppressed,
        ]
    );
}

#[tokio::test]
async fn critical_incidents_bypass_rate_limit() {
    let sink = Arc::new(DummyNotificationSink::new());
    let appender = RecordingAuditAppender::default();
    let dispatcher = dispatcher(sink.clone(), appender, Duration::from_secs(300));

    let first = notification(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        IncidentSeverity::Critical,
    );
    let second = notification(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        IncidentSeverity::Critical,
    );

    assert_eq!(
        dispatcher.dispatch(first).await,
        IncidentDispatchOutcome::Sent
    );
    assert_eq!(
        dispatcher.dispatch(second).await,
        IncidentDispatchOutcome::Sent
    );
    assert_eq!(sink.notification_count(), 2);
}

#[tokio::test]
async fn aggregate_notification_is_sent_after_window_expires() {
    let sink = Arc::new(DummyNotificationSink::new());
    let appender = RecordingAuditAppender::default();
    let dispatcher = dispatcher(sink.clone(), appender.clone(), Duration::from_millis(1));

    let first = notification(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        IncidentSeverity::High,
    );
    let second = notification(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        IncidentSeverity::High,
    );

    assert_eq!(
        dispatcher.dispatch(first).await,
        IncidentDispatchOutcome::Sent
    );
    assert_eq!(
        dispatcher.dispatch(second).await,
        IncidentDispatchOutcome::Suppressed
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
    dispatcher.flush_due_aggregates().await;

    assert_eq!(sink.notification_count(), 2);
    let actions = appender
        .events()
        .into_iter()
        .map(|event| event.action())
        .collect::<Vec<_>>();
    assert_eq!(
        actions,
        vec![
            AuditAction::IncidentNotificationSent,
            AuditAction::IncidentNotificationSuppressed,
            AuditAction::IncidentNotificationSent,
        ]
    );
}

#[tokio::test]
async fn due_aggregate_is_not_sent_twice() {
    let sink = Arc::new(DummyNotificationSink::new());
    let appender = RecordingAuditAppender::default();
    let dispatcher = dispatcher(sink.clone(), appender.clone(), Duration::from_millis(1));

    assert_eq!(
        dispatcher
            .dispatch(notification(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                IncidentSeverity::High
            ))
            .await,
        IncidentDispatchOutcome::Sent
    );
    assert_eq!(
        dispatcher
            .dispatch(notification(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                IncidentSeverity::High
            ))
            .await,
        IncidentDispatchOutcome::Suppressed
    );

    tokio::time::sleep(Duration::from_millis(5)).await;
    dispatcher.flush_due_aggregates().await;
    dispatcher.flush_due_aggregates().await;

    assert_eq!(sink.notification_count(), 2);
    let actions = appender
        .events()
        .into_iter()
        .map(|event| event.action())
        .collect::<Vec<_>>();
    assert_eq!(
        actions,
        vec![
            AuditAction::IncidentNotificationSent,
            AuditAction::IncidentNotificationSuppressed,
            AuditAction::IncidentNotificationSent,
        ]
    );
}

#[tokio::test]
async fn independent_rate_limit_keys_emit_independent_aggregates() {
    let sink = Arc::new(DummyNotificationSink::new());
    let appender = RecordingAuditAppender::default();
    let dispatcher = dispatcher(sink.clone(), appender.clone(), Duration::from_millis(1));

    let scheduler_first = notification_for(
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        IncidentCategory::SchedulerFailure,
        IncidentSeverity::High,
        vec![ComponentName::scheduler()],
        "scheduler job failed three consecutive times",
    );
    let scheduler_second = notification_for(
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        IncidentCategory::SchedulerFailure,
        IncidentSeverity::High,
        vec![ComponentName::scheduler()],
        "scheduler job failed three consecutive times",
    );
    let archive_first = notification_for(
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        IncidentCategory::ArchiveFailurePersistent,
        IncidentSeverity::High,
        vec![ComponentName::archive()],
        "archive export failed for more than twenty four hours",
    );
    let archive_second = notification_for(
        "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        IncidentCategory::ArchiveFailurePersistent,
        IncidentSeverity::High,
        vec![ComponentName::archive()],
        "archive export failed for more than twenty four hours",
    );

    assert_eq!(
        dispatcher.dispatch(scheduler_first).await,
        IncidentDispatchOutcome::Sent
    );
    assert_eq!(
        dispatcher.dispatch(scheduler_second).await,
        IncidentDispatchOutcome::Suppressed
    );
    assert_eq!(
        dispatcher.dispatch(archive_first).await,
        IncidentDispatchOutcome::Sent
    );
    assert_eq!(
        dispatcher.dispatch(archive_second).await,
        IncidentDispatchOutcome::Suppressed
    );

    tokio::time::sleep(Duration::from_millis(5)).await;
    dispatcher.flush_due_aggregates().await;

    assert_eq!(sink.notification_count(), 4);
    let aggregate_summaries = sink
        .notifications()
        .into_iter()
        .filter_map(|notification| {
            let summary = notification.summary.as_str().to_owned();
            summary.starts_with("suppressed ").then_some(summary)
        })
        .collect::<Vec<_>>();
    assert_eq!(aggregate_summaries.len(), 2);
    assert!(
        aggregate_summaries
            .iter()
            .any(|summary| summary.contains("scheduler_failure"))
    );
    assert!(
        aggregate_summaries
            .iter()
            .any(|summary| summary.contains("archive_failure_persistent"))
    );

    let actions = appender
        .events()
        .into_iter()
        .map(|event| event.action())
        .collect::<Vec<_>>();
    assert_eq!(
        actions
            .iter()
            .filter(|action| **action == AuditAction::IncidentNotificationSent)
            .count(),
        4
    );
    assert_eq!(
        actions
            .iter()
            .filter(|action| **action == AuditAction::IncidentNotificationSuppressed)
            .count(),
        2
    );
}

#[tokio::test]
async fn expired_window_without_suppression_does_not_emit_aggregate() {
    let sink = Arc::new(DummyNotificationSink::new());
    let appender = RecordingAuditAppender::default();
    let dispatcher = dispatcher(sink.clone(), appender.clone(), Duration::from_millis(1));

    assert_eq!(
        dispatcher
            .dispatch(notification(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                IncidentSeverity::High
            ))
            .await,
        IncidentDispatchOutcome::Sent
    );
    tokio::time::sleep(Duration::from_millis(5)).await;

    dispatcher.flush_due_aggregates().await;

    assert_eq!(sink.notification_count(), 1);
    let actions = appender
        .events()
        .into_iter()
        .map(|event| event.action())
        .collect::<Vec<_>>();
    assert_eq!(actions, vec![AuditAction::IncidentNotificationSent]);
}

#[tokio::test]
async fn aggregate_notification_preserves_context_and_suppressed_count() {
    let sink = Arc::new(DummyNotificationSink::new());
    let appender = RecordingAuditAppender::default();
    let dispatcher = dispatcher(sink.clone(), appender, Duration::from_millis(1));

    assert_eq!(
        dispatcher
            .dispatch(notification(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                IncidentSeverity::Medium
            ))
            .await,
        IncidentDispatchOutcome::Sent
    );
    assert_eq!(
        dispatcher
            .dispatch(notification(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                IncidentSeverity::Medium
            ))
            .await,
        IncidentDispatchOutcome::Suppressed
    );
    assert_eq!(
        dispatcher
            .dispatch(notification(
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                IncidentSeverity::Medium
            ))
            .await,
        IncidentDispatchOutcome::Suppressed
    );

    tokio::time::sleep(Duration::from_millis(5)).await;
    dispatcher.flush_due_aggregates().await;

    let notifications = sink.notifications();
    assert_eq!(notifications.len(), 2);
    let aggregate = notifications
        .iter()
        .find(|notification| notification.summary.as_str().starts_with("suppressed "))
        .expect("aggregate notification should be sent");
    assert_eq!(aggregate.category, IncidentCategory::SchedulerFailure);
    assert_eq!(aggregate.severity, IncidentSeverity::Medium);
    assert_eq!(
        aggregate
            .affected_components
            .iter()
            .map(ComponentName::as_str)
            .collect::<Vec<_>>(),
        vec!["scheduler"]
    );
    assert_eq!(
        aggregate.summary.as_str(),
        "suppressed 2 incident notifications for scheduler_failure"
    );
}

#[tokio::test]
async fn failed_aggregate_is_audited_once_and_not_retried_by_later_flushes() {
    let sink = Arc::new(FailingNotificationSink::new("test_notifier_failed"));
    let appender = RecordingAuditAppender::default();
    let dispatcher = dispatcher(sink, appender.clone(), Duration::from_millis(1));

    assert_eq!(
        dispatcher
            .dispatch(notification(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                IncidentSeverity::High
            ))
            .await,
        IncidentDispatchOutcome::Failed
    );
    assert_eq!(
        dispatcher
            .dispatch(notification(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                IncidentSeverity::High
            ))
            .await,
        IncidentDispatchOutcome::Suppressed
    );

    tokio::time::sleep(Duration::from_millis(5)).await;
    dispatcher.flush_due_aggregates().await;
    dispatcher.flush_due_aggregates().await;

    let actions = appender
        .events()
        .into_iter()
        .map(|event| event.action())
        .collect::<Vec<_>>();
    assert_eq!(
        actions
            .iter()
            .filter(|action| **action == AuditAction::IncidentNotificationFailed)
            .count(),
        2
    );
    assert_eq!(
        actions
            .iter()
            .filter(|action| **action == AuditAction::IncidentNotificationSuppressed)
            .count(),
        1
    );
}

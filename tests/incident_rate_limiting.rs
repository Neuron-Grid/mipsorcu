use std::sync::{Arc, Mutex};
use std::time::Duration;

use mipsorcu::{
    AuditAction, AuditAppendError, AuditEvent, AuditEventAppender, AuditRecorder, ComponentName,
    DummyNotificationSink, IncidentCategory, IncidentDispatchOutcome, IncidentDispatcher,
    IncidentId, IncidentNotification, IncidentRetryPolicy, IncidentSeverity, IncidentSummary,
    LocalAuditFallbackStore, SourceEventAt,
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
    IncidentNotification::new(
        IncidentId::parse(incident_id).unwrap(),
        timestamp("2026-06-01T02:00:00Z"),
        IncidentCategory::SchedulerFailure,
        severity,
        IncidentSummary::new("scheduler job failed three consecutive times").unwrap(),
        vec![ComponentName::scheduler()],
        timestamp("2026-06-01T02:00:00Z"),
    )
    .unwrap()
}

fn dispatcher(
    sink: Arc<DummyNotificationSink>,
    appender: RecordingAuditAppender,
    window: Duration,
) -> IncidentDispatcher<DummyNotificationSink, RecordingAuditAppender> {
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

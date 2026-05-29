use super::*;
use crate::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditResult, AuthFailureMetadata,
    RequestId,
};

fn build_auth_failure_event() -> AuditEvent {
    let metadata = AuthFailureMetadata::new("authorization_header_missing")
        .build()
        .unwrap()
        .with_current_source_event_at()
        .unwrap();
    AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::generate().unwrap(),
        request_id: RequestId::nil(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::AuthFailure,
        target_secret_id: None,
        result: AuditResult::Failure,
        key_version: None,
        metadata_json: metadata,
    })
    .unwrap()
}

#[tokio::test]
async fn in_memory_sink_stores_events_in_order() {
    let sink = InMemorySiemSink::new();
    let event_a = SiemEvent::from_audit_event(&build_auth_failure_event());
    let event_b = SiemEvent::from_audit_event(&build_auth_failure_event());

    sink.send_event(&event_a).await.unwrap();
    sink.send_event(&event_b).await.unwrap();

    let stored = sink.events();
    assert_eq!(stored.len(), 2);
    assert_eq!(stored[0].event_id(), event_a.event_id());
    assert_eq!(stored[1].event_id(), event_b.event_id());
}

#[tokio::test]
async fn in_memory_sink_is_shared_via_clone() {
    let sink = InMemorySiemSink::new();
    let clone = sink.clone();
    let event = SiemEvent::from_audit_event(&build_auth_failure_event());
    clone.send_event(&event).await.unwrap();
    assert_eq!(sink.event_count(), 1);
}

#[tokio::test]
async fn failing_sink_returns_backend_failed_with_code() {
    let sink = FailingSiemSink::new("simulated_outage");
    let event = SiemEvent::from_audit_event(&build_auth_failure_event());
    let error = sink
        .send_event(&event)
        .await
        .expect_err("must return error");
    match error {
        SiemSinkError::BackendFailed { code } => assert_eq!(code, "simulated_outage"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn in_memory_sink_debug_does_not_expose_event_contents() {
    let sink = InMemorySiemSink::new();
    let debug_string = format!("{sink:?}");
    assert!(debug_string.contains("event_count"));
    assert!(!debug_string.contains("metadata"));
}

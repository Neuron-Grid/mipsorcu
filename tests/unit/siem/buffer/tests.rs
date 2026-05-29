use super::*;
use crate::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditResult, AuthFailureMetadata,
    RequestId,
};

fn build_event() -> SiemEvent {
    let metadata = AuthFailureMetadata::new("authorization_header_missing")
        .build()
        .unwrap()
        .with_current_source_event_at()
        .unwrap();
    let audit_event = AuditEvent::new(AuditEventParts {
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
    .unwrap();
    SiemEvent::from_audit_event(&audit_event)
}

fn tempfile_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "mipsorcu-siem-buffer-{}-{}.jsonl",
        name,
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    path
}

#[test]
fn pending_events_empty_when_file_missing() {
    let path = tempfile_path("missing");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let events = buffer.pending_events().unwrap();
    assert!(events.is_empty());
}

#[test]
fn append_pending_then_pending_events_returns_event() {
    let path = tempfile_path("append");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let event = build_event();
    buffer.append_pending(&event).unwrap();
    let pending = buffer.pending_events().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event_id(), event.event_id());
    let _ = fs::remove_file(&path);
}

#[test]
fn mark_sent_removes_event_from_pending() {
    let path = tempfile_path("sent");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let event = build_event();
    buffer.append_pending(&event).unwrap();
    buffer.mark_sent(&event).unwrap();
    let pending = buffer.pending_events().unwrap();
    assert!(pending.is_empty(), "mark_sent should clear pending");
    let _ = fs::remove_file(&path);
}

#[test]
fn duplicate_append_pending_is_idempotent_at_pending_count() {
    let path = tempfile_path("dup");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let event = build_event();
    buffer.append_pending(&event).unwrap();
    buffer.append_pending(&event).unwrap();
    let pending = buffer.pending_events().unwrap();
    assert_eq!(
        pending.len(),
        1,
        "same event_id must collapse to one pending"
    );
    let _ = fs::remove_file(&path);
}

#[test]
fn clone_shares_underlying_file() {
    let path = tempfile_path("clone");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let clone = buffer.clone();
    let event = build_event();
    clone.append_pending(&event).unwrap();
    let pending = buffer.pending_events().unwrap();
    assert_eq!(pending.len(), 1);
    let _ = fs::remove_file(&path);
}

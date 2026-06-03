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
        "mipsorcu-siem-buffer-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    path.join("siem-buffer-current.jsonl")
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

#[test]
fn append_rotates_current_file_and_pending_batch_replays_rotated_plus_current() {
    let path = tempfile_path("rotate");
    let buffer = LocalSiemFallbackBuffer::with_config(&path, 1);
    let first = build_event();
    let second = build_event();

    buffer.append_pending(&first).unwrap();
    buffer.append_pending(&second).unwrap();

    let parent = path.parent().expect("buffer path has parent");
    let rotated = rotated_files(parent);
    assert_eq!(rotated.len(), 1, "second append should rotate current file");
    let pending = buffer.pending_batch(100).unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].event_id(), first.event_id());
    assert_eq!(pending[1].event_id(), second.event_id());
    assert_eq!(buffer.pending_batch(1).unwrap().len(), 1);
    assert_eq!(buffer.remaining_bytes().unwrap(), 0);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&rotated[0]).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "rotated SIEM buffer file must be 0600");
    }
}

#[test]
fn mark_sent_in_current_file_overrides_pending_record_in_rotated_file() {
    let path = tempfile_path("rotate_sent");
    let buffer = LocalSiemFallbackBuffer::with_config(&path, 1);
    let first = build_event();
    let second = build_event();

    buffer.append_pending(&first).unwrap();
    buffer.append_pending(&second).unwrap();
    buffer.mark_sent(&first).unwrap();

    let pending = buffer.pending_batch(100).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event_id(), second.event_id());
}

fn rotated_files(parent: &std::path::Path) -> Vec<PathBuf> {
    let mut files = fs::read_dir(parent)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.starts_with("siem-buffer-") && name != "siem-buffer-current.jsonl")
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

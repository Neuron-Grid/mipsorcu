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
    let buffer = LocalSiemFallbackBuffer::with_limits(&path, 1, 1024 * 1024);
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
    assert_eq!(
        buffer.remaining_bytes().unwrap(),
        buffer
            .total_max_bytes()
            .saturating_sub(buffer.total_size_bytes().unwrap())
    );

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
    let buffer = LocalSiemFallbackBuffer::with_limits(&path, 1, 1024 * 1024);
    let first = build_event();
    let second = build_event();

    buffer.append_pending(&first).unwrap();
    buffer.append_pending(&second).unwrap();
    buffer.mark_sent(&first).unwrap();

    let pending = buffer.pending_batch(100).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event_id(), second.event_id());
}

#[test]
fn compact_rewrites_latest_pending_only_and_removes_rotated_files() {
    let path = tempfile_path("compact_mixed");
    let buffer = LocalSiemFallbackBuffer::with_limits(&path, 1, 1024 * 1024);
    let first = build_event();
    let second = build_event();
    let third = build_event();

    buffer.append_pending(&first).unwrap();
    buffer.append_pending(&second).unwrap();
    buffer.append_pending(&third).unwrap();
    buffer.mark_sent(&first).unwrap();
    assert!(
        !rotated_files(path.parent().expect("buffer path has parent")).is_empty(),
        "test setup should create rotated files"
    );

    buffer.compact().unwrap();

    let parent = path.parent().expect("buffer path has parent");
    assert!(
        rotated_files(parent).is_empty(),
        "compaction should remove rotated SIEM buffers"
    );
    let pending = buffer.pending_events().unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].event_id(), second.event_id());
    assert_eq!(pending[1].event_id(), third.event_id());
    let current_lines = read_current_lines(&path);
    assert_eq!(current_lines.len(), 2);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "compacted SIEM buffer file must be 0600");
    }
}

#[test]
fn compact_clears_current_when_all_events_are_sent() {
    let path = tempfile_path("compact_all_sent");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let event = build_event();

    buffer.append_pending(&event).unwrap();
    buffer.mark_sent(&event).unwrap();
    assert!(!read_current_lines(&path).is_empty());

    buffer.compact().unwrap();

    assert!(read_current_lines(&path).is_empty());
    assert!(buffer.pending_events().unwrap().is_empty());
    assert!(buffer.pending_batch(100).unwrap().is_empty());
}

#[test]
fn compact_invalid_json_leaves_existing_files_untouched() {
    let path = tempfile_path("compact_invalid_json");
    fs::create_dir_all(path.parent().expect("buffer path has parent")).unwrap();
    fs::write(&path, "{not-json}\n").unwrap();

    let buffer = LocalSiemFallbackBuffer::new(&path);
    let error = buffer
        .compact()
        .expect_err("invalid JSON should fail compaction");

    assert!(matches!(error, LocalSiemBufferError::Serialization(_)));
    assert_eq!(fs::read_to_string(&path).unwrap(), "{not-json}\n");
}

#[test]
fn compact_temp_write_failure_leaves_existing_files_untouched() {
    let path = tempfile_path("compact_temp_write_failure");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let event = build_event();
    buffer.append_pending(&event).unwrap();
    let before = fs::read_to_string(&path).unwrap();
    let temp_path = compaction_temp_path(&path);
    fs::create_dir_all(&temp_path).unwrap();

    let error = buffer
        .compact()
        .expect_err("directory at temp path should fail compaction");

    assert!(matches!(error, LocalSiemBufferError::Io(_)));
    assert_eq!(fs::read_to_string(&path).unwrap(), before);
}

#[test]
fn total_size_and_remaining_bytes_include_rotated_and_current_files() {
    let path = tempfile_path("total_size");
    let buffer = LocalSiemFallbackBuffer::with_limits(&path, 1, 1024 * 1024);
    let first = build_event();
    let second = build_event();

    buffer.append_pending(&first).unwrap();
    buffer.append_pending(&second).unwrap();

    let parent = path.parent().expect("buffer path has parent");
    let expected_total = file_size(&path)
        + rotated_files(parent)
            .into_iter()
            .map(|path| file_size(&path))
            .sum::<u64>();
    assert_eq!(buffer.total_size_bytes().unwrap(), expected_total);
    assert_eq!(
        buffer.remaining_bytes().unwrap(),
        buffer.total_max_bytes().saturating_sub(expected_total)
    );
}

#[test]
fn append_pending_rejects_capacity_exceeded_without_changing_existing_pending() {
    let path = tempfile_path("capacity_reject");
    let initial = LocalSiemFallbackBuffer::with_limits(&path, 1024 * 1024, 1024 * 1024);
    let first = build_event();
    let second = build_event();
    initial.append_pending(&first).unwrap();
    let existing_size = initial.total_size_bytes().unwrap();
    let before = fs::read_to_string(&path).unwrap();

    let limited = LocalSiemFallbackBuffer::with_limits(&path, 1024 * 1024, existing_size);
    let error = limited
        .append_pending(&second)
        .expect_err("new pending record should exceed total capacity");

    assert!(matches!(
        error,
        LocalSiemBufferError::CapacityExceeded {
            total_size_bytes,
            total_max_bytes
        } if total_size_bytes == existing_size && total_max_bytes == existing_size
    ));
    assert_eq!(fs::read_to_string(&path).unwrap(), before);
    let pending = limited.pending_events().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event_id(), first.event_id());
}

#[test]
fn mark_sent_is_allowed_over_capacity_and_compaction_shrinks_buffer() {
    let path = tempfile_path("sent_over_capacity");
    let initial = LocalSiemFallbackBuffer::with_limits(&path, 1024 * 1024, 1024 * 1024);
    let event = build_event();
    initial.append_pending(&event).unwrap();
    let existing_size = initial.total_size_bytes().unwrap();
    let limited = LocalSiemFallbackBuffer::with_limits(&path, 1024 * 1024, existing_size);

    limited.mark_sent(&event).unwrap();
    assert!(
        limited.total_size_bytes().unwrap() > limited.total_max_bytes(),
        "sent marker may temporarily exceed total capacity"
    );

    limited.compact().unwrap();

    assert!(limited.pending_events().unwrap().is_empty());
    assert_eq!(limited.total_size_bytes().unwrap(), 0);
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

fn read_current_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(ToOwned::to_owned)
        .collect()
}

fn file_size(path: &Path) -> u64 {
    fs::metadata(path).unwrap().len()
}

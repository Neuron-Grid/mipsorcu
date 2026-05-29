use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_QUEUE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_queue_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = TEMP_QUEUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let process_id = std::process::id();
    std::env::temp_dir().join(format!(
        "mipsorcu-archive-queue-{process_id}-{nanos}-{counter}.jsonl"
    ))
}

#[test]
fn pending_and_sent_markers_are_idempotent() {
    let path = temp_queue_path();
    let queue = LocalArchiveQueue::new(&path);
    let key = ArchiveObjectKey::new("digests/2026-05/digest.json").unwrap();
    queue
        .append_pending_bytes(&key, br#"{"archive_schema_version":1}"#.to_vec())
        .unwrap();
    let pending = queue.pending_objects().unwrap();
    assert_eq!(pending.len(), 1);
    queue.mark_sent(&pending[0]).unwrap();
    assert!(queue.pending_objects().unwrap().is_empty());
    let _ = std::fs::remove_file(path);
}

#[test]
fn queue_file_does_not_contain_forbidden_secret_markers() {
    let path = temp_queue_path();
    let queue = LocalArchiveQueue::new(&path);
    let key = ArchiveObjectKey::new("digests/2026-05/digest.json").unwrap();
    queue
        .append_pending_bytes(&key, br#"{"digest_hash":"abcd"}"#.to_vec())
        .unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    for forbidden in [
        "plaintext",
        "master_key",
        "data_key",
        "raw_jwt",
        "service_role_key",
    ] {
        assert!(!contents.contains(forbidden));
    }
    let _ = std::fs::remove_file(path);
}

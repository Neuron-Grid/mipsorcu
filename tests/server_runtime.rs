use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mipsorcu::server::runtime::{
    AuditFallbackSizeAlert, audit_fallback_file_size, audit_fallback_size_alert,
};

fn temp_path(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    std::env::temp_dir().join(format!("mipsorcu-runtime-{test_name}-{unique}"))
}

fn write_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::File::create(path).expect("test file should be created");
    file.write_all(bytes).expect("test file should be written");
}

#[test]
fn audit_fallback_file_size_returns_none_when_file_is_missing() {
    let path = temp_path("missing");

    let size = audit_fallback_file_size(&path).expect("missing file should not fail");

    assert_eq!(size, None);
}

#[test]
fn audit_fallback_size_alert_ignores_missing_file() {
    let path = temp_path("missing-alert");

    let alert = audit_fallback_size_alert(&path, 10).expect("missing file should not fail");

    assert_eq!(alert, None);
}

#[test]
fn audit_fallback_size_alert_ignores_files_below_threshold() {
    let path = temp_path("below-threshold");
    write_file(&path, b"12345");

    let alert = audit_fallback_size_alert(&path, 6).expect("size check should succeed");

    assert_eq!(alert, None);
    let _ = fs::remove_file(path);
}

#[test]
fn audit_fallback_size_alert_triggers_at_threshold() {
    let path = temp_path("at-threshold");
    write_file(&path, b"12345");

    let alert = audit_fallback_size_alert(&path, 5).expect("size check should succeed");

    assert_eq!(
        alert,
        Some(AuditFallbackSizeAlert {
            size_bytes: 5,
            threshold_bytes: 5,
        })
    );
    let _ = fs::remove_file(path);
}

#[test]
fn audit_fallback_file_size_ignores_directories() {
    let path = temp_path("directory");
    fs::create_dir(&path).expect("test directory should be created");

    let size = audit_fallback_file_size(&path).expect("directory metadata should be readable");

    assert_eq!(size, None);
    let _ = fs::remove_dir(path);
}

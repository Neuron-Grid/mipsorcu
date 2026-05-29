use super::*;
use crate::audit::event::metadata::SOURCE_EVENT_AT_KEY;

#[test]
fn integrity_check_metadata_builds_expected_keys() {
    let summary = IntegrityCheckViolationSummary::zero();
    let metadata = IntegrityCheckMetadata::new(1, 2, 3, 0, summary, AuditTrigger::Background)
        .with_duration_ms(100)
        .with_error_code("rpc_failed")
        .build()
        .unwrap();
    let value = metadata.as_value();
    assert_eq!(value["check_name"], "mvp_integrity_check");
    assert_eq!(value["checked_secret_count"], 1);
    assert_eq!(value["checked_secret_version_count"], 2);
    assert_eq!(value["checked_audit_event_count"], 3);
    assert_eq!(value["duration_ms"], 100);
    assert_eq!(value["violation_count"], 0);
    assert!(value["violation_summary"].is_object());
    assert_eq!(value["trigger"], "background");
    assert_eq!(value["error_code"], "rpc_failed");
}

#[test]
fn integrity_check_metadata_without_optional_fields() {
    let summary = IntegrityCheckViolationSummary::zero();
    let metadata = IntegrityCheckMetadata::new(0, 0, 0, 0, summary, AuditTrigger::Startup)
        .build()
        .unwrap();
    let value = metadata.as_value();
    assert!(!value.as_object().unwrap().contains_key("error_code"));
    assert!(!value.as_object().unwrap().contains_key(SOURCE_EVENT_AT_KEY));
}

#[test]
fn restore_test_metadata_success_builds_expected_keys() {
    let metadata = RestoreTestMetadata::new(5, AuditTrigger::Background)
        .with_duration_ms(250)
        .build()
        .unwrap();
    let value = metadata.as_value();
    assert_eq!(value["phase"], "verify");
    assert_eq!(value["sample_count"], 5);
    assert_eq!(value["trigger"], "background");
    assert_eq!(value["duration_ms"], 250);
}

#[test]
fn restore_test_metadata_with_error_and_failed_version() {
    let failed_version = SecretVersion::new(3).unwrap();
    let metadata = RestoreTestMetadata::new(5, AuditTrigger::Cli)
        .with_error_code("decrypt_failed")
        .with_failed_version(failed_version)
        .with_reason("no_current_secret_versions")
        .build()
        .unwrap();
    let value = metadata.as_value();
    assert_eq!(value["error_code"], "decrypt_failed");
    assert_eq!(value["failed_version"], 3);
    assert_eq!(value["reason"], "no_current_secret_versions");
}

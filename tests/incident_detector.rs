use std::time::Duration;

use mipsorcu::{IncidentCategory, IncidentDetector, IncidentSeverity};

#[test]
fn scheduler_three_consecutive_failures_produce_incident() {
    let detector = IncidentDetector::new();
    assert!(
        detector
            .scheduler_failure("monthly_digest_generate", 2, "scheduler_job_timeout")
            .unwrap()
            .is_none()
    );

    let notification = detector
        .scheduler_failure("monthly_digest_generate", 3, "scheduler_job_timeout")
        .unwrap()
        .unwrap();
    assert_eq!(notification.category, IncidentCategory::SchedulerFailure);
    assert_eq!(notification.severity, IncidentSeverity::High);
}

#[test]
fn persistent_archive_and_timestamping_failures_require_24_hours() {
    let detector = IncidentDetector::new();
    assert!(
        detector
            .persistent_archive_failure(Duration::from_secs(23 * 60 * 60), "archive_failed")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        detector
            .persistent_archive_failure(Duration::from_secs(24 * 60 * 60), "archive_failed")
            .unwrap()
            .unwrap()
            .category,
        IncidentCategory::ArchiveFailurePersistent
    );
    assert_eq!(
        detector
            .persistent_timestamping_failure(
                Duration::from_secs(24 * 60 * 60),
                "timestamping_failed"
            )
            .unwrap()
            .unwrap()
            .category,
        IncidentCategory::TimestampingFailurePersistent
    );
}

#[test]
fn siem_buffer_threshold_is_80_mib() {
    let detector = IncidentDetector::new();
    assert!(
        detector
            .siem_buffer_threshold(80 * 1024 * 1024 - 1)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        detector
            .siem_buffer_threshold(80 * 1024 * 1024)
            .unwrap()
            .unwrap()
            .category,
        IncidentCategory::SiemBufferThreshold
    );
}

#[test]
fn envelope_and_auth_failure_bursts_are_process_local_global_windows() {
    let detector = IncidentDetector::new();
    for _ in 0..9 {
        assert!(
            detector
                .record_envelope_migration_failure("aad_context_mismatch")
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        detector
            .record_envelope_migration_failure("aad_context_mismatch")
            .unwrap()
            .unwrap()
            .category,
        IncidentCategory::EnvelopeMigrationFailureBurst
    );

    for _ in 0..9 {
        assert!(
            detector
                .record_auth_failure("jwt_verification_failed")
                .unwrap()
                .is_none()
        );
    }
    let auth_notification = detector
        .record_auth_failure("jwt_verification_failed")
        .unwrap()
        .unwrap();
    assert_eq!(
        auth_notification.category,
        IncidentCategory::AuthFailureBurst
    );
    assert_eq!(auth_notification.severity, IncidentSeverity::Medium);
}

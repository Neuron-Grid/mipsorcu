use std::collections::BTreeSet;

use mipsorcu::{AuditAction, AuditResult};

pub(super) fn all_actions() -> Vec<AuditAction> {
    vec![
        AuditAction::EncryptCreate,
        AuditAction::EncryptRotate,
        AuditAction::VersionPurge,
        AuditAction::Decrypt,
        AuditAction::IntegrityCheck,
        AuditAction::RestoreTest,
        AuditAction::AuthFailure,
        AuditAction::KeyRotationStart,
        AuditAction::KeyRotationReencrypt,
        AuditAction::KeyRotationComplete,
        AuditAction::KeyRotationEnvelopeMigrated,
        AuditAction::KeyRotationEnvelopeFailed,
        AuditAction::SignatureKeyCreated,
        AuditAction::SignatureKeyActivated,
        AuditAction::SignatureKeyRetired,
        AuditAction::MonthlyDigestGenerate,
        AuditAction::MonthlyDigestVerify,
        AuditAction::ArchiveExport,
        AuditAction::DigestTimestamping,
        AuditAction::SiemForwardFailure,
        AuditAction::SiemEventForwarded,
        AuditAction::SiemEventFailed,
        AuditAction::SiemBufferFlushed,
        AuditAction::AuditReportGenerate,
        AuditAction::AuditUiRead,
        AuditAction::SchedulerJob,
        AuditAction::SchedulerJobStarted,
        AuditAction::SchedulerJobCompleted,
        AuditAction::SchedulerJobFailed,
        AuditAction::SchedulerJobSkipped,
        AuditAction::IncidentDetected,
        AuditAction::IncidentNotificationSent,
        AuditAction::IncidentNotificationFailed,
        AuditAction::IncidentNotificationSuppressed,
        AuditAction::SecretAliasCreate,
        AuditAction::SecretAliasUpdate,
        AuditAction::SecretAliasDelete,
        AuditAction::SecretAliasList,
    ]
}

pub(super) fn rust_allowlist_for_action_result(
    action: AuditAction,
    result: AuditResult,
) -> BTreeSet<String> {
    // AuditMetadata::validate_allowlist_for_action と同一ロジック
    let mut keys = match action {
        AuditAction::EncryptCreate | AuditAction::EncryptRotate | AuditAction::VersionPurge => {
            vec!["version", "secret_version_id", "source_event_at"]
        }
        AuditAction::Decrypt => {
            if result == AuditResult::Failure {
                vec!["attempted_secret_id", "source_event_at"]
            } else {
                vec!["source_event_at"]
            }
        }
        AuditAction::IntegrityCheck => {
            vec![
                "check_name",
                "checked_secret_count",
                "checked_secret_version_count",
                "checked_audit_event_count",
                "duration_ms",
                "violation_count",
                "violation_summary",
                "trigger",
                "error_code",
                "source_event_at",
            ]
        }
        AuditAction::RestoreTest => {
            vec![
                "phase",
                "sample_count",
                "trigger",
                "duration_ms",
                "error_code",
                "failed_version",
                "reason",
                "source_event_at",
            ]
        }
        AuditAction::AuthFailure => {
            vec!["error_code", "source_event_at"]
        }
        AuditAction::KeyRotationStart => {
            vec!["old_key_version", "new_key_version", "source_event_at"]
        }
        AuditAction::KeyRotationReencrypt => {
            vec![
                "old_key_version",
                "new_key_version",
                "batch_size",
                "processed_count",
                "remaining_count",
                "source_event_at",
            ]
        }
        AuditAction::KeyRotationComplete => {
            vec![
                "old_key_version",
                "new_key_version",
                "remaining_count",
                "source_event_at",
            ]
        }
        AuditAction::KeyRotationEnvelopeMigrated => {
            vec![
                "batch_size",
                "success_count",
                "failure_count",
                "source_event_at",
            ]
        }
        AuditAction::KeyRotationEnvelopeFailed => {
            vec![
                "secret_version_id",
                "version",
                "error_code",
                "source_event_at",
            ]
        }
        AuditAction::SignatureKeyCreated => {
            vec![
                "created_at",
                "public_key_fingerprint",
                "signature_key_version",
                "source_event_at",
            ]
        }
        AuditAction::SignatureKeyActivated => {
            vec![
                "activated_at",
                "public_key_fingerprint",
                "signature_key_version",
                "source_event_at",
            ]
        }
        AuditAction::SignatureKeyRetired => {
            vec![
                "public_key_fingerprint",
                "retired_at",
                "signature_key_version",
                "source_event_at",
            ]
        }
        // 月次 digest 生成（成功・失敗両方を記録、allowlist は result 共通の union）
        AuditAction::MonthlyDigestGenerate => {
            vec![
                "digest_hash",
                "end_sequence_no",
                "entry_count",
                "error_code",
                "signature_key_version",
                "start_sequence_no",
                "target_year_month",
                "source_event_at",
            ]
        }
        // 月次 digest 検証（成功・失敗両方を記録、allowlist は result 共通）
        AuditAction::MonthlyDigestVerify => {
            vec![
                "error_code",
                "target_year_month",
                "verify_result",
                "source_event_at",
            ]
        }
        // archive export（成功・失敗両方を記録、allowlist は result 共通）
        AuditAction::ArchiveExport => {
            vec![
                "archive_key",
                "digest_hash",
                "error_code",
                "source_event_at",
                "target_year_month",
            ]
        }
        // digest timestamping（成功・失敗両方を記録、allowlist は result 共通）
        AuditAction::DigestTimestamping => {
            vec![
                "digest_hash",
                "error_code",
                "source_event_at",
                "target_year_month",
                "timestamp_token_hash",
            ]
        }
        // SIEM forward failure（failure-only）
        AuditAction::SiemForwardFailure => {
            vec!["error_code", "event_count", "event_type", "source_event_at"]
        }
        AuditAction::SiemEventForwarded => {
            vec!["exporter_kind", "batch_size", "source_event_at"]
        }
        AuditAction::SiemEventFailed => {
            vec![
                "exporter_kind",
                "error_code",
                "buffered",
                "batch_size",
                "source_event_at",
            ]
        }
        AuditAction::SiemBufferFlushed => {
            vec!["flushed_count", "buffer_remaining_bytes", "source_event_at"]
        }
        // audit report generation（成功・失敗両方を記録）
        AuditAction::AuditReportGenerate => {
            vec![
                "error_code",
                "format",
                "period_end",
                "period_start",
                "source_event_at",
            ]
        }
        AuditAction::SchedulerJob => {
            vec![
                "duration_ms",
                "error_code",
                "job_name",
                "source_event_at",
                "target_year_month",
                "trigger",
            ]
        }
        AuditAction::SchedulerJobStarted => {
            vec!["job_name", "scheduled_at", "source_event_at", "started_at"]
        }
        AuditAction::SchedulerJobCompleted => {
            vec![
                "completed_at",
                "duration_ms",
                "job_name",
                "result_summary",
                "source_event_at",
                "started_at",
            ]
        }
        AuditAction::SchedulerJobFailed => {
            vec![
                "error_code",
                "failed_at",
                "job_name",
                "retry_count",
                "source_event_at",
                "started_at",
            ]
        }
        AuditAction::SchedulerJobSkipped => {
            vec!["job_name", "reason", "skipped_at", "source_event_at"]
        }
        AuditAction::IncidentDetected => {
            vec![
                "dedupe_key",
                "detection_source",
                "error_code",
                "incident_type",
                "notification_result",
                "notification_sink",
                "source_event_at",
                "source_event_id",
                "target_sequence_no",
                "target_year_month",
                "severity",
            ]
        }
        AuditAction::IncidentNotificationSent => {
            vec![
                "category",
                "duration_ms",
                "incident_id",
                "notifier_kind",
                "source_event_at",
            ]
        }
        AuditAction::IncidentNotificationFailed => {
            vec![
                "category",
                "error_code",
                "incident_id",
                "notifier_kind",
                "retry_count",
                "source_event_at",
            ]
        }
        AuditAction::IncidentNotificationSuppressed => {
            vec![
                "category",
                "incident_id",
                "reason",
                "source_event_at",
                "suppressed_count",
                "window_remaining_sec",
            ]
        }
        AuditAction::SecretAliasCreate => {
            vec![
                "alias_fingerprint",
                "alias_fingerprint_key_version",
                "alias_fingerprint_schema_version",
                "error_code",
                "source_event_at",
            ]
        }
        AuditAction::SecretAliasUpdate => {
            vec![
                "old_alias_fingerprint",
                "new_alias_fingerprint",
                "alias_fingerprint_key_version",
                "alias_fingerprint_schema_version",
                "error_code",
                "source_event_at",
            ]
        }
        AuditAction::SecretAliasDelete => {
            vec![
                "alias_fingerprint",
                "alias_fingerprint_key_version",
                "alias_fingerprint_schema_version",
                "error_code",
                "source_event_at",
            ]
        }
        AuditAction::SecretAliasList => {
            vec!["error_code", "result_count", "source_event_at"]
        }
        AuditAction::AuditUiRead => {
            vec![
                "endpoint",
                "method",
                "resource",
                "result_count",
                "period_start",
                "period_end",
                "start_sequence_no",
                "end_sequence_no",
                "target_year_month",
                "error_code",
                "source_event_at",
            ]
        }
    };
    keys.sort();
    keys.into_iter().map(|s| s.to_owned()).collect()
}

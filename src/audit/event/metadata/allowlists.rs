//! `AuditMetadata` の action / result 別 allowlist・必須キーのデータテーブル。
//!
//! 検証ロジック本体（`validate.rs`）から「どのキーが許可・必須か」という
//! ドメイン定義を分離し、データを一箇所へ集約するための内部モジュール。

use super::{AuditAction, AuditResult, SOURCE_EVENT_AT_KEY, TRIGGER_KEY};

/// action / result に対して許可されるトップレベルメタデータキーの一覧を返す。
///
/// 返り値は包含判定にのみ使う許可集合であり、順序に意味は持たせない。
pub(super) fn allowed_metadata_keys(
    action: AuditAction,
    result: AuditResult,
) -> &'static [&'static str] {
    match action {
        AuditAction::EncryptCreate | AuditAction::EncryptRotate | AuditAction::VersionPurge => {
            &["version", "secret_version_id", SOURCE_EVENT_AT_KEY]
        }
        AuditAction::Decrypt => {
            if result == AuditResult::Failure {
                &["attempted_secret_id", SOURCE_EVENT_AT_KEY]
            } else {
                &[SOURCE_EVENT_AT_KEY]
            }
        }
        AuditAction::IntegrityCheck => &[
            "check_name",
            "checked_secret_count",
            "checked_secret_version_count",
            "checked_audit_event_count",
            "duration_ms",
            "violation_count",
            "violation_summary",
            TRIGGER_KEY,
            "error_code",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::RestoreTest => &[
            "phase",
            "sample_count",
            TRIGGER_KEY,
            "duration_ms",
            "error_code",
            "failed_version",
            "reason",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::AuthFailure => &["error_code", SOURCE_EVENT_AT_KEY],
        AuditAction::KeyRotationStart => {
            &["old_key_version", "new_key_version", SOURCE_EVENT_AT_KEY]
        }
        AuditAction::KeyRotationReencrypt => &[
            "old_key_version",
            "new_key_version",
            "batch_size",
            "processed_count",
            "remaining_count",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::KeyRotationComplete => &[
            "old_key_version",
            "new_key_version",
            "remaining_count",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::KeyRotationEnvelopeMigrated => &[
            "batch_size",
            "success_count",
            "failure_count",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::KeyRotationEnvelopeFailed => &[
            "secret_version_id",
            "version",
            "error_code",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SignatureKeyCreated => &[
            "created_at",
            "public_key_fingerprint",
            "signature_key_version",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SignatureKeyActivated => &[
            "activated_at",
            "public_key_fingerprint",
            "signature_key_version",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SignatureKeyRetired => &[
            "public_key_fingerprint",
            "retired_at",
            "signature_key_version",
            SOURCE_EVENT_AT_KEY,
        ],
        // 月次 digest 生成（成功・失敗両方を記録）。
        // error_code は failure result 時のみ記録する。
        AuditAction::MonthlyDigestGenerate => &[
            "digest_hash",
            "end_sequence_no",
            "entry_count",
            "error_code",
            "signature_key_version",
            "start_sequence_no",
            "target_year_month",
            SOURCE_EVENT_AT_KEY,
        ],
        // 月次 digest 検証（成功・失敗両方を記録）。
        AuditAction::MonthlyDigestVerify => &[
            "error_code",
            "target_year_month",
            "verify_result",
            SOURCE_EVENT_AT_KEY,
        ],
        // 外部アーカイブ export（成功・失敗両方を記録）。
        // archive_key は success 時のみ有効（validate_metadata_values で検証）。
        AuditAction::ArchiveExport => &[
            "archive_key",
            "digest_hash",
            "target_year_month",
            "error_code",
            SOURCE_EVENT_AT_KEY,
        ],
        // 月次 digest 外部 timestamping（成功・失敗両方を記録）。
        // timestamp_token_hash は success 時のみ有効
        // （validate_metadata_values で検証）。
        AuditAction::DigestTimestamping => &[
            "digest_hash",
            "error_code",
            "target_year_month",
            "timestamp_token_hash",
            SOURCE_EVENT_AT_KEY,
        ],
        // SIEM への監査イベント転送失敗（failure-only）。
        AuditAction::SiemForwardFailure => &[
            "error_code",
            "event_type",
            "event_count",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SiemEventForwarded => &["exporter_kind", "batch_size", SOURCE_EVENT_AT_KEY],
        AuditAction::SiemEventFailed => &[
            "exporter_kind",
            "error_code",
            "buffered",
            "batch_size",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SiemBufferFlushed => &[
            "flushed_count",
            "buffer_remaining_bytes",
            SOURCE_EVENT_AT_KEY,
        ],
        // 監査レポート生成（成功・失敗両方を記録）。
        AuditAction::AuditReportGenerate => &[
            "format",
            "period_end",
            "period_start",
            "error_code",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::AuditUiRead => &[
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
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SchedulerJob => &[
            "duration_ms",
            "error_code",
            "job_name",
            "target_year_month",
            TRIGGER_KEY,
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SchedulerJobStarted => &[
            "job_name",
            "scheduled_at",
            "started_at",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SchedulerJobCompleted => &[
            "completed_at",
            "duration_ms",
            "job_name",
            "result_summary",
            "started_at",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SchedulerJobFailed => &[
            "error_code",
            "failed_at",
            "job_name",
            "retry_count",
            "started_at",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SchedulerJobSkipped => {
            &["job_name", "reason", "skipped_at", SOURCE_EVENT_AT_KEY]
        }
        AuditAction::IncidentDetected => &[
            "incident_type",
            "severity",
            "detection_source",
            "dedupe_key",
            "notification_sink",
            "notification_result",
            "error_code",
            SOURCE_EVENT_AT_KEY,
            "source_event_id",
            "target_sequence_no",
            "target_year_month",
        ],
        AuditAction::IncidentNotificationSent => &[
            "incident_id",
            "category",
            "notifier_kind",
            "duration_ms",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::IncidentNotificationFailed => &[
            "incident_id",
            "category",
            "notifier_kind",
            "error_code",
            "retry_count",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::IncidentNotificationSuppressed => &[
            "incident_id",
            "category",
            "reason",
            "suppressed_count",
            "window_remaining_sec",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SecretAliasCreate => &[
            "alias_fingerprint",
            "alias_fingerprint_key_version",
            "alias_fingerprint_schema_version",
            "error_code",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SecretAliasUpdate => &[
            "old_alias_fingerprint",
            "new_alias_fingerprint",
            "alias_fingerprint_key_version",
            "alias_fingerprint_schema_version",
            "error_code",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SecretAliasDelete => &[
            "alias_fingerprint",
            "alias_fingerprint_key_version",
            "alias_fingerprint_schema_version",
            "error_code",
            SOURCE_EVENT_AT_KEY,
        ],
        AuditAction::SecretAliasList => &["result_count", "error_code", SOURCE_EVENT_AT_KEY],
    }
}

/// action / result に対して必須となるトップレベルメタデータキーを返す。
///
/// `source_event_at` はここには含めない（呼び出し側が必要に応じて付与する）。
/// 返り値の順序は「最初に欠落したキーを報告する」既存挙動を保つため意味を持つ。
pub(super) fn required_metadata_keys(
    action: AuditAction,
    result: AuditResult,
) -> &'static [&'static str] {
    match action {
        AuditAction::EncryptCreate | AuditAction::EncryptRotate | AuditAction::VersionPurge => {
            &["version", "secret_version_id"]
        }
        AuditAction::Decrypt => &[],
        AuditAction::IntegrityCheck => &[
            "check_name",
            "checked_secret_count",
            "checked_secret_version_count",
            "checked_audit_event_count",
            "duration_ms",
            "violation_count",
            "violation_summary",
            TRIGGER_KEY,
        ],
        AuditAction::RestoreTest => &["phase", "sample_count", TRIGGER_KEY, "duration_ms"],
        AuditAction::AuthFailure => &["error_code"],
        AuditAction::KeyRotationStart => &["old_key_version", "new_key_version"],
        AuditAction::KeyRotationReencrypt => &[
            "old_key_version",
            "new_key_version",
            "batch_size",
            "processed_count",
            "remaining_count",
        ],
        AuditAction::KeyRotationComplete => {
            &["old_key_version", "new_key_version", "remaining_count"]
        }
        AuditAction::KeyRotationEnvelopeMigrated => {
            &["batch_size", "success_count", "failure_count"]
        }
        AuditAction::KeyRotationEnvelopeFailed => &["secret_version_id", "version", "error_code"],
        AuditAction::SignatureKeyCreated => &[
            "signature_key_version",
            "public_key_fingerprint",
            "created_at",
        ],
        AuditAction::SignatureKeyActivated => &[
            "signature_key_version",
            "public_key_fingerprint",
            "activated_at",
        ],
        AuditAction::SignatureKeyRetired => &[
            "signature_key_version",
            "public_key_fingerprint",
            "retired_at",
        ],
        AuditAction::MonthlyDigestGenerate => {
            if result == AuditResult::Success {
                &[
                    "target_year_month",
                    "start_sequence_no",
                    "end_sequence_no",
                    "entry_count",
                    "signature_key_version",
                    "digest_hash",
                ]
            } else {
                &["target_year_month", "error_code"]
            }
        }
        AuditAction::MonthlyDigestVerify => {
            if result == AuditResult::Success {
                &["target_year_month", "verify_result"]
            } else {
                &["target_year_month", "verify_result", "error_code"]
            }
        }
        // archive export は target_year_month が常に必須。
        AuditAction::ArchiveExport => &["target_year_month"],
        // digest timestamping も target_year_month が常に必須。
        AuditAction::DigestTimestamping => &["target_year_month"],
        // SIEM forward failure は error_code が常に必須（failure-only）。
        AuditAction::SiemForwardFailure => &["error_code"],
        AuditAction::SiemEventForwarded => &["exporter_kind", "batch_size"],
        AuditAction::SiemEventFailed => &["exporter_kind", "error_code", "buffered", "batch_size"],
        AuditAction::SiemBufferFlushed => &["flushed_count", "buffer_remaining_bytes"],
        // audit_report_generate は対象期間と出力形式が常に必須。
        AuditAction::AuditReportGenerate => &["format", "period_end", "period_start"],
        AuditAction::AuditUiRead => &["endpoint", "method", "resource"],
        AuditAction::SchedulerJob => &["job_name", TRIGGER_KEY, "duration_ms"],
        AuditAction::SchedulerJobStarted => &["job_name", "scheduled_at", "started_at"],
        AuditAction::SchedulerJobCompleted => &[
            "job_name",
            "started_at",
            "completed_at",
            "duration_ms",
            "result_summary",
        ],
        AuditAction::SchedulerJobFailed => &[
            "job_name",
            "started_at",
            "failed_at",
            "error_code",
            "retry_count",
        ],
        AuditAction::SchedulerJobSkipped => &["job_name", "skipped_at", "reason"],
        AuditAction::IncidentDetected => &[
            "incident_type",
            "severity",
            "detection_source",
            "dedupe_key",
            "notification_sink",
            "notification_result",
            "error_code",
        ],
        AuditAction::IncidentNotificationSent => {
            &["incident_id", "category", "notifier_kind", "duration_ms"]
        }
        AuditAction::IncidentNotificationFailed => &[
            "incident_id",
            "category",
            "notifier_kind",
            "error_code",
            "retry_count",
        ],
        AuditAction::IncidentNotificationSuppressed => &[
            "incident_id",
            "category",
            "reason",
            "suppressed_count",
            "window_remaining_sec",
        ],
        AuditAction::SecretAliasCreate => {
            if result == AuditResult::Success {
                &[
                    "alias_fingerprint",
                    "alias_fingerprint_key_version",
                    "alias_fingerprint_schema_version",
                ]
            } else {
                &[]
            }
        }
        AuditAction::SecretAliasUpdate => {
            if result == AuditResult::Success {
                &[
                    "old_alias_fingerprint",
                    "new_alias_fingerprint",
                    "alias_fingerprint_key_version",
                    "alias_fingerprint_schema_version",
                ]
            } else {
                &[]
            }
        }
        AuditAction::SecretAliasDelete => {
            if result == AuditResult::Success {
                &[
                    "alias_fingerprint",
                    "alias_fingerprint_key_version",
                    "alias_fingerprint_schema_version",
                ]
            } else {
                &[]
            }
        }
        AuditAction::SecretAliasList => {
            if result == AuditResult::Success {
                &["result_count"]
            } else {
                &[]
            }
        }
    }
}

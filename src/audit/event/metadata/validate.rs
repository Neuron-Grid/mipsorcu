//! `AuditMetadata` の action 別 allowlist / 必須キー / 値検証ロジック。
//!
//! `AuditMetadata::validate_allowlist_for_action` から呼び出される検証関数を
//! まとめている。`metadata.rs` 本体（構築・正規化・禁止キー排除）から検証の
//! 詳細を分離するための内部モジュール。allowlist / 必須キーのデータ定義自体は
//! `allowlists.rs` に分離している。

use serde_json::{Map, Value};

use super::allowlists::{allowed_metadata_keys, required_metadata_keys};
use super::{
    AuditAction, AuditEventError, AuditEventId, AuditResult, SOURCE_EVENT_AT_KEY, SecretVersionId,
    SourceEventAt,
};

/// Validates that all top-level keys in `object` are in the allowlist for the
/// given action and result. Also checks `violation_summary` sub-object keys for
/// the `integrity_check` action.
pub(super) fn validate_allowlist_for_action(
    object: &Map<String, Value>,
    action: AuditAction,
    result: AuditResult,
) -> Result<(), AuditEventError> {
    // ── 1. IntegrityCheck の violation_summary サブオブジェクトキーを検証 ──
    validate_violation_summary_allowlist(action, object)?;

    // ── 2. action/result 別 allowlist でトップレベルキーを検証 ──
    let allowed = allowed_metadata_keys(action, result);
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(AuditEventError::UnknownMetadataKey { key: key.clone() });
        }
    }

    // ── 3. 必須キー・値の検証へ委譲 ──
    validate_required_metadata_keys(action, result, object, true)?;
    validate_metadata_values(action, result, object)?;

    Ok(())
}

/// IntegrityCheck の `violation_summary` サブオブジェクトのキーが allowlist 内かを検証する。
///
/// IntegrityCheck 以外の action では何もしない。`violation_summary` が存在するが
/// オブジェクトでない場合は `ViolationSummaryMustBeObject` を返す。
fn validate_violation_summary_allowlist(
    action: AuditAction,
    object: &Map<String, Value>,
) -> Result<(), AuditEventError> {
    if action != AuditAction::IntegrityCheck {
        return Ok(());
    }

    if let Some(summary) = object.get("violation_summary")
        && let Some(summary_obj) = summary.as_object()
    {
        for key in summary_obj.keys() {
            if !INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST.contains(&key.as_str()) {
                return Err(AuditEventError::UnknownMetadataKey { key: key.clone() });
            }
        }
    } else if object.get("violation_summary").is_some() {
        return Err(AuditEventError::ViolationSummaryMustBeObject);
    }

    Ok(())
}

fn validate_required_metadata_keys(
    action: AuditAction,
    result: AuditResult,
    object: &Map<String, Value>,
    require_source_event_at: bool,
) -> Result<(), AuditEventError> {
    // ── 1. action/result 別の必須トップレベルキーを突合 ──
    for key in required_metadata_keys(action, result) {
        if !object.contains_key(*key) {
            return Err(AuditEventError::MissingMetadataKey { key });
        }
    }

    if require_source_event_at && !object.contains_key(SOURCE_EVENT_AT_KEY) {
        return Err(AuditEventError::MissingMetadataKey {
            key: SOURCE_EVENT_AT_KEY,
        });
    }

    // ── 2. IntegrityCheck の violation_summary 必須サブフィールドを突合 ──
    validate_required_violation_summary_keys(action, object)
}

/// IntegrityCheck の `violation_summary` に必須サブフィールドが揃っているか検証する。
fn validate_required_violation_summary_keys(
    action: AuditAction,
    object: &Map<String, Value>,
) -> Result<(), AuditEventError> {
    if action != AuditAction::IntegrityCheck {
        return Ok(());
    }

    let summary = object
        .get("violation_summary")
        .and_then(Value::as_object)
        .ok_or(AuditEventError::ViolationSummaryMustBeObject)?;
    for key in INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST {
        if !summary.contains_key(*key) {
            return Err(AuditEventError::MissingMetadataKey { key });
        }
    }

    Ok(())
}

fn validate_metadata_values(
    action: AuditAction,
    result: AuditResult,
    object: &Map<String, Value>,
) -> Result<(), AuditEventError> {
    validate_numeric_metadata_values(result, object)?;
    validate_id_metadata_values(action, result, object)?;
    validate_string_metadata_values(action, result, object)?;
    validate_timestamp_metadata_values(object)?;
    validate_object_metadata_values(object)?;
    validate_bool_metadata_values(object)?;
    validate_integrity_violation_summary_values(action, object)?;
    Ok(())
}

/// 数値メタデータ（u64 / 正の u64 / failed_version）の値域を検証する。
fn validate_numeric_metadata_values(
    result: AuditResult,
    object: &Map<String, Value>,
) -> Result<(), AuditEventError> {
    for key in [
        "checked_secret_count",
        "checked_secret_version_count",
        "checked_audit_event_count",
        "duration_ms",
        "violation_count",
        "sample_count",
        "processed_count",
        "remaining_count",
        "result_count",
        "success_count",
        "failure_count",
        "flushed_count",
        "buffer_remaining_bytes",
        "retry_count",
        "suppressed_count",
        "window_remaining_sec",
    ] {
        if let Some(value) = object.get(key) {
            validate_u64_value(key, value)?;
        }
    }

    for key in [
        "version",
        "old_key_version",
        "new_key_version",
        "signature_key_version",
        "batch_size",
        "target_sequence_no",
        "start_sequence_no",
        "end_sequence_no",
        "entry_count",
        "signature_key_version",
        "alias_fingerprint_key_version",
        "alias_fingerprint_schema_version",
    ] {
        if let Some(value) = object.get(key) {
            validate_positive_u64_value(key, value)?;
        }
    }

    if let Some(value) = object.get("failed_version") {
        if !value.is_null() {
            validate_positive_u64_value("failed_version", value)?;
        }
        if result == AuditResult::Success {
            return Err(AuditEventError::InvalidMetadataValue {
                key: "failed_version",
            });
        }
    }

    Ok(())
}

/// ID 系メタデータの解析と、action/result に依存する出現可否を検証する。
fn validate_id_metadata_values(
    action: AuditAction,
    result: AuditResult,
    object: &Map<String, Value>,
) -> Result<(), AuditEventError> {
    for key in ["secret_version_id", "attempted_secret_id"] {
        if let Some(value) = object.get(key) {
            let text = value
                .as_str()
                .ok_or(AuditEventError::InvalidMetadataValue { key })?;
            SecretVersionId::parse(text)
                .map_err(|_| AuditEventError::InvalidMetadataValue { key })?;
        }
    }

    if let Some(value) = object.get("source_event_id") {
        let text = value
            .as_str()
            .ok_or(AuditEventError::InvalidMetadataValue {
                key: "source_event_id",
            })?;
        AuditEventId::parse(text).map_err(|_| AuditEventError::InvalidMetadataValue {
            key: "source_event_id",
        })?;
    }

    if let Some(value) = object.get("incident_id") {
        let text = value
            .as_str()
            .ok_or(AuditEventError::InvalidMetadataValue { key: "incident_id" })?;
        crate::incident::IncidentId::parse(text)
            .map_err(|_| AuditEventError::InvalidMetadataValue { key: "incident_id" })?;
    }

    if object.contains_key("source_event_id") && action != AuditAction::IncidentDetected {
        return Err(AuditEventError::InvalidMetadataValue {
            key: "source_event_id",
        });
    }

    if object.contains_key("attempted_secret_id")
        && !(action == AuditAction::Decrypt && result == AuditResult::Failure)
    {
        return Err(AuditEventError::InvalidMetadataValue {
            key: "attempted_secret_id",
        });
    }

    Ok(())
}

/// 文字列・列挙・hex 系メタデータの形式と、result に依存する出現可否を検証する。
fn validate_string_metadata_values(
    action: AuditAction,
    result: AuditResult,
    object: &Map<String, Value>,
) -> Result<(), AuditEventError> {
    if let Some(value) = object.get("error_code") {
        if result != AuditResult::Failure {
            return Err(AuditEventError::InvalidMetadataValue { key: "error_code" });
        }
        validate_non_blank_short_string("error_code", value, 64)?;
    }

    if let Some(value) = object.get("job_name") {
        validate_non_blank_short_string("job_name", value, 96)?;
    }

    for key in ["endpoint", "resource"] {
        if let Some(value) = object.get(key) {
            validate_non_blank_short_string(key, value, 128)?;
        }
    }

    if let Some(value) = object.get("method") {
        validate_exact_string("method", value, "GET")?;
    }

    if let Some(value) = object.get("public_key_fingerprint") {
        validate_hex_string("public_key_fingerprint", value, 64)?;
    }

    if let Some(value) = object.get("digest_hash") {
        validate_hex_string("digest_hash", value, 64)?;
    }

    if let Some(value) = object.get("verify_result") {
        let text = value
            .as_str()
            .ok_or(AuditEventError::InvalidMetadataValue {
                key: "verify_result",
            })?;
        let expected = if result == AuditResult::Success {
            "valid"
        } else {
            "invalid"
        };
        if text != expected {
            return Err(AuditEventError::InvalidMetadataValue {
                key: "verify_result",
            });
        }
    }

    for key in [
        "alias_fingerprint",
        "old_alias_fingerprint",
        "new_alias_fingerprint",
    ] {
        if let Some(value) = object.get(key) {
            validate_hex_string(key, value, 64)?;
        }
    }

    for key in ["detection_source", "dedupe_key", "notification_sink"] {
        if let Some(value) = object.get(key) {
            validate_non_blank_short_string(key, value, 128)?;
        }
    }

    if let Some(value) = object.get("incident_type") {
        let text = value
            .as_str()
            .ok_or(AuditEventError::InvalidMetadataValue {
                key: "incident_type",
            })?;
        if !incident_type_allowed(text) {
            return Err(AuditEventError::InvalidMetadataValue {
                key: "incident_type",
            });
        }
    }

    if let Some(value) = object.get("severity") {
        validate_enum_metadata_value("severity", value, &["critical", "high", "medium", "low"])?;
    }

    if let Some(value) = object.get("category") {
        validate_enum_metadata_value(
            "category",
            value,
            &[
                "ledger_anomaly",
                "scheduler_failure",
                "archive_failure_persistent",
                "timestamping_failure_persistent",
                "siem_buffer_threshold",
                "envelope_migration_failure_burst",
                "auth_failure_burst",
                "key_rotation_failure",
            ],
        )?;
    }

    if let Some(value) = object.get("notifier_kind") {
        validate_enum_metadata_value("notifier_kind", value, &["dummy", "webhook"])?;
    }

    if let Some(value) = object.get("notification_result") {
        validate_enum_metadata_value(
            "notification_result",
            value,
            &["sent", "failed", "suppressed", "not_configured"],
        )?;
    }

    if let Some(value) = object.get("format") {
        validate_enum_metadata_value("format", value, &["json", "markdown"])?;
    }

    if let Some(value) = object.get("exporter_kind") {
        validate_enum_metadata_value("exporter_kind", value, &["in_memory", "otlp", "splunk_hec"])?;
    }

    if let Some(value) = object.get("archive_key") {
        if result == AuditResult::Failure {
            return Err(AuditEventError::InvalidMetadataValue { key: "archive_key" });
        }
        validate_non_blank_short_string("archive_key", value, 256)?;
    }

    if let Some(value) = object.get("check_name") {
        validate_exact_string("check_name", value, "mvp_integrity_check")?;
    }

    if let Some(value) = object.get("phase") {
        validate_exact_string("phase", value, "verify")?;
    }

    if let Some(value) = object.get("reason") {
        if action == AuditAction::SchedulerJobSkipped {
            validate_enum_metadata_value("reason", value, &["lock_not_acquired"])?;
        } else if action == AuditAction::IncidentNotificationSuppressed {
            validate_enum_metadata_value("reason", value, &["rate_limited"])?;
        } else {
            validate_exact_string("reason", value, "no_current_secret_versions")?;
        }
    }

    Ok(())
}

/// 時刻・期間系メタデータ（タイムスタンプ / 年月）の形式を検証する。
fn validate_timestamp_metadata_values(object: &Map<String, Value>) -> Result<(), AuditEventError> {
    for key in [
        "created_at",
        "activated_at",
        "retired_at",
        "scheduled_at",
        "started_at",
        "completed_at",
        "failed_at",
        "skipped_at",
    ] {
        if let Some(value) = object.get(key) {
            let text = value
                .as_str()
                .ok_or(AuditEventError::InvalidMetadataValue { key })?;
            SourceEventAt::parse(text)
                .map_err(|_| AuditEventError::InvalidMetadataValue { key })?;
        }
    }

    if let Some(value) = object.get("target_year_month") {
        let text = value
            .as_str()
            .ok_or(AuditEventError::InvalidMetadataValue {
                key: "target_year_month",
            })?;
        crate::ledger::MonthlyDigestPeriod::parse(text).map_err(|_| {
            AuditEventError::InvalidMetadataValue {
                key: "target_year_month",
            }
        })?;
    }

    for key in ["period_start", "period_end"] {
        if let Some(value) = object.get(key) {
            let text = value
                .as_str()
                .ok_or(AuditEventError::InvalidMetadataValue { key })?;
            SourceEventAt::parse(text)
                .map_err(|_| AuditEventError::InvalidMetadataValue { key })?;
        }
    }

    Ok(())
}

fn validate_object_metadata_values(object: &Map<String, Value>) -> Result<(), AuditEventError> {
    if let Some(value) = object.get("result_summary")
        && !value.is_object()
    {
        return Err(AuditEventError::InvalidMetadataValue {
            key: "result_summary",
        });
    }

    Ok(())
}

fn validate_bool_metadata_values(object: &Map<String, Value>) -> Result<(), AuditEventError> {
    if let Some(value) = object.get("buffered")
        && !value.is_boolean()
    {
        return Err(AuditEventError::InvalidMetadataValue { key: "buffered" });
    }

    Ok(())
}

/// IntegrityCheck の violation_summary 内の各カウンタ値を検証する。
fn validate_integrity_violation_summary_values(
    action: AuditAction,
    object: &Map<String, Value>,
) -> Result<(), AuditEventError> {
    if action == AuditAction::IntegrityCheck
        && let Some(summary_value) = object.get("violation_summary")
    {
        let summary = summary_value
            .as_object()
            .ok_or(AuditEventError::ViolationSummaryMustBeObject)?;
        for (key, value) in summary {
            validate_u64_value(
                INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST
                    .iter()
                    .copied()
                    .find(|allowed| *allowed == key.as_str())
                    .unwrap_or("violation_summary"),
                value,
            )?;
        }
    }

    Ok(())
}

fn validate_u64_value(key: &'static str, value: &Value) -> Result<(), AuditEventError> {
    value
        .as_u64()
        .map(|_| ())
        .ok_or(AuditEventError::InvalidMetadataValue { key })
}

fn validate_positive_u64_value(key: &'static str, value: &Value) -> Result<(), AuditEventError> {
    let parsed = value
        .as_u64()
        .ok_or(AuditEventError::InvalidMetadataValue { key })?;
    if parsed == 0 {
        return Err(AuditEventError::InvalidMetadataValue { key });
    }

    Ok(())
}

fn validate_non_blank_short_string(
    key: &'static str,
    value: &Value,
    max_len: usize,
) -> Result<(), AuditEventError> {
    let text = value
        .as_str()
        .ok_or(AuditEventError::InvalidMetadataValue { key })?;
    if text.trim().is_empty() || text.len() > max_len {
        return Err(AuditEventError::InvalidMetadataValue { key });
    }

    Ok(())
}

fn validate_hex_string(
    key: &'static str,
    value: &Value,
    expected_len: usize,
) -> Result<(), AuditEventError> {
    let text = value
        .as_str()
        .ok_or(AuditEventError::InvalidMetadataValue { key })?;

    if text.len() != expected_len
        || !text
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
    {
        return Err(AuditEventError::InvalidMetadataValue { key });
    }

    Ok(())
}

fn validate_exact_string(
    key: &'static str,
    value: &Value,
    expected: &'static str,
) -> Result<(), AuditEventError> {
    let text = value
        .as_str()
        .ok_or(AuditEventError::InvalidMetadataValue { key })?;
    if text != expected {
        return Err(AuditEventError::InvalidMetadataValue { key });
    }

    Ok(())
}

/// 文字列メタデータが許可値リストのいずれかに一致するかを検証する。
fn validate_enum_metadata_value(
    key: &'static str,
    value: &Value,
    allowed: &[&str],
) -> Result<(), AuditEventError> {
    let text = value
        .as_str()
        .ok_or(AuditEventError::InvalidMetadataValue { key })?;
    if !allowed.contains(&text) {
        return Err(AuditEventError::InvalidMetadataValue { key });
    }

    Ok(())
}

fn incident_type_allowed(value: &str) -> bool {
    matches!(
        value,
        "hash_chain_mismatch"
            | "signature_mismatch"
            | "monthly_digest_mismatch"
            | "digest_timestamping_mismatch"
            | "archive_export_mismatch"
            | "sequence_gap"
            | "unknown_signature_key"
            | "non_auditor_ledger_read"
            | "ledger_secret_leak_suspected"
            | "siem_long_failure"
            | "audit_ui_forbidden_operation"
            | "scheduler_failure"
    )
}

pub const INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST: &[&str] = &[
    "current_version_invalid",
    "version_invalid",
    "retention_exceeded",
    "ciphertext_empty",
    "encrypted_data_key_empty",
    "nonce_length_invalid",
    "algorithm_invalid",
    "nonce_duplicate",
    "aad_keys_invalid",
    "aad_row_mismatch",
    "created_at_mismatch",
    "audit_action_invalid",
    "audit_result_invalid",
    "audit_metadata_not_object",
    "audit_metadata_forbidden_key",
    "audit_source_event_at_invalid",
];

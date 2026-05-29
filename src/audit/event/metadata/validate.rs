//! `AuditMetadata` の action 別 allowlist / 必須キー / 値検証ロジック。
//!
//! `AuditMetadata::validate_allowlist_for_action` から呼び出される検証関数を
//! まとめている。`metadata.rs` 本体（構築・正規化・禁止キー排除）から検証の
//! 詳細を分離するための内部モジュール。

use std::collections::HashSet;

use serde_json::{Map, Value};

use super::{
    AuditAction, AuditEventError, AuditEventId, AuditResult, SOURCE_EVENT_AT_KEY, SecretVersionId,
    SourceEventAt, TRIGGER_KEY,
};

/// Validates that all top-level keys in `object` are in the allowlist for the
/// given action and result. Also checks `violation_summary` sub-object keys for
/// the `integrity_check` action.
pub(super) fn validate_allowlist_for_action(
    object: &Map<String, Value>,
    action: AuditAction,
    result: AuditResult,
) -> Result<(), AuditEventError> {
    let allowed_keys: HashSet<&str> = match action {
        AuditAction::EncryptCreate | AuditAction::EncryptRotate | AuditAction::VersionPurge => {
            ["version", "secret_version_id", SOURCE_EVENT_AT_KEY]
                .iter()
                .cloned()
                .collect()
        }
        AuditAction::Decrypt => {
            if result == AuditResult::Failure {
                ["attempted_secret_id", SOURCE_EVENT_AT_KEY]
                    .iter()
                    .cloned()
                    .collect()
            } else {
                [SOURCE_EVENT_AT_KEY].iter().cloned().collect()
            }
        }
        AuditAction::IntegrityCheck => {
            if let Some(summary) = object.get("violation_summary")
                && let Some(summary_obj) = summary.as_object()
            {
                let allowed_summary_keys: HashSet<&str> =
                    INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST
                        .iter()
                        .cloned()
                        .collect();
                for key in summary_obj.keys() {
                    if !allowed_summary_keys.contains(key.as_str()) {
                        return Err(AuditEventError::UnknownMetadataKey { key: key.clone() });
                    }
                }
            } else if object.get("violation_summary").is_some() {
                return Err(AuditEventError::ViolationSummaryMustBeObject);
            }
            [
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
            ]
            .iter()
            .cloned()
            .collect()
        }
        AuditAction::RestoreTest => [
            "phase",
            "sample_count",
            TRIGGER_KEY,
            "duration_ms",
            "error_code",
            "failed_version",
            "reason",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::AuthFailure => ["error_code", SOURCE_EVENT_AT_KEY]
            .iter()
            .cloned()
            .collect(),
        AuditAction::KeyRotationStart => {
            ["old_key_version", "new_key_version", SOURCE_EVENT_AT_KEY]
                .iter()
                .cloned()
                .collect()
        }
        AuditAction::KeyRotationReencrypt => [
            "old_key_version",
            "new_key_version",
            "batch_size",
            "processed_count",
            "remaining_count",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::KeyRotationComplete => [
            "old_key_version",
            "new_key_version",
            "remaining_count",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::KeyRotationEnvelopeMigrated => [
            "batch_size",
            "success_count",
            "failure_count",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::KeyRotationEnvelopeFailed => [
            "secret_version_id",
            "version",
            "error_code",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::SignatureKeyCreated => [
            "created_at",
            "public_key_fingerprint",
            "signature_key_version",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::SignatureKeyActivated => [
            "activated_at",
            "public_key_fingerprint",
            "signature_key_version",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::SignatureKeyRetired => [
            "public_key_fingerprint",
            "retired_at",
            "signature_key_version",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        // 月次 digest 生成失敗時の監査記録。
        // error_code は failure result 時のみ記録する。
        AuditAction::MonthlyDigestGenerate => [
            "digest_hash",
            "end_sequence_no",
            "entry_count",
            "error_code",
            "signature_key_version",
            "start_sequence_no",
            "target_year_month",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        // 月次 digest 検証失敗時の監査記録。
        AuditAction::MonthlyDigestVerify => [
            "error_code",
            "target_year_month",
            "verify_result",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        // 外部アーカイブ export（成功・失敗両方を記録）。
        // archive_key は success 時のみ有効（validate_metadata_values で検証）。
        AuditAction::ArchiveExport => [
            "archive_key",
            "digest_hash",
            "target_year_month",
            "error_code",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        // 月次 digest 外部 timestamping（成功・失敗両方を記録）。
        // timestamp_token_hash は success 時のみ有効
        // （validate_metadata_values で検証）。
        AuditAction::DigestTimestamping => [
            "digest_hash",
            "error_code",
            "target_year_month",
            "timestamp_token_hash",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        // SIEM への監査イベント転送失敗（failure-only）。
        // event_type は転送しようとした監査の audit_action 文字列、
        // event_count はバッチ送信時の件数。
        AuditAction::SiemForwardFailure => [
            "error_code",
            "event_type",
            "event_count",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        // 監査レポート生成（成功・失敗両方を記録）。
        AuditAction::AuditReportGenerate => [
            "format",
            "period_end",
            "period_start",
            "error_code",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::AuditUiRead => [
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
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::SchedulerJob => [
            "duration_ms",
            "error_code",
            "job_name",
            "target_year_month",
            TRIGGER_KEY,
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::IncidentDetected => [
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
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::SecretAliasCreate => [
            "alias_fingerprint",
            "alias_fingerprint_key_version",
            "alias_fingerprint_schema_version",
            "error_code",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::SecretAliasUpdate => [
            "old_alias_fingerprint",
            "new_alias_fingerprint",
            "alias_fingerprint_key_version",
            "alias_fingerprint_schema_version",
            "error_code",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::SecretAliasDelete => [
            "alias_fingerprint",
            "alias_fingerprint_key_version",
            "alias_fingerprint_schema_version",
            "error_code",
            SOURCE_EVENT_AT_KEY,
        ]
        .iter()
        .cloned()
        .collect(),
        AuditAction::SecretAliasList => ["result_count", "error_code", SOURCE_EVENT_AT_KEY]
            .iter()
            .cloned()
            .collect(),
    };

    for key in object.keys() {
        if !allowed_keys.contains(key.as_str()) {
            return Err(AuditEventError::UnknownMetadataKey { key: key.clone() });
        }
    }

    validate_required_metadata_keys(action, result, object, true)?;
    validate_metadata_values(action, result, object)?;

    Ok(())
}

fn validate_required_metadata_keys(
    action: AuditAction,
    result: AuditResult,
    object: &Map<String, Value>,
    require_source_event_at: bool,
) -> Result<(), AuditEventError> {
    let mut required: Vec<&'static str> = match action {
        AuditAction::EncryptCreate | AuditAction::EncryptRotate | AuditAction::VersionPurge => {
            vec!["version", "secret_version_id"]
        }
        AuditAction::Decrypt => Vec::new(),
        AuditAction::IntegrityCheck => vec![
            "check_name",
            "checked_secret_count",
            "checked_secret_version_count",
            "checked_audit_event_count",
            "duration_ms",
            "violation_count",
            "violation_summary",
            TRIGGER_KEY,
        ],
        AuditAction::RestoreTest => vec!["phase", "sample_count", TRIGGER_KEY, "duration_ms"],
        AuditAction::AuthFailure => vec!["error_code"],
        AuditAction::KeyRotationStart => vec!["old_key_version", "new_key_version"],
        AuditAction::KeyRotationReencrypt => vec![
            "old_key_version",
            "new_key_version",
            "batch_size",
            "processed_count",
            "remaining_count",
        ],
        AuditAction::KeyRotationComplete => {
            vec!["old_key_version", "new_key_version", "remaining_count"]
        }
        AuditAction::KeyRotationEnvelopeMigrated => {
            vec!["batch_size", "success_count", "failure_count"]
        }
        AuditAction::KeyRotationEnvelopeFailed => {
            vec!["secret_version_id", "version", "error_code"]
        }
        AuditAction::SignatureKeyCreated => {
            vec![
                "signature_key_version",
                "public_key_fingerprint",
                "created_at",
            ]
        }
        AuditAction::SignatureKeyActivated => {
            vec![
                "signature_key_version",
                "public_key_fingerprint",
                "activated_at",
            ]
        }
        AuditAction::SignatureKeyRetired => {
            vec![
                "signature_key_version",
                "public_key_fingerprint",
                "retired_at",
            ]
        }
        AuditAction::MonthlyDigestGenerate => {
            if result == AuditResult::Success {
                vec![
                    "target_year_month",
                    "start_sequence_no",
                    "end_sequence_no",
                    "entry_count",
                    "signature_key_version",
                    "digest_hash",
                ]
            } else {
                vec!["target_year_month", "error_code"]
            }
        }
        AuditAction::MonthlyDigestVerify => {
            if result == AuditResult::Success {
                vec!["target_year_month", "verify_result"]
            } else {
                vec!["target_year_month", "verify_result", "error_code"]
            }
        }
        // archive export は target_year_month が常に必須。
        AuditAction::ArchiveExport => vec!["target_year_month"],
        // digest timestamping も target_year_month が常に必須。
        AuditAction::DigestTimestamping => vec!["target_year_month"],
        // SIEM forward failure は error_code が常に必須（failure-only）。
        AuditAction::SiemForwardFailure => vec!["error_code"],
        // audit_report_generate は対象期間と出力形式が常に必須。
        AuditAction::AuditReportGenerate => vec!["format", "period_end", "period_start"],
        AuditAction::AuditUiRead => vec!["endpoint", "method", "resource"],
        AuditAction::SchedulerJob => vec!["job_name", TRIGGER_KEY, "duration_ms"],
        AuditAction::IncidentDetected => vec![
            "incident_type",
            "severity",
            "detection_source",
            "dedupe_key",
            "notification_sink",
            "notification_result",
            "error_code",
        ],
        AuditAction::SecretAliasCreate => {
            if result == AuditResult::Success {
                vec![
                    "alias_fingerprint",
                    "alias_fingerprint_key_version",
                    "alias_fingerprint_schema_version",
                ]
            } else {
                Vec::new()
            }
        }
        AuditAction::SecretAliasUpdate => {
            if result == AuditResult::Success {
                vec![
                    "old_alias_fingerprint",
                    "new_alias_fingerprint",
                    "alias_fingerprint_key_version",
                    "alias_fingerprint_schema_version",
                ]
            } else {
                Vec::new()
            }
        }
        AuditAction::SecretAliasDelete => {
            if result == AuditResult::Success {
                vec![
                    "alias_fingerprint",
                    "alias_fingerprint_key_version",
                    "alias_fingerprint_schema_version",
                ]
            } else {
                Vec::new()
            }
        }
        AuditAction::SecretAliasList => {
            if result == AuditResult::Success {
                vec!["result_count"]
            } else {
                Vec::new()
            }
        }
    };

    if require_source_event_at {
        required.push(SOURCE_EVENT_AT_KEY);
    }

    for key in required {
        if !object.contains_key(key) {
            return Err(AuditEventError::MissingMetadataKey { key });
        }
    }

    if action == AuditAction::IntegrityCheck {
        let summary = object
            .get("violation_summary")
            .and_then(Value::as_object)
            .ok_or(AuditEventError::ViolationSummaryMustBeObject)?;
        for key in INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST {
            if !summary.contains_key(*key) {
                return Err(AuditEventError::MissingMetadataKey { key });
            }
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
    validate_string_metadata_values(result, object)?;
    validate_timestamp_metadata_values(object)?;
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
        let text = value
            .as_str()
            .ok_or(AuditEventError::InvalidMetadataValue { key: "severity" })?;
        if !matches!(text, "critical" | "high" | "medium" | "low") {
            return Err(AuditEventError::InvalidMetadataValue { key: "severity" });
        }
    }

    if let Some(value) = object.get("notification_result") {
        let text = value
            .as_str()
            .ok_or(AuditEventError::InvalidMetadataValue {
                key: "notification_result",
            })?;
        if !matches!(text, "sent" | "failed" | "suppressed" | "not_configured") {
            return Err(AuditEventError::InvalidMetadataValue {
                key: "notification_result",
            });
        }
    }

    if let Some(value) = object.get("format") {
        let text = value
            .as_str()
            .ok_or(AuditEventError::InvalidMetadataValue { key: "format" })?;
        if text != "json" && text != "markdown" {
            return Err(AuditEventError::InvalidMetadataValue { key: "format" });
        }
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
        validate_exact_string("reason", value, "no_current_secret_versions")?;
    }

    Ok(())
}

/// 時刻・期間系メタデータ（タイムスタンプ / 年月）の形式を検証する。
fn validate_timestamp_metadata_values(object: &Map<String, Value>) -> Result<(), AuditEventError> {
    for key in ["created_at", "activated_at", "retired_at"] {
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

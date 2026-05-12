mod builders;

use std::collections::HashSet;
use std::fmt;

use serde_json::{Map, Value, json};

pub use builders::{
    ArchiveExportMetadata, AuditReportGenerateMetadata, AuthFailureMetadata, DecryptMetadata,
    DigestTimestampingMetadata, EncryptCreateMetadata, EncryptRotateMetadata,
    IntegrityCheckMetadata, KeyRotationCompleteMetadata, KeyRotationReencryptMetadata,
    KeyRotationStartMetadata, MonthlyDigestGenerateMetadata, MonthlyDigestVerifyMetadata,
    RestoreTestMetadata, SchedulerJobMetadata, SiemForwardFailureMetadata, VersionPurgeMetadata,
};

use crate::types::{SecretId, SecretVersionId, SourceEventAt};

use super::super::error::AuditEventError;
use super::action::{AuditAction, AuditResult};
use super::validation::canonicalize_source_event_at;

pub(super) const SOURCE_EVENT_AT_KEY: &str = "source_event_at";
const TRIGGER_KEY: &str = "trigger";

pub const FORBIDDEN_AUDIT_METADATA_KEYS: &[&str] = &[
    "authorization",
    "authorization_header",
    "bearer_token",
    "ciphertext",
    "data_key",
    "decrypt_result",
    "decrypted",
    "decrypted_data",
    "encrypted_data_key",
    "jwt",
    "jwt_full",
    "master_key",
    "passphrase",
    "password",
    "plain_text",
    "plaintext",
    "raw_jwt",
    "request_body",
    "request_body_full",
    "response_body",
    "response_body_full",
    "secret_key",
    "secret_value",
    "service_role",
    "service_role_key",
    "token",
];

#[derive(Clone, PartialEq, Eq)]
pub struct AuditMetadata(Value);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditTrigger {
    Startup,
    Background,
    Cli,
}

impl AuditTrigger {
    pub fn parse(value: &str) -> Result<Self, AuditEventError> {
        match value {
            "startup" => Ok(Self::Startup),
            "background" => Ok(Self::Background),
            "cli" => Ok(Self::Cli),
            _ => Err(AuditEventError::InvalidTrigger {
                value: value.to_owned(),
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Background => "background",
            Self::Cli => "cli",
        }
    }
}

impl AuditMetadata {
    /// Constructs audit metadata from a JSON object.
    ///
    /// New action-specific code should prefer the typed builders in
    /// `audit::event::metadata::builders` so unknown keys cannot be introduced
    /// at call sites. This constructor remains public for compatibility and for
    /// deserializing persisted fallback records.
    pub fn new(value: Value) -> Result<Self, AuditEventError> {
        let object = value
            .as_object()
            .cloned()
            .ok_or(AuditEventError::MetadataMustBeObject)?;
        Self::from_object(object)
    }

    pub(crate) fn from_object(mut object: Map<String, Value>) -> Result<Self, AuditEventError> {
        reject_forbidden_metadata_keys_in_object(&object)?;
        validate_trigger(&object)?;
        canonicalize_source_event_at(&mut object)?;

        Ok(Self(Value::Object(object)))
    }

    pub fn empty() -> Self {
        Self(json!({}))
    }

    pub fn with_current_source_event_at(self) -> Result<Self, AuditEventError> {
        if self.source_event_at()?.is_some() {
            return Ok(self);
        }

        let source_event_at =
            SourceEventAt::now_utc().map_err(|_| AuditEventError::SourceEventAtUnavailable)?;

        self.with_source_event_at(source_event_at)
    }

    pub fn with_trigger(self, trigger: AuditTrigger) -> Result<Self, AuditEventError> {
        let mut object = self
            .0
            .as_object()
            .cloned()
            .ok_or(AuditEventError::MetadataMustBeObject)?;
        object.insert(
            TRIGGER_KEY.to_owned(),
            Value::String(trigger.as_str().to_owned()),
        );

        Self::new(Value::Object(object))
    }

    pub fn with_attempted_secret_id(self, secret_id: &SecretId) -> Result<Self, AuditEventError> {
        let mut object = self
            .0
            .as_object()
            .cloned()
            .ok_or(AuditEventError::MetadataMustBeObject)?;
        object.insert(
            "attempted_secret_id".to_owned(),
            Value::String(secret_id.as_canonical_string()),
        );

        Self::new(Value::Object(object))
    }

    pub fn with_source_event_at(
        self,
        source_event_at: SourceEventAt,
    ) -> Result<Self, AuditEventError> {
        let mut object = self
            .0
            .as_object()
            .cloned()
            .ok_or(AuditEventError::MetadataMustBeObject)?;
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(source_event_at.as_str().to_owned()),
        );

        Self::new(Value::Object(object))
    }

    pub fn as_value(&self) -> &Value {
        &self.0
    }

    pub fn source_event_at_required(&self) -> Result<SourceEventAt, AuditEventError> {
        self.require_source_event_at()
    }

    pub(super) fn require_source_event_at(&self) -> Result<SourceEventAt, AuditEventError> {
        self.source_event_at()?
            .ok_or(AuditEventError::MissingSourceEventAt)
    }

    fn source_event_at(&self) -> Result<Option<SourceEventAt>, AuditEventError> {
        let object = self
            .0
            .as_object()
            .ok_or(AuditEventError::MetadataMustBeObject)?;
        let Some(value) = object.get(SOURCE_EVENT_AT_KEY) else {
            return Ok(None);
        };
        let text = value
            .as_str()
            .ok_or(AuditEventError::InvalidSourceEventAt)?;

        SourceEventAt::parse(text)
            .map(Some)
            .map_err(|_| AuditEventError::InvalidSourceEventAt)
    }

    fn key_count(&self) -> usize {
        self.0.as_object().map_or(0, Map::len)
    }

    /// Validates that all top-level keys in this metadata are in the allowlist
    /// for the given action and result. Also checks `violation_summary` sub-object
    /// keys for `integrity_check` action.
    pub fn validate_allowlist_for_action(
        &self,
        action: AuditAction,
        result: AuditResult,
    ) -> Result<(), AuditEventError> {
        let object = self
            .0
            .as_object()
            .ok_or(AuditEventError::MetadataMustBeObject)?;

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
            // 月次 digest 生成失敗時の監査記録。
            // error_code は failure result 時のみ記録する。
            AuditAction::MonthlyDigestGenerate => {
                ["error_code", "target_year_month", SOURCE_EVENT_AT_KEY]
                    .iter()
                    .cloned()
                    .collect()
            }
            // 月次 digest 検証失敗時の監査記録。
            AuditAction::MonthlyDigestVerify => {
                ["error_code", "target_year_month", SOURCE_EVENT_AT_KEY]
                    .iter()
                    .cloned()
                    .collect()
            }
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
        };

        for key in object.keys() {
            if !allowed_keys.contains(key.as_str()) {
                return Err(AuditEventError::UnknownMetadataKey { key: key.clone() });
            }
        }

        validate_required_metadata_keys(action, object, true)?;
        validate_metadata_values(action, result, object)?;

        Ok(())
    }
}

fn validate_required_metadata_keys(
    action: AuditAction,
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
        // monthly_digest_generate / verify は failure 時のみ記録されるが、
        // error_code は必須ではなく、source_event_at のみが必須。
        AuditAction::MonthlyDigestGenerate | AuditAction::MonthlyDigestVerify => Vec::new(),
        // archive export は target_year_month が常に必須。
        AuditAction::ArchiveExport => vec!["target_year_month"],
        // digest timestamping も target_year_month が常に必須。
        AuditAction::DigestTimestamping => vec!["target_year_month"],
        // SIEM forward failure は error_code が常に必須（failure-only）。
        AuditAction::SiemForwardFailure => vec!["error_code"],
        // audit_report_generate は対象期間と出力形式が常に必須。
        AuditAction::AuditReportGenerate => vec!["format", "period_end", "period_start"],
        AuditAction::SchedulerJob => vec!["job_name", TRIGGER_KEY, "duration_ms"],
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
    for key in [
        "checked_secret_count",
        "checked_secret_version_count",
        "checked_audit_event_count",
        "duration_ms",
        "violation_count",
        "sample_count",
        "processed_count",
        "remaining_count",
    ] {
        if let Some(value) = object.get(key) {
            validate_u64_value(key, value)?;
        }
    }

    for key in [
        "version",
        "old_key_version",
        "new_key_version",
        "batch_size",
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

    for key in ["secret_version_id", "attempted_secret_id"] {
        if let Some(value) = object.get(key) {
            let text = value
                .as_str()
                .ok_or(AuditEventError::InvalidMetadataValue { key })?;
            SecretVersionId::parse(text)
                .map_err(|_| AuditEventError::InvalidMetadataValue { key })?;
        }
    }

    if object.contains_key("attempted_secret_id")
        && !(action == AuditAction::Decrypt && result == AuditResult::Failure)
    {
        return Err(AuditEventError::InvalidMetadataValue {
            key: "attempted_secret_id",
        });
    }

    if let Some(value) = object.get("error_code") {
        if result != AuditResult::Failure {
            return Err(AuditEventError::InvalidMetadataValue { key: "error_code" });
        }
        validate_non_blank_short_string("error_code", value, 64)?;
    }

    if let Some(value) = object.get("job_name") {
        validate_non_blank_short_string("job_name", value, 96)?;
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

    if let Some(value) = object.get("format") {
        let text = value
            .as_str()
            .ok_or(AuditEventError::InvalidMetadataValue { key: "format" })?;
        if text != "json" && text != "markdown" {
            return Err(AuditEventError::InvalidMetadataValue { key: "format" });
        }
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

impl fmt::Debug for AuditMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditMetadata")
            .field("key_count", &self.key_count())
            .field("contents", &"<redacted>")
            .finish()
    }
}

fn reject_forbidden_metadata_keys_in_object(
    object: &Map<String, Value>,
) -> Result<(), AuditEventError> {
    for (key, value) in object {
        if is_forbidden_metadata_key(key) {
            return Err(AuditEventError::ForbiddenMetadataKey {
                key: key.to_owned(),
            });
        }

        reject_forbidden_metadata_keys(value)?;
    }

    Ok(())
}

fn reject_forbidden_metadata_keys(value: &Value) -> Result<(), AuditEventError> {
    match value {
        Value::Object(object) => reject_forbidden_metadata_keys_in_object(object),
        Value::Array(values) => {
            for value in values {
                reject_forbidden_metadata_keys(value)?;
            }

            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
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

fn is_forbidden_metadata_key(key: &str) -> bool {
    let normalized = key.trim().to_ascii_lowercase();
    FORBIDDEN_AUDIT_METADATA_KEYS
        .iter()
        .any(|forbidden| normalized == *forbidden)
}

fn validate_trigger(object: &Map<String, Value>) -> Result<(), AuditEventError> {
    let Some(value) = object.get(TRIGGER_KEY) else {
        return Ok(());
    };
    let text = value
        .as_str()
        .ok_or_else(|| AuditEventError::InvalidTrigger {
            value: value.to_string(),
        })?;

    AuditTrigger::parse(text).map(|_| ())
}

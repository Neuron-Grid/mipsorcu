mod builders;

use std::collections::HashSet;
use std::fmt;

use serde_json::{Map, Value, json};

pub use builders::{
    AuthFailureMetadata, DecryptMetadata, EncryptCreateMetadata, EncryptRotateMetadata,
    IntegrityCheckMetadata, KeyRotationCompleteMetadata, KeyRotationReencryptMetadata,
    KeyRotationStartMetadata, RestoreTestMetadata, VersionPurgeMetadata,
};

use crate::types::{SecretId, SourceEventAt};

use super::super::error::AuditEventError;
use super::action::{AuditAction, AuditResult};
use super::validation::canonicalize_source_event_at;

pub(super) const SOURCE_EVENT_AT_KEY: &str = "source_event_at";
const TRIGGER_KEY: &str = "trigger";

pub const FORBIDDEN_AUDIT_METADATA_KEYS: &[&str] = &[
    "authorization",
    "ciphertext",
    "data_key",
    "decrypt_result",
    "decrypted",
    "decrypted_data",
    "encrypted_data_key",
    "jwt",
    "master_key",
    "passphrase",
    "password",
    "plain_text",
    "plaintext",
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
    pub fn new(value: Value) -> Result<Self, AuditEventError> {
        let mut object = value
            .as_object()
            .cloned()
            .ok_or(AuditEventError::MetadataMustBeObject)?;
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
                [
                    "version",
                    "secret_version_id",
                    "attempted_secret_id",
                    SOURCE_EVENT_AT_KEY,
                ]
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
        };

        for key in object.keys() {
            if !allowed_keys.contains(key.as_str()) {
                return Err(AuditEventError::UnknownMetadataKey { key: key.clone() });
            }
        }

        Ok(())
    }
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

mod allowlists;
mod builders;
mod validate;

use std::fmt;

use serde_json::{Map, Value, json};

pub use allowlists::required_metadata_keys;
pub use validate::{
    INCIDENT_NOTIFICATION_CATEGORY_ALLOWLIST, INCIDENT_TYPE_ALLOWLIST,
    INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST, NOTIFIER_KIND_ALLOWLIST,
};

pub use builders::{
    ArchiveExportMetadata, AuditReportGenerateMetadata, AuditUiReadMetadata, AuthFailureMetadata,
    DecryptMetadata, DigestTimestampingMetadata, EncryptCreateMetadata, EncryptRotateMetadata,
    IncidentDetectedMetadata, IncidentNotificationFailedMetadata, IncidentNotificationSentMetadata,
    IncidentNotificationSuppressedMetadata, IntegrityCheckMetadata, KeyRotationCompleteMetadata,
    KeyRotationEnvelopeFailedMetadata, KeyRotationEnvelopeMigratedMetadata,
    KeyRotationReencryptMetadata, KeyRotationStartMetadata, MonthlyDigestGenerateMetadata,
    MonthlyDigestVerifyMetadata, RestoreTestMetadata, SchedulerJobMetadata,
    SecretAliasCreateMetadata, SecretAliasDeleteMetadata, SecretAliasListMetadata,
    SecretAliasUpdateMetadata, SiemBufferFlushedMetadata, SiemEventFailedMetadata,
    SiemEventForwardedMetadata, SiemForwardFailureMetadata, SignatureKeyActivatedMetadata,
    SignatureKeyCreatedMetadata, SignatureKeyRetiredMetadata, VersionPurgeMetadata,
};

use crate::types::{SecretId, SecretVersionId, SourceEventAt};

use super::super::error::AuditEventError;
use super::action::{AuditAction, AuditResult};
use super::id::AuditEventId;
use super::validation::canonicalize_source_event_at;

pub(super) const SOURCE_EVENT_AT_KEY: &str = "source_event_at";
const TRIGGER_KEY: &str = "trigger";

pub const FORBIDDEN_AUDIT_METADATA_KEYS: &[&str] = &[
    "alias_decryption_key",
    "alias_encryption_key",
    "alias_fingerprint_key",
    "alias_nonce",
    "authorization",
    "authorization_header",
    "bearer_token",
    "canonical_alias_plaintext",
    "ciphertext",
    "data_key",
    "decrypt_result",
    "decrypted",
    "decrypted_data",
    "ed25519_private_key",
    "encrypted_data_key",
    "jwt",
    "jwt_full",
    "kek_value",
    "ledger_signing_key",
    "master_key",
    "nonce",
    "nonce_or_iv",
    "passphrase",
    "password",
    "plain_text",
    "plaintext",
    "raw_jwt",
    "request_body",
    "request_body_full",
    "response_body",
    "response_body_full",
    "secret_body",
    "secret_key",
    "secret_value",
    "service_role",
    "service_role_key",
    "signature_private_key",
    "token",
    "wrapped_dek",
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

        validate::validate_allowlist_for_action(object, action, result)
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

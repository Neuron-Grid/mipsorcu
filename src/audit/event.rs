use std::fmt;

use serde_json::{Map, Value, json};
use uuid::{Builder, Uuid};

use crate::types::{DeviceId, KeyVersion, OwnerUserId, SecretId, SourceEventAt};

use super::error::{AuditAppendError, AuditEventError, LocalAuditStoreError};
use super::fallback::{DeliveryStatus, current_occurred_at};

const SOURCE_EVENT_AT_KEY: &str = "source_event_at";

pub const FORBIDDEN_AUDIT_METADATA_KEYS: &[&str] = &[
    "plaintext",
    "plain_text",
    "decrypted",
    "decrypted_data",
    "master_key",
    "data_key",
    "jwt",
    "service_role_key",
    "secret_key",
    "passphrase",
    "ciphertext",
    "encrypted_data_key",
];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditEventId(Uuid);

impl AuditEventId {
    pub fn generate() -> Result<Self, AuditEventError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| AuditEventError::InvalidUuid {
            field: "audit_event_id",
        })?;
        let uuid = Builder::from_random_bytes(bytes).into_uuid();

        Ok(Self(uuid))
    }

    pub fn parse(value: &str) -> Result<Self, AuditEventError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| AuditEventError::InvalidUuid {
                field: "audit_event_id",
            })
    }

    pub fn as_canonical_string(&self) -> String {
        self.0.hyphenated().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(Uuid);

impl RequestId {
    pub fn generate() -> Result<Self, AuditEventError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| AuditEventError::InvalidUuid {
            field: "request_id",
        })?;
        let uuid = Builder::from_random_bytes(bytes).into_uuid();

        Ok(Self(uuid))
    }

    pub fn nil() -> Self {
        Self(Uuid::nil())
    }

    pub fn parse(value: &str) -> Result<Self, AuditEventError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| AuditEventError::InvalidUuid {
                field: "request_id",
            })
    }

    pub fn as_canonical_string(&self) -> String {
        self.0.hyphenated().to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditAction {
    EncryptCreate,
    EncryptRotate,
    Decrypt,
    VersionPurge,
    IntegrityCheck,
    RestoreTest,
    KeyRotationStart,
    KeyRotationReencrypt,
    KeyRotationComplete,
}

impl AuditAction {
    pub fn parse(value: &str) -> Result<Self, AuditEventError> {
        match value {
            "encrypt_create" => Ok(Self::EncryptCreate),
            "encrypt_rotate" => Ok(Self::EncryptRotate),
            "decrypt" => Ok(Self::Decrypt),
            "version_purge" => Ok(Self::VersionPurge),
            "integrity_check" => Ok(Self::IntegrityCheck),
            "restore_test" => Ok(Self::RestoreTest),
            "key_rotation_start" => Ok(Self::KeyRotationStart),
            "key_rotation_reencrypt" => Ok(Self::KeyRotationReencrypt),
            "key_rotation_complete" => Ok(Self::KeyRotationComplete),
            _ => Err(AuditEventError::UnknownAction {
                value: value.to_owned(),
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EncryptCreate => "encrypt_create",
            Self::EncryptRotate => "encrypt_rotate",
            Self::Decrypt => "decrypt",
            Self::VersionPurge => "version_purge",
            Self::IntegrityCheck => "integrity_check",
            Self::RestoreTest => "restore_test",
            Self::KeyRotationStart => "key_rotation_start",
            Self::KeyRotationReencrypt => "key_rotation_reencrypt",
            Self::KeyRotationComplete => "key_rotation_complete",
        }
    }

    pub(super) fn is_write_success_only(self) -> bool {
        matches!(
            self,
            Self::EncryptCreate | Self::EncryptRotate | Self::VersionPurge
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditResult {
    Success,
    Failure,
}

impl AuditResult {
    pub fn parse(value: &str) -> Result<Self, AuditEventError> {
        match value {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            _ => Err(AuditEventError::UnknownResult {
                value: value.to_owned(),
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuditMetadata(Value);

impl AuditMetadata {
    pub fn new(value: Value) -> Result<Self, AuditEventError> {
        let mut object = value
            .as_object()
            .cloned()
            .ok_or(AuditEventError::MetadataMustBeObject)?;
        reject_forbidden_metadata_keys_in_object(&object)?;
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

    fn require_source_event_at(&self) -> Result<SourceEventAt, AuditEventError> {
        self.source_event_at()?
            .ok_or(AuditEventError::MissingSourceEventAt)
    }

    fn key_count(&self) -> usize {
        self.0.as_object().map_or(0, Map::len)
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

#[derive(Clone, PartialEq, Eq)]
pub struct AuditEvent {
    audit_event_id: AuditEventId,
    request_id: RequestId,
    actor_user_id: Option<OwnerUserId>,
    actor_device_id: Option<DeviceId>,
    action: AuditAction,
    target_secret_id: Option<SecretId>,
    result: AuditResult,
    key_version: Option<KeyVersion>,
    metadata_json: AuditMetadata,
}

impl AuditEvent {
    pub fn new(parts: AuditEventParts) -> Result<Self, AuditEventError> {
        if parts.result == AuditResult::Success && parts.action.is_write_success_only() {
            return Err(AuditEventError::WriteSuccessActionNotAllowed {
                action: parts.action,
            });
        }

        parts.metadata_json.require_source_event_at()?;
        let metadata_json = parts.metadata_json;

        Ok(Self {
            audit_event_id: parts.audit_event_id,
            request_id: parts.request_id,
            actor_user_id: parts.actor_user_id,
            actor_device_id: parts.actor_device_id,
            action: parts.action,
            target_secret_id: parts.target_secret_id,
            result: parts.result,
            key_version: parts.key_version,
            metadata_json,
        })
    }

    pub fn audit_event_id(&self) -> &AuditEventId {
        &self.audit_event_id
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn actor_user_id(&self) -> Option<&OwnerUserId> {
        self.actor_user_id.as_ref()
    }

    pub fn actor_device_id(&self) -> Option<&DeviceId> {
        self.actor_device_id.as_ref()
    }

    pub fn action(&self) -> AuditAction {
        self.action
    }

    pub fn target_secret_id(&self) -> Option<&SecretId> {
        self.target_secret_id.as_ref()
    }

    pub fn result(&self) -> AuditResult {
        self.result
    }

    pub fn key_version(&self) -> Option<KeyVersion> {
        self.key_version
    }

    pub fn metadata_json(&self) -> &AuditMetadata {
        &self.metadata_json
    }

    pub(super) fn to_fallback_json(
        &self,
        delivery_status: DeliveryStatus,
    ) -> Result<Value, LocalAuditStoreError> {
        Ok(json!({
            "audit_event_id": self.audit_event_id.as_canonical_string(),
            "request_id": self.request_id.as_canonical_string(),
            "actor_user_id": self.actor_user_id
                .as_ref()
                .map(OwnerUserId::as_canonical_string),
            "actor_device_id": self.actor_device_id.as_ref().map(DeviceId::as_str),
            "action": self.action.as_str(),
            "target_secret_id": self.target_secret_id
                .as_ref()
                .map(SecretId::as_canonical_string),
            "result": self.result.as_str(),
            "key_version": self.key_version.map(KeyVersion::get),
            "metadata_json": self.metadata_json.as_value(),
            "occurred_at": current_occurred_at()?,
            "delivery_status": delivery_status.as_str(),
        }))
    }
}

impl fmt::Debug for AuditEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditEvent")
            .field("audit_event_id", &self.audit_event_id)
            .field("request_id", &self.request_id)
            .field("actor_user_id", &self.actor_user_id)
            .field("actor_device_id", &self.actor_device_id)
            .field("action", &self.action)
            .field("target_secret_id", &self.target_secret_id)
            .field("result", &self.result)
            .field("key_version", &self.key_version)
            .field("metadata_json", &self.metadata_json)
            .finish()
    }
}

pub struct AuditEventParts {
    pub audit_event_id: AuditEventId,
    pub request_id: RequestId,
    pub actor_user_id: Option<OwnerUserId>,
    pub actor_device_id: Option<DeviceId>,
    pub action: AuditAction,
    pub target_secret_id: Option<SecretId>,
    pub result: AuditResult,
    pub key_version: Option<KeyVersion>,
    pub metadata_json: AuditMetadata,
}

pub trait AuditEventAppender {
    fn append_audit_event(&self, event: &AuditEvent) -> Result<(), AuditAppendError>;
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

fn canonicalize_source_event_at(object: &mut Map<String, Value>) -> Result<(), AuditEventError> {
    let Some(value) = object.get(SOURCE_EVENT_AT_KEY) else {
        return Ok(());
    };
    let text = value
        .as_str()
        .ok_or(AuditEventError::InvalidSourceEventAt)?;
    let canonical =
        SourceEventAt::parse(text).map_err(|_| AuditEventError::InvalidSourceEventAt)?;
    object.insert(
        SOURCE_EVENT_AT_KEY.to_owned(),
        Value::String(canonical.as_str().to_owned()),
    );

    Ok(())
}

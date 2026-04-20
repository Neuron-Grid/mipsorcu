use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::{Builder, Uuid};

use crate::types::{DeviceId, KeyVersion, OwnerUserId, SecretId};

const DELIVERY_STATUS_PENDING: &str = "pending";
const DELIVERY_STATUS_SENT: &str = "sent";

const FORBIDDEN_METADATA_KEYS: &[&str] = &[
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEventError {
    InvalidUuid { field: &'static str },
    UnknownAction { value: String },
    UnknownResult { value: String },
    WriteSuccessActionNotAllowed { action: AuditAction },
    MetadataMustBeObject,
    ForbiddenMetadataKey { key: String },
}

impl fmt::Display for AuditEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUuid { field } => {
                write!(formatter, "{field} must be a valid UUID")
            }
            Self::UnknownAction { value } => {
                write!(formatter, "unknown audit action: {value}")
            }
            Self::UnknownResult { value } => {
                write!(formatter, "unknown audit result: {value}")
            }
            Self::WriteSuccessActionNotAllowed { action } => {
                write!(
                    formatter,
                    "success audit for {} must be recorded by the write RPC",
                    action.as_str()
                )
            }
            Self::MetadataMustBeObject => {
                write!(formatter, "audit metadata must be a JSON object")
            }
            Self::ForbiddenMetadataKey { key } => {
                write!(formatter, "audit metadata contains forbidden key: {key}")
            }
        }
    }
}

impl std::error::Error for AuditEventError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditAppendError {
    ExternalDependencyFailed { code: &'static str },
    IdempotencyConflict,
}

impl fmt::Display for AuditAppendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExternalDependencyFailed { code } => {
                write!(formatter, "audit append external dependency failed: {code}")
            }
            Self::IdempotencyConflict => {
                write!(formatter, "audit append idempotency conflict")
            }
        }
    }
}

impl std::error::Error for AuditAppendError {}

#[derive(Debug)]
pub enum LocalAuditStoreError {
    Io(std::io::Error),
    Json(serde_json::Error),
    TimestampFormat(time::error::Format),
    InvalidLine {
        line_number: usize,
        reason: &'static str,
    },
    Event(AuditEventError),
}

impl fmt::Display for LocalAuditStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "local audit store I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "local audit store JSON failed: {error}"),
            Self::TimestampFormat(error) => {
                write!(
                    formatter,
                    "local audit store timestamp format failed: {error}"
                )
            }
            Self::InvalidLine {
                line_number,
                reason,
            } => {
                write!(
                    formatter,
                    "local audit store line {line_number} is invalid: {reason}"
                )
            }
            Self::Event(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for LocalAuditStoreError {}

impl From<std::io::Error> for LocalAuditStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for LocalAuditStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<AuditEventError> for LocalAuditStoreError {
    fn from(error: AuditEventError) -> Self {
        Self::Event(error)
    }
}

#[derive(Debug)]
pub enum AuditRecordError {
    PrimaryAndFallbackFailed {
        append_error: AuditAppendError,
        store_error: LocalAuditStoreError,
    },
    ResendReadFailed(LocalAuditStoreError),
    ResendMarkSentFailed(LocalAuditStoreError),
}

impl fmt::Display for AuditRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrimaryAndFallbackFailed {
                append_error,
                store_error,
            } => {
                write!(
                    formatter,
                    "audit append failed ({append_error}) and fallback write failed: {store_error}"
                )
            }
            Self::ResendReadFailed(error) => {
                write!(
                    formatter,
                    "failed to read pending audit fallback events: {error}"
                )
            }
            Self::ResendMarkSentFailed(error) => {
                write!(
                    formatter,
                    "failed to mark audit fallback event as sent: {error}"
                )
            }
        }
    }
}

impl std::error::Error for AuditRecordError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditRecordOutcome {
    PrimarySucceeded,
    FallbackSucceeded,
}

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

    fn is_write_success_only(self) -> bool {
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
        let object = value
            .as_object()
            .ok_or(AuditEventError::MetadataMustBeObject)?;
        reject_forbidden_metadata_keys_in_object(object)?;

        Ok(Self(value))
    }

    pub fn empty() -> Self {
        Self(json!({}))
    }

    pub fn as_value(&self) -> &Value {
        &self.0
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

        Ok(Self {
            audit_event_id: parts.audit_event_id,
            request_id: parts.request_id,
            actor_user_id: parts.actor_user_id,
            actor_device_id: parts.actor_device_id,
            action: parts.action,
            target_secret_id: parts.target_secret_id,
            result: parts.result,
            key_version: parts.key_version,
            metadata_json: parts.metadata_json,
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

    fn to_fallback_json(
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

#[derive(Debug, Clone)]
pub struct LocalAuditFallbackStore {
    path: PathBuf,
}

impl LocalAuditFallbackStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append_pending(&self, event: &AuditEvent) -> Result<(), LocalAuditStoreError> {
        self.append_line(&event.to_fallback_json(DeliveryStatus::Pending)?)
    }

    pub fn mark_sent(&self, event: &AuditEvent) -> Result<(), LocalAuditStoreError> {
        self.append_line(&event.to_fallback_json(DeliveryStatus::Sent)?)
    }

    pub fn pending_events(&self) -> Result<Vec<AuditEvent>, LocalAuditStoreError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut states = BTreeMap::<String, LocalAuditEventState>::new();

        for (index, line) in reader.lines().enumerate() {
            let line_number = index + 1;
            let line = line?;

            if line.trim().is_empty() {
                continue;
            }

            let record: LocalAuditFallbackRecord = serde_json::from_str(&line)?;
            let event = record.to_event(line_number)?;
            let event_id = event.audit_event_id().as_canonical_string();
            states.insert(
                event_id,
                LocalAuditEventState {
                    event,
                    delivery_status: record.delivery_status,
                },
            );
        }

        Ok(states
            .into_values()
            .filter_map(|state| {
                if state.delivery_status == DeliveryStatus::Pending {
                    Some(state.event)
                } else {
                    None
                }
            })
            .collect())
    }

    fn append_line(&self, value: &Value) -> Result<(), LocalAuditStoreError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_data()?;

        Ok(())
    }
}

pub struct AuditRecorder<A> {
    appender: A,
    fallback_store: LocalAuditFallbackStore,
}

impl<A> AuditRecorder<A>
where
    A: AuditEventAppender,
{
    pub fn new(appender: A, fallback_store: LocalAuditFallbackStore) -> Self {
        Self {
            appender,
            fallback_store,
        }
    }

    pub fn record(&self, event: &AuditEvent) -> Result<AuditRecordOutcome, AuditRecordError> {
        match self.appender.append_audit_event(event) {
            Ok(()) => Ok(AuditRecordOutcome::PrimarySucceeded),
            Err(append_error) => self
                .fallback_store
                .append_pending(event)
                .map(|()| AuditRecordOutcome::FallbackSucceeded)
                .map_err(|store_error| AuditRecordError::PrimaryAndFallbackFailed {
                    append_error,
                    store_error,
                }),
        }
    }

    pub fn resend_pending(&self) -> Result<ResendAuditSummary, AuditRecordError> {
        let pending_events = self
            .fallback_store
            .pending_events()
            .map_err(AuditRecordError::ResendReadFailed)?;
        let attempted = pending_events.len();
        let mut sent = 0;
        let mut failed = 0;

        for event in pending_events {
            match self.appender.append_audit_event(&event) {
                Ok(()) => {
                    self.fallback_store
                        .mark_sent(&event)
                        .map_err(AuditRecordError::ResendMarkSentFailed)?;
                    sent += 1;
                }
                Err(_) => {
                    failed += 1;
                }
            }
        }

        Ok(ResendAuditSummary {
            attempted,
            sent,
            failed,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResendAuditSummary {
    pub attempted: usize,
    pub sent: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum DeliveryStatus {
    Pending,
    Sent,
}

impl DeliveryStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => DELIVERY_STATUS_PENDING,
            Self::Sent => DELIVERY_STATUS_SENT,
        }
    }
}

#[derive(Debug)]
struct LocalAuditEventState {
    event: AuditEvent,
    delivery_status: DeliveryStatus,
}

#[derive(Debug, Deserialize)]
struct LocalAuditFallbackRecord {
    audit_event_id: String,
    request_id: String,
    actor_user_id: Option<String>,
    actor_device_id: Option<String>,
    action: String,
    target_secret_id: Option<String>,
    result: String,
    key_version: Option<u32>,
    metadata_json: Value,
    delivery_status: DeliveryStatus,
}

impl LocalAuditFallbackRecord {
    fn to_event(&self, line_number: usize) -> Result<AuditEvent, LocalAuditStoreError> {
        let actor_user_id = self
            .actor_user_id
            .as_deref()
            .map(OwnerUserId::parse)
            .transpose()
            .map_err(|_| LocalAuditStoreError::InvalidLine {
                line_number,
                reason: "actor_user_id is invalid",
            })?;
        let actor_device_id = self
            .actor_device_id
            .as_deref()
            .map(DeviceId::new)
            .transpose()
            .map_err(|_| LocalAuditStoreError::InvalidLine {
                line_number,
                reason: "actor_device_id is invalid",
            })?;
        let target_secret_id = self
            .target_secret_id
            .as_deref()
            .map(SecretId::parse)
            .transpose()
            .map_err(|_| LocalAuditStoreError::InvalidLine {
                line_number,
                reason: "target_secret_id is invalid",
            })?;
        let key_version = self
            .key_version
            .map(KeyVersion::new)
            .transpose()
            .map_err(|_| LocalAuditStoreError::InvalidLine {
                line_number,
                reason: "key_version is invalid",
            })?;

        AuditEvent::new(AuditEventParts {
            audit_event_id: AuditEventId::parse(&self.audit_event_id)?,
            request_id: RequestId::parse(&self.request_id)?,
            actor_user_id,
            actor_device_id,
            action: AuditAction::parse(&self.action)?,
            target_secret_id,
            result: AuditResult::parse(&self.result)?,
            key_version,
            metadata_json: AuditMetadata::new(self.metadata_json.clone())?,
        })
        .map_err(LocalAuditStoreError::from)
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
    FORBIDDEN_METADATA_KEYS
        .iter()
        .any(|forbidden| normalized == *forbidden)
}

fn current_occurred_at() -> Result<String, LocalAuditStoreError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(LocalAuditStoreError::TimestampFormat)
}

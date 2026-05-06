use std::fmt;
use std::num::NonZeroU32;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::{Builder, Uuid, Version};
use zeroize::Zeroize;

use crate::audit::{AuditEventId, RequestId};
use crate::types::{DeviceId, OwnerUserId, SecretId, SourceEventAt};

pub const LEDGER_CANONICALIZATION_VERSION_V1: u8 = 1;
pub const LEDGER_CANONICAL_SCHEMA_V1: &str = "mipsorcu.ledger_entry.v1";
pub const LEDGER_HASH_ALGORITHM_SHA256: &str = "sha-256";
pub const LEDGER_SIGNATURE_ALGORITHM_ED25519: &str = "ed25519";
pub const LEDGER_HASH_LENGTH: usize = 32;
pub const LEDGER_SIGNATURE_LENGTH: usize = 64;
pub const LEDGER_ED25519_SECRET_KEY_LENGTH: usize = 32;
pub const LEDGER_ED25519_PUBLIC_KEY_LENGTH: usize = 32;
pub const LEDGER_PAYLOAD_MAX_CANONICAL_BYTES: usize = 8192;

const LEDGER_I64_MAX_U64: u64 = 9_223_372_036_854_775_807;

pub const FORBIDDEN_LEDGER_PAYLOAD_KEYS: &[&str] = &[
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
    "request_body",
    "response_body",
    "secret_key",
    "secret_value",
    "service_role",
    "service_role_key",
    "token",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    InvalidUuid {
        field: &'static str,
    },
    InvalidUuidVersion {
        field: &'static str,
        expected: &'static str,
    },
    InvalidPositiveInteger {
        field: &'static str,
    },
    InvalidNonNegativeInteger {
        field: &'static str,
    },
    SequenceOverflow,
    UnknownEntryType {
        value: String,
    },
    UnknownResult {
        value: String,
    },
    PayloadMustBeObject,
    ForbiddenPayloadKey {
        key: String,
    },
    UnknownPayloadKey {
        key: String,
        entry_type: LedgerEntryType,
    },
    PayloadValueMustBeScalar {
        key: String,
    },
    InvalidPayloadField {
        key: String,
        expected: &'static str,
    },
    PayloadTooLarge {
        max_bytes: usize,
    },
    InvalidErrorCode {
        field: &'static str,
    },
    InvalidActorDeviceId,
    InvalidHashLength {
        actual: usize,
    },
    InvalidHashEncoding,
    InvalidSignatureLength {
        actual: usize,
    },
    InvalidSignatureEncoding,
    InvalidSigningKeyLength {
        actual: usize,
    },
    InvalidVerificationKeyLength {
        actual: usize,
    },
    InvalidVerificationKey,
    SignatureKeyVersionMismatch {
        expected: u32,
        actual: u32,
    },
    UnknownSignatureKey {
        key_version: u32,
    },
    SignatureInvalid,
    HashMismatch {
        sequence_no: u64,
    },
    PreviousHashMismatch {
        sequence_no: u64,
    },
    SequenceGap {
        expected: u64,
        actual: u64,
    },
    SerializationFailed(String),
    RandomnessUnavailable,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUuid { field } => write!(formatter, "ledger {field} must be a UUID"),
            Self::InvalidUuidVersion { field, expected } => {
                write!(formatter, "ledger {field} must be a {expected} UUID")
            }
            Self::InvalidPositiveInteger { field } => {
                write!(formatter, "ledger {field} must be a positive integer")
            }
            Self::InvalidNonNegativeInteger { field } => {
                write!(formatter, "ledger {field} must be a non-negative integer")
            }
            Self::SequenceOverflow => write!(formatter, "ledger sequence number overflow"),
            Self::UnknownEntryType { value } => {
                write!(formatter, "unknown ledger entry_type: {value}")
            }
            Self::UnknownResult { value } => write!(formatter, "unknown ledger result: {value}"),
            Self::PayloadMustBeObject => write!(formatter, "ledger payload must be a JSON object"),
            Self::ForbiddenPayloadKey { key } => {
                write!(formatter, "ledger payload contains a forbidden key: {key}")
            }
            Self::UnknownPayloadKey { key, entry_type } => write!(
                formatter,
                "ledger payload key {key} is not allowed for entry_type {}",
                entry_type.as_str()
            ),
            Self::PayloadValueMustBeScalar { key } => {
                write!(formatter, "ledger payload field {key} must be scalar")
            }
            Self::InvalidPayloadField { key, expected } => {
                write!(formatter, "ledger payload field {key} must be {expected}")
            }
            Self::PayloadTooLarge { max_bytes } => {
                write!(
                    formatter,
                    "ledger payload canonical JSON exceeds {max_bytes} bytes"
                )
            }
            Self::InvalidErrorCode { field } => {
                write!(
                    formatter,
                    "ledger {field} must be non-blank and at most 128 bytes"
                )
            }
            Self::InvalidActorDeviceId => {
                write!(
                    formatter,
                    "ledger actor_device_id must be at most 128 bytes"
                )
            }
            Self::InvalidHashLength { actual } => {
                write!(
                    formatter,
                    "ledger hash must be 32 bytes: actual length {actual}"
                )
            }
            Self::InvalidHashEncoding => write!(formatter, "ledger hash bytea encoding is invalid"),
            Self::InvalidSignatureLength { actual } => {
                write!(
                    formatter,
                    "ledger signature must be 64 bytes: actual length {actual}"
                )
            }
            Self::InvalidSignatureEncoding => {
                write!(formatter, "ledger signature bytea encoding is invalid")
            }
            Self::InvalidSigningKeyLength { actual } => {
                write!(
                    formatter,
                    "ledger signing key must be 32 bytes: actual length {actual}"
                )
            }
            Self::InvalidVerificationKeyLength { actual } => write!(
                formatter,
                "ledger verification key must be 32 bytes: actual length {actual}"
            ),
            Self::InvalidVerificationKey => write!(formatter, "ledger verification key is invalid"),
            Self::SignatureKeyVersionMismatch { expected, actual } => write!(
                formatter,
                "ledger signature key version mismatch: expected {expected}, actual {actual}"
            ),
            Self::UnknownSignatureKey { key_version } => {
                write!(
                    formatter,
                    "unknown ledger signature key version: {key_version}"
                )
            }
            Self::SignatureInvalid => write!(formatter, "ledger signature is invalid"),
            Self::HashMismatch { sequence_no } => {
                write!(
                    formatter,
                    "ledger entry hash mismatch at sequence {sequence_no}"
                )
            }
            Self::PreviousHashMismatch { sequence_no } => write!(
                formatter,
                "ledger previous hash mismatch at sequence {sequence_no}"
            ),
            Self::SequenceGap { expected, actual } => write!(
                formatter,
                "ledger sequence gap: expected {expected}, actual {actual}"
            ),
            Self::SerializationFailed(message) => {
                write!(
                    formatter,
                    "failed to serialize canonical ledger payload: {message}"
                )
            }
            Self::RandomnessUnavailable => write!(formatter, "ledger randomness unavailable"),
        }
    }
}

impl std::error::Error for LedgerError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LedgerEntryId(Uuid);

impl LedgerEntryId {
    pub fn generate() -> Result<Self, LedgerError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| LedgerError::RandomnessUnavailable)?;
        let uuid = Builder::from_random_bytes(bytes).into_uuid();

        Ok(Self(uuid))
    }

    pub fn parse(value: &str) -> Result<Self, LedgerError> {
        let uuid = parse_uuid(value, "ledger_entry_id")?;
        require_uuid_v4(uuid, "ledger_entry_id")?;

        Ok(Self(uuid))
    }

    pub fn as_canonical_string(&self) -> String {
        self.0.hyphenated().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LedgerTargetSecretVersionId(Uuid);

impl LedgerTargetSecretVersionId {
    pub fn parse(value: &str) -> Result<Self, LedgerError> {
        parse_uuid(value, "target_secret_version_id").map(Self)
    }

    pub fn as_canonical_string(&self) -> String {
        self.0.hyphenated().to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LedgerSequenceNo(u64);

impl LedgerSequenceNo {
    pub fn new(value: u64) -> Result<Self, LedgerError> {
        if value == 0 || value > LEDGER_I64_MAX_U64 {
            return Err(LedgerError::InvalidPositiveInteger {
                field: "sequence_no",
            });
        }

        Ok(Self(value))
    }

    pub fn from_i64(value: i64) -> Result<Self, LedgerError> {
        let converted = u64::try_from(value).map_err(|_| LedgerError::InvalidPositiveInteger {
            field: "sequence_no",
        })?;

        Self::new(converted)
    }

    pub fn get(self) -> u64 {
        self.0
    }

    pub fn as_i64(self) -> Result<i64, LedgerError> {
        i64::try_from(self.0).map_err(|_| LedgerError::InvalidPositiveInteger {
            field: "sequence_no",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LedgerEntryType {
    SecretCreated,
    SecretVersionCreated,
    SecretDecrypted,
    SecretVersionPurged,
    IntegrityCheckCompleted,
    RestoreTestCompleted,
    KeyRotationStarted,
    KeyRotationReencrypted,
    KeyRotationCompleted,
    KeyRotationAborted,
    LedgerVerified,
    LedgerVerificationFailed,
    AuditFallbackResent,
}

impl LedgerEntryType {
    pub fn parse(value: &str) -> Result<Self, LedgerError> {
        match value {
            "secret_created" => Ok(Self::SecretCreated),
            "secret_version_created" => Ok(Self::SecretVersionCreated),
            "secret_decrypted" => Ok(Self::SecretDecrypted),
            "secret_version_purged" => Ok(Self::SecretVersionPurged),
            "integrity_check_completed" => Ok(Self::IntegrityCheckCompleted),
            "restore_test_completed" => Ok(Self::RestoreTestCompleted),
            "key_rotation_started" => Ok(Self::KeyRotationStarted),
            "key_rotation_reencrypted" => Ok(Self::KeyRotationReencrypted),
            "key_rotation_completed" => Ok(Self::KeyRotationCompleted),
            "key_rotation_aborted" => Ok(Self::KeyRotationAborted),
            "ledger_verified" => Ok(Self::LedgerVerified),
            "ledger_verification_failed" => Ok(Self::LedgerVerificationFailed),
            "audit_fallback_resent" => Ok(Self::AuditFallbackResent),
            _ => Err(LedgerError::UnknownEntryType {
                value: value.to_owned(),
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecretCreated => "secret_created",
            Self::SecretVersionCreated => "secret_version_created",
            Self::SecretDecrypted => "secret_decrypted",
            Self::SecretVersionPurged => "secret_version_purged",
            Self::IntegrityCheckCompleted => "integrity_check_completed",
            Self::RestoreTestCompleted => "restore_test_completed",
            Self::KeyRotationStarted => "key_rotation_started",
            Self::KeyRotationReencrypted => "key_rotation_reencrypted",
            Self::KeyRotationCompleted => "key_rotation_completed",
            Self::KeyRotationAborted => "key_rotation_aborted",
            Self::LedgerVerified => "ledger_verified",
            Self::LedgerVerificationFailed => "ledger_verification_failed",
            Self::AuditFallbackResent => "audit_fallback_resent",
        }
    }

    fn allowed_payload_keys(self) -> &'static [&'static str] {
        match self {
            Self::SecretCreated | Self::SecretVersionCreated => {
                &["algorithm", "classification", "key_version", "version"]
            }
            Self::SecretDecrypted => &["algorithm", "key_version", "version"],
            Self::SecretVersionPurged => &["key_version", "retention_limit", "version"],
            Self::IntegrityCheckCompleted => &[
                "checked_audit_event_count",
                "checked_secret_count",
                "checked_secret_version_count",
                "duration_ms",
                "violation_count",
            ],
            Self::RestoreTestCompleted => &[
                "duration_ms",
                "failure_count",
                "sample_count",
                "success_count",
                "trigger",
            ],
            Self::KeyRotationStarted => &["new_key_version", "old_key_version"],
            Self::KeyRotationReencrypted => &[
                "batch_size",
                "new_key_version",
                "old_key_version",
                "processed_count",
                "remaining_count",
            ],
            Self::KeyRotationCompleted => {
                &["new_key_version", "old_key_version", "remaining_count"]
            }
            Self::KeyRotationAborted => &["new_key_version", "old_key_version", "reason_code"],
            Self::LedgerVerified => &[
                "checked_count",
                "duration_ms",
                "end_sequence_no",
                "start_sequence_no",
            ],
            Self::LedgerVerificationFailed => &[
                "end_sequence_no",
                "error_code",
                "failed_count",
                "start_sequence_no",
            ],
            Self::AuditFallbackResent => &["duration_ms", "failed_count", "resent_count"],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LedgerResult {
    Success,
    Failure,
}

impl LedgerResult {
    pub fn parse(value: &str) -> Result<Self, LedgerError> {
        match value {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            _ => Err(LedgerError::UnknownResult {
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
pub struct LedgerPayload {
    entry_type: LedgerEntryType,
    object: Map<String, Value>,
}

impl LedgerPayload {
    pub fn new(entry_type: LedgerEntryType, value: Value) -> Result<Self, LedgerError> {
        let object = value
            .as_object()
            .cloned()
            .ok_or(LedgerError::PayloadMustBeObject)?;

        reject_forbidden_payload_keys(&Value::Object(object.clone()))?;
        validate_payload_object(entry_type, &object)?;
        ensure_payload_size(entry_type, &object)?;

        Ok(Self { entry_type, object })
    }

    pub fn empty(entry_type: LedgerEntryType) -> Result<Self, LedgerError> {
        Self::new(entry_type, Value::Object(Map::new()))
    }

    pub fn entry_type(&self) -> LedgerEntryType {
        self.entry_type
    }

    pub fn as_value(&self) -> Value {
        Value::Object(self.object.clone())
    }

    fn canonical_serializer(&self) -> CanonicalPayloadObject<'_> {
        CanonicalPayloadObject {
            entry_type: self.entry_type,
            object: &self.object,
        }
    }

    fn key_count(&self) -> usize {
        self.object.len()
    }
}

impl fmt::Debug for LedgerPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerPayload")
            .field("entry_type", &self.entry_type)
            .field("key_count", &self.key_count())
            .field("contents", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct LedgerCanonicalPayload(Vec<u8>);

impl LedgerCanonicalPayload {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for LedgerCanonicalPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerCanonicalPayload")
            .field("len", &self.0.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LedgerHash([u8; LEDGER_HASH_LENGTH]);

impl LedgerHash {
    pub fn genesis() -> Self {
        Self([0u8; LEDGER_HASH_LENGTH])
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LedgerError> {
        if bytes.len() != LEDGER_HASH_LENGTH {
            return Err(LedgerError::InvalidHashLength {
                actual: bytes.len(),
            });
        }

        let mut hash = [0u8; LEDGER_HASH_LENGTH];
        hash.copy_from_slice(bytes);

        Ok(Self(hash))
    }

    pub fn from_hex(value: &str) -> Result<Self, LedgerError> {
        let bytes = hex::decode(value).map_err(|_| LedgerError::InvalidHashEncoding)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytea_hex(value: &str) -> Result<Self, LedgerError> {
        let hex_value = value
            .strip_prefix("\\x")
            .ok_or(LedgerError::InvalidHashEncoding)?;
        Self::from_hex(hex_value)
    }

    pub fn from_canonical_payload(payload: &LedgerCanonicalPayload) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let digest = hasher.finalize();
        let mut hash = [0u8; LEDGER_HASH_LENGTH];
        hash.copy_from_slice(&digest);

        Self(hash)
    }

    pub fn as_bytes(&self) -> &[u8; LEDGER_HASH_LENGTH] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn to_bytea_hex(self) -> String {
        format!("\\x{}", self.to_hex())
    }
}

impl fmt::Debug for LedgerHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerHash")
            .field("hex", &self.to_hex())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LedgerSignature([u8; LEDGER_SIGNATURE_LENGTH]);

impl LedgerSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LedgerError> {
        if bytes.len() != LEDGER_SIGNATURE_LENGTH {
            return Err(LedgerError::InvalidSignatureLength {
                actual: bytes.len(),
            });
        }

        let mut signature = [0u8; LEDGER_SIGNATURE_LENGTH];
        signature.copy_from_slice(bytes);

        Ok(Self(signature))
    }

    pub fn from_bytea_hex(value: &str) -> Result<Self, LedgerError> {
        let hex_value = value
            .strip_prefix("\\x")
            .ok_or(LedgerError::InvalidSignatureEncoding)?;
        let bytes = hex::decode(hex_value).map_err(|_| LedgerError::InvalidSignatureEncoding)?;

        Self::from_bytes(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8; LEDGER_SIGNATURE_LENGTH] {
        &self.0
    }

    pub fn to_bytea_hex(self) -> String {
        format!("\\x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for LedgerSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerSignature")
            .field("len", &LEDGER_SIGNATURE_LENGTH)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LedgerSignatureKeyVersion(NonZeroU32);

impl LedgerSignatureKeyVersion {
    pub fn new(value: u32) -> Result<Self, LedgerError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or(LedgerError::InvalidPositiveInteger {
                field: "signature_key_version",
            })
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

#[derive(Clone)]
pub struct LedgerSigningKey {
    key_version: LedgerSignatureKeyVersion,
    signing_key: SigningKey,
}

impl LedgerSigningKey {
    pub fn from_secret_key_bytes(
        key_version: LedgerSignatureKeyVersion,
        secret_key: &[u8],
    ) -> Result<Self, LedgerError> {
        if secret_key.len() != LEDGER_ED25519_SECRET_KEY_LENGTH {
            return Err(LedgerError::InvalidSigningKeyLength {
                actual: secret_key.len(),
            });
        }

        let mut bytes = [0u8; LEDGER_ED25519_SECRET_KEY_LENGTH];
        bytes.copy_from_slice(secret_key);
        let signing_key = SigningKey::from_bytes(&bytes);
        bytes.zeroize();

        Ok(Self {
            key_version,
            signing_key,
        })
    }

    pub fn key_version(&self) -> LedgerSignatureKeyVersion {
        self.key_version
    }

    pub fn verification_key(&self) -> LedgerVerifyingKey {
        LedgerVerifyingKey {
            key_version: self.key_version,
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    fn sign_payload(
        &self,
        expected_key_version: LedgerSignatureKeyVersion,
        payload: &LedgerCanonicalPayload,
    ) -> Result<LedgerSignature, LedgerError> {
        if self.key_version != expected_key_version {
            return Err(LedgerError::SignatureKeyVersionMismatch {
                expected: expected_key_version.get(),
                actual: self.key_version.get(),
            });
        }

        let signature: Signature = self.signing_key.sign(payload.as_bytes());
        LedgerSignature::from_bytes(&signature.to_bytes())
    }
}

impl fmt::Debug for LedgerSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerSigningKey")
            .field("key_version", &self.key_version)
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct LedgerVerifyingKey {
    key_version: LedgerSignatureKeyVersion,
    verifying_key: VerifyingKey,
}

impl LedgerVerifyingKey {
    pub fn from_public_key_bytes(
        key_version: LedgerSignatureKeyVersion,
        public_key: &[u8],
    ) -> Result<Self, LedgerError> {
        if public_key.len() != LEDGER_ED25519_PUBLIC_KEY_LENGTH {
            return Err(LedgerError::InvalidVerificationKeyLength {
                actual: public_key.len(),
            });
        }

        let mut bytes = [0u8; LEDGER_ED25519_PUBLIC_KEY_LENGTH];
        bytes.copy_from_slice(public_key);
        let verifying_key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| LedgerError::InvalidVerificationKey)?;

        Ok(Self {
            key_version,
            verifying_key,
        })
    }

    pub fn key_version(&self) -> LedgerSignatureKeyVersion {
        self.key_version
    }

    pub fn as_bytes(&self) -> [u8; LEDGER_ED25519_PUBLIC_KEY_LENGTH] {
        self.verifying_key.to_bytes()
    }

    fn verify_payload(
        &self,
        expected_key_version: LedgerSignatureKeyVersion,
        payload: &LedgerCanonicalPayload,
        signature: &LedgerSignature,
    ) -> Result<(), LedgerError> {
        if self.key_version != expected_key_version {
            return Err(LedgerError::SignatureKeyVersionMismatch {
                expected: expected_key_version.get(),
                actual: self.key_version.get(),
            });
        }

        let signature = Signature::from_bytes(signature.as_bytes());
        self.verifying_key
            .verify(payload.as_bytes(), &signature)
            .map_err(|_| LedgerError::SignatureInvalid)
    }
}

impl fmt::Debug for LedgerVerifyingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerVerifyingKey")
            .field("key_version", &self.key_version)
            .finish()
    }
}

pub type LedgerVerificationKey = LedgerVerifyingKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerChainHead {
    last_sequence_no: u64,
    last_entry_hash: LedgerHash,
}

impl LedgerChainHead {
    pub fn genesis() -> Self {
        Self {
            last_sequence_no: 0,
            last_entry_hash: LedgerHash::genesis(),
        }
    }

    pub fn new(last_sequence_no: u64, last_entry_hash: LedgerHash) -> Result<Self, LedgerError> {
        if last_sequence_no > LEDGER_I64_MAX_U64 {
            return Err(LedgerError::InvalidNonNegativeInteger {
                field: "last_sequence_no",
            });
        }

        Ok(Self {
            last_sequence_no,
            last_entry_hash,
        })
    }

    pub fn from_i64(
        last_sequence_no: i64,
        last_entry_hash: LedgerHash,
    ) -> Result<Self, LedgerError> {
        let converted = u64::try_from(last_sequence_no).map_err(|_| {
            LedgerError::InvalidNonNegativeInteger {
                field: "last_sequence_no",
            }
        })?;

        Self::new(converted, last_entry_hash)
    }

    pub fn last_sequence_no(self) -> u64 {
        self.last_sequence_no
    }

    pub fn last_entry_hash(self) -> LedgerHash {
        self.last_entry_hash
    }

    pub fn next_sequence_no(self) -> Result<LedgerSequenceNo, LedgerError> {
        let next = self
            .last_sequence_no
            .checked_add(1)
            .ok_or(LedgerError::SequenceOverflow)?;

        LedgerSequenceNo::new(next)
    }
}

#[derive(Clone)]
pub struct LedgerEntryDraft {
    ledger_entry_id: LedgerEntryId,
    sequence_no: LedgerSequenceNo,
    entry_type: LedgerEntryType,
    source_event_at: SourceEventAt,
    request_id: RequestId,
    source_event_id: Option<AuditEventId>,
    target_secret_id: Option<SecretId>,
    target_secret_version_id: Option<LedgerTargetSecretVersionId>,
    actor_user_id: Option<OwnerUserId>,
    actor_device_id: Option<DeviceId>,
    result: LedgerResult,
    error_code: Option<String>,
    payload: LedgerPayload,
    previous_entry_hash: LedgerHash,
    signature_key_version: LedgerSignatureKeyVersion,
}

impl LedgerEntryDraft {
    pub fn new(parts: LedgerEntryDraftParts) -> Result<Self, LedgerError> {
        if parts.payload.entry_type() != parts.entry_type {
            return Err(LedgerError::UnknownPayloadKey {
                key: "payload.entry_type".to_owned(),
                entry_type: parts.entry_type,
            });
        }

        validate_error_code(parts.result, parts.error_code.as_deref(), "error_code")?;
        validate_actor_device_id(parts.actor_device_id.as_ref())?;

        Ok(Self {
            ledger_entry_id: parts.ledger_entry_id,
            sequence_no: parts.sequence_no,
            entry_type: parts.entry_type,
            source_event_at: parts.source_event_at,
            request_id: parts.request_id,
            source_event_id: parts.source_event_id,
            target_secret_id: parts.target_secret_id,
            target_secret_version_id: parts.target_secret_version_id,
            actor_user_id: parts.actor_user_id,
            actor_device_id: parts.actor_device_id,
            result: parts.result,
            error_code: parts.error_code,
            payload: parts.payload,
            previous_entry_hash: parts.previous_entry_hash,
            signature_key_version: parts.signature_key_version,
        })
    }

    pub fn canonical_payload(&self) -> Result<LedgerCanonicalPayload, LedgerError> {
        build_canonical_payload(CanonicalBuildFields {
            sequence_no: self.sequence_no,
            entry_type: self.entry_type,
            source_event_at: &self.source_event_at,
            request_id: &self.request_id,
            source_event_id: self.source_event_id.as_ref(),
            target_secret_id: self.target_secret_id.as_ref(),
            target_secret_version_id: self.target_secret_version_id.as_ref(),
            actor_user_id: self.actor_user_id.as_ref(),
            actor_device_id: self.actor_device_id.as_ref(),
            result: self.result,
            error_code: self.error_code.as_deref(),
            payload: &self.payload,
            previous_entry_hash: self.previous_entry_hash,
            signature_key_version: self.signature_key_version,
        })
    }

    pub fn sign(&self, signing_key: &LedgerSigningKey) -> Result<SignedLedgerEntry, LedgerError> {
        let canonical_payload = self.canonical_payload()?;
        let entry_hash = LedgerHash::from_canonical_payload(&canonical_payload);
        let signature = signing_key.sign_payload(self.signature_key_version, &canonical_payload)?;

        Ok(SignedLedgerEntry {
            ledger_entry_id: self.ledger_entry_id.clone(),
            sequence_no: self.sequence_no,
            entry_type: self.entry_type,
            source_event_at: self.source_event_at.clone(),
            request_id: self.request_id.clone(),
            source_event_id: self.source_event_id.clone(),
            target_secret_id: self.target_secret_id.clone(),
            target_secret_version_id: self.target_secret_version_id.clone(),
            actor_user_id: self.actor_user_id.clone(),
            actor_device_id: self.actor_device_id.clone(),
            result: self.result,
            error_code: self.error_code.clone(),
            payload: self.payload.clone(),
            canonical_payload,
            previous_entry_hash: self.previous_entry_hash,
            entry_hash,
            signature,
            signature_key_version: self.signature_key_version,
        })
    }
}

impl fmt::Debug for LedgerEntryDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerEntryDraft")
            .field("ledger_entry_id", &self.ledger_entry_id)
            .field("sequence_no", &self.sequence_no)
            .field("entry_type", &self.entry_type)
            .field("source_event_at", &self.source_event_at)
            .field("request_id", &self.request_id)
            .field("source_event_id", &self.source_event_id)
            .field("target_secret_id", &self.target_secret_id)
            .field("target_secret_version_id", &self.target_secret_version_id)
            .field("actor_user_id", &self.actor_user_id)
            .field("actor_device_id", &self.actor_device_id)
            .field("result", &self.result)
            .field("error_code", &self.error_code)
            .field("payload", &self.payload)
            .field("previous_entry_hash", &self.previous_entry_hash)
            .field("signature_key_version", &self.signature_key_version)
            .finish()
    }
}

pub struct LedgerEntryDraftParts {
    pub ledger_entry_id: LedgerEntryId,
    pub sequence_no: LedgerSequenceNo,
    pub entry_type: LedgerEntryType,
    pub source_event_at: SourceEventAt,
    pub request_id: RequestId,
    pub source_event_id: Option<AuditEventId>,
    pub target_secret_id: Option<SecretId>,
    pub target_secret_version_id: Option<LedgerTargetSecretVersionId>,
    pub actor_user_id: Option<OwnerUserId>,
    pub actor_device_id: Option<DeviceId>,
    pub result: LedgerResult,
    pub error_code: Option<String>,
    pub payload: LedgerPayload,
    pub previous_entry_hash: LedgerHash,
    pub signature_key_version: LedgerSignatureKeyVersion,
}

#[derive(Clone)]
pub struct SignedLedgerEntry {
    ledger_entry_id: LedgerEntryId,
    sequence_no: LedgerSequenceNo,
    entry_type: LedgerEntryType,
    source_event_at: SourceEventAt,
    request_id: RequestId,
    source_event_id: Option<AuditEventId>,
    target_secret_id: Option<SecretId>,
    target_secret_version_id: Option<LedgerTargetSecretVersionId>,
    actor_user_id: Option<OwnerUserId>,
    actor_device_id: Option<DeviceId>,
    result: LedgerResult,
    error_code: Option<String>,
    payload: LedgerPayload,
    canonical_payload: LedgerCanonicalPayload,
    previous_entry_hash: LedgerHash,
    entry_hash: LedgerHash,
    signature: LedgerSignature,
    signature_key_version: LedgerSignatureKeyVersion,
}

impl SignedLedgerEntry {
    pub fn from_stored_parts(parts: SignedLedgerEntryParts) -> Result<Self, LedgerError> {
        if parts.payload.entry_type() != parts.entry_type {
            return Err(LedgerError::UnknownPayloadKey {
                key: "payload.entry_type".to_owned(),
                entry_type: parts.entry_type,
            });
        }

        validate_error_code(parts.result, parts.error_code.as_deref(), "error_code")?;
        validate_actor_device_id(parts.actor_device_id.as_ref())?;

        let canonical_payload = build_canonical_payload(CanonicalBuildFields {
            sequence_no: parts.sequence_no,
            entry_type: parts.entry_type,
            source_event_at: &parts.source_event_at,
            request_id: &parts.request_id,
            source_event_id: parts.source_event_id.as_ref(),
            target_secret_id: parts.target_secret_id.as_ref(),
            target_secret_version_id: parts.target_secret_version_id.as_ref(),
            actor_user_id: parts.actor_user_id.as_ref(),
            actor_device_id: parts.actor_device_id.as_ref(),
            result: parts.result,
            error_code: parts.error_code.as_deref(),
            payload: &parts.payload,
            previous_entry_hash: parts.previous_entry_hash,
            signature_key_version: parts.signature_key_version,
        })?;

        Ok(Self {
            ledger_entry_id: parts.ledger_entry_id,
            sequence_no: parts.sequence_no,
            entry_type: parts.entry_type,
            source_event_at: parts.source_event_at,
            request_id: parts.request_id,
            source_event_id: parts.source_event_id,
            target_secret_id: parts.target_secret_id,
            target_secret_version_id: parts.target_secret_version_id,
            actor_user_id: parts.actor_user_id,
            actor_device_id: parts.actor_device_id,
            result: parts.result,
            error_code: parts.error_code,
            payload: parts.payload,
            canonical_payload,
            previous_entry_hash: parts.previous_entry_hash,
            entry_hash: parts.entry_hash,
            signature: parts.signature,
            signature_key_version: parts.signature_key_version,
        })
    }

    pub fn ledger_entry_id(&self) -> &LedgerEntryId {
        &self.ledger_entry_id
    }

    pub fn sequence_no(&self) -> LedgerSequenceNo {
        self.sequence_no
    }

    pub fn entry_type(&self) -> LedgerEntryType {
        self.entry_type
    }

    pub fn source_event_at(&self) -> &SourceEventAt {
        &self.source_event_at
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn source_event_id(&self) -> Option<&AuditEventId> {
        self.source_event_id.as_ref()
    }

    pub fn target_secret_id(&self) -> Option<&SecretId> {
        self.target_secret_id.as_ref()
    }

    pub fn target_secret_version_id(&self) -> Option<&LedgerTargetSecretVersionId> {
        self.target_secret_version_id.as_ref()
    }

    pub fn actor_user_id(&self) -> Option<&OwnerUserId> {
        self.actor_user_id.as_ref()
    }

    pub fn actor_device_id(&self) -> Option<&DeviceId> {
        self.actor_device_id.as_ref()
    }

    pub fn result(&self) -> LedgerResult {
        self.result
    }

    pub fn error_code(&self) -> Option<&str> {
        self.error_code.as_deref()
    }

    pub fn payload(&self) -> &LedgerPayload {
        &self.payload
    }

    pub fn canonical_payload(&self) -> &LedgerCanonicalPayload {
        &self.canonical_payload
    }

    pub fn previous_entry_hash(&self) -> LedgerHash {
        self.previous_entry_hash
    }

    pub fn entry_hash(&self) -> LedgerHash {
        self.entry_hash
    }

    pub fn signature(&self) -> LedgerSignature {
        self.signature
    }

    pub fn signature_key_version(&self) -> LedgerSignatureKeyVersion {
        self.signature_key_version
    }

    pub fn recompute_entry_hash(&self) -> LedgerHash {
        LedgerHash::from_canonical_payload(&self.canonical_payload)
    }

    pub fn verify_signature(&self, key: &LedgerVerifyingKey) -> Result<(), LedgerError> {
        key.verify_payload(
            self.signature_key_version,
            &self.canonical_payload,
            &self.signature,
        )
    }
}

impl fmt::Debug for SignedLedgerEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedLedgerEntry")
            .field("ledger_entry_id", &self.ledger_entry_id)
            .field("sequence_no", &self.sequence_no)
            .field("entry_type", &self.entry_type)
            .field("source_event_at", &self.source_event_at)
            .field("request_id", &self.request_id)
            .field("source_event_id", &self.source_event_id)
            .field("target_secret_id", &self.target_secret_id)
            .field("target_secret_version_id", &self.target_secret_version_id)
            .field("actor_user_id", &self.actor_user_id)
            .field("actor_device_id", &self.actor_device_id)
            .field("result", &self.result)
            .field("error_code", &self.error_code)
            .field("payload", &self.payload)
            .field("canonical_payload", &self.canonical_payload)
            .field("previous_entry_hash", &self.previous_entry_hash)
            .field("entry_hash", &self.entry_hash)
            .field("signature", &self.signature)
            .field("signature_key_version", &self.signature_key_version)
            .finish()
    }
}

pub struct SignedLedgerEntryParts {
    pub ledger_entry_id: LedgerEntryId,
    pub sequence_no: LedgerSequenceNo,
    pub entry_type: LedgerEntryType,
    pub source_event_at: SourceEventAt,
    pub request_id: RequestId,
    pub source_event_id: Option<AuditEventId>,
    pub target_secret_id: Option<SecretId>,
    pub target_secret_version_id: Option<LedgerTargetSecretVersionId>,
    pub actor_user_id: Option<OwnerUserId>,
    pub actor_device_id: Option<DeviceId>,
    pub result: LedgerResult,
    pub error_code: Option<String>,
    pub payload: LedgerPayload,
    pub previous_entry_hash: LedgerHash,
    pub entry_hash: LedgerHash,
    pub signature: LedgerSignature,
    pub signature_key_version: LedgerSignatureKeyVersion,
}

pub fn verify_ledger_chain(
    entries: &[SignedLedgerEntry],
    initial_head: LedgerChainHead,
    verification_keys: &[LedgerVerifyingKey],
) -> Result<LedgerChainHead, LedgerError> {
    let mut previous_sequence_no = initial_head.last_sequence_no();
    let mut previous_hash = initial_head.last_entry_hash();

    for entry in entries {
        let expected_sequence_no = previous_sequence_no
            .checked_add(1)
            .ok_or(LedgerError::SequenceOverflow)?;
        let actual_sequence_no = entry.sequence_no().get();

        if actual_sequence_no != expected_sequence_no {
            return Err(LedgerError::SequenceGap {
                expected: expected_sequence_no,
                actual: actual_sequence_no,
            });
        }

        if entry.previous_entry_hash() != previous_hash {
            return Err(LedgerError::PreviousHashMismatch {
                sequence_no: actual_sequence_no,
            });
        }

        if entry.recompute_entry_hash() != entry.entry_hash() {
            return Err(LedgerError::HashMismatch {
                sequence_no: actual_sequence_no,
            });
        }

        let verification_key =
            find_verification_key(verification_keys, entry.signature_key_version())?;
        entry.verify_signature(verification_key)?;

        previous_sequence_no = actual_sequence_no;
        previous_hash = entry.entry_hash();
    }

    LedgerChainHead::new(previous_sequence_no, previous_hash)
}

struct CanonicalBuildFields<'a> {
    sequence_no: LedgerSequenceNo,
    entry_type: LedgerEntryType,
    source_event_at: &'a SourceEventAt,
    request_id: &'a RequestId,
    source_event_id: Option<&'a AuditEventId>,
    target_secret_id: Option<&'a SecretId>,
    target_secret_version_id: Option<&'a LedgerTargetSecretVersionId>,
    actor_user_id: Option<&'a OwnerUserId>,
    actor_device_id: Option<&'a DeviceId>,
    result: LedgerResult,
    error_code: Option<&'a str>,
    payload: &'a LedgerPayload,
    previous_entry_hash: LedgerHash,
    signature_key_version: LedgerSignatureKeyVersion,
}

fn build_canonical_payload(
    fields: CanonicalBuildFields<'_>,
) -> Result<LedgerCanonicalPayload, LedgerError> {
    let request_id = fields.request_id.as_canonical_string();
    let source_event_id = fields
        .source_event_id
        .map(AuditEventId::as_canonical_string);
    let target_secret_id = fields.target_secret_id.map(SecretId::as_canonical_string);
    let target_secret_version_id = fields
        .target_secret_version_id
        .map(LedgerTargetSecretVersionId::as_canonical_string);
    let actor_user_id = fields.actor_user_id.map(OwnerUserId::as_canonical_string);
    let actor_device_id = fields
        .actor_device_id
        .map(|device_id| device_id.as_str().to_owned());
    let previous_entry_hash = fields.previous_entry_hash.to_hex();

    let document = CanonicalLedgerDocument {
        schema: LEDGER_CANONICAL_SCHEMA_V1,
        sequence_no: fields.sequence_no.get(),
        entry_type: fields.entry_type.as_str(),
        source_event_at: fields.source_event_at.as_str(),
        request_id: &request_id,
        source_event_id: source_event_id.as_deref(),
        target_secret_id: target_secret_id.as_deref(),
        target_secret_version_id: target_secret_version_id.as_deref(),
        actor_user_id: actor_user_id.as_deref(),
        actor_device_id: actor_device_id.as_deref(),
        result: fields.result.as_str(),
        error_code: fields.error_code,
        payload: fields.payload.canonical_serializer(),
        canonicalization_version: LEDGER_CANONICALIZATION_VERSION_V1,
        previous_entry_hash: &previous_entry_hash,
        hash_algorithm: LEDGER_HASH_ALGORITHM_SHA256,
        signature_algorithm: LEDGER_SIGNATURE_ALGORITHM_ED25519,
        signature_key_version: fields.signature_key_version.get(),
    };
    let bytes = serde_json::to_vec(&document)
        .map_err(|error| LedgerError::SerializationFailed(error.to_string()))?;

    Ok(LedgerCanonicalPayload(bytes))
}

#[derive(Serialize)]
struct CanonicalLedgerDocument<'a> {
    schema: &'static str,
    sequence_no: u64,
    entry_type: &'static str,
    source_event_at: &'a str,
    request_id: &'a str,
    source_event_id: Option<&'a str>,
    target_secret_id: Option<&'a str>,
    target_secret_version_id: Option<&'a str>,
    actor_user_id: Option<&'a str>,
    actor_device_id: Option<&'a str>,
    result: &'static str,
    error_code: Option<&'a str>,
    payload: CanonicalPayloadObject<'a>,
    canonicalization_version: u8,
    previous_entry_hash: &'a str,
    hash_algorithm: &'static str,
    signature_algorithm: &'static str,
    signature_key_version: u32,
}

struct CanonicalPayloadObject<'a> {
    entry_type: LedgerEntryType,
    object: &'a Map<String, Value>,
}

impl Serialize for CanonicalPayloadObject<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.object.len()))?;
        for key in self.entry_type.allowed_payload_keys() {
            if let Some(value) = self.object.get(*key) {
                map.serialize_entry(key, value)?;
            }
        }
        map.end()
    }
}

fn reject_forbidden_payload_keys(value: &Value) -> Result<(), LedgerError> {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                if is_forbidden_payload_key(key) {
                    return Err(LedgerError::ForbiddenPayloadKey {
                        key: key.to_owned(),
                    });
                }

                reject_forbidden_payload_keys(nested)?;
            }

            Ok(())
        }
        Value::Array(values) => {
            for nested in values {
                reject_forbidden_payload_keys(nested)?;
            }

            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

fn is_forbidden_payload_key(key: &str) -> bool {
    let normalized = key.trim().to_ascii_lowercase();
    FORBIDDEN_LEDGER_PAYLOAD_KEYS
        .iter()
        .any(|forbidden| normalized == *forbidden)
}

fn validate_payload_object(
    entry_type: LedgerEntryType,
    object: &Map<String, Value>,
) -> Result<(), LedgerError> {
    for (key, value) in object {
        if !entry_type.allowed_payload_keys().contains(&key.as_str()) {
            return Err(LedgerError::UnknownPayloadKey {
                key: key.to_owned(),
                entry_type,
            });
        }

        if matches!(value, Value::Object(_) | Value::Array(_)) {
            return Err(LedgerError::PayloadValueMustBeScalar {
                key: key.to_owned(),
            });
        }

        validate_payload_field(key, value)?;
    }

    validate_old_new_key_versions(object)
}

fn validate_payload_field(key: &str, value: &Value) -> Result<(), LedgerError> {
    match key {
        "version" | "key_version" | "old_key_version" | "new_key_version" | "retention_limit"
        | "start_sequence_no" | "end_sequence_no" => {
            let parsed = require_positive_json_u64(key, value)?;
            if key == "retention_limit" && parsed != 4 {
                return Err(LedgerError::InvalidPayloadField {
                    key: key.to_owned(),
                    expected: "the integer 4",
                });
            }
            Ok(())
        }
        "batch_size"
        | "checked_audit_event_count"
        | "checked_count"
        | "checked_secret_count"
        | "checked_secret_version_count"
        | "duration_ms"
        | "failed_count"
        | "failure_count"
        | "processed_count"
        | "remaining_count"
        | "resent_count"
        | "sample_count"
        | "success_count"
        | "violation_count" => require_non_negative_json_u64(key, value).map(|_| ()),
        "algorithm" => require_string_value(key, value, "xchacha20-poly1305"),
        "classification" => validate_classification_value(key, value),
        "trigger" => validate_trigger_value(key, value),
        "error_code" | "reason_code" => validate_non_blank_short_string(key, value),
        _ => Err(LedgerError::UnknownPayloadKey {
            key: key.to_owned(),
            entry_type: LedgerEntryType::SecretCreated,
        }),
    }
}

fn require_positive_json_u64(key: &str, value: &Value) -> Result<u64, LedgerError> {
    let parsed = require_json_u64(key, value, "a positive integer")?;
    if parsed == 0 {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a positive integer",
        });
    }

    Ok(parsed)
}

fn require_non_negative_json_u64(key: &str, value: &Value) -> Result<u64, LedgerError> {
    require_json_u64(key, value, "a non-negative integer")
}

fn require_json_u64(key: &str, value: &Value, expected: &'static str) -> Result<u64, LedgerError> {
    let parsed = value
        .as_u64()
        .ok_or_else(|| LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected,
        })?;

    if parsed > LEDGER_I64_MAX_U64 {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected,
        });
    }

    Ok(parsed)
}

fn require_string_value(
    key: &str,
    value: &Value,
    expected_value: &'static str,
) -> Result<(), LedgerError> {
    if value.as_str() == Some(expected_value) {
        return Ok(());
    }

    Err(LedgerError::InvalidPayloadField {
        key: key.to_owned(),
        expected: expected_value,
    })
}

fn validate_classification_value(key: &str, value: &Value) -> Result<(), LedgerError> {
    let Some(text) = value.as_str() else {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a non-blank string at most 128 bytes",
        });
    };

    if text.trim().is_empty() || text.len() > 128 {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a non-blank string at most 128 bytes",
        });
    }

    Ok(())
}

fn validate_trigger_value(key: &str, value: &Value) -> Result<(), LedgerError> {
    match value.as_str() {
        Some("background" | "cli" | "scheduled" | "startup") => Ok(()),
        _ => Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "one of background, cli, scheduled, startup",
        }),
    }
}

fn validate_non_blank_short_string(key: &str, value: &Value) -> Result<(), LedgerError> {
    let Some(text) = value.as_str() else {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a non-blank string at most 128 bytes",
        });
    };

    if text.trim().is_empty() || text.len() > 128 {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a non-blank string at most 128 bytes",
        });
    }

    Ok(())
}

fn validate_old_new_key_versions(object: &Map<String, Value>) -> Result<(), LedgerError> {
    let Some(old_value) = object.get("old_key_version") else {
        return Ok(());
    };
    let Some(new_value) = object.get("new_key_version") else {
        return Ok(());
    };

    let old_key_version = require_positive_json_u64("old_key_version", old_value)?;
    let new_key_version = require_positive_json_u64("new_key_version", new_value)?;

    if old_key_version == new_key_version {
        return Err(LedgerError::InvalidPayloadField {
            key: "new_key_version".to_owned(),
            expected: "a different value from old_key_version",
        });
    }

    Ok(())
}

fn ensure_payload_size(
    entry_type: LedgerEntryType,
    object: &Map<String, Value>,
) -> Result<(), LedgerError> {
    let bytes = serde_json::to_vec(&CanonicalPayloadObject { entry_type, object })
        .map_err(|error| LedgerError::SerializationFailed(error.to_string()))?;

    if bytes.len() > LEDGER_PAYLOAD_MAX_CANONICAL_BYTES {
        return Err(LedgerError::PayloadTooLarge {
            max_bytes: LEDGER_PAYLOAD_MAX_CANONICAL_BYTES,
        });
    }

    Ok(())
}

fn validate_error_code(
    result: LedgerResult,
    error_code: Option<&str>,
    field: &'static str,
) -> Result<(), LedgerError> {
    if result == LedgerResult::Success && error_code.is_some() {
        return Err(LedgerError::InvalidErrorCode { field });
    }

    if let Some(value) = error_code
        && (value.trim().is_empty() || value.len() > 128)
    {
        return Err(LedgerError::InvalidErrorCode { field });
    }

    Ok(())
}

fn validate_actor_device_id(actor_device_id: Option<&DeviceId>) -> Result<(), LedgerError> {
    if actor_device_id.is_some_and(|device_id| device_id.as_str().len() > 128) {
        return Err(LedgerError::InvalidActorDeviceId);
    }

    Ok(())
}

fn find_verification_key(
    verification_keys: &[LedgerVerifyingKey],
    key_version: LedgerSignatureKeyVersion,
) -> Result<&LedgerVerifyingKey, LedgerError> {
    verification_keys
        .iter()
        .find(|key| key.key_version() == key_version)
        .ok_or_else(|| LedgerError::UnknownSignatureKey {
            key_version: key_version.get(),
        })
}

fn parse_uuid(value: &str, field: &'static str) -> Result<Uuid, LedgerError> {
    Uuid::parse_str(value).map_err(|_| LedgerError::InvalidUuid { field })
}

fn require_uuid_v4(uuid: Uuid, field: &'static str) -> Result<(), LedgerError> {
    if uuid.get_version() != Some(Version::Random) {
        return Err(LedgerError::InvalidUuidVersion {
            field,
            expected: "v4",
        });
    }

    Ok(())
}

use std::fmt;
use std::num::NonZeroU32;

use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use uuid::{Builder, Uuid, Version};
use zeroize::Zeroize;

use crate::error::{AadError, CryptoError, InputError};

pub const DATA_KEY_LENGTH: usize = 32;
pub const MASTER_KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 24;
pub const ENCRYPTED_DATA_KEY_VERSION: u8 = 1;
pub const ENCRYPTED_DATA_KEY_TAG_LENGTH: usize = 16;
pub const ENCRYPTED_DATA_KEY_CIPHERTEXT_LENGTH: usize =
    DATA_KEY_LENGTH + ENCRYPTED_DATA_KEY_TAG_LENGTH;
pub const ENCRYPTED_DATA_KEY_LENGTH: usize =
    1 + NONCE_LENGTH + ENCRYPTED_DATA_KEY_CIPHERTEXT_LENGTH;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretId(Uuid);

impl SecretId {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
        let uuid = Builder::from_random_bytes(bytes).into_uuid();

        Ok(Self(uuid))
    }

    pub fn parse(value: &str) -> Result<Self, AadError> {
        let uuid = Uuid::parse_str(value).map_err(|_| AadError::InvalidUuid {
            field: "secret_id",
            value: value.to_owned(),
        })?;

        if uuid.get_version() != Some(Version::Random) {
            return Err(AadError::InvalidUuidVersion {
                field: "secret_id",
                value: value.to_owned(),
                expected: "v4",
            });
        }

        Ok(Self(uuid))
    }

    pub fn as_canonical_string(&self) -> String {
        self.0.hyphenated().to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretVersion(NonZeroU32);

impl SecretVersion {
    pub fn first() -> Self {
        Self(NonZeroU32::MIN)
    }

    pub fn new(value: u32) -> Result<Self, AadError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or(AadError::InvalidPositiveInteger {
                field: "version",
                value: value.to_string(),
            })
    }

    pub fn next(self) -> Result<Self, InputError> {
        let next = self
            .0
            .get()
            .checked_add(1)
            .ok_or(InputError::SecretVersionOverflow)?;

        NonZeroU32::new(next)
            .map(Self)
            .ok_or(InputError::SecretVersionOverflow)
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnerUserId(Uuid);

impl OwnerUserId {
    pub fn parse(value: &str) -> Result<Self, AadError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| AadError::InvalidUuid {
                field: "owner_user_id",
                value: value.to_owned(),
            })
    }

    pub fn as_canonical_string(&self) -> String {
        self.0.hyphenated().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Classification(String);

impl Classification {
    pub fn new(value: &str) -> Result<Self, AadError> {
        if value.trim().is_empty() {
            return Err(AadError::InvalidClassification);
        }

        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DeviceId(String);

impl DeviceId {
    pub fn new(value: &str) -> Result<Self, InputError> {
        if value.trim().is_empty() {
            return Err(InputError::InvalidDeviceId);
        }

        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceId")
            .field("len", &self.0.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CreatedAt(OffsetDateTime);

impl CreatedAt {
    pub fn parse(value: &str) -> Result<Self, AadError> {
        let normalized_value = rewrite_utc_suffix(value);
        let parsed = OffsetDateTime::parse(&normalized_value, &Rfc3339).map_err(|_| {
            AadError::InvalidTimestamp {
                field: "created_at",
                value: value.to_owned(),
            }
        })?;

        if parsed.offset() != UtcOffset::UTC {
            return Err(AadError::InvalidTimestamp {
                field: "created_at",
                value: value.to_owned(),
            });
        }

        Ok(Self(parsed.to_offset(UtcOffset::UTC)))
    }

    pub fn as_rfc3339_utc(&self) -> Result<String, AadError> {
        self.0
            .format(&Rfc3339)
            .map_err(|error| AadError::SerializationFailed(error.to_string()))
    }
}

fn rewrite_utc_suffix(value: &str) -> String {
    let trimmed = value.trim();
    let upper = trimmed.to_ascii_uppercase();

    if upper.ends_with(" UTC") {
        let prefix = &trimmed[..trimmed.len() - 4];
        return format!("{prefix}Z");
    }

    if upper.ends_with("UTC") {
        let prefix = &trimmed[..trimmed.len() - 3];
        return format!("{prefix}Z");
    }

    trimmed.to_owned()
}

pub struct DataKey([u8; DATA_KEY_LENGTH]);

impl DataKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; DATA_KEY_LENGTH];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;

        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; DATA_KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != DATA_KEY_LENGTH {
            return Err(CryptoError::InvalidDataKeyLength {
                actual: bytes.len(),
            });
        }

        let mut data_key = [0u8; DATA_KEY_LENGTH];
        data_key.copy_from_slice(bytes);

        Ok(Self(data_key))
    }

    pub fn as_bytes(&self) -> &[u8; DATA_KEY_LENGTH] {
        &self.0
    }
}

impl Drop for DataKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DataKey(<redacted>)")
    }
}

pub struct MasterKey([u8; MASTER_KEY_LENGTH]);

impl MasterKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; MASTER_KEY_LENGTH];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;

        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; MASTER_KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != MASTER_KEY_LENGTH {
            return Err(CryptoError::InvalidMasterKeyLength {
                actual: bytes.len(),
            });
        }

        let mut master_key = [0u8; MASTER_KEY_LENGTH];
        master_key.copy_from_slice(bytes);

        Ok(Self(master_key))
    }

    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LENGTH] {
        &self.0
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MasterKey(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyVersion(NonZeroU32);

impl KeyVersion {
    pub fn new(value: u32) -> Result<Self, CryptoError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or(CryptoError::InvalidKeyVersion { value })
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedDataKey(Vec<u8>);

impl EncryptedDataKey {
    pub fn parse(bytes: &[u8]) -> Result<Self, CryptoError> {
        validate_encrypted_data_key_envelope(bytes)?;

        Ok(Self(bytes.to_vec()))
    }

    pub fn from_envelope_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        validate_encrypted_data_key_envelope(&bytes)?;

        Ok(Self(bytes))
    }

    pub fn version(&self) -> u8 {
        self.0[0]
    }

    pub fn nonce_bytes(&self) -> &[u8] {
        &self.0[1..1 + NONCE_LENGTH]
    }

    pub fn ciphertext_bytes(&self) -> &[u8] {
        &self.0[1 + NONCE_LENGTH..]
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

fn validate_encrypted_data_key_envelope(bytes: &[u8]) -> Result<(), CryptoError> {
    if bytes.len() != ENCRYPTED_DATA_KEY_LENGTH {
        return Err(CryptoError::InvalidEncryptedDataKeyLength {
            actual: bytes.len(),
        });
    }

    let version = bytes[0];
    if version != ENCRYPTED_DATA_KEY_VERSION {
        return Err(CryptoError::UnsupportedEncryptedDataKeyVersion { version });
    }

    Ok(())
}

impl fmt::Debug for EncryptedDataKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedDataKey")
            .field("version", &self.version())
            .field("len", &self.0.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce([u8; NONCE_LENGTH]);

impl Nonce {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; NONCE_LENGTH];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;

        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; NONCE_LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != NONCE_LENGTH {
            return Err(CryptoError::InvalidNonceLength {
                actual: bytes.len(),
            });
        }

        let mut nonce = [0u8; NONCE_LENGTH];
        nonce.copy_from_slice(bytes);

        Ok(Self(nonce))
    }

    pub fn as_bytes(&self) -> &[u8; NONCE_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Nonce")
            .field("len", &NONCE_LENGTH)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext(Vec<u8>);

impl Ciphertext {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.is_empty() {
            return Err(CryptoError::EmptyCiphertext);
        }

        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ciphertext")
            .field("len", &self.0.len())
            .finish()
    }
}

pub struct Plaintext(Vec<u8>);

impl Plaintext {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Plaintext {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Plaintext")
            .field("len", &self.0.len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

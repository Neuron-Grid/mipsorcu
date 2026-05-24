use std::fmt;
use std::num::NonZeroU32;

use uuid::{Builder, Uuid, Version};

use crate::alias::NormalizedAlias;
use crate::error::{AadError, CryptoError, InputError};

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretAliasId(Uuid);

impl SecretAliasId {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
        let uuid = Builder::from_random_bytes(bytes).into_uuid();

        Ok(Self(uuid))
    }

    pub fn parse(value: &str) -> Result<Self, AadError> {
        let uuid = Uuid::parse_str(value).map_err(|_| AadError::InvalidUuid {
            field: "secret_alias_id",
            value: value.to_owned(),
        })?;

        if uuid.get_version() != Some(Version::Random) {
            return Err(AadError::InvalidUuidVersion {
                field: "secret_alias_id",
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

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum SecretRef {
    Id(SecretId),
    Alias(NormalizedAlias),
}

impl SecretRef {
    pub fn parse(value: &str) -> Result<Self, InputError> {
        let trimmed = value.trim();
        if let Ok(secret_id) = SecretId::parse(trimmed) {
            return Ok(Self::Id(secret_id));
        }

        NormalizedAlias::parse(trimmed)
            .map(Self::Alias)
            .map_err(|_| InputError::InvalidSecretAlias)
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(secret_id) => formatter.debug_tuple("Id").field(secret_id).finish(),
            Self::Alias(alias) => formatter.debug_tuple("Alias").field(alias).finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretVersionId(Uuid);

impl SecretVersionId {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
        let uuid = Builder::from_random_bytes(bytes).into_uuid();

        Ok(Self(uuid))
    }

    pub fn parse(value: &str) -> Result<Self, AadError> {
        let uuid = Uuid::parse_str(value).map_err(|_| AadError::InvalidUuid {
            field: "secret_version_id",
            value: value.to_owned(),
        })?;

        if uuid.get_version() != Some(Version::Random) {
            return Err(AadError::InvalidUuidVersion {
                field: "secret_version_id",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KekVersion(KeyVersion);

impl KekVersion {
    pub fn new(value: u32) -> Result<Self, CryptoError> {
        KeyVersion::new(value).map(Self)
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<KeyVersion> for KekVersion {
    fn from(value: KeyVersion) -> Self {
        Self(value)
    }
}

impl From<KekVersion> for KeyVersion {
    fn from(value: KekVersion) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AliasFingerprintSchemaVersion(NonZeroU32);

impl AliasFingerprintSchemaVersion {
    pub const V1: Self = Self(NonZeroU32::MIN);

    pub fn new(value: u32) -> Result<Self, CryptoError> {
        let value = NonZeroU32::new(value).ok_or(CryptoError::InvalidKeyVersion { value })?;
        if value != Self::V1.0 {
            return Err(CryptoError::UnsupportedAliasFingerprintSchemaVersion {
                value: value.get(),
            });
        }

        Ok(Self(value))
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

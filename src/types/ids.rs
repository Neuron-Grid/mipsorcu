use std::fmt;
use std::num::NonZeroU32;

use uuid::{Builder, Uuid, Version};

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

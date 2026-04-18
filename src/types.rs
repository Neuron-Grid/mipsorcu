use std::num::NonZeroU32;

use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use uuid::Uuid;

use crate::error::AadError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretId(Uuid);

impl SecretId {
    pub fn parse(value: &str) -> Result<Self, AadError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| AadError::InvalidUuid {
                field: "secret_id",
                value: value.to_owned(),
            })
    }

    pub fn as_canonical_string(&self) -> String {
        self.0.hyphenated().to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretVersion(NonZeroU32);

impl SecretVersion {
    pub fn new(value: u32) -> Result<Self, AadError> {
        NonZeroU32::new(value)
            .map(Self)
            .ok_or(AadError::InvalidPositiveInteger {
                field: "version",
                value: value.to_string(),
            })
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

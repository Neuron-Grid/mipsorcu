use uuid::{Builder, Uuid, Version};

use crate::types::SecretVersionId;

use super::constants::LEDGER_I64_MAX_U64;
use super::error::LedgerError;

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

    pub fn from_secret_version_id(value: &SecretVersionId) -> Result<Self, LedgerError> {
        Self::parse(&value.as_canonical_string())
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

use std::fmt;

use sha2::{Digest, Sha256};

use super::canonical::LedgerCanonicalPayload;
use super::constants::LEDGER_HASH_LENGTH;
use super::error::LedgerError;

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

use std::fmt;

use hmac::{KeyInit, Mac, SimpleHmac};
use sha3::Sha3_256;

use crate::alias::input::NormalizedAlias;
use crate::error::CryptoError;
use crate::types::{AliasFingerprintKey, OwnerUserId};

type HmacSha3_256 = SimpleHmac<Sha3_256>;

pub const ALIAS_FINGERPRINT_LENGTH: usize = 32;
pub const ALIAS_FINGERPRINT_SCHEMA_VERSION_V1: u32 = 1;
const FINGERPRINT_DOMAIN: &str = "mipsorcu:v1:secret-alias-fingerprint";

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AliasFingerprint([u8; ALIAS_FINGERPRINT_LENGTH]);

impl AliasFingerprint {
    pub fn from_bytes(bytes: [u8; ALIAS_FINGERPRINT_LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ALIAS_FINGERPRINT_LENGTH {
            return Err(CryptoError::InvalidAliasFingerprintLength {
                actual: bytes.len(),
            });
        }

        let mut output = [0u8; ALIAS_FINGERPRINT_LENGTH];
        output.copy_from_slice(bytes);

        Ok(Self(output))
    }

    pub fn as_bytes(&self) -> &[u8; ALIAS_FINGERPRINT_LENGTH] {
        &self.0
    }

    pub fn to_hex_string(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for AliasFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AliasFingerprint")
            .field("len", &ALIAS_FINGERPRINT_LENGTH)
            .finish()
    }
}

pub fn compute_alias_fingerprint(
    fingerprint_key: &AliasFingerprintKey,
    owner_user_id: &OwnerUserId,
    alias: &NormalizedAlias,
) -> Result<AliasFingerprint, CryptoError> {
    let mut mac = HmacSha3_256::new_from_slice(fingerprint_key.as_bytes())
        .map_err(|_| CryptoError::FingerprintComputationFailed)?;
    let owner_canonical = owner_user_id.as_canonical_string();

    debug_assert_eq!(owner_canonical.len(), 36);
    debug_assert_eq!(FINGERPRINT_DOMAIN.len(), 36);

    mac.update(FINGERPRINT_DOMAIN.as_bytes());
    mac.update(owner_canonical.as_bytes());
    mac.update(alias.as_bytes());

    let result = mac.finalize().into_bytes();
    let mut output = [0u8; ALIAS_FINGERPRINT_LENGTH];
    output.copy_from_slice(&result);

    Ok(AliasFingerprint(output))
}

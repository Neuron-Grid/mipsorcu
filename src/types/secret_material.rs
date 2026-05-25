use std::fmt;

use zeroize::Zeroize;

use crate::error::{CryptoError, KekError};

use super::ids::KekVersion;

pub const DATA_KEY_LENGTH: usize = 32;
pub const MASTER_KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 24;
pub const ENCRYPTED_DATA_KEY_VERSION: u8 = 1;
pub const ENCRYPTED_DATA_KEY_TAG_LENGTH: usize = 16;
pub const ENCRYPTED_DATA_KEY_CIPHERTEXT_LENGTH: usize =
    DATA_KEY_LENGTH + ENCRYPTED_DATA_KEY_TAG_LENGTH;
pub const ENCRYPTED_DATA_KEY_LENGTH: usize =
    1 + NONCE_LENGTH + ENCRYPTED_DATA_KEY_CIPHERTEXT_LENGTH;

pub struct DekPlaintext([u8; DATA_KEY_LENGTH]);

impl DekPlaintext {
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

        let mut dek = [0u8; DATA_KEY_LENGTH];
        dek.copy_from_slice(bytes);

        Ok(Self(dek))
    }

    pub fn as_bytes(&self) -> &[u8; DATA_KEY_LENGTH] {
        &self.0
    }
}

impl Drop for DekPlaintext {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for DekPlaintext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DekPlaintext(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum KekAlgorithm {
    LegacyMasterKeyV1,
    EnvvarXchachaV2,
}

impl KekAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyMasterKeyV1 => "legacy-master-key-v1",
            Self::EnvvarXchachaV2 => "envvar-xchacha-v2",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CryptoError> {
        match value {
            "legacy-master-key-v1" => Ok(Self::LegacyMasterKeyV1),
            "envvar-xchacha-v2" => Ok(Self::EnvvarXchachaV2),
            _ => Err(CryptoError::UnknownDekWrapAlgorithm),
        }
    }
}

impl fmt::Display for KekAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for KekAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WrappedDek {
    kek_version: KekVersion,
    bytes: Vec<u8>,
}

impl WrappedDek {
    pub fn new(kek_version: KekVersion, bytes: Vec<u8>) -> Result<Self, KekError> {
        validate_wrapped_dek_bytes(&bytes)?;

        Ok(Self { kek_version, bytes })
    }

    pub fn parse(kek_version: KekVersion, bytes: &[u8]) -> Result<Self, KekError> {
        Self::new(kek_version, bytes.to_vec())
    }

    pub fn kek_version(&self) -> KekVersion {
        self.kek_version
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

fn validate_wrapped_dek_bytes(bytes: &[u8]) -> Result<(), KekError> {
    if bytes.len() <= NONCE_LENGTH {
        return Err(KekError::InvalidWrappedFormat {
            actual_len: bytes.len(),
        });
    }

    Ok(())
}

impl fmt::Debug for WrappedDek {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WrappedDek")
            .field("kek_version", &self.kek_version)
            .field("len", &self.bytes.len())
            .finish()
    }
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

pub struct AliasEncryptionKey([u8; MASTER_KEY_LENGTH]);

impl AliasEncryptionKey {
    pub fn from_bytes(bytes: [u8; MASTER_KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != MASTER_KEY_LENGTH {
            return Err(CryptoError::InvalidAliasEncryptionKeyLength {
                actual: bytes.len(),
            });
        }

        let mut alias_encryption_key = [0u8; MASTER_KEY_LENGTH];
        alias_encryption_key.copy_from_slice(bytes);

        Ok(Self(alias_encryption_key))
    }

    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LENGTH] {
        &self.0
    }
}

impl Drop for AliasEncryptionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for AliasEncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AliasEncryptionKey(<redacted>)")
    }
}

pub struct AliasFingerprintKey([u8; MASTER_KEY_LENGTH]);

impl AliasFingerprintKey {
    pub fn from_bytes(bytes: [u8; MASTER_KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != MASTER_KEY_LENGTH {
            return Err(CryptoError::InvalidAliasFingerprintKeyLength {
                actual: bytes.len(),
            });
        }

        let mut alias_fingerprint_key = [0u8; MASTER_KEY_LENGTH];
        alias_fingerprint_key.copy_from_slice(bytes);

        Ok(Self(alias_fingerprint_key))
    }

    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LENGTH] {
        &self.0
    }
}

impl Drop for AliasFingerprintKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for AliasFingerprintKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AliasFingerprintKey(<redacted>)")
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

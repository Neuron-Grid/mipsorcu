use std::fmt;

use zeroize::Zeroize;

use crate::error::CryptoError;

pub const DATA_KEY_LENGTH: usize = 32;
pub const MASTER_KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 24;
pub const ENCRYPTED_DATA_KEY_VERSION: u8 = 1;
pub const ENCRYPTED_DATA_KEY_TAG_LENGTH: usize = 16;
pub const ENCRYPTED_DATA_KEY_CIPHERTEXT_LENGTH: usize =
    DATA_KEY_LENGTH + ENCRYPTED_DATA_KEY_TAG_LENGTH;
pub const ENCRYPTED_DATA_KEY_LENGTH: usize =
    1 + NONCE_LENGTH + ENCRYPTED_DATA_KEY_CIPHERTEXT_LENGTH;

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

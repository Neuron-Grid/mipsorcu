use std::collections::BTreeMap;
use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::error::{KekError, KeyringError};
use crate::types::{
    DATA_KEY_LENGTH, DekPlaintext, KekAlgorithm, KekVersion, MasterKey, NONCE_LENGTH, Nonce,
    WrappedDek,
};

use super::KekProvider;

const WRAPPED_DEK_TAG_LENGTH: usize = 16;
const ENVVAR_WRAPPED_DEK_LENGTH: usize = NONCE_LENGTH + DATA_KEY_LENGTH + WRAPPED_DEK_TAG_LENGTH;
const KEY_FINGERPRINT_PREFIX_BYTES: usize = 8;

pub struct EnvVarKek {
    active_version: KekVersion,
    keys: BTreeMap<KekVersion, MasterKey>,
}

impl EnvVarKek {
    pub fn new(
        active_version: KekVersion,
        keys: BTreeMap<KekVersion, MasterKey>,
    ) -> Result<Self, KeyringError> {
        if keys.is_empty() {
            return Err(KeyringError::Empty);
        }

        if !keys.contains_key(&active_version) {
            return Err(KeyringError::ActiveKeyMissing {
                key_version: active_version.get(),
            });
        }

        Ok(Self {
            active_version,
            keys,
        })
    }

    pub fn from_key_entries<I>(active_version: KekVersion, entries: I) -> Result<Self, KeyringError>
    where
        I: IntoIterator<Item = (KekVersion, MasterKey)>,
    {
        let mut keys = BTreeMap::new();

        for (key_version, master_key) in entries {
            if keys.insert(key_version, master_key).is_some() {
                return Err(KeyringError::DuplicateKeyVersion {
                    key_version: key_version.get(),
                });
            }
        }

        Self::new(active_version, keys)
    }

    pub fn single(active_version: KekVersion, master_key: MasterKey) -> Result<Self, KeyringError> {
        Self::from_key_entries(active_version, [(active_version, master_key)])
    }

    pub fn active(&self) -> (KekVersion, &MasterKey) {
        let Some(master_key) = self.keys.get(&self.active_version) else {
            // Construction validates that the active key is present; reaching this branch
            // means the keyring invariant was broken after construction.
            unreachable!(
                "EnvVarKek invariant violated: active key version must be present after construction"
            );
        };

        (self.active_version, master_key)
    }

    pub fn active_version(&self) -> KekVersion {
        self.active_version
    }

    pub fn get(&self, key_version: KekVersion) -> Result<&MasterKey, KeyringError> {
        self.keys
            .get(&key_version)
            .ok_or(KeyringError::KeyUnavailable {
                key_version: key_version.get(),
            })
    }

    pub fn contains(&self, key_version: KekVersion) -> bool {
        self.keys.contains_key(&key_version)
    }

    pub fn key_versions(&self) -> Vec<KekVersion> {
        self.keys.keys().copied().collect()
    }

    pub fn active_key_fingerprint_hex(&self) -> Result<String, KeyringError> {
        self.key_fingerprint_hex(self.active_version)
    }

    pub fn key_fingerprint_hex(&self, key_version: KekVersion) -> Result<String, KeyringError> {
        self.get(key_version).map(master_key_fingerprint_hex)
    }
}

impl fmt::Debug for EnvVarKek {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvVarKek")
            .field("active_version", &self.active_version)
            .field("key_versions", &self.key_versions())
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl KekProvider for EnvVarKek {
    fn wrap_dek(&self, dek: &DekPlaintext) -> Result<WrappedDek, KekError> {
        let (key_version, master_key) = self.active();
        let nonce = Nonce::generate().map_err(|_| KekError::WrapFailed)?;
        let aad = kek_wrap_aad(key_version);
        let cipher = cipher_from_master_key(master_key).map_err(|_| KekError::WrapFailed)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(nonce.as_bytes()),
                Payload {
                    msg: dek.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| KekError::WrapFailed)?;

        if ciphertext.len() != DATA_KEY_LENGTH + WRAPPED_DEK_TAG_LENGTH {
            return Err(KekError::WrapFailed);
        }

        let mut envelope = Vec::with_capacity(ENVVAR_WRAPPED_DEK_LENGTH);
        envelope.extend_from_slice(nonce.as_bytes());
        envelope.extend_from_slice(&ciphertext);

        WrappedDek::new(key_version, envelope).map_err(|_| KekError::WrapFailed)
    }

    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<DekPlaintext, KekError> {
        let (nonce_bytes, ciphertext_bytes) = split_wrapped_dek_bytes(wrapped.as_bytes())?;
        let key_version = wrapped.kek_version();
        let master_key = self
            .get(key_version)
            .map_err(|_| KekError::KekNotAvailable {
                kek_version: key_version.get(),
            })?;
        let aad = kek_wrap_aad(key_version);
        let cipher = cipher_from_master_key(master_key).map_err(|_| KekError::UnwrapFailed)?;
        let mut plaintext = cipher
            .decrypt(
                XNonce::from_slice(nonce_bytes),
                Payload {
                    msg: ciphertext_bytes,
                    aad: &aad,
                },
            )
            .map_err(|_| KekError::UnwrapFailed)?;

        let parsed = DekPlaintext::parse(&plaintext).map_err(|_| KekError::UnwrapFailed);
        plaintext.zeroize();

        parsed
    }

    fn kek_version(&self) -> KekVersion {
        self.active_version
    }

    fn kek_algorithm(&self) -> KekAlgorithm {
        KekAlgorithm::EnvvarXchachaV2
    }
}

fn split_wrapped_dek_bytes(bytes: &[u8]) -> Result<(&[u8], &[u8]), KekError> {
    if bytes.len() != ENVVAR_WRAPPED_DEK_LENGTH {
        return Err(KekError::InvalidWrappedFormat {
            actual_len: bytes.len(),
        });
    }

    let Some(nonce_bytes) = bytes.get(..NONCE_LENGTH) else {
        return Err(KekError::InvalidWrappedFormat {
            actual_len: bytes.len(),
        });
    };
    let Some(ciphertext_bytes) = bytes.get(NONCE_LENGTH..) else {
        return Err(KekError::InvalidWrappedFormat {
            actual_len: bytes.len(),
        });
    };

    Ok((nonce_bytes, ciphertext_bytes))
}

fn kek_wrap_aad(key_version: KekVersion) -> Vec<u8> {
    format!("kek_version={};", key_version.get()).into_bytes()
}

fn cipher_from_master_key(master_key: &MasterKey) -> Result<XChaCha20Poly1305, ()> {
    XChaCha20Poly1305::new_from_slice(master_key.as_bytes()).map_err(|_| ())
}

fn master_key_fingerprint_hex(master_key: &MasterKey) -> String {
    let digest = Sha3_256::digest(master_key.as_bytes());
    let prefix = digest
        .iter()
        .take(KEY_FINGERPRINT_PREFIX_BYTES)
        .copied()
        .collect::<Vec<_>>();

    hex::encode(prefix)
}

#[cfg(test)]
#[path = "../../../tests/unit/crypto/kek/envvar/tests.rs"]
mod tests;

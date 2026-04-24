use std::collections::BTreeMap;
use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroize;

use crate::aad::AadV1;
use crate::error::{CryptoError, KeyringError};
use crate::types::{
    Ciphertext, DATA_KEY_LENGTH, DataKey, ENCRYPTED_DATA_KEY_CIPHERTEXT_LENGTH,
    ENCRYPTED_DATA_KEY_LENGTH, ENCRYPTED_DATA_KEY_VERSION, EncryptedDataKey, KeyVersion, MasterKey,
    Nonce, Plaintext, SecretId,
};

pub const ALGORITHM_XCHACHA20_POLY1305: &str = "xchacha20-poly1305";
const KEY_WRAP_CONTEXT: &str = "data_key_wrap";
const KEY_WRAP_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapContext {
    secret_id: SecretId,
    key_version: KeyVersion,
}

impl KeyWrapContext {
    pub fn new(secret_id: SecretId, key_version: KeyVersion) -> Self {
        Self {
            secret_id,
            key_version,
        }
    }

    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    pub fn key_version(&self) -> KeyVersion {
        self.key_version
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let secret_id = self.secret_id.as_canonical_string();
        let aad = CanonicalKeyWrapAad {
            context: KEY_WRAP_CONTEXT,
            key_version: self.key_version.get(),
            secret_id: &secret_id,
            wrap_version: KEY_WRAP_VERSION,
        };

        serde_json::to_vec(&aad).map_err(|_| CryptoError::AadFailed)
    }
}

pub struct MasterKeyRing {
    active_key_version: KeyVersion,
    keys: BTreeMap<KeyVersion, MasterKey>,
}

impl MasterKeyRing {
    pub fn new(
        active_key_version: KeyVersion,
        keys: BTreeMap<KeyVersion, MasterKey>,
    ) -> Result<Self, KeyringError> {
        if keys.is_empty() {
            return Err(KeyringError::Empty);
        }

        if !keys.contains_key(&active_key_version) {
            return Err(KeyringError::ActiveKeyMissing {
                key_version: active_key_version.get(),
            });
        }

        Ok(Self {
            active_key_version,
            keys,
        })
    }

    pub fn from_key_entries<I>(
        active_key_version: KeyVersion,
        entries: I,
    ) -> Result<Self, KeyringError>
    where
        I: IntoIterator<Item = (KeyVersion, MasterKey)>,
    {
        let mut keys = BTreeMap::new();

        for (key_version, master_key) in entries {
            if keys.insert(key_version, master_key).is_some() {
                return Err(KeyringError::DuplicateKeyVersion {
                    key_version: key_version.get(),
                });
            }
        }

        Self::new(active_key_version, keys)
    }

    pub fn single(
        active_key_version: KeyVersion,
        master_key: MasterKey,
    ) -> Result<Self, KeyringError> {
        Self::from_key_entries(active_key_version, [(active_key_version, master_key)])
    }

    pub fn active(&self) -> (KeyVersion, &MasterKey) {
        let master_key = self.keys.get(&self.active_key_version).expect(
            "MasterKeyRing invariant violated: active key version must be present after construction",
        );

        (self.active_key_version, master_key)
    }

    pub fn active_key_version(&self) -> KeyVersion {
        self.active_key_version
    }

    pub fn get(&self, key_version: KeyVersion) -> Result<&MasterKey, KeyringError> {
        self.keys
            .get(&key_version)
            .ok_or(KeyringError::KeyUnavailable {
                key_version: key_version.get(),
            })
    }

    pub fn contains(&self, key_version: KeyVersion) -> bool {
        self.keys.contains_key(&key_version)
    }

    pub fn key_versions(&self) -> Vec<KeyVersion> {
        self.keys.keys().copied().collect()
    }
}

impl fmt::Debug for MasterKeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MasterKeyRing")
            .field("active_key_version", &self.active_key_version)
            .field("key_versions", &self.key_versions())
            .field("keys", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize)]
struct CanonicalKeyWrapAad<'a> {
    context: &'a str,
    key_version: u32,
    secret_id: &'a str,
    wrap_version: u8,
}

pub struct EncryptedPayload {
    ciphertext: Ciphertext,
    nonce: Nonce,
    aad_context: Value,
}

impl EncryptedPayload {
    fn new(ciphertext: Ciphertext, nonce: Nonce, aad_context: Value) -> Self {
        Self {
            ciphertext,
            nonce,
            aad_context,
        }
    }

    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn aad_context(&self) -> &Value {
        &self.aad_context
    }

    pub fn into_parts(self) -> (Ciphertext, Nonce, Value) {
        (self.ciphertext, self.nonce, self.aad_context)
    }
}

impl fmt::Debug for EncryptedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedPayload")
            .field("ciphertext", &self.ciphertext)
            .field("nonce", &self.nonce)
            .field("aad_context", &"<redacted>")
            .finish()
    }
}

pub fn encrypt_secret(
    data_key: &DataKey,
    aad: &AadV1,
    plaintext: &Plaintext,
) -> Result<EncryptedPayload, CryptoError> {
    let nonce = Nonce::generate()?;
    let aad_bytes = aad.canonical_bytes()?;
    let cipher = cipher_from_data_key(data_key)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
        .and_then(Ciphertext::new)?;
    let aad_context = aad.to_stored_context()?;

    Ok(EncryptedPayload::new(ciphertext, nonce, aad_context))
}

pub fn decrypt_secret(
    data_key: &DataKey,
    aad: &AadV1,
    nonce: &Nonce,
    ciphertext: &Ciphertext,
) -> Result<Plaintext, CryptoError> {
    let aad_bytes = aad.canonical_bytes()?;
    let cipher = cipher_from_data_key(data_key)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: ciphertext.as_bytes(),
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(Plaintext::new(plaintext))
}

pub fn wrap_data_key(
    master_key: &MasterKey,
    context: &KeyWrapContext,
    data_key: &DataKey,
) -> Result<EncryptedDataKey, CryptoError> {
    let nonce = Nonce::generate()?;
    let aad_bytes = context.canonical_bytes()?;
    let cipher = cipher_from_master_key(master_key)?;
    let encrypted_data_key = cipher
        .encrypt(
            XNonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: data_key.as_bytes(),
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::KeyWrapFailed)?;

    if encrypted_data_key.len() != ENCRYPTED_DATA_KEY_CIPHERTEXT_LENGTH {
        return Err(CryptoError::KeyWrapFailed);
    }

    let mut envelope = Vec::with_capacity(ENCRYPTED_DATA_KEY_LENGTH);
    envelope.push(ENCRYPTED_DATA_KEY_VERSION);
    envelope.extend_from_slice(nonce.as_bytes());
    envelope.extend_from_slice(&encrypted_data_key);

    EncryptedDataKey::from_envelope_bytes(envelope)
}

pub fn unwrap_data_key(
    master_key: &MasterKey,
    context: &KeyWrapContext,
    encrypted_data_key: &EncryptedDataKey,
) -> Result<DataKey, CryptoError> {
    let aad_bytes = context.canonical_bytes()?;
    let cipher = cipher_from_master_key(master_key)?;
    let mut data_key = cipher
        .decrypt(
            XNonce::from_slice(encrypted_data_key.nonce_bytes()),
            Payload {
                msg: encrypted_data_key.ciphertext_bytes(),
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::KeyUnwrapFailed)?;

    if data_key.len() != DATA_KEY_LENGTH {
        data_key.zeroize();
        return Err(CryptoError::KeyUnwrapFailed);
    }

    let parsed_data_key = DataKey::parse(&data_key).map_err(|_| CryptoError::KeyUnwrapFailed);
    data_key.zeroize();

    parsed_data_key
}

fn cipher_from_data_key(data_key: &DataKey) -> Result<XChaCha20Poly1305, CryptoError> {
    XChaCha20Poly1305::new_from_slice(data_key.as_bytes()).map_err(|_| {
        CryptoError::InvalidDataKeyLength {
            actual: data_key.as_bytes().len(),
        }
    })
}

fn cipher_from_master_key(master_key: &MasterKey) -> Result<XChaCha20Poly1305, CryptoError> {
    XChaCha20Poly1305::new_from_slice(master_key.as_bytes()).map_err(|_| {
        CryptoError::InvalidMasterKeyLength {
            actual: master_key.as_bytes().len(),
        }
    })
}

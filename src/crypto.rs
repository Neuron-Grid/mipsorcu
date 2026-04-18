use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde_json::Value;

use crate::aad::AadV1;
use crate::error::CryptoError;
use crate::types::{Ciphertext, DataKey, Nonce, Plaintext};

pub const ALGORITHM_XCHACHA20_POLY1305: &str = "xchacha20-poly1305";

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

fn cipher_from_data_key(data_key: &DataKey) -> Result<XChaCha20Poly1305, CryptoError> {
    XChaCha20Poly1305::new_from_slice(data_key.as_bytes()).map_err(|_| {
        CryptoError::InvalidDataKeyLength {
            actual: data_key.as_bytes().len(),
        }
    })
}

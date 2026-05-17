use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::alias::aad::AliasAadV1;
use crate::alias::input::NormalizedAlias;
use crate::error::CryptoError;
use crate::types::{AliasEncryptionKey, Ciphertext, Nonce};

pub struct EncryptedAlias {
    ciphertext: Ciphertext,
    nonce: Nonce,
}

impl EncryptedAlias {
    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn into_parts(self) -> (Ciphertext, Nonce) {
        (self.ciphertext, self.nonce)
    }
}

impl fmt::Debug for EncryptedAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedAlias")
            .field("ciphertext", &self.ciphertext)
            .field("nonce", &self.nonce)
            .finish()
    }
}

pub fn encrypt_alias(
    encryption_key: &AliasEncryptionKey,
    aad: &AliasAadV1,
    alias: &NormalizedAlias,
) -> Result<EncryptedAlias, CryptoError> {
    let nonce = Nonce::generate()?;
    let aad_bytes = aad.canonical_bytes()?;
    let cipher = cipher_from_alias_key(encryption_key)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: alias.as_bytes(),
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
        .and_then(Ciphertext::new)?;

    Ok(EncryptedAlias { ciphertext, nonce })
}

pub fn decrypt_alias(
    encryption_key: &AliasEncryptionKey,
    aad: &AliasAadV1,
    nonce: &Nonce,
    ciphertext: &Ciphertext,
) -> Result<NormalizedAlias, CryptoError> {
    let aad_bytes = aad.canonical_bytes()?;
    let cipher = cipher_from_alias_key(encryption_key)?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: ciphertext.as_bytes(),
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let plaintext = std::str::from_utf8(&plaintext).map_err(|_| CryptoError::DecryptionFailed)?;

    NormalizedAlias::parse(plaintext).map_err(|_| CryptoError::DecryptionFailed)
}

fn cipher_from_alias_key(key: &AliasEncryptionKey) -> Result<XChaCha20Poly1305, CryptoError> {
    XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| {
        CryptoError::InvalidAliasEncryptionKeyLength {
            actual: key.as_bytes().len(),
        }
    })
}

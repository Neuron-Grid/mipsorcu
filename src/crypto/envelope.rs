use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde_json::Value;

use crate::aad::AadV1;
use crate::crypto::kek::KekProvider;
use crate::error::{CryptoError, KekError, KeyringError, SecretDecryptError};
use crate::types::{
    Ciphertext, DekPlaintext, EncryptedDataKey, KekAlgorithm, KekVersion, KeyVersion, Nonce,
    Plaintext, SecretId, WrappedDek,
};

use super::{KeyWrapContext, MasterKeyRing, decrypt_secret, unwrap_data_key};

#[derive(Clone, PartialEq, Eq)]
pub struct SecretVersionRecord {
    pub secret_id: SecretId,
    pub key_version: KeyVersion,
    pub ciphertext: Ciphertext,
    pub nonce: Nonce,
    pub encrypted_data_key: Option<EncryptedDataKey>,
    pub wrapped_dek: Option<WrappedDek>,
    pub dek_wrap_algorithm: Option<KekAlgorithm>,
}

impl fmt::Debug for SecretVersionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretVersionRecord")
            .field("secret_id", &self.secret_id)
            .field("key_version", &self.key_version)
            .field("ciphertext", &self.ciphertext)
            .field("nonce", &self.nonce)
            .field("encrypted_data_key", &self.encrypted_data_key)
            .field("wrapped_dek", &self.wrapped_dek)
            .field("dek_wrap_algorithm", &self.dek_wrap_algorithm)
            .finish()
    }
}

pub struct EnvelopeOutput {
    ciphertext: Ciphertext,
    nonce: Nonce,
    wrapped_dek: WrappedDek,
    dek_wrap_algorithm: KekAlgorithm,
    kek_version: KekVersion,
    aad_context: Value,
}

impl EnvelopeOutput {
    fn new(
        ciphertext: Ciphertext,
        nonce: Nonce,
        wrapped_dek: WrappedDek,
        dek_wrap_algorithm: KekAlgorithm,
        kek_version: KekVersion,
        aad_context: Value,
    ) -> Self {
        Self {
            ciphertext,
            nonce,
            wrapped_dek,
            dek_wrap_algorithm,
            kek_version,
            aad_context,
        }
    }

    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    pub fn wrapped_dek(&self) -> &WrappedDek {
        &self.wrapped_dek
    }

    pub fn dek_wrap_algorithm(&self) -> KekAlgorithm {
        self.dek_wrap_algorithm
    }

    pub fn kek_version(&self) -> KekVersion {
        self.kek_version
    }

    pub fn aad_context(&self) -> &Value {
        &self.aad_context
    }

    pub fn into_parts(
        self,
    ) -> (
        Ciphertext,
        Nonce,
        WrappedDek,
        KekAlgorithm,
        KekVersion,
        Value,
    ) {
        (
            self.ciphertext,
            self.nonce,
            self.wrapped_dek,
            self.dek_wrap_algorithm,
            self.kek_version,
            self.aad_context,
        )
    }
}

impl fmt::Debug for EnvelopeOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnvelopeOutput")
            .field("ciphertext", &self.ciphertext)
            .field("nonce", &self.nonce)
            .field("wrapped_dek", &self.wrapped_dek)
            .field("dek_wrap_algorithm", &self.dek_wrap_algorithm)
            .field("kek_version", &self.kek_version)
            .field("aad_context", &"<redacted>")
            .finish()
    }
}

pub fn seal_v02<K: KekProvider>(
    kek: &K,
    plaintext: &[u8],
    aad: &AadV1,
) -> Result<EnvelopeOutput, CryptoError> {
    let dek = DekPlaintext::generate()?;
    let nonce = Nonce::generate()?;
    let aad_bytes = aad.canonical_bytes()?;
    let cipher = cipher_from_dek(&dek)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: plaintext,
                aad: &aad_bytes,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
        .and_then(Ciphertext::new)?;
    let wrapped_dek = kek.wrap_dek(&dek).map_err(|_| CryptoError::KeyWrapFailed)?;
    let aad_context = aad.to_stored_context()?;

    Ok(EnvelopeOutput::new(
        ciphertext,
        nonce,
        wrapped_dek,
        kek.kek_algorithm(),
        kek.kek_version(),
        aad_context,
    ))
}

pub fn open_legacy_v01(
    keyring: &MasterKeyRing,
    record: &SecretVersionRecord,
    aad: &AadV1,
) -> Result<Plaintext, SecretDecryptError> {
    let encrypted_data_key = record
        .encrypted_data_key
        .as_ref()
        .ok_or(CryptoError::MissingEncryptedDataKey)?;
    let master_key = keyring.get(record.key_version)?;
    let key_wrap_context = KeyWrapContext::new(record.secret_id.clone(), record.key_version);
    let data_key = unwrap_data_key(master_key, &key_wrap_context, encrypted_data_key)?;

    decrypt_secret(&data_key, aad, &record.nonce, &record.ciphertext)
        .map_err(SecretDecryptError::from)
}

pub fn open_v02<K: KekProvider>(
    kek: &K,
    wrapped_dek: &WrappedDek,
    ciphertext: &Ciphertext,
    nonce: &Nonce,
    aad: &AadV1,
) -> Result<Plaintext, SecretDecryptError> {
    let dek = kek.unwrap_dek(wrapped_dek).map_err(map_kek_unwrap_error)?;
    let aad_bytes = aad.canonical_bytes()?;
    let cipher = cipher_from_dek(&dek)?;
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

pub fn open_dispatched(
    keyring: &MasterKeyRing,
    record: &SecretVersionRecord,
    aad: &AadV1,
) -> Result<Plaintext, SecretDecryptError> {
    match record.dek_wrap_algorithm {
        None | Some(KekAlgorithm::LegacyMasterKeyV1) => open_legacy_v01(keyring, record, aad),
        Some(KekAlgorithm::EnvvarXchachaV2) => {
            let wrapped_dek = record
                .wrapped_dek
                .as_ref()
                .ok_or(CryptoError::MissingWrappedDek)?;

            open_v02(
                keyring.as_envvar_kek(),
                wrapped_dek,
                &record.ciphertext,
                &record.nonce,
                aad,
            )
        }
    }
}

fn map_kek_unwrap_error(error: KekError) -> SecretDecryptError {
    match error {
        KekError::KekNotAvailable { kek_version } => {
            SecretDecryptError::Keyring(KeyringError::KeyUnavailable {
                key_version: kek_version,
            })
        }
        KekError::UnwrapFailed
        | KekError::VersionMismatch { .. }
        | KekError::InvalidWrappedFormat { .. } => {
            SecretDecryptError::Crypto(CryptoError::KeyUnwrapFailed)
        }
        KekError::WrapFailed => SecretDecryptError::Crypto(CryptoError::KeyUnwrapFailed),
    }
}

fn cipher_from_dek(dek: &DekPlaintext) -> Result<XChaCha20Poly1305, CryptoError> {
    XChaCha20Poly1305::new_from_slice(dek.as_bytes()).map_err(|_| {
        CryptoError::InvalidDataKeyLength {
            actual: dek.as_bytes().len(),
        }
    })
}

#[cfg(test)]
#[path = "../../tests/unit/crypto/envelope/tests.rs"]
mod tests;

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
mod tests {
    use super::*;
    use crate::crypto::{KeyWrapContext, decrypt_secret, encrypt_secret, wrap_data_key};
    use crate::types::{
        DATA_KEY_LENGTH, DataKey, MASTER_KEY_LENGTH, MasterKey, Plaintext, SecretId,
    };
    use crate::{EnvVarKek, KekProvider, MasterKeyRing};

    fn version(value: u32) -> crate::KekVersion {
        crate::KekVersion::new(value).expect("test version should be positive")
    }

    fn sample_kek() -> EnvVarKek {
        EnvVarKek::single(version(2), MasterKey::from_bytes([22u8; MASTER_KEY_LENGTH]))
            .expect("test kek should be valid")
    }

    fn sample_aad() -> AadV1 {
        AadV1::parse(
            "550e8400-e29b-41d4-a716-446655440000",
            1,
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "confidential",
            "2026-04-08T12:00:00Z",
        )
        .expect("sample aad should be valid")
    }

    fn sample_secret_id() -> SecretId {
        SecretId::parse("550e8400-e29b-41d4-a716-446655440000")
            .expect("sample secret id should be valid")
    }

    fn legacy_record(plaintext: &[u8]) -> (MasterKeyRing, SecretVersionRecord, AadV1) {
        let key_version = KeyVersion::new(1).expect("legacy test key version should be positive");
        let master_key = MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH]);
        let keyring = MasterKeyRing::single(
            key_version,
            MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH]),
        )
        .expect("legacy keyring should be valid");
        let data_key = DataKey::from_bytes([7u8; DATA_KEY_LENGTH]);
        let secret_id = sample_secret_id();
        let aad = sample_aad();
        let encrypted_payload =
            encrypt_secret(&data_key, &aad, &Plaintext::new(plaintext.to_vec()))
                .expect("legacy payload encryption should succeed");
        let encrypted_data_key = wrap_data_key(
            &master_key,
            &KeyWrapContext::new(secret_id.clone(), key_version),
            &data_key,
        )
        .expect("legacy data key wrapping should succeed");
        let (ciphertext, nonce, _) = encrypted_payload.into_parts();

        (
            keyring,
            SecretVersionRecord {
                secret_id,
                key_version,
                ciphertext,
                nonce,
                encrypted_data_key: Some(encrypted_data_key),
                wrapped_dek: None,
                dek_wrap_algorithm: None,
            },
            aad,
        )
    }

    #[test]
    fn seal_v02_round_trips_with_unwrapped_dek() {
        let kek = sample_kek();
        let aad = sample_aad();
        let plaintext = b"dummy envelope secret";

        let output = seal_v02(&kek, plaintext, &aad).expect("seal should succeed");
        let unwrapped = kek
            .unwrap_dek(output.wrapped_dek())
            .expect("unwrap should succeed");
        let data_key = DataKey::parse(unwrapped.as_bytes()).expect("DEK should be 32 bytes");
        let restored_aad =
            AadV1::from_stored_context(output.aad_context()).expect("stored AAD should parse");
        let decrypted = decrypt_secret(
            &data_key,
            &restored_aad,
            output.nonce(),
            output.ciphertext(),
        )
        .expect("decrypt should succeed");

        assert_eq!(decrypted.as_bytes(), plaintext);
        assert_eq!(output.dek_wrap_algorithm(), KekAlgorithm::EnvvarXchachaV2);
        assert_eq!(output.kek_version(), version(2));
        assert_eq!(unwrapped.as_bytes().len(), DATA_KEY_LENGTH);
    }

    #[test]
    fn open_legacy_v01_round_trips_existing_format() {
        let (keyring, record, aad) = legacy_record(b"legacy envelope secret");

        let decrypted =
            open_legacy_v01(&keyring, &record, &aad).expect("legacy open should succeed");

        assert_eq!(decrypted.as_bytes(), b"legacy envelope secret");
    }

    #[test]
    fn open_dispatched_routes_legacy_none_and_explicit_legacy() {
        let (keyring, mut record, aad) = legacy_record(b"legacy dispatch secret");

        let none_decrypted =
            open_dispatched(&keyring, &record, &aad).expect("none discriminator should be legacy");
        record.dek_wrap_algorithm = Some(KekAlgorithm::LegacyMasterKeyV1);
        let explicit_decrypted = open_dispatched(&keyring, &record, &aad)
            .expect("explicit legacy discriminator should be legacy");

        assert_eq!(none_decrypted.as_bytes(), b"legacy dispatch secret");
        assert_eq!(explicit_decrypted.as_bytes(), b"legacy dispatch secret");
    }

    #[test]
    fn open_dispatched_routes_v02_envelope() {
        let kek = sample_kek();
        let keyring = MasterKeyRing::single(
            version(2).into(),
            MasterKey::from_bytes([22u8; MASTER_KEY_LENGTH]),
        )
        .expect("test keyring should be valid");
        let aad = sample_aad();
        let output = seal_v02(&kek, b"v02 dispatch secret", &aad).expect("seal should succeed");
        let (ciphertext, nonce, wrapped_dek, dek_wrap_algorithm, kek_version, _) =
            output.into_parts();
        let record = SecretVersionRecord {
            secret_id: sample_secret_id(),
            key_version: kek_version.into(),
            ciphertext,
            nonce,
            encrypted_data_key: None,
            wrapped_dek: Some(wrapped_dek),
            dek_wrap_algorithm: Some(dek_wrap_algorithm),
        };

        let decrypted = open_dispatched(&keyring, &record, &aad).expect("v0.2 open should succeed");

        assert_eq!(decrypted.as_bytes(), b"v02 dispatch secret");
    }

    #[test]
    fn open_dispatched_rejects_missing_key_material() {
        let (keyring, mut legacy_record, aad) = legacy_record(b"missing legacy key");
        legacy_record.encrypted_data_key = None;

        assert!(matches!(
            open_dispatched(&keyring, &legacy_record, &aad),
            Err(SecretDecryptError::Crypto(
                CryptoError::MissingEncryptedDataKey
            ))
        ));

        let kek = sample_kek();
        let output = seal_v02(&kek, b"missing wrapped dek", &aad).expect("seal should succeed");
        let (ciphertext, nonce, _, dek_wrap_algorithm, kek_version, _) = output.into_parts();
        let v02_record = SecretVersionRecord {
            secret_id: sample_secret_id(),
            key_version: kek_version.into(),
            ciphertext,
            nonce,
            encrypted_data_key: None,
            wrapped_dek: None,
            dek_wrap_algorithm: Some(dek_wrap_algorithm),
        };

        assert!(matches!(
            open_dispatched(&keyring, &v02_record, &aad),
            Err(SecretDecryptError::Crypto(CryptoError::MissingWrappedDek))
        ));
    }

    #[test]
    fn dek_wrap_algorithm_parse_rejects_unknown_vocabulary() {
        assert!(matches!(
            KekAlgorithm::parse("envvar-xchacha-v3"),
            Err(CryptoError::UnknownDekWrapAlgorithm)
        ));
    }

    #[test]
    fn seal_v02_uses_fresh_dek_nonce_and_wrapped_dek() {
        let kek = sample_kek();
        let aad = sample_aad();

        let first = seal_v02(&kek, b"same plaintext", &aad).expect("first seal should succeed");
        let second = seal_v02(&kek, b"same plaintext", &aad).expect("second seal should succeed");

        assert_ne!(first.nonce().as_bytes(), second.nonce().as_bytes());
        assert_ne!(
            first.ciphertext().as_bytes(),
            second.ciphertext().as_bytes()
        );
        assert_ne!(
            first.wrapped_dek().as_bytes(),
            second.wrapped_dek().as_bytes()
        );
    }

    #[test]
    fn seal_v02_detects_tampering_after_unwrap() {
        let kek = sample_kek();
        let aad = sample_aad();
        let mut output = seal_v02(&kek, b"tamper target", &aad).expect("seal should succeed");
        let unwrapped = kek
            .unwrap_dek(output.wrapped_dek())
            .expect("unwrap should succeed");
        let data_key = DataKey::parse(unwrapped.as_bytes()).expect("DEK should be 32 bytes");
        let mut ciphertext = output.ciphertext().as_bytes().to_vec();
        let byte = ciphertext
            .first_mut()
            .expect("ciphertext should contain bytes");
        *byte ^= 1;
        output.ciphertext = Ciphertext::new(ciphertext).expect("tampered ciphertext is non-empty");
        let wrong_aad = AadV1::parse(
            "550e8400-e29b-41d4-a716-446655440000",
            2,
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "confidential",
            "2026-04-08T12:00:00Z",
        )
        .expect("wrong aad should be valid");

        assert!(matches!(
            decrypt_secret(&data_key, &aad, output.nonce(), output.ciphertext()),
            Err(CryptoError::DecryptionFailed)
        ));
        assert!(matches!(
            decrypt_secret(&data_key, &wrong_aad, output.nonce(), output.ciphertext()),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn seal_v02_wrapped_dek_tampering_fails_closed() {
        let kek = sample_kek();
        let aad = sample_aad();
        let output =
            seal_v02(&kek, b"wrapped dek tamper target", &aad).expect("seal should succeed");
        let mut wrapped_dek_bytes = output.wrapped_dek().as_bytes().to_vec();
        let byte = wrapped_dek_bytes
            .last_mut()
            .expect("wrapped DEK should contain bytes");
        *byte ^= 1;
        let tampered_wrapped_dek = WrappedDek::parse(output.kek_version(), &wrapped_dek_bytes)
            .expect("tampered wrapped DEK should keep valid outer length");

        assert!(kek.unwrap_dek(&tampered_wrapped_dek).is_err());
    }

    #[test]
    fn debug_output_redacts_sensitive_material() {
        let kek = sample_kek();
        let aad = sample_aad();
        let output =
            seal_v02(&kek, b"never-log-envelope-plaintext", &aad).expect("seal should succeed");
        let rendered = format!("{output:?}");

        assert!(rendered.contains("EnvelopeOutput"));
        assert!(rendered.contains("WrappedDek"));
        assert!(!rendered.contains("never-log-envelope-plaintext"));
        assert!(!rendered.contains("22, 22"));
    }
}

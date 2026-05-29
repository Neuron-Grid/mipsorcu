use super::*;
use crate::crypto::{KeyWrapContext, decrypt_secret, encrypt_secret, wrap_data_key};
use crate::types::{DATA_KEY_LENGTH, DataKey, MASTER_KEY_LENGTH, MasterKey, Plaintext, SecretId};
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
    let encrypted_payload = encrypt_secret(&data_key, &aad, &Plaintext::new(plaintext.to_vec()))
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

    let decrypted = open_legacy_v01(&keyring, &record, &aad).expect("legacy open should succeed");

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
    let (ciphertext, nonce, wrapped_dek, dek_wrap_algorithm, kek_version, _) = output.into_parts();
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
    let output = seal_v02(&kek, b"wrapped dek tamper target", &aad).expect("seal should succeed");
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

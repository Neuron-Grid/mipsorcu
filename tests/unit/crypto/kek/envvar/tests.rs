use super::*;
use crate::types::MASTER_KEY_LENGTH;

fn version(value: u32) -> KekVersion {
    KekVersion::new(value).expect("test version should be positive")
}

fn sample_kek() -> EnvVarKek {
    EnvVarKek::from_key_entries(
        version(2),
        [
            (version(1), MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH])),
            (version(2), MasterKey::from_bytes([22u8; MASTER_KEY_LENGTH])),
        ],
    )
    .expect("test kek should be valid")
}

fn sample_dek() -> DekPlaintext {
    DekPlaintext::from_bytes([7u8; DATA_KEY_LENGTH])
}

#[test]
fn wrap_then_unwrap_round_trips_with_active_version() {
    let kek = sample_kek();
    let dek = sample_dek();

    let wrapped = kek.wrap_dek(&dek).expect("wrap should succeed");
    let unwrapped = kek.unwrap_dek(&wrapped).expect("unwrap should succeed");

    assert_eq!(wrapped.kek_version(), version(2));
    assert_eq!(wrapped.as_bytes().len(), ENVVAR_WRAPPED_DEK_LENGTH);
    assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
    assert_eq!(kek.kek_version(), version(2));
    assert_eq!(kek.kek_algorithm(), KekAlgorithm::EnvvarXchachaV2);
}

#[test]
fn unwrap_uses_wrapped_dek_version_not_active_version() {
    let old_kek = EnvVarKek::single(version(1), MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH]))
        .expect("old kek should be valid");
    let rotated_kek = sample_kek();
    let dek = sample_dek();

    let wrapped = old_kek.wrap_dek(&dek).expect("wrap should succeed");
    let unwrapped = rotated_kek
        .unwrap_dek(&wrapped)
        .expect("old version should be available");

    assert_eq!(wrapped.kek_version(), version(1));
    assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
}

#[test]
fn unwrap_rejects_missing_kek_version() {
    let wrapping_kek =
        EnvVarKek::single(version(1), MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH]))
            .expect("wrapping kek should be valid");
    let active_only_kek =
        EnvVarKek::single(version(2), MasterKey::from_bytes([22u8; MASTER_KEY_LENGTH]))
            .expect("active kek should be valid");
    let wrapped = wrapping_kek
        .wrap_dek(&sample_dek())
        .expect("wrap should succeed");

    assert!(matches!(
        active_only_kek.unwrap_dek(&wrapped),
        Err(KekError::KekNotAvailable { kek_version }) if kek_version == 1
    ));
}

#[test]
fn unwrap_rejects_tampered_wrapped_dek_nonce() {
    let kek = sample_kek();
    let wrapped = kek.wrap_dek(&sample_dek()).expect("wrap should succeed");
    let mut tampered = wrapped.as_bytes().to_vec();
    let byte = tampered
        .first_mut()
        .expect("wrapped dek should contain bytes");
    *byte ^= 1;
    let tampered = WrappedDek::new(wrapped.kek_version(), tampered).expect("format remains valid");

    assert!(matches!(
        kek.unwrap_dek(&tampered),
        Err(KekError::UnwrapFailed)
    ));
}

#[test]
fn unwrap_rejects_tampered_wrapped_dek_ciphertext() {
    let kek = sample_kek();
    let wrapped = kek.wrap_dek(&sample_dek()).expect("wrap should succeed");
    let mut tampered = wrapped.as_bytes().to_vec();
    let byte = tampered
        .get_mut(NONCE_LENGTH)
        .expect("wrapped dek should contain ciphertext bytes");
    *byte ^= 1;
    let tampered = WrappedDek::new(wrapped.kek_version(), tampered).expect("format remains valid");

    assert!(matches!(
        kek.unwrap_dek(&tampered),
        Err(KekError::UnwrapFailed)
    ));
}

#[test]
fn unwrap_rejects_invalid_wrapped_dek_length() {
    let kek = sample_kek();
    let malformed = WrappedDek::new(version(2), vec![0u8; NONCE_LENGTH + 1])
        .expect("generic wrapped dek only requires nonce plus ciphertext bytes");

    assert!(matches!(
        kek.unwrap_dek(&malformed),
        Err(KekError::InvalidWrappedFormat { actual_len })
            if actual_len == NONCE_LENGTH + 1
    ));
}

#[test]
fn wrap_uses_fresh_nonce() {
    let kek = sample_kek();
    let dek = sample_dek();

    let first = kek.wrap_dek(&dek).expect("first wrap should succeed");
    let second = kek.wrap_dek(&dek).expect("second wrap should succeed");

    assert_ne!(first.as_bytes(), second.as_bytes());
}

#[test]
fn debug_output_redacts_key_and_dek_material() {
    let kek = sample_kek();
    let wrapped = kek.wrap_dek(&sample_dek()).expect("wrap should succeed");
    let output = format!(
        "{:?}\n{:?}\n{:?}\n{}",
        kek,
        sample_dek(),
        wrapped,
        KekError::WrapFailed
    );

    assert!(output.contains("EnvVarKek"));
    assert!(output.contains("DekPlaintext(<redacted>)"));
    assert!(output.contains("WrappedDek"));
    assert!(!output.contains("7, 7"));
    assert!(!output.contains("11, 11"));
    assert!(!output.contains("22, 22"));
}

#[test]
fn key_fingerprint_is_sha3_256_prefix_hex() {
    let kek = EnvVarKek::single(
        version(1),
        MasterKey::from_bytes([0xabu8; MASTER_KEY_LENGTH]),
    )
    .expect("kek should be valid");
    let expected_digest = Sha3_256::digest([0xabu8; MASTER_KEY_LENGTH]);
    let expected_prefix = expected_digest
        .iter()
        .take(KEY_FINGERPRINT_PREFIX_BYTES)
        .copied()
        .collect::<Vec<_>>();

    assert_eq!(
        kek.active_key_fingerprint_hex()
            .expect("fingerprint should be available"),
        hex::encode(expected_prefix)
    );
}

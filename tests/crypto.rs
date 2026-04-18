use mipsorcu::{
    ALGORITHM_XCHACHA20_POLY1305, AadV1, Ciphertext, CryptoError, DATA_KEY_LENGTH, DataKey,
    NONCE_LENGTH, Nonce, Plaintext, decrypt_secret, encrypt_secret,
};

fn sample_aad() -> Result<AadV1, CryptoError> {
    AadV1::parse(
        "550e8400-e29b-41d4-a716-446655440000",
        3,
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "confidential",
        "2026-04-08T12:00:00Z",
    )
    .map_err(CryptoError::from)
}

fn mismatched_aad() -> Result<AadV1, CryptoError> {
    AadV1::parse(
        "550e8400-e29b-41d4-a716-446655440000",
        4,
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "confidential",
        "2026-04-08T12:00:00Z",
    )
    .map_err(CryptoError::from)
}

fn sample_data_key() -> DataKey {
    DataKey::from_bytes([7u8; DATA_KEY_LENGTH])
}

#[test]
fn algorithm_constant_is_fixed_to_mvp_value() {
    assert_eq!(ALGORITHM_XCHACHA20_POLY1305, "xchacha20-poly1305");
}

#[test]
fn encrypt_then_decrypt_round_trips_plaintext() -> Result<(), CryptoError> {
    let data_key = sample_data_key();
    let aad = sample_aad()?;
    let plaintext = Plaintext::new(b"dummy test secret".to_vec());

    let encrypted = encrypt_secret(&data_key, &aad, &plaintext)?;
    let decrypted = decrypt_secret(&data_key, &aad, encrypted.nonce(), encrypted.ciphertext())?;

    assert_eq!(decrypted.as_bytes(), plaintext.as_bytes());

    Ok(())
}

#[test]
fn stored_aad_context_round_trips_for_decryption() -> Result<(), CryptoError> {
    let data_key = sample_data_key();
    let aad = sample_aad()?;
    let plaintext = Plaintext::new(b"dummy test secret".to_vec());

    let encrypted = encrypt_secret(&data_key, &aad, &plaintext)?;
    let restored_aad = AadV1::from_stored_context(encrypted.aad_context())?;
    let decrypted = decrypt_secret(
        &data_key,
        &restored_aad,
        encrypted.nonce(),
        encrypted.ciphertext(),
    )?;

    assert_eq!(decrypted.as_bytes(), plaintext.as_bytes());

    Ok(())
}

#[test]
fn aad_mismatch_fails_decryption() -> Result<(), CryptoError> {
    let data_key = sample_data_key();
    let aad = sample_aad()?;
    let mismatched_aad = mismatched_aad()?;
    let plaintext = Plaintext::new(b"dummy test secret".to_vec());

    let encrypted = encrypt_secret(&data_key, &aad, &plaintext)?;
    let result = decrypt_secret(
        &data_key,
        &mismatched_aad,
        encrypted.nonce(),
        encrypted.ciphertext(),
    );

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

    Ok(())
}

#[test]
fn ciphertext_tampering_fails_decryption() -> Result<(), CryptoError> {
    let data_key = sample_data_key();
    let aad = sample_aad()?;
    let plaintext = Plaintext::new(b"dummy test secret".to_vec());

    let encrypted = encrypt_secret(&data_key, &aad, &plaintext)?;
    let mut tampered_bytes = encrypted.ciphertext().as_bytes().to_vec();
    let first_byte = tampered_bytes
        .first_mut()
        .ok_or(CryptoError::DecryptionFailed)?;
    *first_byte ^= 1;
    let tampered_ciphertext = Ciphertext::new(tampered_bytes)?;
    let result = decrypt_secret(&data_key, &aad, encrypted.nonce(), &tampered_ciphertext);

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

    Ok(())
}

#[test]
fn data_key_parse_rejects_invalid_lengths() {
    assert!(matches!(
        DataKey::parse(&[0u8; DATA_KEY_LENGTH - 1]),
        Err(CryptoError::InvalidDataKeyLength { actual }) if actual == DATA_KEY_LENGTH - 1
    ));
    assert!(matches!(
        DataKey::parse(&[0u8; DATA_KEY_LENGTH + 1]),
        Err(CryptoError::InvalidDataKeyLength { actual }) if actual == DATA_KEY_LENGTH + 1
    ));
    assert!(matches!(
        DataKey::parse(&[]),
        Err(CryptoError::InvalidDataKeyLength { actual }) if actual == 0
    ));
    assert!(DataKey::parse(&[0u8; DATA_KEY_LENGTH]).is_ok());
}

#[test]
fn nonce_parse_rejects_invalid_lengths() {
    assert!(matches!(
        Nonce::parse(&[0u8; NONCE_LENGTH - 1]),
        Err(CryptoError::InvalidNonceLength { actual }) if actual == NONCE_LENGTH - 1
    ));
    assert!(matches!(
        Nonce::parse(&[0u8; NONCE_LENGTH + 1]),
        Err(CryptoError::InvalidNonceLength { actual }) if actual == NONCE_LENGTH + 1
    ));
    assert!(matches!(
        Nonce::parse(&[]),
        Err(CryptoError::InvalidNonceLength { actual }) if actual == 0
    ));
    assert!(Nonce::parse(&[0u8; NONCE_LENGTH]).is_ok());
}

#[test]
fn ciphertext_rejects_empty_bytes() {
    assert!(matches!(
        Ciphertext::new(Vec::new()),
        Err(CryptoError::EmptyCiphertext)
    ));
}

#[test]
fn generated_key_and_nonce_have_required_lengths() -> Result<(), CryptoError> {
    let data_key = DataKey::generate()?;
    let nonce = Nonce::generate()?;

    assert_eq!(data_key.as_bytes().len(), DATA_KEY_LENGTH);
    assert_eq!(nonce.as_bytes().len(), NONCE_LENGTH);

    Ok(())
}

#[test]
fn debug_and_error_messages_do_not_expose_secret_material() -> Result<(), CryptoError> {
    let data_key = DataKey::from_bytes([42u8; DATA_KEY_LENGTH]);
    let nonce = Nonce::from_bytes([24u8; NONCE_LENGTH]);
    let ciphertext = Ciphertext::new(vec![99u8; 16])?;
    let plaintext = Plaintext::new(b"never-log-this".to_vec());

    let output = [
        format!("{data_key:?}"),
        format!("{nonce:?}"),
        format!("{ciphertext:?}"),
        format!("{plaintext:?}"),
        CryptoError::DecryptionFailed.to_string(),
    ]
    .join("\n");

    assert!(!output.contains("never-log-this"));
    assert!(!output.contains("42, 42"));
    assert!(!output.contains("24, 24"));
    assert!(!output.contains("99, 99"));

    Ok(())
}

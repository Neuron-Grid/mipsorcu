use mipsorcu::{
    ALGORITHM_XCHACHA20_POLY1305, AadV1, AliasEncryptionKey, AliasFingerprintKey,
    AliasFingerprintSchemaVersion, Ciphertext, CryptoError, DATA_KEY_LENGTH, DataKey,
    ENCRYPTED_DATA_KEY_LENGTH, ENCRYPTED_DATA_KEY_VERSION, EncryptedDataKey, KeyVersion,
    KeyWrapContext, KeyringError, MASTER_KEY_LENGTH, MasterKey, MasterKeyRing, NONCE_LENGTH, Nonce,
    Plaintext, SecretAliasId, SecretId, decrypt_secret, encrypt_secret, unwrap_data_key,
    wrap_data_key,
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

fn sample_master_key() -> MasterKey {
    MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH])
}

fn sample_key_wrap_context() -> Result<KeyWrapContext, CryptoError> {
    let secret_id = SecretId::parse("550e8400-e29b-41d4-a716-446655440000")?;
    let key_version = KeyVersion::new(1)?;

    Ok(KeyWrapContext::new(secret_id, key_version))
}

fn alternate_key_wrap_context() -> Result<KeyWrapContext, CryptoError> {
    let secret_id = SecretId::parse("650e8400-e29b-41d4-a716-446655440000")?;
    let key_version = KeyVersion::new(1)?;

    Ok(KeyWrapContext::new(secret_id, key_version))
}

fn key_wrap_context_with_version(version: u32) -> Result<KeyWrapContext, CryptoError> {
    let secret_id = SecretId::parse("550e8400-e29b-41d4-a716-446655440000")?;
    let key_version = KeyVersion::new(version)?;

    Ok(KeyWrapContext::new(secret_id, key_version))
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
fn master_key_parse_rejects_invalid_lengths() {
    assert!(matches!(
        MasterKey::parse(&[0u8; MASTER_KEY_LENGTH - 1]),
        Err(CryptoError::InvalidMasterKeyLength { actual }) if actual == MASTER_KEY_LENGTH - 1
    ));
    assert!(matches!(
        MasterKey::parse(&[0u8; MASTER_KEY_LENGTH + 1]),
        Err(CryptoError::InvalidMasterKeyLength { actual }) if actual == MASTER_KEY_LENGTH + 1
    ));
    assert!(matches!(
        MasterKey::parse(&[]),
        Err(CryptoError::InvalidMasterKeyLength { actual }) if actual == 0
    ));
    assert!(MasterKey::parse(&[0u8; MASTER_KEY_LENGTH]).is_ok());
}

#[test]
fn alias_keys_parse_reject_invalid_lengths() {
    assert!(matches!(
        AliasEncryptionKey::parse(&[0u8; MASTER_KEY_LENGTH - 1]),
        Err(CryptoError::InvalidAliasEncryptionKeyLength { actual })
            if actual == MASTER_KEY_LENGTH - 1
    ));
    assert!(matches!(
        AliasFingerprintKey::parse(&[0u8; MASTER_KEY_LENGTH + 1]),
        Err(CryptoError::InvalidAliasFingerprintKeyLength { actual })
            if actual == MASTER_KEY_LENGTH + 1
    ));
    assert!(AliasEncryptionKey::parse(&[0u8; MASTER_KEY_LENGTH]).is_ok());
    assert!(AliasFingerprintKey::parse(&[0u8; MASTER_KEY_LENGTH]).is_ok());
}

#[test]
fn alias_key_debug_redacts_key_material() {
    let encryption_key = AliasEncryptionKey::from_bytes([3u8; MASTER_KEY_LENGTH]);
    let fingerprint_key = AliasFingerprintKey::from_bytes([4u8; MASTER_KEY_LENGTH]);

    assert_eq!(
        format!("{encryption_key:?}"),
        "AliasEncryptionKey(<redacted>)"
    );
    assert_eq!(
        format!("{fingerprint_key:?}"),
        "AliasFingerprintKey(<redacted>)"
    );
}

#[test]
fn key_version_rejects_zero() {
    assert!(matches!(
        KeyVersion::new(0),
        Err(CryptoError::InvalidKeyVersion { value }) if value == 0
    ));
    assert_eq!(KeyVersion::new(1).map(KeyVersion::get), Ok(1));
}

#[test]
fn alias_fingerprint_schema_version_rejects_zero() {
    assert!(matches!(
        AliasFingerprintSchemaVersion::new(0),
        Err(CryptoError::InvalidKeyVersion { value }) if value == 0
    ));
    assert!(matches!(
        AliasFingerprintSchemaVersion::new(2),
        Err(CryptoError::UnsupportedAliasFingerprintSchemaVersion { value }) if value == 2
    ));
    assert_eq!(AliasFingerprintSchemaVersion::V1.get(), 1);
}

#[test]
fn secret_alias_id_requires_uuid_v4() {
    assert!(SecretAliasId::parse("550e8400-e29b-11d4-a716-446655440000").is_err());
    assert!(SecretAliasId::parse("750e8400-e29b-41d4-a716-446655440000").is_ok());
}

#[test]
fn master_key_ring_selects_active_and_versioned_keys() -> Result<(), CryptoError> {
    let old_version = KeyVersion::new(1)?;
    let new_version = KeyVersion::new(2)?;
    let keyring = MasterKeyRing::from_key_entries(
        new_version,
        [
            (
                old_version,
                MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH]),
            ),
            (
                new_version,
                MasterKey::from_bytes([12u8; MASTER_KEY_LENGTH]),
            ),
        ],
    )
    .expect("keyring should be valid");

    assert_eq!(keyring.active().0, new_version);
    assert!(keyring.contains(old_version));
    assert!(keyring.contains(new_version));
    assert_eq!(
        keyring.get(old_version).unwrap().as_bytes(),
        &[11u8; MASTER_KEY_LENGTH]
    );
    assert_eq!(
        keyring.get(new_version).unwrap().as_bytes(),
        &[12u8; MASTER_KEY_LENGTH]
    );
    assert!(matches!(
        keyring.get(KeyVersion::new(3)?),
        Err(KeyringError::KeyUnavailable { key_version }) if key_version == 3
    ));

    Ok(())
}

#[test]
fn master_key_ring_rejects_invalid_construction() -> Result<(), CryptoError> {
    let version_one = KeyVersion::new(1)?;
    let version_two = KeyVersion::new(2)?;

    assert!(matches!(
        MasterKeyRing::from_key_entries(version_one, []),
        Err(KeyringError::Empty)
    ));
    assert!(matches!(
        MasterKeyRing::from_key_entries(
            version_one,
            [
                (version_one, MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH])),
                (version_one, MasterKey::from_bytes([12u8; MASTER_KEY_LENGTH])),
            ],
        ),
        Err(KeyringError::DuplicateKeyVersion { key_version }) if key_version == 1
    ));
    assert!(matches!(
        MasterKeyRing::from_key_entries(
            version_two,
            [(version_one, MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH]))],
        ),
        Err(KeyringError::ActiveKeyMissing { key_version }) if key_version == 2
    ));

    Ok(())
}

#[test]
fn master_key_ring_debug_redacts_key_material() -> Result<(), CryptoError> {
    let keyring = MasterKeyRing::single(
        KeyVersion::new(1)?,
        MasterKey::from_bytes([77u8; MASTER_KEY_LENGTH]),
    )
    .expect("keyring should be valid");

    let output = format!("{keyring:?}");

    assert!(output.contains("active_key_version"));
    assert!(!output.contains("77, 77"));
    assert!(!output.contains("MasterKey(<redacted>)"));

    Ok(())
}

#[test]
fn encrypted_data_key_parse_rejects_invalid_envelopes() {
    assert!(matches!(
        EncryptedDataKey::parse(&[]),
        Err(CryptoError::InvalidEncryptedDataKeyLength { actual }) if actual == 0
    ));
    assert!(matches!(
        EncryptedDataKey::parse(&[0u8; ENCRYPTED_DATA_KEY_LENGTH - 1]),
        Err(CryptoError::InvalidEncryptedDataKeyLength { actual })
            if actual == ENCRYPTED_DATA_KEY_LENGTH - 1
    ));
    assert!(matches!(
        EncryptedDataKey::parse(&[0u8; ENCRYPTED_DATA_KEY_LENGTH + 1]),
        Err(CryptoError::InvalidEncryptedDataKeyLength { actual })
            if actual == ENCRYPTED_DATA_KEY_LENGTH + 1
    ));

    let mut unsupported = vec![0u8; ENCRYPTED_DATA_KEY_LENGTH];
    unsupported[0] = ENCRYPTED_DATA_KEY_VERSION + 1;
    assert!(matches!(
        EncryptedDataKey::parse(&unsupported),
        Err(CryptoError::UnsupportedEncryptedDataKeyVersion { version })
            if version == ENCRYPTED_DATA_KEY_VERSION + 1
    ));
}

#[test]
fn wrap_then_unwrap_data_key_round_trips() -> Result<(), CryptoError> {
    let master_key = sample_master_key();
    let data_key = sample_data_key();
    let context = sample_key_wrap_context()?;

    let encrypted_data_key = wrap_data_key(&master_key, &context, &data_key)?;
    let decrypted_data_key = unwrap_data_key(&master_key, &context, &encrypted_data_key)?;

    assert_eq!(
        encrypted_data_key.as_bytes().len(),
        ENCRYPTED_DATA_KEY_LENGTH
    );
    assert_eq!(encrypted_data_key.version(), ENCRYPTED_DATA_KEY_VERSION);
    assert_eq!(decrypted_data_key.as_bytes(), data_key.as_bytes());

    Ok(())
}

#[test]
fn data_key_unwrap_rejects_wrong_secret_context() -> Result<(), CryptoError> {
    let master_key = sample_master_key();
    let data_key = sample_data_key();
    let context = sample_key_wrap_context()?;
    let wrong_context = alternate_key_wrap_context()?;

    let encrypted_data_key = wrap_data_key(&master_key, &context, &data_key)?;
    let result = unwrap_data_key(&master_key, &wrong_context, &encrypted_data_key);

    assert!(matches!(result, Err(CryptoError::KeyUnwrapFailed)));

    Ok(())
}

#[test]
fn data_key_unwrap_rejects_wrong_key_version_context() -> Result<(), CryptoError> {
    let master_key = sample_master_key();
    let data_key = sample_data_key();
    let context = sample_key_wrap_context()?;
    let wrong_context = key_wrap_context_with_version(2)?;

    let encrypted_data_key = wrap_data_key(&master_key, &context, &data_key)?;
    let result = unwrap_data_key(&master_key, &wrong_context, &encrypted_data_key);

    assert!(matches!(result, Err(CryptoError::KeyUnwrapFailed)));

    Ok(())
}

#[test]
fn data_key_unwrap_rejects_wrong_master_key() -> Result<(), CryptoError> {
    let master_key = sample_master_key();
    let wrong_master_key = MasterKey::from_bytes([12u8; MASTER_KEY_LENGTH]);
    let data_key = sample_data_key();
    let context = sample_key_wrap_context()?;

    let encrypted_data_key = wrap_data_key(&master_key, &context, &data_key)?;
    let result = unwrap_data_key(&wrong_master_key, &context, &encrypted_data_key);

    assert!(matches!(result, Err(CryptoError::KeyUnwrapFailed)));

    Ok(())
}

#[test]
fn data_key_unwrap_rejects_tampered_envelope() -> Result<(), CryptoError> {
    let master_key = sample_master_key();
    let data_key = sample_data_key();
    let context = sample_key_wrap_context()?;
    let encrypted_data_key = wrap_data_key(&master_key, &context, &data_key)?;

    let mut tampered_nonce = encrypted_data_key.as_bytes().to_vec();
    tampered_nonce[1] ^= 1;
    let tampered_nonce = EncryptedDataKey::parse(&tampered_nonce)?;
    let nonce_result = unwrap_data_key(&master_key, &context, &tampered_nonce);

    let mut tampered_ciphertext = encrypted_data_key.as_bytes().to_vec();
    let last_index = tampered_ciphertext.len() - 1;
    tampered_ciphertext[last_index] ^= 1;
    let tampered_ciphertext = EncryptedDataKey::parse(&tampered_ciphertext)?;
    let ciphertext_result = unwrap_data_key(&master_key, &context, &tampered_ciphertext);

    assert!(matches!(nonce_result, Err(CryptoError::KeyUnwrapFailed)));
    assert!(matches!(
        ciphertext_result,
        Err(CryptoError::KeyUnwrapFailed)
    ));

    Ok(())
}

#[test]
fn generated_key_and_nonce_have_required_lengths() -> Result<(), CryptoError> {
    let data_key = DataKey::generate()?;
    let master_key = MasterKey::generate()?;
    let nonce = Nonce::generate()?;

    assert_eq!(data_key.as_bytes().len(), DATA_KEY_LENGTH);
    assert_eq!(master_key.as_bytes().len(), MASTER_KEY_LENGTH);
    assert_eq!(nonce.as_bytes().len(), NONCE_LENGTH);

    Ok(())
}

#[test]
fn debug_and_error_messages_do_not_expose_secret_material() -> Result<(), CryptoError> {
    let data_key = DataKey::from_bytes([42u8; DATA_KEY_LENGTH]);
    let master_key = MasterKey::from_bytes([43u8; MASTER_KEY_LENGTH]);
    let nonce = Nonce::from_bytes([24u8; NONCE_LENGTH]);
    let ciphertext = Ciphertext::new(vec![99u8; 16])?;
    let plaintext = Plaintext::new(b"never-log-this".to_vec());
    let mut encrypted_data_key_bytes = vec![88u8; ENCRYPTED_DATA_KEY_LENGTH];
    encrypted_data_key_bytes[0] = ENCRYPTED_DATA_KEY_VERSION;
    let encrypted_data_key = EncryptedDataKey::parse(&encrypted_data_key_bytes)?;

    let output = [
        format!("{data_key:?}"),
        format!("{master_key:?}"),
        format!("{nonce:?}"),
        format!("{ciphertext:?}"),
        format!("{plaintext:?}"),
        format!("{encrypted_data_key:?}"),
        CryptoError::DecryptionFailed.to_string(),
        CryptoError::KeyUnwrapFailed.to_string(),
    ]
    .join("\n");

    assert!(!output.contains("never-log-this"));
    assert!(!output.contains("42, 42"));
    assert!(!output.contains("43, 43"));
    assert!(!output.contains("24, 24"));
    assert!(!output.contains("99, 99"));
    assert!(!output.contains("88, 88"));

    Ok(())
}

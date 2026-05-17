use mipsorcu::{
    ALIAS_AAD_VERSION_V1, ALIAS_FINGERPRINT_LENGTH, AadError, AliasAadV1, AliasEncryptionKey,
    AliasFingerprint, AliasFingerprintKey, Ciphertext, CryptoError, KeyVersion, MASTER_KEY_LENGTH,
    NONCE_LENGTH, Nonce, NormalizedAlias, OwnerUserId, SecretAliasId, SecretId,
    compute_alias_fingerprint, decrypt_alias, encrypt_alias,
};
use serde_json::{Value, json};

const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const ALT_OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d480";
const SECRET_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const SECRET_ALIAS_ID: &str = "650e8400-e29b-41d4-a716-446655440000";

fn sample_aad() -> Result<AliasAadV1, CryptoError> {
    Ok(AliasAadV1::new(
        SecretAliasId::parse(SECRET_ALIAS_ID)?,
        SecretId::parse(SECRET_ID)?,
        OwnerUserId::parse(OWNER_USER_ID)?,
        KeyVersion::new(1)?,
    ))
}

fn sample_alias() -> Result<NormalizedAlias, mipsorcu::AliasInputError> {
    NormalizedAlias::parse("github-api")
}

fn sample_encryption_key() -> AliasEncryptionKey {
    AliasEncryptionKey::from_bytes([21u8; MASTER_KEY_LENGTH])
}

fn sample_fingerprint_key() -> AliasFingerprintKey {
    AliasFingerprintKey::from_bytes([22u8; MASTER_KEY_LENGTH])
}

fn sample_stored_context() -> Result<Value, CryptoError> {
    sample_aad()?.to_stored_context().map_err(CryptoError::from)
}

#[test]
fn canonical_json_uses_stable_alias_field_order() -> Result<(), CryptoError> {
    let aad = sample_aad()?;
    let canonical = aad.canonical_json()?;
    let expected = r#"{"aad_version":1,"alias_key_version":1,"owner_user_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479","secret_alias_id":"650e8400-e29b-41d4-a716-446655440000","secret_id":"550e8400-e29b-41d4-a716-446655440000"}"#;

    assert_eq!(canonical, expected);

    Ok(())
}

#[test]
fn stored_context_round_trips_to_canonical_bytes() -> Result<(), CryptoError> {
    let aad = sample_aad()?;
    let stored = aad.to_stored_context()?;
    let restored = AliasAadV1::from_stored_context(&stored)?;

    assert_eq!(restored.canonical_bytes()?, aad.canonical_bytes()?);

    Ok(())
}

#[test]
fn stored_context_rejects_unexpected_fields() -> Result<(), CryptoError> {
    let mut stored = sample_stored_context()?;
    stored
        .as_object_mut()
        .ok_or(CryptoError::AadFailed)?
        .insert("unexpected".to_owned(), json!("value"));

    let result = AliasAadV1::from_stored_context(&stored);

    assert!(matches!(
        result,
        Err(AadError::UnexpectedField { field }) if field == "unexpected"
    ));

    Ok(())
}

#[test]
fn stored_context_rejects_missing_fields() -> Result<(), CryptoError> {
    let mut stored = sample_stored_context()?;
    stored
        .as_object_mut()
        .ok_or(CryptoError::AadFailed)?
        .remove("secret_alias_id");

    let result = AliasAadV1::from_stored_context(&stored);

    assert!(matches!(
        result,
        Err(AadError::MissingField {
            field: "secret_alias_id"
        })
    ));

    Ok(())
}

#[test]
fn stored_context_rejects_invalid_aad_version() -> Result<(), CryptoError> {
    let mut stored = sample_stored_context()?;
    stored
        .as_object_mut()
        .ok_or(CryptoError::AadFailed)?
        .insert("aad_version".to_owned(), json!(2));

    let result = AliasAadV1::from_stored_context(&stored);

    assert!(matches!(
        result,
        Err(AadError::UnsupportedAadVersion { .. })
    ));

    Ok(())
}

#[test]
fn alias_fingerprint_parse_rejects_invalid_lengths() {
    assert!(matches!(
        AliasFingerprint::parse(&[0u8; ALIAS_FINGERPRINT_LENGTH - 1]),
        Err(CryptoError::InvalidAliasFingerprintLength { actual })
            if actual == ALIAS_FINGERPRINT_LENGTH - 1
    ));
    assert!(AliasFingerprint::parse(&[0u8; ALIAS_FINGERPRINT_LENGTH]).is_ok());
}

#[test]
fn fingerprint_is_deterministic() -> Result<(), CryptoError> {
    let key = sample_fingerprint_key();
    let owner = OwnerUserId::parse(OWNER_USER_ID)?;
    let alias = sample_alias().map_err(|_| CryptoError::FingerprintComputationFailed)?;

    let first = compute_alias_fingerprint(&key, &owner, &alias)?;
    let second = compute_alias_fingerprint(&key, &owner, &alias)?;

    assert_eq!(first, second);

    Ok(())
}

#[test]
fn fingerprint_differs_per_owner() -> Result<(), CryptoError> {
    let key = sample_fingerprint_key();
    let owner_a = OwnerUserId::parse(OWNER_USER_ID)?;
    let owner_b = OwnerUserId::parse(ALT_OWNER_USER_ID)?;
    let alias = sample_alias().map_err(|_| CryptoError::FingerprintComputationFailed)?;

    let fingerprint_a = compute_alias_fingerprint(&key, &owner_a, &alias)?;
    let fingerprint_b = compute_alias_fingerprint(&key, &owner_b, &alias)?;

    assert_ne!(fingerprint_a, fingerprint_b);

    Ok(())
}

#[test]
fn fingerprint_differs_per_alias() -> Result<(), CryptoError> {
    let key = sample_fingerprint_key();
    let owner = OwnerUserId::parse(OWNER_USER_ID)?;
    let alias_a = NormalizedAlias::parse("github-api")
        .map_err(|_| CryptoError::FingerprintComputationFailed)?;
    let alias_b = NormalizedAlias::parse("github_api")
        .map_err(|_| CryptoError::FingerprintComputationFailed)?;

    let fingerprint_a = compute_alias_fingerprint(&key, &owner, &alias_a)?;
    let fingerprint_b = compute_alias_fingerprint(&key, &owner, &alias_b)?;

    assert_ne!(fingerprint_a, fingerprint_b);

    Ok(())
}

#[test]
fn encrypt_then_decrypt_round_trips() -> Result<(), CryptoError> {
    let key = sample_encryption_key();
    let aad = sample_aad()?;
    let alias = sample_alias().map_err(|_| CryptoError::EncryptionFailed)?;
    let encrypted = encrypt_alias(&key, &aad, &alias)?;
    let decrypted = decrypt_alias(&key, &aad, encrypted.nonce(), encrypted.ciphertext())?;

    assert_eq!(decrypted.as_str(), alias.as_str());

    Ok(())
}

#[test]
fn decrypt_fails_when_secret_alias_id_differs() -> Result<(), CryptoError> {
    let key = sample_encryption_key();
    let aad = sample_aad()?;
    let alias = sample_alias().map_err(|_| CryptoError::EncryptionFailed)?;
    let encrypted = encrypt_alias(&key, &aad, &alias)?;
    let tampered_aad = AliasAadV1::new(
        SecretAliasId::parse("750e8400-e29b-41d4-a716-446655440000")?,
        SecretId::parse(SECRET_ID)?,
        OwnerUserId::parse(OWNER_USER_ID)?,
        KeyVersion::new(1)?,
    );

    let result = decrypt_alias(
        &key,
        &tampered_aad,
        encrypted.nonce(),
        encrypted.ciphertext(),
    );

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

    Ok(())
}

#[test]
fn decrypt_fails_when_alias_key_version_differs() -> Result<(), CryptoError> {
    let key = sample_encryption_key();
    let aad = sample_aad()?;
    let alias = sample_alias().map_err(|_| CryptoError::EncryptionFailed)?;
    let encrypted = encrypt_alias(&key, &aad, &alias)?;
    let tampered_aad = AliasAadV1::new(
        SecretAliasId::parse(SECRET_ALIAS_ID)?,
        SecretId::parse(SECRET_ID)?,
        OwnerUserId::parse(OWNER_USER_ID)?,
        KeyVersion::new(2)?,
    );

    let result = decrypt_alias(
        &key,
        &tampered_aad,
        encrypted.nonce(),
        encrypted.ciphertext(),
    );

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

    Ok(())
}

#[test]
fn decrypt_fails_when_nonce_is_tampered() -> Result<(), CryptoError> {
    let key = sample_encryption_key();
    let aad = sample_aad()?;
    let alias = sample_alias().map_err(|_| CryptoError::EncryptionFailed)?;
    let encrypted = encrypt_alias(&key, &aad, &alias)?;
    let mut nonce_bytes = *encrypted.nonce().as_bytes();
    nonce_bytes[0] ^= 1;
    let tampered_nonce = Nonce::from_bytes(nonce_bytes);

    let result = decrypt_alias(&key, &aad, &tampered_nonce, encrypted.ciphertext());

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

    Ok(())
}

#[test]
fn decrypt_fails_when_ciphertext_is_tampered() -> Result<(), CryptoError> {
    let key = sample_encryption_key();
    let aad = sample_aad()?;
    let alias = sample_alias().map_err(|_| CryptoError::EncryptionFailed)?;
    let encrypted = encrypt_alias(&key, &aad, &alias)?;
    let mut tampered_bytes = encrypted.ciphertext().as_bytes().to_vec();
    let first_byte = tampered_bytes
        .first_mut()
        .ok_or(CryptoError::DecryptionFailed)?;
    *first_byte ^= 1;
    let tampered_ciphertext = Ciphertext::new(tampered_bytes)?;

    let result = decrypt_alias(&key, &aad, encrypted.nonce(), &tampered_ciphertext);

    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

    Ok(())
}

#[test]
fn debug_output_does_not_expose_alias_material() -> Result<(), CryptoError> {
    let key = sample_encryption_key();
    let aad = sample_aad()?;
    let alias = sample_alias().map_err(|_| CryptoError::EncryptionFailed)?;
    let encrypted = encrypt_alias(&key, &aad, &alias)?;
    let fingerprint = compute_alias_fingerprint(
        &sample_fingerprint_key(),
        &OwnerUserId::parse(OWNER_USER_ID)?,
        &alias,
    )?;
    let output = format!("{key:?}\n{alias:?}\n{encrypted:?}\n{fingerprint:?}");

    assert!(!output.contains("github-api"));
    assert!(!output.contains("21, 21"));
    assert!(!output.contains("22, 22"));
    assert!(output.contains("AliasFingerprint"));
    assert!(output.contains("EncryptedAlias"));

    Ok(())
}

#[test]
fn alias_constants_match_expected_versions() {
    assert_eq!(ALIAS_AAD_VERSION_V1, 1);
    assert_eq!(NONCE_LENGTH, 24);
}

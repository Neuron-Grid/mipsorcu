use mipsorcu::{
    ALIAS_AAD_VERSION_V1, ALIAS_FINGERPRINT_LENGTH, AadError, AliasAadV1, AliasEncryptionKey,
    AliasFingerprint, AliasFingerprintKey, Ciphertext, CreatedAt, CryptoError, KeyVersion,
    MASTER_KEY_LENGTH, NONCE_LENGTH, Nonce, NormalizedAlias, OwnerUserId, SecretAliasId, SecretId,
    compute_alias_fingerprint, compute_lookup_fingerprint, decrypt_alias, decrypt_alias_row,
    encrypt_alias, prepare_alias_create, prepare_alias_update,
};
use proptest::prelude::*;
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

fn distinct_valid_alias(value: &str) -> NormalizedAlias {
    let mut bytes = value.as_bytes().to_vec();
    let first = bytes
        .first_mut()
        .expect("proptest alias generator produces non-empty aliases");
    *first = if *first == b'a' { b'b' } else { b'a' };
    let candidate = String::from_utf8(bytes).expect("proptest alias generator produces ASCII");
    NormalizedAlias::parse(&candidate).expect("mutated alias preserves the valid alias grammar")
}

#[test]
fn prepare_alias_create_generates_encrypted_material() -> Result<(), Box<dyn std::error::Error>> {
    let prepared = prepare_alias_create(
        &sample_encryption_key(),
        KeyVersion::new(1)?,
        &sample_fingerprint_key(),
        KeyVersion::new(2)?,
        SecretId::parse(SECRET_ID)?,
        OwnerUserId::parse(OWNER_USER_ID)?,
        sample_alias()?,
        CreatedAt::parse("2026-04-08T12:00:00Z")?,
    )?;
    let aad_object = prepared
        .aad_context
        .as_object()
        .expect("alias AAD context should be an object");

    SecretAliasId::parse(&prepared.secret_alias_id.as_canonical_string())?;
    assert_eq!(prepared.nonce.as_bytes().len(), NONCE_LENGTH);
    assert_eq!(
        prepared.alias_fingerprint.as_bytes().len(),
        ALIAS_FINGERPRINT_LENGTH
    );
    assert_eq!(prepared.fingerprint_key_version.get(), 2);
    assert_eq!(prepared.fingerprint_schema_version.get(), 1);
    assert_eq!(aad_object.len(), 5);
    assert_eq!(aad_object["aad_version"], 1);
    assert_eq!(aad_object["alias_key_version"], 1);
    assert_eq!(aad_object["secret_id"], SECRET_ID);
    assert_eq!(aad_object["owner_user_id"], OWNER_USER_ID);
    assert_eq!(
        prepared.created_at.as_rfc3339_utc()?,
        "2026-04-08T12:00:00Z"
    );

    Ok(())
}

#[test]
fn prepare_alias_update_keeps_existing_identity_and_reencrypts()
-> Result<(), Box<dyn std::error::Error>> {
    let secret_alias_id = SecretAliasId::parse(SECRET_ALIAS_ID)?;
    let secret_id = SecretId::parse(SECRET_ID)?;
    let owner_user_id = OwnerUserId::parse(OWNER_USER_ID)?;
    let new_alias = NormalizedAlias::parse("github-api-v2")?;
    let prepared = prepare_alias_update(
        &sample_encryption_key(),
        KeyVersion::new(3)?,
        &sample_fingerprint_key(),
        KeyVersion::new(4)?,
        secret_alias_id.clone(),
        secret_id.clone(),
        owner_user_id.clone(),
        new_alias.clone(),
    )?;
    let decrypted = decrypt_alias_row(
        &sample_encryption_key(),
        secret_alias_id,
        secret_id,
        owner_user_id,
        prepared.alias_key_version,
        &prepared.ciphertext,
        &prepared.nonce,
        &prepared.aad_context,
    )?;

    assert_eq!(
        prepared.secret_alias_id.as_canonical_string(),
        SECRET_ALIAS_ID
    );
    assert_eq!(prepared.secret_id.as_canonical_string(), SECRET_ID);
    assert_eq!(prepared.alias_key_version.get(), 3);
    assert_eq!(prepared.fingerprint_key_version.get(), 4);
    assert_eq!(decrypted.alias.as_str(), new_alias.as_str());

    Ok(())
}

#[test]
fn decrypt_alias_row_rejects_context_or_ciphertext_tampering()
-> Result<(), Box<dyn std::error::Error>> {
    let prepared = prepare_alias_create(
        &sample_encryption_key(),
        KeyVersion::new(1)?,
        &sample_fingerprint_key(),
        KeyVersion::new(1)?,
        SecretId::parse(SECRET_ID)?,
        OwnerUserId::parse(OWNER_USER_ID)?,
        sample_alias()?,
        CreatedAt::parse("2026-04-08T12:00:00Z")?,
    )?;
    let decrypted = decrypt_alias_row(
        &sample_encryption_key(),
        prepared.secret_alias_id.clone(),
        prepared.secret_id.clone(),
        prepared.owner_user_id.clone(),
        prepared.alias_key_version,
        &prepared.ciphertext,
        &prepared.nonce,
        &prepared.aad_context,
    )?;
    assert_eq!(decrypted.alias.as_str(), "github-api");

    let mut extra_context = prepared.aad_context.clone();
    extra_context
        .as_object_mut()
        .expect("alias AAD context should be an object")
        .insert("unexpected".to_owned(), json!("value"));
    assert!(
        decrypt_alias_row(
            &sample_encryption_key(),
            prepared.secret_alias_id.clone(),
            prepared.secret_id.clone(),
            prepared.owner_user_id.clone(),
            prepared.alias_key_version,
            &prepared.ciphertext,
            &prepared.nonce,
            &extra_context,
        )
        .is_err()
    );

    assert!(
        decrypt_alias_row(
            &sample_encryption_key(),
            prepared.secret_alias_id.clone(),
            SecretId::parse("750e8400-e29b-41d4-a716-446655440000")?,
            prepared.owner_user_id.clone(),
            prepared.alias_key_version,
            &prepared.ciphertext,
            &prepared.nonce,
            &prepared.aad_context,
        )
        .is_err()
    );

    let mut tampered_ciphertext_bytes = prepared.ciphertext.as_bytes().to_vec();
    tampered_ciphertext_bytes[0] ^= 1;
    let tampered_ciphertext = Ciphertext::new(tampered_ciphertext_bytes)?;
    assert!(
        decrypt_alias_row(
            &sample_encryption_key(),
            prepared.secret_alias_id.clone(),
            prepared.secret_id.clone(),
            prepared.owner_user_id.clone(),
            prepared.alias_key_version,
            &tampered_ciphertext,
            &prepared.nonce,
            &prepared.aad_context,
        )
        .is_err()
    );

    let mut tampered_nonce_bytes = *prepared.nonce.as_bytes();
    tampered_nonce_bytes[0] ^= 1;
    let tampered_nonce = Nonce::from_bytes(tampered_nonce_bytes);
    assert!(
        decrypt_alias_row(
            &sample_encryption_key(),
            prepared.secret_alias_id,
            prepared.secret_id,
            prepared.owner_user_id,
            prepared.alias_key_version,
            &prepared.ciphertext,
            &tampered_nonce,
            &prepared.aad_context,
        )
        .is_err()
    );

    Ok(())
}

#[test]
fn compute_lookup_fingerprint_is_owner_scoped_and_case_sensitive()
-> Result<(), Box<dyn std::error::Error>> {
    let key = sample_fingerprint_key();
    let owner = OwnerUserId::parse(OWNER_USER_ID)?;
    let alias = NormalizedAlias::parse("github-api")?;
    let same = compute_lookup_fingerprint(&key, &owner, &alias)?;
    let expected = compute_alias_fingerprint(&key, &owner, &alias)?;
    let different_case =
        compute_lookup_fingerprint(&key, &owner, &NormalizedAlias::parse("GitHub-api")?)?;
    let different_owner =
        compute_lookup_fingerprint(&key, &OwnerUserId::parse(ALT_OWNER_USER_ID)?, &alias)?;

    assert_eq!(same, expected);
    assert_ne!(same, different_case);
    assert_ne!(same, different_owner);

    Ok(())
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

proptest! {
    #[test]
    fn fingerprint_is_deterministic_for_any_valid_alias(alias in "[A-Za-z0-9_\\-]{1,128}") {
        let key = sample_fingerprint_key();
        let owner = OwnerUserId::parse(OWNER_USER_ID).expect("test owner UUID is valid");
        let normalized_alias =
            NormalizedAlias::parse(&alias).expect("proptest generator emits valid aliases");

        let first = compute_alias_fingerprint(&key, &owner, &normalized_alias)
            .expect("fingerprint computation should succeed");
        let second = compute_alias_fingerprint(&key, &owner, &normalized_alias)
            .expect("fingerprint computation should succeed");

        prop_assert_eq!(first, second);
    }

    #[test]
    fn fingerprint_matches_for_trim_normalized_aliases(alias in "[A-Za-z0-9_\\-]{1,128}") {
        let key = sample_fingerprint_key();
        let owner = OwnerUserId::parse(OWNER_USER_ID).expect("test owner UUID is valid");
        let normalized_alias =
            NormalizedAlias::parse(&alias).expect("proptest generator emits valid aliases");
        let padded_alias = NormalizedAlias::parse(&format!("  {alias}  "))
            .expect("padded generated alias should normalize successfully");

        prop_assert_eq!(normalized_alias.as_str(), padded_alias.as_str());

        let normalized_fingerprint = compute_alias_fingerprint(&key, &owner, &normalized_alias)
            .expect("fingerprint computation should succeed");
        let padded_fingerprint = compute_alias_fingerprint(&key, &owner, &padded_alias)
            .expect("fingerprint computation should succeed");

        prop_assert_eq!(normalized_fingerprint, padded_fingerprint);
    }

    #[test]
    fn fingerprint_differs_for_different_valid_aliases(alias in "[A-Za-z0-9_\\-]{1,128}") {
        let key = sample_fingerprint_key();
        let owner = OwnerUserId::parse(OWNER_USER_ID).expect("test owner UUID is valid");
        let normalized_alias =
            NormalizedAlias::parse(&alias).expect("proptest generator emits valid aliases");
        let distinct_alias = distinct_valid_alias(normalized_alias.as_str());

        prop_assert_ne!(normalized_alias.as_str(), distinct_alias.as_str());

        let original_fingerprint = compute_alias_fingerprint(&key, &owner, &normalized_alias)
            .expect("fingerprint computation should succeed");
        let distinct_fingerprint = compute_alias_fingerprint(&key, &owner, &distinct_alias)
            .expect("fingerprint computation should succeed");

        prop_assert_ne!(original_fingerprint, distinct_fingerprint);
    }

    #[test]
    fn fingerprint_is_owner_scoped_for_any_valid_alias(alias in "[A-Za-z0-9_\\-]{1,128}") {
        let key = sample_fingerprint_key();
        let owner = OwnerUserId::parse(OWNER_USER_ID).expect("test owner UUID is valid");
        let alternate_owner =
            OwnerUserId::parse(ALT_OWNER_USER_ID).expect("alternate test owner UUID is valid");
        let normalized_alias =
            NormalizedAlias::parse(&alias).expect("proptest generator emits valid aliases");

        let owner_fingerprint = compute_alias_fingerprint(&key, &owner, &normalized_alias)
            .expect("fingerprint computation should succeed");
        let alternate_owner_fingerprint =
            compute_alias_fingerprint(&key, &alternate_owner, &normalized_alias)
                .expect("fingerprint computation should succeed");

        prop_assert_ne!(owner_fingerprint, alternate_owner_fingerprint);
    }
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
fn decrypt_fails_when_secret_id_differs() -> Result<(), CryptoError> {
    let key = sample_encryption_key();
    let aad = sample_aad()?;
    let alias = sample_alias().map_err(|_| CryptoError::EncryptionFailed)?;
    let encrypted = encrypt_alias(&key, &aad, &alias)?;
    let tampered_aad = AliasAadV1::new(
        SecretAliasId::parse(SECRET_ALIAS_ID)?,
        SecretId::parse("650e8400-e29b-41d4-a716-446655440000")?,
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
fn decrypt_fails_when_owner_user_id_differs() -> Result<(), CryptoError> {
    let key = sample_encryption_key();
    let aad = sample_aad()?;
    let alias = sample_alias().map_err(|_| CryptoError::EncryptionFailed)?;
    let encrypted = encrypt_alias(&key, &aad, &alias)?;
    let tampered_aad = AliasAadV1::new(
        SecretAliasId::parse(SECRET_ALIAS_ID)?,
        SecretId::parse(SECRET_ID)?,
        OwnerUserId::parse(ALT_OWNER_USER_ID)?,
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

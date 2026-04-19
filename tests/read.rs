use std::error::Error;

use mipsorcu::{
    AadError, AuthorizationError, Ciphertext, Classification, CreatedAt, CryptoError,
    DecryptCurrentSecretVersionInput, DecryptCurrentSecretVersionInputParts, DecryptIntegrityError,
    KeyVersion, MASTER_KEY_LENGTH, MasterKey, NewSecretVersionInput, OwnerUserId, Plaintext,
    PreparedSecretVersion, SecretDecryptError, SecretId, SecretVersion, VerifiedJwtClaims,
    decrypt_current_secret_version, prepare_new_secret_version,
};
use serde_json::{Value, json};

const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const OTHER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d480";
const WRONG_SECRET_ID: &str = "650e8400-e29b-41d4-a716-446655440000";
const CLASSIFICATION: &str = "confidential";
const CREATED_AT: &str = "2026-04-08T12:00:00Z";
const DEVICE_ID: &str = "sbc-device-1";

type TestResult<T> = Result<T, Box<dyn Error>>;

fn sample_master_key() -> MasterKey {
    MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH])
}

fn sample_new_input(plaintext: Vec<u8>) -> TestResult<NewSecretVersionInput> {
    Ok(NewSecretVersionInput::new(
        OwnerUserId::parse(OWNER_USER_ID)?,
        Classification::new(CLASSIFICATION)?,
        mipsorcu::DeviceId::new(DEVICE_ID)?,
        CreatedAt::parse(CREATED_AT)?,
        KeyVersion::new(1)?,
        Plaintext::new(plaintext),
    ))
}

fn prepared_secret_with_plaintext(
    plaintext: Vec<u8>,
) -> TestResult<(MasterKey, PreparedSecretVersion, Vec<u8>)> {
    let master_key = sample_master_key();
    let input = sample_new_input(plaintext.clone())?;
    let prepared = prepare_new_secret_version(&master_key, input)?;

    Ok((master_key, prepared, plaintext))
}

fn base_input_parts(
    prepared: &PreparedSecretVersion,
    subject_user_id: &str,
    current_version: SecretVersion,
) -> TestResult<DecryptCurrentSecretVersionInputParts> {
    Ok(DecryptCurrentSecretVersionInputParts {
        claims: VerifiedJwtClaims::from_verified_subject(OwnerUserId::parse(subject_user_id)?),
        secret_id: prepared.secret_id().clone(),
        version: prepared.version(),
        current_version,
        owner_user_id: prepared.owner_user_id().clone(),
        classification: prepared.classification().clone(),
        created_at: prepared.created_at().clone(),
        key_version: prepared.key_version(),
        encrypted_data_key: prepared.encrypted_data_key().clone(),
        nonce_or_iv: *prepared.nonce_or_iv(),
        ciphertext: prepared.ciphertext().clone(),
        aad_context: prepared.aad_context().clone(),
    })
}

fn base_input(
    prepared: &PreparedSecretVersion,
    subject_user_id: &str,
    current_version: SecretVersion,
) -> TestResult<DecryptCurrentSecretVersionInput> {
    Ok(DecryptCurrentSecretVersionInput::new(base_input_parts(
        prepared,
        subject_user_id,
        current_version,
    )?))
}

fn replace_aad_field(context: &Value, field: &'static str, value: Value) -> TestResult<Value> {
    let mut context = context.clone();
    let object = context
        .as_object_mut()
        .ok_or(AadError::ExpectedJsonObject)?;
    object.insert(field.to_owned(), value);

    Ok(context)
}

fn remove_aad_field(context: &Value, field: &'static str) -> TestResult<Value> {
    let mut context = context.clone();
    let object = context
        .as_object_mut()
        .ok_or(AadError::ExpectedJsonObject)?;
    object.remove(field);

    Ok(context)
}

fn tampered_ciphertext(prepared: &PreparedSecretVersion) -> TestResult<Ciphertext> {
    let mut bytes = prepared.ciphertext().as_bytes().to_vec();
    let first_byte = bytes.first_mut().ok_or(CryptoError::DecryptionFailed)?;
    *first_byte ^= 1;

    Ok(Ciphertext::new(bytes)?)
}

#[test]
fn decrypt_current_secret_version_round_trips_for_owner_and_current_version() -> TestResult<()> {
    let (master_key, prepared, plaintext) =
        prepared_secret_with_plaintext(b"dummy secret from read test".to_vec())?;
    let input = base_input(&prepared, OWNER_USER_ID, prepared.version())?;

    let decrypted = decrypt_current_secret_version(&master_key, input)?;

    assert_eq!(decrypted.as_bytes(), plaintext.as_slice());

    Ok(())
}

#[test]
fn decrypt_rejects_non_owner_before_crypto() -> TestResult<()> {
    let (_, prepared, _) = prepared_secret_with_plaintext(b"dummy secret from read test".to_vec())?;
    let wrong_master_key = MasterKey::from_bytes([99u8; MASTER_KEY_LENGTH]);
    let input = base_input(&prepared, OTHER_USER_ID, prepared.version())?;

    let result = decrypt_current_secret_version(&wrong_master_key, input);

    assert!(matches!(
        result,
        Err(SecretDecryptError::Authorization(
            AuthorizationError::OwnerMismatch
        ))
    ));

    Ok(())
}

#[test]
fn decrypt_rejects_non_current_version_before_crypto() -> TestResult<()> {
    let (_, prepared, _) = prepared_secret_with_plaintext(b"dummy secret from read test".to_vec())?;
    let wrong_master_key = MasterKey::from_bytes([99u8; MASTER_KEY_LENGTH]);
    let input = base_input(&prepared, OWNER_USER_ID, SecretVersion::new(2)?)?;

    let result = decrypt_current_secret_version(&wrong_master_key, input);

    assert!(matches!(
        result,
        Err(SecretDecryptError::Authorization(
            AuthorizationError::NotCurrentVersion
        ))
    ));

    Ok(())
}

#[test]
fn decrypt_rejects_aad_context_metadata_tampering() -> TestResult<()> {
    let (master_key, prepared, _) =
        prepared_secret_with_plaintext(b"dummy secret from read test".to_vec())?;
    let cases = [
        ("version", json!(2)),
        ("owner_user_id", json!(OTHER_USER_ID)),
        ("classification", json!("restricted")),
        ("created_at", json!("2026-04-08T12:01:00Z")),
    ];

    for (field, value) in cases {
        let mut parts = base_input_parts(&prepared, OWNER_USER_ID, prepared.version())?;
        parts.aad_context = replace_aad_field(prepared.aad_context(), field, value)?;
        let input = DecryptCurrentSecretVersionInput::new(parts);

        let result = decrypt_current_secret_version(&master_key, input);

        assert!(
            matches!(
                result,
                Err(SecretDecryptError::Integrity(
                    DecryptIntegrityError::AadContextMismatch
                ))
            ),
            "field {field} should fail with AAD mismatch"
        );
    }

    Ok(())
}

#[test]
fn decrypt_rejects_missing_aad_context_field_as_aad_error() -> TestResult<()> {
    let (master_key, prepared, _) =
        prepared_secret_with_plaintext(b"dummy secret from read test".to_vec())?;
    let mut parts = base_input_parts(&prepared, OWNER_USER_ID, prepared.version())?;
    parts.aad_context = remove_aad_field(prepared.aad_context(), "created_at")?;
    let input = DecryptCurrentSecretVersionInput::new(parts);

    let result = decrypt_current_secret_version(&master_key, input);

    assert!(matches!(
        result,
        Err(SecretDecryptError::Aad(AadError::MissingField { field }))
            if field == "created_at"
    ));

    Ok(())
}

#[test]
fn decrypt_rejects_invalid_aad_context_field_type_as_aad_error() -> TestResult<()> {
    let (master_key, prepared, _) =
        prepared_secret_with_plaintext(b"dummy secret from read test".to_vec())?;
    let mut parts = base_input_parts(&prepared, OWNER_USER_ID, prepared.version())?;
    parts.aad_context = replace_aad_field(prepared.aad_context(), "classification", json!(123))?;
    let input = DecryptCurrentSecretVersionInput::new(parts);

    let result = decrypt_current_secret_version(&master_key, input);

    assert!(matches!(
        result,
        Err(SecretDecryptError::Aad(AadError::InvalidFieldType {
            field,
            ..
        })) if field == "classification"
    ));

    Ok(())
}

#[test]
fn decrypt_rejects_ciphertext_tampering_as_crypto_error() -> TestResult<()> {
    let (master_key, prepared, _) =
        prepared_secret_with_plaintext(b"dummy secret from read test".to_vec())?;
    let mut parts = base_input_parts(&prepared, OWNER_USER_ID, prepared.version())?;
    parts.ciphertext = tampered_ciphertext(&prepared)?;
    let input = DecryptCurrentSecretVersionInput::new(parts);

    let result = decrypt_current_secret_version(&master_key, input);

    assert!(matches!(
        result,
        Err(SecretDecryptError::Crypto(CryptoError::DecryptionFailed))
    ));

    Ok(())
}

#[test]
fn decrypt_rejects_wrong_key_version_as_key_unwrap_failure() -> TestResult<()> {
    let (master_key, prepared, _) =
        prepared_secret_with_plaintext(b"dummy secret from read test".to_vec())?;
    let mut parts = base_input_parts(&prepared, OWNER_USER_ID, prepared.version())?;
    parts.key_version = KeyVersion::new(2)?;
    let input = DecryptCurrentSecretVersionInput::new(parts);

    let result = decrypt_current_secret_version(&master_key, input);

    assert!(matches!(
        result,
        Err(SecretDecryptError::Crypto(CryptoError::KeyUnwrapFailed))
    ));

    Ok(())
}

#[test]
fn decrypt_rejects_wrong_secret_id_as_key_unwrap_failure_when_aad_matches_row() -> TestResult<()> {
    let (master_key, prepared, _) =
        prepared_secret_with_plaintext(b"dummy secret from read test".to_vec())?;
    let mut parts = base_input_parts(&prepared, OWNER_USER_ID, prepared.version())?;
    parts.secret_id = SecretId::parse(WRONG_SECRET_ID)?;
    parts.aad_context =
        replace_aad_field(prepared.aad_context(), "secret_id", json!(WRONG_SECRET_ID))?;
    let input = DecryptCurrentSecretVersionInput::new(parts);

    let result = decrypt_current_secret_version(&master_key, input);

    assert!(matches!(
        result,
        Err(SecretDecryptError::Crypto(CryptoError::KeyUnwrapFailed))
    ));

    Ok(())
}

#[test]
fn debug_and_error_messages_do_not_expose_plaintext_keys_jwt_or_aad_context() -> TestResult<()> {
    let (master_key, prepared, _) = prepared_secret_with_plaintext(b"never-log-this".to_vec())?;
    let mut parts = base_input_parts(&prepared, OWNER_USER_ID, prepared.version())?;
    parts.ciphertext = tampered_ciphertext(&prepared)?;
    let input = DecryptCurrentSecretVersionInput::new(parts);
    let input_debug = format!("{input:?}");
    let result = decrypt_current_secret_version(&master_key, input);
    let error = match result {
        Ok(_) => return Err(Box::new(CryptoError::DecryptionFailed)),
        Err(error) => error,
    };
    let output = format!("{input_debug}\n{error:?}\n{error}");

    assert!(!output.contains("never-log-this"));
    assert!(!output.contains("11, 11"));
    assert!(!output.contains("aad_version"));
    assert!(!output.contains("ciphertext\":["));
    assert!(!output.contains("eyJhbGci"));

    Ok(())
}

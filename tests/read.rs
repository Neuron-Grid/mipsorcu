use std::error::Error;

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mipsorcu::{
    AadError, AuthorizationError, Ciphertext, Classification, CreatedAt, CryptoError,
    DecryptCurrentSecretVersionInput, DecryptCurrentSecretVersionInputParts, DecryptIntegrityError,
    Jwk, Jwks, JwtVerifier, JwtVerifierConfig, KeyVersion, KeyringError, MASTER_KEY_LENGTH,
    MasterKey, MasterKeyRing, NewSecretVersionInput, OwnerUserId, Plaintext, PreparedSecretVersion,
    RawJwt, SecretDecryptError, SecretId, SecretVersion, VerifiedJwtClaims,
    decrypt_current_secret_version, decrypt_current_secret_version_with_keyring,
    prepare_new_secret_version,
};
use serde::Serialize;
use serde_json::{Value, json};

const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const OTHER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d480";
const WRONG_SECRET_ID: &str = "650e8400-e29b-41d4-a716-446655440000";
const CLASSIFICATION: &str = "confidential";
const CREATED_AT: &str = "2026-04-08T12:00:00Z";
const DEVICE_ID: &str = "sbc-device-1";
const KEY_ID: &str = "test-key-1";
const ISSUER: &str = "https://project-ref.supabase.co/auth/v1";
const AUDIENCE: &str = "authenticated";
const RSA_MODULUS: &str = "0cOAzuft7zMhmD42QSngblYMsfhQD5IqUDK2S8sZw_TM0tNaPvMj-JqyM1bx4PaWDDjX018m8ys7wmOFSyfrl0TpWFzFMwUxLzsTgM1izd_a_Kk1IBRUREuYuAHr1TDZOoXqGncTC6xb-Jd4n58zjxsB3wO3OFBn_qP_Wsv4oPhiqLcya1UdyXEO905iIkigCdDa7VT7T6ogTrR-RGqZHON05UYXCmqSfAUBTy6dHowjQio0eHLUYAhDTv5q7oIcvb_SHbL-W-Q6GqsdFlQXJMXydSsTqBwlxs_7fSbOPqGfTxUeEzN5kyH1kn78oRK-toDT-ASKyu3Uh9sMV7fdqw";
const RSA_EXPONENT: &str = "AQAB";
const RSA_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRw4DO5+3vMyGY
PjZBKeBuVgyx+FAPkipQMrZLyxnD9MzS01o+8yP4mrIzVvHg9pYMONfTXybzKzvC
Y4VLJ+uXROlYXMUzBTEvOxOAzWLN39r8qTUgFFRES5i4AevVMNk6heoadxMLrFv4
l3ifnzOPGwHfA7c4UGf+o/9ay/ig+GKotzJrVR3JcQ73TmIiSKAJ0NrtVPtPqiBO
tH5Eapkc43TlRhcKapJ8BQFPLp0ejCNCKjR4ctRgCENO/mrughy9v9Idsv5b5Doa
qx0WVBckxfJ1KxOoHCXGz/t9Js4+oZ9PFR4TM3mTIfWSfvyhEr62gNP4BIrK7dSH
2wxXt92rAgMBAAECggEAAewnItm/dZRomg5ixDH7Rc52Oy55yDmbyc/y4sPx+d1J
25EUdt/yT4XEAaAFcQ+YWgcJ6aFgsV2ztrkooqd8XcWfRQJop2pEaOsMecg6ZIVb
WF9SD660liY5OE8UxSw3gpnfKy5/MrBno6tDuNI4oq2gndWP9IisHsFDBqcUD1dQ
5wUILJiQwI4wW0Bm5MHkzMjuSx0W5ZwkRjfc8EI17mbmBYQD56l6NJsiPatvYn2T
dFeW/jtPhnX8xXslxIDlKgdT/HODUE/azNJKw8vzDWjTAbSejuEJriZXcQxvtZfN
YY6P9Au5IQsjamJdas75PzF6XhT6QODatnxVV7ySPQKBgQDpSxX8wVwF/qHFk0YM
59ACc71kOkkkaT2Hc1fCoZPYbgYR4seO2cOkkRpiFoi5HrA5lNEoQBJJIJvtoL/4
cLSFIWRqGNtvH/NDoGEeF7GSn2i0LCb2jX5vuiY3bSlEj2JHiFTwizsmwhydokQM
jFKzDBJ+snk6gddUx1DgKaMMVwKBgQDmLiKiSwI615c3fCAEXP5UakK9VwjpkYAp
KIIz/RIokcW7+NP1xbFtj/06M7O4IasLOvugMPDzN/WJQ/gzA1m+bajwl22f7lRn
l4GMnFztVmGptTg+EzU0GORkRd3boEtwpd2FZ/WhfaTLP8BGIcvNu7frdGbpkcWK
iVNqtjNkzQKBgD9FO+tWzYxaqKka7g6l+AYSObUrEZcsa6GGqLCCfcRe4oqLRK/7
Y1IIgG1Fy0LZjdWwBKGz7sGidGeYBzhr6KmKit8zap/SvHkE0BIHPwOS9CSZLOAF
M9s9UwwJMP4FHRRlZxPtztcOIhCmZ2o3zF3+0i1GXhZ+DFZT0B1bbXr1AoGBANC5
XSaVpfv9q13g7JeITAf4I3TWC3rhOboYxZinD2RCa2+8f1gKYI3dV98DKyD5RsT0
Q2BLgPLL95b1T4fSrfqELgGdDwdLcrZNKGh9EbcV8ZGWht2jRUdsmw5iXH/fpwkL
Hwjt8Er0SA8WTCBMXSa95lVYREngqaSqSj4l4gyxAoGBAMf4zUq0pOLJA2rk9k7f
P7LJUPgASNpxGsG/FBDE+rTQl1tqVgHsI20KULCrQ5a2ob4sGlGfF8p2M5s5dcoM
fgr74PXMRn15mEnR/ieIFJEIIKAqG+eJE8E4wtXf8L3swtrg1s2mYe3km/Ly0gNH
o6OiVJrW2fR4F3HzG53Td7eh
-----END PRIVATE KEY-----"#;

type TestResult<T> = Result<T, Box<dyn Error>>;

#[derive(Clone, Serialize)]
struct TestClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
}

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
        claims: verified_claims_for(subject_user_id)?,
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

fn verified_claims_for(subject_user_id: &str) -> TestResult<VerifiedJwtClaims> {
    let key = EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_PEM.as_bytes())?;
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KEY_ID.to_owned());
    let token = encode(
        &header,
        &TestClaims {
            sub: subject_user_id.to_owned(),
            iss: ISSUER.to_owned(),
            aud: AUDIENCE.to_owned(),
            exp: 4_102_444_800,
        },
        &key,
    )?;
    let raw_jwt = RawJwt::new(&token)?;
    let verifier = JwtVerifier::new(
        JwtVerifierConfig::new(ISSUER, AUDIENCE)?,
        Jwks::new(vec![Jwk::new(
            "RSA",
            KEY_ID,
            Some("RS256".to_owned()),
            Some("sig".to_owned()),
            RSA_MODULUS,
            RSA_EXPONENT,
        )])?,
    );

    Ok(verifier.verify(&raw_jwt)?)
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
        ("secret_id", json!(WRONG_SECRET_ID)),
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
fn decrypt_rejects_unexpected_aad_context_field_as_aad_error() -> TestResult<()> {
    let (master_key, prepared, _) =
        prepared_secret_with_plaintext(b"dummy secret from read test".to_vec())?;
    let mut context = prepared.aad_context().clone();
    let object = context
        .as_object_mut()
        .ok_or(AadError::ExpectedJsonObject)?;
    object.insert("debug".to_owned(), json!("must-not-be-stored"));

    let mut parts = base_input_parts(&prepared, OWNER_USER_ID, prepared.version())?;
    parts.aad_context = context;
    let input = DecryptCurrentSecretVersionInput::new(parts);

    let result = decrypt_current_secret_version(&master_key, input);

    assert!(matches!(
        result,
        Err(SecretDecryptError::Aad(AadError::UnexpectedField { field }))
            if field == "debug"
    ));

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
fn decrypt_with_keyring_selects_row_key_version() -> TestResult<()> {
    let (old_master_key, prepared, plaintext) =
        prepared_secret_with_plaintext(b"old key row still decrypts".to_vec())?;
    let keyring = MasterKeyRing::from_key_entries(
        KeyVersion::new(2)?,
        [
            (KeyVersion::new(1)?, old_master_key),
            (
                KeyVersion::new(2)?,
                MasterKey::from_bytes([12u8; MASTER_KEY_LENGTH]),
            ),
        ],
    )?;
    let input = base_input(&prepared, OWNER_USER_ID, prepared.version())?;

    let decrypted = decrypt_current_secret_version_with_keyring(&keyring, input)?;

    assert_eq!(decrypted.as_bytes(), plaintext.as_slice());

    Ok(())
}

#[test]
fn decrypt_with_keyring_fails_closed_when_row_key_is_unavailable() -> TestResult<()> {
    let (_, prepared, _) = prepared_secret_with_plaintext(b"missing key row".to_vec())?;
    let keyring = MasterKeyRing::single(
        KeyVersion::new(2)?,
        MasterKey::from_bytes([12u8; MASTER_KEY_LENGTH]),
    )?;
    let input = base_input(&prepared, OWNER_USER_ID, prepared.version())?;

    let result = decrypt_current_secret_version_with_keyring(&keyring, input);

    assert!(matches!(
        result,
        Err(SecretDecryptError::Keyring(
            KeyringError::KeyUnavailable { key_version }
        )) if key_version == 1
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

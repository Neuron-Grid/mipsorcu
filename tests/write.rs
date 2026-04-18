use mipsorcu::{
    ALGORITHM_XCHACHA20_POLY1305, AadV1, Classification, CreatedAt, DATA_KEY_LENGTH, DeviceId,
    KeyVersion, KeyWrapContext, MASTER_KEY_LENGTH, MasterKey, OwnerUserId, Plaintext,
    SecretWriteError, decrypt_secret, prepare_new_secret_version, unwrap_data_key,
};
use serde_json::Value;

const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const CLASSIFICATION: &str = "confidential";
const CREATED_AT: &str = "2026-04-08T12:00:00Z";
const DEVICE_ID: &str = "sbc-device-1";

fn sample_master_key() -> MasterKey {
    MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH])
}

fn sample_input(plaintext: Plaintext) -> Result<mipsorcu::NewSecretVersionInput, SecretWriteError> {
    Ok(mipsorcu::NewSecretVersionInput::new(
        OwnerUserId::parse(OWNER_USER_ID)?,
        Classification::new(CLASSIFICATION)?,
        DeviceId::new(DEVICE_ID)?,
        CreatedAt::parse(CREATED_AT)?,
        KeyVersion::new(1)?,
        plaintext,
    ))
}

#[test]
fn prepare_new_secret_version_builds_rpc_payload_and_round_trips() -> Result<(), SecretWriteError> {
    let master_key = sample_master_key();
    let plaintext_bytes = b"dummy secret from test".to_vec();
    let input = sample_input(Plaintext::new(plaintext_bytes.clone()))?;

    let prepared = prepare_new_secret_version(&master_key, input)?;
    let secret_id = prepared.secret_id().as_canonical_string();

    mipsorcu::SecretId::parse(&secret_id)?;
    assert_eq!(prepared.version().get(), 1);
    assert_eq!(prepared.key_version().get(), 1);
    assert_eq!(prepared.algorithm(), ALGORITHM_XCHACHA20_POLY1305);
    assert_eq!(
        prepared.nonce_or_iv().as_bytes().len(),
        mipsorcu::NONCE_LENGTH
    );
    assert!(!prepared.ciphertext().as_bytes().is_empty());
    assert_eq!(
        prepared.encrypted_data_key().as_bytes().len(),
        mipsorcu::ENCRYPTED_DATA_KEY_LENGTH
    );
    assert_eq!(prepared.created_by_device_id().as_str(), DEVICE_ID);

    assert_eq!(
        prepared
            .aad_context()
            .get("secret_id")
            .and_then(Value::as_str),
        Some(secret_id.as_str())
    );
    assert_eq!(
        prepared
            .aad_context()
            .get("version")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        prepared
            .aad_context()
            .get("owner_user_id")
            .and_then(Value::as_str),
        Some(OWNER_USER_ID)
    );
    assert_eq!(
        prepared
            .aad_context()
            .get("classification")
            .and_then(Value::as_str),
        Some(CLASSIFICATION)
    );
    assert_eq!(
        prepared
            .aad_context()
            .get("created_at")
            .and_then(Value::as_str),
        Some(CREATED_AT)
    );

    let key_wrap_context =
        KeyWrapContext::new(prepared.secret_id().clone(), prepared.key_version());
    let data_key = unwrap_data_key(
        &master_key,
        &key_wrap_context,
        prepared.encrypted_data_key(),
    )?;
    assert_eq!(data_key.as_bytes().len(), DATA_KEY_LENGTH);

    let aad = AadV1::from_stored_context(prepared.aad_context())?;
    let decrypted = decrypt_secret(
        &data_key,
        &aad,
        prepared.nonce_or_iv(),
        prepared.ciphertext(),
    )?;

    assert_eq!(decrypted.as_bytes(), plaintext_bytes.as_slice());

    Ok(())
}

#[test]
fn device_id_rejects_empty_or_whitespace_values() {
    assert!(matches!(
        DeviceId::new(""),
        Err(mipsorcu::InputError::InvalidDeviceId)
    ));
    assert!(matches!(
        DeviceId::new("   "),
        Err(mipsorcu::InputError::InvalidDeviceId)
    ));
    assert!(DeviceId::new("sbc-device-1").is_ok());
}

#[test]
fn debug_output_does_not_expose_plaintext_or_keys() -> Result<(), SecretWriteError> {
    let master_key = sample_master_key();
    let input = sample_input(Plaintext::new(b"never-log-this".to_vec()))?;
    let input_debug = format!("{input:?}");

    let prepared = prepare_new_secret_version(&master_key, input)?;
    let prepared_debug = format!("{prepared:?}");
    let output = format!("{input_debug}\n{prepared_debug}");

    assert!(!output.contains("never-log-this"));
    assert!(!output.contains("11, 11"));
    assert!(!output.contains("MasterKey(<redacted>)"));

    Ok(())
}

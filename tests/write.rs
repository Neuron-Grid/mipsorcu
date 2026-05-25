use mipsorcu::{
    ALGORITHM_XCHACHA20_POLY1305, AadV1, Classification, CreatedAt, CryptoError,
    CurrentSecretVersionState, DATA_KEY_LENGTH, DataKey, DeviceId, ExistingSecretVersionInput,
    InputError, KekAlgorithm, KekProvider, KeyVersion, KeyWrapContext, MASTER_KEY_LENGTH,
    MasterKey, MasterKeyRing, OwnerUserId, Plaintext, SecretId, SecretVersion, SecretWriteError,
    decrypt_secret, prepare_existing_secret_version, prepare_existing_secret_version_with_keyring,
    prepare_new_secret_version, prepare_new_secret_version_with_keyring, unwrap_data_key,
};
use serde_json::Value;

const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const CLASSIFICATION: &str = "confidential";
const CREATED_AT: &str = "2026-04-08T12:00:00Z";
const ROTATED_CREATED_AT: &str = "2026-04-08T12:01:00Z";
const DEVICE_ID: &str = "sbc-device-1";

fn sample_master_key() -> MasterKey {
    MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH])
}

fn rotation_keyring() -> Result<MasterKeyRing, SecretWriteError> {
    Ok(MasterKeyRing::from_key_entries(
        KeyVersion::new(2)?,
        [
            (
                KeyVersion::new(1)?,
                MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH]),
            ),
            (
                KeyVersion::new(2)?,
                MasterKey::from_bytes([12u8; MASTER_KEY_LENGTH]),
            ),
        ],
    )?)
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

fn current_state_from_prepared(
    prepared: &mipsorcu::PreparedSecretVersion,
) -> CurrentSecretVersionState {
    CurrentSecretVersionState::new(
        prepared.secret_id().clone(),
        prepared.version(),
        prepared.owner_user_id().clone(),
        prepared.classification().clone(),
        prepared.key_version(),
        prepared
            .encrypted_data_key()
            .expect("legacy prepared version should include encrypted_data_key")
            .clone(),
    )
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
    assert_eq!(prepared.write_action().as_str(), "encrypt_create");
    assert_eq!(prepared.algorithm(), ALGORITHM_XCHACHA20_POLY1305);
    assert_eq!(
        prepared.nonce_or_iv().as_bytes().len(),
        mipsorcu::NONCE_LENGTH
    );
    assert!(!prepared.ciphertext().as_bytes().is_empty());
    assert_eq!(
        prepared
            .encrypted_data_key()
            .expect("legacy prepared version should include encrypted_data_key")
            .as_bytes()
            .len(),
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
        prepared
            .encrypted_data_key()
            .expect("legacy prepared version should include encrypted_data_key"),
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
fn prepare_existing_secret_version_reuses_data_key_and_round_trips() -> Result<(), SecretWriteError>
{
    let master_key = sample_master_key();
    let current_plaintext = b"current dummy secret".to_vec();
    let current_input = sample_input(Plaintext::new(current_plaintext))?;
    let current = prepare_new_secret_version(&master_key, current_input)?;
    let current_state = current_state_from_prepared(&current);
    let next_plaintext = b"rotated dummy secret".to_vec();
    let input = ExistingSecretVersionInput::new(
        current_state,
        DeviceId::new(DEVICE_ID)?,
        CreatedAt::parse(ROTATED_CREATED_AT)?,
        Plaintext::new(next_plaintext.clone()),
    );

    let rotated = prepare_existing_secret_version(&master_key, input)?;

    assert_eq!(rotated.write_action().as_str(), "encrypt_rotate");
    assert_eq!(rotated.secret_id(), current.secret_id());
    assert_eq!(rotated.version().get(), current.version().get() + 1);
    assert_eq!(
        rotated.owner_user_id().as_canonical_string(),
        current.owner_user_id().as_canonical_string()
    );
    assert_eq!(
        rotated.classification().as_str(),
        current.classification().as_str()
    );
    assert_eq!(rotated.key_version(), current.key_version());
    assert_eq!(rotated.created_by_device_id().as_str(), DEVICE_ID);
    assert_eq!(
        rotated
            .encrypted_data_key()
            .expect("legacy rotated version should include encrypted_data_key")
            .as_bytes(),
        current
            .encrypted_data_key()
            .expect("legacy current version should include encrypted_data_key")
            .as_bytes()
    );
    assert_eq!(
        rotated
            .aad_context()
            .get("secret_id")
            .and_then(Value::as_str),
        Some(current.secret_id().as_canonical_string().as_str())
    );
    assert_eq!(
        rotated.aad_context().get("version").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        rotated
            .aad_context()
            .get("owner_user_id")
            .and_then(Value::as_str),
        Some(OWNER_USER_ID)
    );
    assert_eq!(
        rotated
            .aad_context()
            .get("classification")
            .and_then(Value::as_str),
        Some(CLASSIFICATION)
    );
    assert_eq!(
        rotated
            .aad_context()
            .get("created_at")
            .and_then(Value::as_str),
        Some(ROTATED_CREATED_AT)
    );

    let current_context = KeyWrapContext::new(current.secret_id().clone(), current.key_version());
    let current_data_key = unwrap_data_key(
        &master_key,
        &current_context,
        current
            .encrypted_data_key()
            .expect("legacy current version should include encrypted_data_key"),
    )?;
    let rotated_context = KeyWrapContext::new(rotated.secret_id().clone(), rotated.key_version());
    let rotated_data_key = unwrap_data_key(
        &master_key,
        &rotated_context,
        rotated
            .encrypted_data_key()
            .expect("legacy rotated version should include encrypted_data_key"),
    )?;
    assert_eq!(rotated_data_key.as_bytes(), current_data_key.as_bytes());
    assert_eq!(rotated_data_key.as_bytes().len(), DATA_KEY_LENGTH);

    let aad = AadV1::from_stored_context(rotated.aad_context())?;
    let decrypted = decrypt_secret(
        &rotated_data_key,
        &aad,
        rotated.nonce_or_iv(),
        rotated.ciphertext(),
    )?;

    assert_eq!(decrypted.as_bytes(), next_plaintext.as_slice());

    Ok(())
}

#[test]
fn prepare_new_secret_version_with_keyring_uses_active_key_version() -> Result<(), SecretWriteError>
{
    let keyring = rotation_keyring()?;
    let input = sample_input(Plaintext::new(b"new active key secret".to_vec()))?;

    let prepared = prepare_new_secret_version_with_keyring(&keyring, input)?;

    assert_eq!(prepared.key_version().get(), 2);
    assert!(prepared.encrypted_data_key().is_none());
    assert_eq!(
        prepared.dek_wrap_algorithm(),
        Some(KekAlgorithm::EnvvarXchachaV2)
    );
    assert_eq!(prepared.kek_version().map(|version| version.get()), Some(2));
    let unwrapped = keyring
        .as_envvar_kek()
        .unwrap_dek(
            prepared
                .wrapped_dek()
                .expect("v0.2 prepared version should include wrapped_dek"),
        )
        .expect("v0.2 wrapped DEK should unwrap with active KEK");
    let data_key = DataKey::parse(unwrapped.as_bytes())?;
    assert_eq!(data_key.as_bytes().len(), DATA_KEY_LENGTH);

    Ok(())
}

#[test]
fn prepare_existing_secret_version_with_keyring_generates_fresh_envelope_dek()
-> Result<(), SecretWriteError> {
    let old_master_key = sample_master_key();
    let current = prepare_new_secret_version(
        &old_master_key,
        sample_input(Plaintext::new(b"current dummy secret".to_vec()))?,
    )?;
    let current_state = current_state_from_prepared(&current);
    let keyring = rotation_keyring()?;
    let next_plaintext = b"rotated under active key".to_vec();
    let input = ExistingSecretVersionInput::new(
        current_state,
        DeviceId::new(DEVICE_ID)?,
        CreatedAt::parse(ROTATED_CREATED_AT)?,
        Plaintext::new(next_plaintext.clone()),
    );

    let rotated = prepare_existing_secret_version_with_keyring(&keyring, input)?;

    assert_eq!(rotated.key_version().get(), 2);
    assert!(rotated.encrypted_data_key().is_none());
    assert_eq!(
        rotated.dek_wrap_algorithm(),
        Some(KekAlgorithm::EnvvarXchachaV2)
    );
    assert_eq!(rotated.kek_version().map(|version| version.get()), Some(2));
    assert_ne!(rotated.nonce_or_iv(), current.nonce_or_iv());

    let old_context = KeyWrapContext::new(current.secret_id().clone(), current.key_version());
    let old_data_key = unwrap_data_key(
        keyring.get(KeyVersion::new(1)?)?,
        &old_context,
        current
            .encrypted_data_key()
            .expect("legacy current version should include encrypted_data_key"),
    )?;
    let new_dek = keyring
        .as_envvar_kek()
        .unwrap_dek(
            rotated
                .wrapped_dek()
                .expect("v0.2 rotated version should include wrapped_dek"),
        )
        .expect("v0.2 wrapped DEK should unwrap with active KEK");
    let new_data_key = DataKey::parse(new_dek.as_bytes())?;
    assert_ne!(new_data_key.as_bytes(), old_data_key.as_bytes());
    assert_eq!(new_data_key.as_bytes().len(), DATA_KEY_LENGTH);

    let aad = AadV1::from_stored_context(rotated.aad_context())?;
    let decrypted = decrypt_secret(
        &new_data_key,
        &aad,
        rotated.nonce_or_iv(),
        rotated.ciphertext(),
    )?;
    assert_eq!(decrypted.as_bytes(), next_plaintext.as_slice());

    Ok(())
}

#[test]
fn prepare_existing_secret_version_with_keyring_accepts_metadata_only_current_state()
-> Result<(), SecretWriteError> {
    let keyring = rotation_keyring()?;
    let current_secret_id = SecretId::generate()?;
    let current_state = CurrentSecretVersionState::from_metadata(
        current_secret_id.clone(),
        SecretVersion::new(7)?,
        OwnerUserId::parse(OWNER_USER_ID)?,
        Classification::new(CLASSIFICATION)?,
    );
    let next_plaintext = b"rotated from metadata only".to_vec();
    let input = ExistingSecretVersionInput::new(
        current_state,
        DeviceId::new(DEVICE_ID)?,
        CreatedAt::parse(ROTATED_CREATED_AT)?,
        Plaintext::new(next_plaintext.clone()),
    );

    let rotated = prepare_existing_secret_version_with_keyring(&keyring, input)?;

    assert_eq!(rotated.secret_id(), &current_secret_id);
    assert_eq!(rotated.version().get(), 8);
    assert!(rotated.encrypted_data_key().is_none());
    assert!(rotated.wrapped_dek().is_some());
    let aad = AadV1::from_stored_context(rotated.aad_context())?;
    let unwrapped = keyring
        .as_envvar_kek()
        .unwrap_dek(
            rotated
                .wrapped_dek()
                .expect("v0.2 rotated version should include wrapped_dek"),
        )
        .expect("v0.2 wrapped DEK should unwrap with active KEK");
    let data_key = DataKey::parse(unwrapped.as_bytes())?;
    let decrypted = decrypt_secret(&data_key, &aad, rotated.nonce_or_iv(), rotated.ciphertext())?;
    assert_eq!(decrypted.as_bytes(), next_plaintext.as_slice());

    Ok(())
}

#[test]
fn prepare_existing_secret_version_rejects_wrong_secret_context() -> Result<(), SecretWriteError> {
    let master_key = sample_master_key();
    let current = prepare_new_secret_version(
        &master_key,
        sample_input(Plaintext::new(b"current dummy secret".to_vec()))?,
    )?;
    let wrong_secret_id = SecretId::parse("650e8400-e29b-41d4-a716-446655440000")?;
    let current_state = CurrentSecretVersionState::new(
        wrong_secret_id,
        current.version(),
        current.owner_user_id().clone(),
        current.classification().clone(),
        current.key_version(),
        current
            .encrypted_data_key()
            .expect("legacy current version should include encrypted_data_key")
            .clone(),
    );
    let input = ExistingSecretVersionInput::new(
        current_state,
        DeviceId::new(DEVICE_ID)?,
        CreatedAt::parse(ROTATED_CREATED_AT)?,
        Plaintext::new(b"rotated dummy secret".to_vec()),
    );
    let result = prepare_existing_secret_version(&master_key, input);

    assert!(matches!(
        result,
        Err(SecretWriteError::Crypto(CryptoError::KeyUnwrapFailed))
    ));

    Ok(())
}

#[test]
fn prepare_existing_secret_version_rejects_wrong_key_version_context()
-> Result<(), SecretWriteError> {
    let master_key = sample_master_key();
    let current = prepare_new_secret_version(
        &master_key,
        sample_input(Plaintext::new(b"current dummy secret".to_vec()))?,
    )?;
    let current_state = CurrentSecretVersionState::new(
        current.secret_id().clone(),
        current.version(),
        current.owner_user_id().clone(),
        current.classification().clone(),
        KeyVersion::new(2)?,
        current
            .encrypted_data_key()
            .expect("legacy current version should include encrypted_data_key")
            .clone(),
    );
    let input = ExistingSecretVersionInput::new(
        current_state,
        DeviceId::new(DEVICE_ID)?,
        CreatedAt::parse(ROTATED_CREATED_AT)?,
        Plaintext::new(b"rotated dummy secret".to_vec()),
    );
    let result = prepare_existing_secret_version(&master_key, input);

    assert!(matches!(
        result,
        Err(SecretWriteError::Crypto(CryptoError::KeyUnwrapFailed))
    ));

    Ok(())
}

#[test]
fn prepare_existing_secret_version_rejects_version_overflow() -> Result<(), SecretWriteError> {
    let master_key = sample_master_key();
    let current = prepare_new_secret_version(
        &master_key,
        sample_input(Plaintext::new(b"current dummy secret".to_vec()))?,
    )?;
    let current_state = CurrentSecretVersionState::new(
        current.secret_id().clone(),
        SecretVersion::new(u32::MAX)?,
        current.owner_user_id().clone(),
        current.classification().clone(),
        current.key_version(),
        current
            .encrypted_data_key()
            .expect("legacy current version should include encrypted_data_key")
            .clone(),
    );
    let input = ExistingSecretVersionInput::new(
        current_state,
        DeviceId::new(DEVICE_ID)?,
        CreatedAt::parse(ROTATED_CREATED_AT)?,
        Plaintext::new(b"rotated dummy secret".to_vec()),
    );
    let result = prepare_existing_secret_version(&master_key, input);

    assert!(matches!(
        result,
        Err(SecretWriteError::Input(InputError::SecretVersionOverflow))
    ));

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
    let current_state = current_state_from_prepared(&prepared);
    let current_state_debug = format!("{current_state:?}");
    let existing_input = ExistingSecretVersionInput::new(
        current_state,
        DeviceId::new(DEVICE_ID)?,
        CreatedAt::parse(ROTATED_CREATED_AT)?,
        Plaintext::new(b"never-log-this-either".to_vec()),
    );
    let existing_input_debug = format!("{existing_input:?}");
    let prepared_debug = format!("{prepared:?}");
    let output =
        format!("{input_debug}\n{current_state_debug}\n{existing_input_debug}\n{prepared_debug}");

    assert!(!output.contains("never-log-this"));
    assert!(!output.contains("never-log-this-either"));
    assert!(!output.contains("11, 11"));
    assert!(!output.contains("MasterKey(<redacted>)"));
    assert!(!output.contains("EncryptedDataKey(["));

    Ok(())
}

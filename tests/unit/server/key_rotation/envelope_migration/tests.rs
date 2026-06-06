use super::*;
use crate::crypto::open_dispatched;
use crate::{
    DeviceId, KekVersion, MASTER_KEY_LENGTH, MasterKey, NewSecretVersionInput, Plaintext,
    prepare_new_secret_version,
};

#[test]
fn prepared_migration_row_round_trips_with_v02_open_dispatched()
-> Result<(), Box<dyn std::error::Error>> {
    let legacy_key = MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH]);
    let keyring = MasterKeyRing::from_key_entries(
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
    )?;
    let plaintext_bytes = b"task-07 envelope migration round trip".to_vec();
    let legacy = prepare_new_secret_version(
        &legacy_key,
        NewSecretVersionInput::new(
            OwnerUserId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
            Classification::new("confidential")?,
            DeviceId::new("sbc-device-1")?,
            CreatedAt::parse("2026-04-08T12:00:00Z")?,
            KeyVersion::new(1)?,
            Plaintext::new(plaintext_bytes.clone()),
        ),
    )?;
    let row = EnvelopeMigrationBatchRow {
        id: legacy.secret_version_id().as_canonical_string(),
        secret_id: legacy.secret_id().as_canonical_string(),
        version: i32::try_from(legacy.version().get())?,
        ciphertext: encode_bytea(legacy.ciphertext().as_bytes()),
        encrypted_data_key: encode_bytea(
            legacy
                .encrypted_data_key()
                .ok_or("legacy fixture is missing encrypted_data_key")?
                .as_bytes(),
        ),
        key_version: i32::try_from(legacy.key_version().get())?,
        algorithm: legacy.algorithm().to_owned(),
        classification: legacy.classification().as_str().to_owned(),
        nonce_or_iv: encode_bytea(legacy.nonce_or_iv().as_bytes()),
        aad_context: legacy.aad_context().clone(),
        created_at: legacy.created_at().as_rfc3339_utc()?,
        owner_user_id: legacy.owner_user_id().as_canonical_string(),
    };

    let migrated = match prepare_row(&keyring, row) {
        Ok(row) => row,
        Err(RowPreparationError::Failure(failure)) => {
            panic!("migration fixture failed with {}", failure.error_code);
        }
        Err(RowPreparationError::Fatal(error)) => return Err(Box::new(error)),
    };
    assert_eq!(migrated.dek_wrap_algorithm, "envvar-xchacha-v2");
    assert_eq!(migrated.kek_version, 2);

    let aad = AadV1::from_stored_context(legacy.aad_context())?;
    let record = SecretVersionRecord {
        secret_id: SecretId::parse(&migrated.secret_id)?,
        key_version: KeyVersion::new(migrated.kek_version)?,
        ciphertext: Ciphertext::new(decode_bytea(&migrated.ciphertext)?)?,
        nonce: Nonce::parse(&decode_bytea(&migrated.nonce_or_iv)?)?,
        encrypted_data_key: None,
        wrapped_dek: Some(crate::WrappedDek::parse(
            KekVersion::new(migrated.kek_version)?,
            &decode_bytea(&migrated.wrapped_dek)?,
        )?),
        dek_wrap_algorithm: Some(KekAlgorithm::EnvvarXchachaV2),
    };
    let opened = open_dispatched(&keyring, &record, &aad)?;
    assert_eq!(opened.as_bytes(), plaintext_bytes.as_slice());

    Ok(())
}

#[test]
fn prepare_batch_maps_pre_crypto_failures_to_safe_error_codes()
-> Result<(), Box<dyn std::error::Error>> {
    let (keyring, mut aad_mismatch_row) = migration_fixture_row()?;
    aad_mismatch_row.aad_context["classification"] = serde_json::json!("restricted");
    assert_single_failure_code(&keyring, aad_mismatch_row, "aad_context_mismatch")?;

    let (keyring, mut encrypted_data_key_row) = migration_fixture_row()?;
    encrypted_data_key_row.encrypted_data_key = "\\x00".to_owned();
    assert_single_failure_code(
        &keyring,
        encrypted_data_key_row,
        "encrypted_data_key_invalid",
    )?;

    let (keyring, mut nonce_row) = migration_fixture_row()?;
    nonce_row.nonce_or_iv = "\\x00".to_owned();
    assert_single_failure_code(&keyring, nonce_row, "nonce_invalid")?;

    let (keyring, mut decrypt_row) = migration_fixture_row()?;
    decrypt_row.ciphertext = format!("\\x{}", "ff".repeat(32));
    assert_single_failure_code(&keyring, decrypt_row, "legacy_decrypt_failed")?;

    Ok(())
}

fn assert_single_failure_code(
    keyring: &MasterKeyRing,
    row: EnvelopeMigrationBatchRow,
    expected_error_code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let prepared = prepare_batch(keyring, vec![row])?;
    assert!(prepared.success_rows.is_empty());
    assert_eq!(prepared.failure_rows.len(), 1);
    assert_eq!(prepared.failure_rows[0].error_code, expected_error_code);

    Ok(())
}

fn migration_fixture_row()
-> Result<(MasterKeyRing, EnvelopeMigrationBatchRow), Box<dyn std::error::Error>> {
    let legacy_key = MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH]);
    let keyring = MasterKeyRing::from_key_entries(
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
    )?;
    let legacy = prepare_new_secret_version(
        &legacy_key,
        NewSecretVersionInput::new(
            OwnerUserId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
            Classification::new("confidential")?,
            DeviceId::new("sbc-device-1")?,
            CreatedAt::parse("2026-04-08T12:00:00Z")?,
            KeyVersion::new(1)?,
            Plaintext::new(b"task-07 envelope migration failure mapping".to_vec()),
        ),
    )?;
    let row = EnvelopeMigrationBatchRow {
        id: legacy.secret_version_id().as_canonical_string(),
        secret_id: legacy.secret_id().as_canonical_string(),
        version: i32::try_from(legacy.version().get())?,
        ciphertext: encode_bytea(legacy.ciphertext().as_bytes()),
        encrypted_data_key: encode_bytea(
            legacy
                .encrypted_data_key()
                .ok_or("legacy fixture is missing encrypted_data_key")?
                .as_bytes(),
        ),
        key_version: i32::try_from(legacy.key_version().get())?,
        algorithm: legacy.algorithm().to_owned(),
        classification: legacy.classification().as_str().to_owned(),
        nonce_or_iv: encode_bytea(legacy.nonce_or_iv().as_bytes()),
        aad_context: legacy.aad_context().clone(),
        created_at: legacy.created_at().as_rfc3339_utc()?,
        owner_user_id: legacy.owner_user_id().as_canonical_string(),
    };

    Ok((keyring, row))
}

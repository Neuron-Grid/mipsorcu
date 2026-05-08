use crate::types::supabase::KeyRotationBatchRow;
use crate::types::{EncryptedDataKey, KeyVersion, SecretId, SecretVersion};

use super::KeyRotationCliError;
use super::bytea::decode_bytea;

pub(super) struct ParsedRotationBatchRow {
    pub(super) id: String,
    pub(super) secret_id: SecretId,
    pub(super) encrypted_data_key: EncryptedDataKey,
}

pub(super) fn parse_rotation_batch_row(
    row: KeyRotationBatchRow,
    expected_key_version: KeyVersion,
) -> Result<ParsedRotationBatchRow, KeyRotationCliError> {
    let key_version = u32::try_from(row.key_version)
        .ok()
        .and_then(|value| KeyVersion::new(value).ok())
        .ok_or_else(|| {
            KeyRotationCliError::Config("rotation row key_version is invalid".to_owned())
        })?;
    if key_version != expected_key_version {
        return Err(KeyRotationCliError::Config(
            "rotation row key_version does not match requested old key version".to_owned(),
        ));
    }

    let _version = u32::try_from(row.version)
        .ok()
        .and_then(|value| SecretVersion::new(value).ok())
        .ok_or_else(|| KeyRotationCliError::Config("rotation row version is invalid".to_owned()))?;
    let secret_id = SecretId::parse(&row.secret_id)
        .map_err(|_| KeyRotationCliError::Config("rotation row secret_id is invalid".to_owned()))?;
    let encrypted_data_key_bytes = decode_bytea(&row.encrypted_data_key)?;
    let encrypted_data_key = EncryptedDataKey::parse(&encrypted_data_key_bytes).map_err(|_| {
        KeyRotationCliError::Config("rotation row encrypted_data_key is invalid".to_owned())
    })?;

    Ok(ParsedRotationBatchRow {
        id: row.id,
        secret_id,
        encrypted_data_key,
    })
}

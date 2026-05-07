use super::KeyRotationCliError;

pub(super) fn decode_bytea(value: &str) -> Result<Vec<u8>, KeyRotationCliError> {
    let hex_value = value.strip_prefix("\\x").ok_or_else(|| {
        KeyRotationCliError::Config("rotation row bytea is not hex encoded".to_owned())
    })?;

    hex::decode(hex_value)
        .map_err(|_| KeyRotationCliError::Config("rotation row bytea is invalid".to_owned()))
}

pub(super) fn encode_bytea(bytes: &[u8]) -> String {
    format!("\\x{}", hex::encode(bytes))
}

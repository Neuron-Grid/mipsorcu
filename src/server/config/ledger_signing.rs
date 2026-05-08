use crate::ledger::{
    LEDGER_ED25519_SECRET_KEY_LENGTH, LedgerSignatureKeyVersion, LedgerSigningKey,
};
use zeroize::Zeroize;

use super::constants::{ENV_LEDGER_SIGNATURE_KEY_VERSION, ENV_LEDGER_SIGNING_KEY};
use super::env::{DotenvVars, required_var};
use super::error::ConfigError;

pub(super) fn load_ledger_signing_key<F>(
    dotenv: &DotenvVars,
    get_process_var: &F,
) -> Result<LedgerSigningKey, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let key_version = parse_ledger_signature_key_version(&required_var(
        ENV_LEDGER_SIGNATURE_KEY_VERSION,
        dotenv,
        get_process_var,
    )?)?;
    let mut key_bytes = hex::decode(required_var(
        ENV_LEDGER_SIGNING_KEY,
        dotenv,
        get_process_var,
    )?)
    .map_err(|error| ConfigError::InvalidValue {
        name: ENV_LEDGER_SIGNING_KEY,
        reason: error.to_string(),
    })?;

    let result = if key_bytes.len() == LEDGER_ED25519_SECRET_KEY_LENGTH {
        LedgerSigningKey::from_secret_key_bytes(key_version, &key_bytes).map_err(|error| {
            ConfigError::InvalidValue {
                name: ENV_LEDGER_SIGNING_KEY,
                reason: error.to_string(),
            }
        })
    } else {
        Err(ConfigError::InvalidValue {
            name: ENV_LEDGER_SIGNING_KEY,
            reason: format!("decoded key must be {LEDGER_ED25519_SECRET_KEY_LENGTH} bytes"),
        })
    };
    key_bytes.zeroize();

    result
}

fn parse_ledger_signature_key_version(
    value: &str,
) -> Result<LedgerSignatureKeyVersion, ConfigError> {
    let parsed = value
        .parse::<u32>()
        .map_err(|error| ConfigError::InvalidValue {
            name: ENV_LEDGER_SIGNATURE_KEY_VERSION,
            reason: error.to_string(),
        })?;

    LedgerSignatureKeyVersion::new(parsed).map_err(|error| ConfigError::InvalidValue {
        name: ENV_LEDGER_SIGNATURE_KEY_VERSION,
        reason: error.to_string(),
    })
}

use std::fs;
use std::path::{Path, PathBuf};

use crate::MasterKeyRing;
use crate::error::KeyringError;
use crate::types::{KeyVersion, MasterKey};

use super::constants::{
    ENV_ACTIVE_KEY_VERSION, ENV_KEY_VERSION, ENV_MASTER_KEY, ENV_MASTER_KEY_DIR,
};
use super::env::{DotenvVars, optional_var, required_var};
use super::error::ConfigError;

pub(super) fn load_master_key_ring<F>(
    dotenv: &DotenvVars,
    get_process_var: &F,
) -> Result<MasterKeyRing, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    match optional_var(ENV_MASTER_KEY_DIR, dotenv, get_process_var) {
        Some(directory) => {
            load_master_key_ring_from_directory(&PathBuf::from(directory), dotenv, get_process_var)
        }
        None => load_legacy_single_master_key_ring(dotenv, get_process_var),
    }
}

fn load_legacy_single_master_key_ring<F>(
    dotenv: &DotenvVars,
    get_process_var: &F,
) -> Result<MasterKeyRing, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let master_key = parse_master_key_hex(
        ENV_MASTER_KEY,
        &required_var(ENV_MASTER_KEY, dotenv, get_process_var)?,
    )?;
    let key_version = parse_key_version_config(
        ENV_KEY_VERSION,
        &required_var(ENV_KEY_VERSION, dotenv, get_process_var)?,
    )?;

    MasterKeyRing::single(key_version, master_key).map_err(keyring_config_error)
}

fn load_master_key_ring_from_directory<F>(
    directory: &Path,
    dotenv: &DotenvVars,
    get_process_var: &F,
) -> Result<MasterKeyRing, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let active_key_version = parse_key_version_config(
        ENV_ACTIVE_KEY_VERSION,
        &required_var(ENV_ACTIVE_KEY_VERSION, dotenv, get_process_var)?,
    )?;
    let entries = fs::read_dir(directory)
        .map_err(|error| ConfigError::InvalidValue {
            name: ENV_MASTER_KEY_DIR,
            reason: format!("failed to read directory {}: {error}", directory.display()),
        })?
        .map(|entry| parse_master_key_file_entry(directory, entry))
        .collect::<Result<Vec<_>, _>>()?;

    MasterKeyRing::from_key_entries(active_key_version, entries).map_err(keyring_config_error)
}

fn parse_master_key_file_entry(
    directory: &Path,
    entry: Result<fs::DirEntry, std::io::Error>,
) -> Result<(KeyVersion, MasterKey), ConfigError> {
    let entry = entry.map_err(|error| ConfigError::InvalidValue {
        name: ENV_MASTER_KEY_DIR,
        reason: format!(
            "failed to read directory entry in {}: {error}",
            directory.display()
        ),
    })?;
    let path = entry.path();
    let metadata = entry
        .metadata()
        .map_err(|error| ConfigError::InvalidValue {
            name: ENV_MASTER_KEY_DIR,
            reason: format!("failed to inspect key file {}: {error}", path.display()),
        })?;

    if !metadata.is_file() {
        return Err(ConfigError::InvalidValue {
            name: ENV_MASTER_KEY_DIR,
            reason: format!("keyring entry must be a file: {}", path.display()),
        });
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ConfigError::InvalidValue {
            name: ENV_MASTER_KEY_DIR,
            reason: format!("key file name must be UTF-8: {}", path.display()),
        })?;
    let Some(key_version_text) = file_name.strip_suffix(".key") else {
        return Err(ConfigError::InvalidValue {
            name: ENV_MASTER_KEY_DIR,
            reason: format!("key file name must match <positive-version>.key: {file_name}"),
        });
    };
    let key_version = parse_key_version_config(ENV_MASTER_KEY_DIR, key_version_text)?;
    let key_hex = fs::read_to_string(&path).map_err(|error| ConfigError::InvalidValue {
        name: ENV_MASTER_KEY_DIR,
        reason: format!("failed to read key file {}: {error}", path.display()),
    })?;
    let master_key = parse_master_key_hex(ENV_MASTER_KEY_DIR, key_hex.trim())?;

    Ok((key_version, master_key))
}

fn parse_master_key_hex(name: &'static str, value: &str) -> Result<MasterKey, ConfigError> {
    let master_key_bytes = hex::decode(value).map_err(|error| ConfigError::InvalidValue {
        name,
        reason: error.to_string(),
    })?;

    MasterKey::parse(&master_key_bytes).map_err(|error| ConfigError::InvalidValue {
        name,
        reason: error.to_string(),
    })
}

fn parse_key_version_config(name: &'static str, value: &str) -> Result<KeyVersion, ConfigError> {
    let parsed = value
        .parse::<u32>()
        .map_err(|error| ConfigError::InvalidValue {
            name,
            reason: error.to_string(),
        })?;

    KeyVersion::new(parsed).map_err(|error| ConfigError::InvalidValue {
        name,
        reason: error.to_string(),
    })
}

fn keyring_config_error(error: KeyringError) -> ConfigError {
    ConfigError::InvalidValue {
        name: ENV_MASTER_KEY_DIR,
        reason: error.to_string(),
    }
}

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::types::{KeyVersion, MasterKey};

const DEFAULT_DOTENV_PATH: &str = ".env";
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_AUDIT_FALLBACK_PATH: &str = "/var/lib/mipsorcu/audit-fallback-current.jsonl";
const DEFAULT_AUDIT_RESEND_INTERVAL_SECONDS: u64 = 60;
const DEFAULT_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;
const DEFAULT_AUDIT_FALLBACK_ROTATE_SIZE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_AUDIT_FALLBACK_ARCHIVE_RETENTION_DAYS: u64 = 90;
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
const DEFAULT_RESTORE_TEST_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_RESTORE_TEST_SAMPLE_LIMIT: u32 = 3;
const DEFAULT_JWKS_REFRESH_INTERVAL_SECONDS: u64 = 60 * 60;

const ENV_LISTEN_ADDR: &str = "MIPSORCU_LISTEN_ADDR";
const ENV_MASTER_KEY: &str = "MIPSORCU_MASTER_KEY";
const ENV_KEY_VERSION: &str = "MIPSORCU_KEY_VERSION";
const ENV_SUPABASE_URL: &str = "MIPSORCU_SUPABASE_URL";
const ENV_SUPABASE_SERVICE_ROLE_KEY: &str = "MIPSORCU_SUPABASE_SERVICE_ROLE_KEY";
const ENV_SUPABASE_PUBLISHABLE_KEY: &str = "MIPSORCU_SUPABASE_PUBLISHABLE_KEY";
const ENV_JWT_ISSUER: &str = "MIPSORCU_JWT_ISSUER";
const ENV_JWT_AUDIENCE: &str = "MIPSORCU_JWT_AUDIENCE";
const ENV_JWKS_URL: &str = "MIPSORCU_JWKS_URL";
const ENV_AUDIT_FALLBACK_PATH: &str = "MIPSORCU_AUDIT_FALLBACK_PATH";
const ENV_AUDIT_RESEND_INTERVAL_SECONDS: &str = "MIPSORCU_AUDIT_RESEND_INTERVAL_SECONDS";
const ENV_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES: &str =
    "MIPSORCU_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES";
const ENV_AUDIT_FALLBACK_ROTATE_SIZE_BYTES: &str = "MIPSORCU_AUDIT_FALLBACK_ROTATE_SIZE_BYTES";
const ENV_AUDIT_FALLBACK_ARCHIVE_DIR: &str = "MIPSORCU_AUDIT_FALLBACK_ARCHIVE_DIR";
const ENV_AUDIT_FALLBACK_ARCHIVE_AUTO_DELETE_ENABLED: &str =
    "MIPSORCU_AUDIT_FALLBACK_ARCHIVE_AUTO_DELETE_ENABLED";
const ENV_AUDIT_FALLBACK_ARCHIVE_RETENTION_DAYS: &str =
    "MIPSORCU_AUDIT_FALLBACK_ARCHIVE_RETENTION_DAYS";
const ENV_RESTORE_TEST_INTERVAL_SECONDS: &str = "MIPSORCU_RESTORE_TEST_INTERVAL_SECONDS";
const ENV_RESTORE_TEST_SAMPLE_LIMIT: &str = "MIPSORCU_RESTORE_TEST_SAMPLE_LIMIT";
const ENV_JWKS_REFRESH_INTERVAL_SECONDS: &str = "MIPSORCU_JWKS_REFRESH_INTERVAL_SECONDS";

#[doc(hidden)]
pub type DotenvVars = HashMap<String, String>;

pub struct AppConfig {
    pub listen_addr: SocketAddr,
    pub master_key: MasterKey,
    pub key_version: KeyVersion,
    pub supabase_url: String,
    pub supabase_service_role_key: String,
    pub supabase_publishable_key: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwks_url: String,
    pub jwks_refresh_interval: Duration,
    pub audit_fallback_path: PathBuf,
    pub audit_resend_interval: Duration,
    pub audit_fallback_alert_threshold_bytes: u64,
    pub audit_fallback_rotate_size_bytes: u64,
    pub audit_fallback_archive_dir: PathBuf,
    pub audit_fallback_archive_auto_delete_enabled: bool,
    pub audit_fallback_archive_retention: Duration,
    pub restore_test_interval: Duration,
    pub restore_test_sample_limit: u32,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppConfig")
            .field("listen_addr", &self.listen_addr)
            .field("master_key", &"<redacted>")
            .field("key_version", &self.key_version)
            .field("supabase_url", &self.supabase_url)
            .field("supabase_service_role_key", &"<redacted>")
            .field("supabase_publishable_key", &"<redacted>")
            .field("jwt_issuer", &self.jwt_issuer)
            .field("jwt_audience", &self.jwt_audience)
            .field("jwks_url", &self.jwks_url)
            .field(
                "jwks_refresh_interval_seconds",
                &self.jwks_refresh_interval.as_secs(),
            )
            .field("audit_fallback_path", &self.audit_fallback_path)
            .field(
                "audit_resend_interval_seconds",
                &self.audit_resend_interval.as_secs(),
            )
            .field(
                "audit_fallback_alert_threshold_bytes",
                &self.audit_fallback_alert_threshold_bytes,
            )
            .field(
                "audit_fallback_rotate_size_bytes",
                &self.audit_fallback_rotate_size_bytes,
            )
            .field(
                "audit_fallback_archive_dir",
                &self.audit_fallback_archive_dir,
            )
            .field(
                "audit_fallback_archive_auto_delete_enabled",
                &self.audit_fallback_archive_auto_delete_enabled,
            )
            .field(
                "audit_fallback_archive_retention_days",
                &(self.audit_fallback_archive_retention.as_secs() / SECONDS_PER_DAY),
            )
            .field(
                "restore_test_interval_seconds",
                &self.restore_test_interval.as_secs(),
            )
            .field("restore_test_sample_limit", &self.restore_test_sample_limit)
            .finish()
    }
}

#[derive(Debug)]
pub enum ConfigError {
    MissingVar { name: &'static str },
    InvalidValue { name: &'static str, reason: String },
    DotenvLoad { path: PathBuf, reason: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVar { name } => {
                write!(
                    formatter,
                    "required environment variable is not set: {name}"
                )
            }
            Self::InvalidValue { name, reason } => {
                write!(
                    formatter,
                    "environment variable {name} has an invalid value: {reason}"
                )
            }
            Self::DotenvLoad { path, reason } => {
                write!(
                    formatter,
                    "failed to load dotenv file {}: {reason}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn load_config() -> Result<AppConfig, ConfigError> {
    let dotenv = load_dotenv_file(Path::new(DEFAULT_DOTENV_PATH))?;
    load_config_from_sources(&current_process_var, &dotenv)
}

#[doc(hidden)]
pub fn load_config_from_sources<F>(
    get_process_var: &F,
    dotenv: &DotenvVars,
) -> Result<AppConfig, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let listen_addr = optional_var(ENV_LISTEN_ADDR, dotenv, get_process_var)
        .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_owned())
        .parse::<SocketAddr>()
        .map_err(|error| ConfigError::InvalidValue {
            name: ENV_LISTEN_ADDR,
            reason: error.to_string(),
        })?;

    let master_key_hex = required_var(ENV_MASTER_KEY, dotenv, get_process_var)?;
    let master_key_bytes =
        hex::decode(&master_key_hex).map_err(|error| ConfigError::InvalidValue {
            name: ENV_MASTER_KEY,
            reason: error.to_string(),
        })?;
    let master_key =
        MasterKey::parse(&master_key_bytes).map_err(|error| ConfigError::InvalidValue {
            name: ENV_MASTER_KEY,
            reason: error.to_string(),
        })?;

    let key_version_str = required_var(ENV_KEY_VERSION, dotenv, get_process_var)?;
    let key_version_u32 =
        key_version_str
            .parse::<u32>()
            .map_err(|error| ConfigError::InvalidValue {
                name: ENV_KEY_VERSION,
                reason: error.to_string(),
            })?;
    let key_version =
        KeyVersion::new(key_version_u32).map_err(|error| ConfigError::InvalidValue {
            name: ENV_KEY_VERSION,
            reason: error.to_string(),
        })?;

    let supabase_url = required_var(ENV_SUPABASE_URL, dotenv, get_process_var)?;
    let supabase_service_role_key =
        required_var(ENV_SUPABASE_SERVICE_ROLE_KEY, dotenv, get_process_var)?;
    let supabase_publishable_key =
        required_var(ENV_SUPABASE_PUBLISHABLE_KEY, dotenv, get_process_var)?;
    let jwt_issuer = required_var(ENV_JWT_ISSUER, dotenv, get_process_var)?;
    let jwt_audience = required_var(ENV_JWT_AUDIENCE, dotenv, get_process_var)?;
    let jwks_url = required_var(ENV_JWKS_URL, dotenv, get_process_var)?;
    let jwks_refresh_interval = parse_jwks_refresh_interval(optional_var(
        ENV_JWKS_REFRESH_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;

    let audit_fallback_path = PathBuf::from(
        optional_var(ENV_AUDIT_FALLBACK_PATH, dotenv, get_process_var)
            .unwrap_or_else(|| DEFAULT_AUDIT_FALLBACK_PATH.to_owned()),
    );
    let audit_fallback_archive_dir =
        optional_var(ENV_AUDIT_FALLBACK_ARCHIVE_DIR, dotenv, get_process_var)
            .map(PathBuf::from)
            .unwrap_or_else(|| default_audit_fallback_archive_dir(&audit_fallback_path));
    let audit_resend_interval = parse_audit_resend_interval(optional_var(
        ENV_AUDIT_RESEND_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let audit_fallback_alert_threshold_bytes = parse_audit_fallback_alert_threshold(optional_var(
        ENV_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES,
        dotenv,
        get_process_var,
    ))?;
    let audit_fallback_rotate_size_bytes = parse_audit_fallback_rotate_size(optional_var(
        ENV_AUDIT_FALLBACK_ROTATE_SIZE_BYTES,
        dotenv,
        get_process_var,
    ))?;
    let audit_fallback_archive_auto_delete_enabled =
        parse_audit_fallback_archive_auto_delete_enabled(optional_var(
            ENV_AUDIT_FALLBACK_ARCHIVE_AUTO_DELETE_ENABLED,
            dotenv,
            get_process_var,
        ))?;
    let audit_fallback_archive_retention =
        parse_audit_fallback_archive_retention_days(optional_var(
            ENV_AUDIT_FALLBACK_ARCHIVE_RETENTION_DAYS,
            dotenv,
            get_process_var,
        ))?;
    let restore_test_interval = parse_restore_test_interval(optional_var(
        ENV_RESTORE_TEST_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let restore_test_sample_limit = parse_restore_test_sample_limit(optional_var(
        ENV_RESTORE_TEST_SAMPLE_LIMIT,
        dotenv,
        get_process_var,
    ))?;

    Ok(AppConfig {
        listen_addr,
        master_key,
        key_version,
        supabase_url,
        supabase_service_role_key,
        supabase_publishable_key,
        jwt_issuer,
        jwt_audience,
        jwks_url,
        jwks_refresh_interval,
        audit_fallback_path,
        audit_resend_interval,
        audit_fallback_alert_threshold_bytes,
        audit_fallback_rotate_size_bytes,
        audit_fallback_archive_dir,
        audit_fallback_archive_auto_delete_enabled,
        audit_fallback_archive_retention,
        restore_test_interval,
        restore_test_sample_limit,
    })
}

pub fn parse_audit_resend_interval(value: Option<String>) -> Result<Duration, ConfigError> {
    let Some(value) = value else {
        return Ok(Duration::from_secs(DEFAULT_AUDIT_RESEND_INTERVAL_SECONDS));
    };

    let seconds = value
        .parse::<u64>()
        .map_err(|error| ConfigError::InvalidValue {
            name: ENV_AUDIT_RESEND_INTERVAL_SECONDS,
            reason: error.to_string(),
        })?;

    if seconds == 0 {
        return Err(ConfigError::InvalidValue {
            name: ENV_AUDIT_RESEND_INTERVAL_SECONDS,
            reason: "value must be greater than zero".to_owned(),
        });
    }

    Ok(Duration::from_secs(seconds))
}

pub fn parse_audit_fallback_alert_threshold(value: Option<String>) -> Result<u64, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES,
        DEFAULT_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES,
    )
}

pub fn parse_audit_fallback_rotate_size(value: Option<String>) -> Result<u64, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_AUDIT_FALLBACK_ROTATE_SIZE_BYTES,
        DEFAULT_AUDIT_FALLBACK_ROTATE_SIZE_BYTES,
    )
}

pub fn parse_audit_fallback_archive_auto_delete_enabled(
    value: Option<String>,
) -> Result<bool, ConfigError> {
    let Some(value) = value else {
        return Ok(false);
    };
    let normalized = value.trim().to_ascii_lowercase();

    match normalized.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ConfigError::InvalidValue {
            name: ENV_AUDIT_FALLBACK_ARCHIVE_AUTO_DELETE_ENABLED,
            reason: "value must be true or false".to_owned(),
        }),
    }
}

pub fn parse_audit_fallback_archive_retention_days(
    value: Option<String>,
) -> Result<Duration, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_AUDIT_FALLBACK_ARCHIVE_RETENTION_DAYS,
        DEFAULT_AUDIT_FALLBACK_ARCHIVE_RETENTION_DAYS,
    )
    .and_then(|days| {
        days.checked_mul(SECONDS_PER_DAY)
            .map(Duration::from_secs)
            .ok_or_else(|| ConfigError::InvalidValue {
                name: ENV_AUDIT_FALLBACK_ARCHIVE_RETENTION_DAYS,
                reason: "value is too large".to_owned(),
            })
    })
}

pub fn parse_restore_test_interval(value: Option<String>) -> Result<Duration, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_RESTORE_TEST_INTERVAL_SECONDS,
        DEFAULT_RESTORE_TEST_INTERVAL_SECONDS,
    )
    .map(Duration::from_secs)
}

pub fn parse_restore_test_sample_limit(value: Option<String>) -> Result<u32, ConfigError> {
    let Some(value) = value else {
        return Ok(DEFAULT_RESTORE_TEST_SAMPLE_LIMIT);
    };

    let parsed = value
        .parse::<u32>()
        .map_err(|error| ConfigError::InvalidValue {
            name: ENV_RESTORE_TEST_SAMPLE_LIMIT,
            reason: error.to_string(),
        })?;

    if parsed == 0 {
        return Err(ConfigError::InvalidValue {
            name: ENV_RESTORE_TEST_SAMPLE_LIMIT,
            reason: "value must be greater than zero".to_owned(),
        });
    }

    Ok(parsed)
}

pub fn parse_jwks_refresh_interval(value: Option<String>) -> Result<Duration, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_JWKS_REFRESH_INTERVAL_SECONDS,
        DEFAULT_JWKS_REFRESH_INTERVAL_SECONDS,
    )
    .map(Duration::from_secs)
}

fn parse_positive_u64_config(
    value: Option<String>,
    name: &'static str,
    default_value: u64,
) -> Result<u64, ConfigError> {
    let Some(value) = value else {
        return Ok(default_value);
    };

    let parsed = value
        .parse::<u64>()
        .map_err(|error| ConfigError::InvalidValue {
            name,
            reason: error.to_string(),
        })?;

    if parsed == 0 {
        return Err(ConfigError::InvalidValue {
            name,
            reason: "value must be greater than zero".to_owned(),
        });
    }

    Ok(parsed)
}

fn current_process_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn required_var<F>(
    name: &'static str,
    dotenv: &DotenvVars,
    get_process_var: &F,
) -> Result<String, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let value = get_process_var(name)
        .or_else(|| dotenv.get(name).cloned())
        .ok_or(ConfigError::MissingVar { name })?;
    if value.trim().is_empty() {
        return Err(ConfigError::InvalidValue {
            name,
            reason: "value must not be empty".to_owned(),
        });
    }
    Ok(value)
}

fn optional_var<F>(name: &str, dotenv: &DotenvVars, get_process_var: &F) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    match get_process_var(name) {
        Some(value) if !value.trim().is_empty() => Some(value),
        Some(_) => None,
        None => dotenv
            .get(name)
            .cloned()
            .filter(|value| !value.trim().is_empty()),
    }
}

fn default_audit_fallback_archive_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("archive")
}

fn load_dotenv_file(path: &Path) -> Result<DotenvVars, ConfigError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DotenvVars::new());
        }
        Err(error) => {
            return Err(ConfigError::DotenvLoad {
                path: path.to_path_buf(),
                reason: error.to_string(),
            });
        }
    };

    parse_dotenv_contents(&contents, path)
}

#[doc(hidden)]
pub fn parse_dotenv_contents(contents: &str, path: &Path) -> Result<DotenvVars, ConfigError> {
    let mut dotenv = DotenvVars::new();

    for (index, line) in contents.lines().enumerate() {
        let Some((name, value)) = parse_dotenv_line(line, path, index + 1)? else {
            continue;
        };
        dotenv.insert(name, value);
    }

    Ok(dotenv)
}

fn parse_dotenv_line(
    line: &str,
    path: &Path,
    line_number: usize,
) -> Result<Option<(String, String)>, ConfigError> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    let binding = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    let Some((name, raw_value)) = binding.split_once('=') else {
        return Err(dotenv_parse_error(
            path,
            line_number,
            "line must contain `=`".to_owned(),
        ));
    };

    let name = name.trim();
    if !is_valid_dotenv_key(name) {
        return Err(dotenv_parse_error(
            path,
            line_number,
            format!("invalid key `{name}`"),
        ));
    }

    let value = parse_dotenv_value(raw_value.trim(), path, line_number)?;
    Ok(Some((name.to_owned(), value)))
}

fn parse_dotenv_value(
    raw_value: &str,
    path: &Path,
    line_number: usize,
) -> Result<String, ConfigError> {
    if raw_value.starts_with('"') {
        if raw_value.len() < 2 || !raw_value.ends_with('"') {
            return Err(dotenv_parse_error(
                path,
                line_number,
                "double-quoted value must terminate on the same line".to_owned(),
            ));
        }

        return parse_double_quoted_dotenv_value(
            &raw_value[1..raw_value.len() - 1],
            path,
            line_number,
        );
    }

    if raw_value.starts_with('\'') {
        if raw_value.len() < 2 || !raw_value.ends_with('\'') {
            return Err(dotenv_parse_error(
                path,
                line_number,
                "single-quoted value must terminate on the same line".to_owned(),
            ));
        }

        return Ok(raw_value[1..raw_value.len() - 1].to_owned());
    }

    Ok(raw_value.to_owned())
}

fn parse_double_quoted_dotenv_value(
    raw_value: &str,
    path: &Path,
    line_number: usize,
) -> Result<String, ConfigError> {
    let mut value = String::with_capacity(raw_value.len());
    let mut chars = raw_value.chars();

    while let Some(character) = chars.next() {
        if character != '\\' {
            value.push(character);
            continue;
        }

        let Some(escaped) = chars.next() else {
            return Err(dotenv_parse_error(
                path,
                line_number,
                "unterminated escape sequence".to_owned(),
            ));
        };

        match escaped {
            '\\' => value.push('\\'),
            '"' => value.push('"'),
            'n' => value.push('\n'),
            'r' => value.push('\r'),
            't' => value.push('\t'),
            _ => {
                return Err(dotenv_parse_error(
                    path,
                    line_number,
                    format!("unsupported escape sequence `\\{escaped}`"),
                ));
            }
        }
    }

    Ok(value)
}

fn is_valid_dotenv_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }

    chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn dotenv_parse_error(path: &Path, line_number: usize, reason: String) -> ConfigError {
    ConfigError::DotenvLoad {
        path: path.to_path_buf(),
        reason: format!("line {line_number}: {reason}"),
    }
}

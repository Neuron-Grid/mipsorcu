use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::MasterKeyRing;
use crate::error::KeyringError;
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
const DEFAULT_RESTORE_TEST_STARTUP_DELAY_SECONDS: u64 = 300;
const DEFAULT_RESTORE_TEST_SAMPLE_LIMIT: u32 = 3;
const DEFAULT_INTEGRITY_CHECK_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_INTEGRITY_CHECK_STARTUP_DELAY_SECONDS: u64 = 3900;
const DEFAULT_JWKS_REFRESH_INTERVAL_SECONDS: u64 = 60 * 60;
const DEFAULT_HEALTH_READINESS_POLL_INTERVAL_SECONDS: u64 = 30;
const DEFAULT_OUTBOUND_HTTP_CONNECT_TIMEOUT_SECONDS: u64 = 5;
const DEFAULT_OUTBOUND_HTTP_REQUEST_TIMEOUT_SECONDS: u64 = 20;
const DEFAULT_HTTP_HANDLER_TIMEOUT_SECONDS: u64 = 75;
const DEFAULT_HTTP_RATE_LIMIT_REQUESTS: u64 = 300;
const DEFAULT_HTTP_RATE_LIMIT_WINDOW_SECONDS: u64 = 60;

const ENV_LISTEN_ADDR: &str = "MIPSORCU_LISTEN_ADDR";
const ENV_MASTER_KEY: &str = "MIPSORCU_MASTER_KEY";
const ENV_KEY_VERSION: &str = "MIPSORCU_KEY_VERSION";
const ENV_ACTIVE_KEY_VERSION: &str = "MIPSORCU_ACTIVE_KEY_VERSION";
const ENV_MASTER_KEY_DIR: &str = "MIPSORCU_MASTER_KEY_DIR";
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
const ENV_RESTORE_TEST_STARTUP_DELAY_SECONDS: &str = "MIPSORCU_RESTORE_TEST_STARTUP_DELAY_SECONDS";
const ENV_RESTORE_TEST_SAMPLE_LIMIT: &str = "MIPSORCU_RESTORE_TEST_SAMPLE_LIMIT";
const ENV_INTEGRITY_CHECK_INTERVAL_SECONDS: &str = "MIPSORCU_INTEGRITY_CHECK_INTERVAL_SECONDS";
const ENV_INTEGRITY_CHECK_STARTUP_DELAY_SECONDS: &str =
    "MIPSORCU_INTEGRITY_CHECK_STARTUP_DELAY_SECONDS";
const ENV_JWKS_REFRESH_INTERVAL_SECONDS: &str = "MIPSORCU_JWKS_REFRESH_INTERVAL_SECONDS";
const ENV_HEALTH_READINESS_POLL_INTERVAL_SECONDS: &str =
    "MIPSORCU_HEALTH_READINESS_POLL_INTERVAL_SECONDS";
const ENV_OUTBOUND_HTTP_CONNECT_TIMEOUT_SECONDS: &str =
    "MIPSORCU_OUTBOUND_HTTP_CONNECT_TIMEOUT_SECONDS";
const ENV_OUTBOUND_HTTP_REQUEST_TIMEOUT_SECONDS: &str =
    "MIPSORCU_OUTBOUND_HTTP_REQUEST_TIMEOUT_SECONDS";
const ENV_HTTP_HANDLER_TIMEOUT_SECONDS: &str = "MIPSORCU_HTTP_HANDLER_TIMEOUT_SECONDS";
const ENV_HTTP_RATE_LIMIT_REQUESTS: &str = "MIPSORCU_HTTP_RATE_LIMIT_REQUESTS";
const ENV_HTTP_RATE_LIMIT_WINDOW_SECONDS: &str = "MIPSORCU_HTTP_RATE_LIMIT_WINDOW_SECONDS";

#[doc(hidden)]
pub type DotenvVars = HashMap<String, String>;

pub struct AppConfig {
    pub listen_addr: SocketAddr,
    pub master_key_ring: MasterKeyRing,
    pub supabase_url: String,
    pub supabase_service_role_key: String,
    pub supabase_publishable_key: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwks_url: String,
    pub jwks_refresh_interval: Duration,
    pub health_readiness_poll_interval: Duration,
    pub outbound_http_connect_timeout: Duration,
    pub outbound_http_request_timeout: Duration,
    pub http_handler_timeout: Duration,
    pub http_rate_limit_requests: u64,
    pub http_rate_limit_window: Duration,
    pub audit_fallback_path: PathBuf,
    pub audit_resend_interval: Duration,
    pub audit_fallback_alert_threshold_bytes: u64,
    pub audit_fallback_rotate_size_bytes: u64,
    pub audit_fallback_archive_dir: PathBuf,
    pub audit_fallback_archive_auto_delete_enabled: bool,
    pub audit_fallback_archive_retention: Duration,
    pub restore_test_interval: Duration,
    pub restore_test_startup_delay: Duration,
    pub restore_test_sample_limit: u32,
    pub integrity_check_interval: Duration,
    pub integrity_check_startup_delay: Duration,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppConfig")
            .field("listen_addr", &self.listen_addr)
            .field("master_key_ring", &self.master_key_ring)
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
            .field(
                "health_readiness_poll_interval_seconds",
                &self.health_readiness_poll_interval.as_secs(),
            )
            .field(
                "outbound_http_connect_timeout_seconds",
                &self.outbound_http_connect_timeout.as_secs(),
            )
            .field(
                "outbound_http_request_timeout_seconds",
                &self.outbound_http_request_timeout.as_secs(),
            )
            .field(
                "http_handler_timeout_seconds",
                &self.http_handler_timeout.as_secs(),
            )
            .field("http_rate_limit_requests", &self.http_rate_limit_requests)
            .field(
                "http_rate_limit_window_seconds",
                &self.http_rate_limit_window.as_secs(),
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
            .field(
                "restore_test_startup_delay_seconds",
                &self.restore_test_startup_delay.as_secs(),
            )
            .field("restore_test_sample_limit", &self.restore_test_sample_limit)
            .field(
                "integrity_check_interval_seconds",
                &self.integrity_check_interval.as_secs(),
            )
            .field(
                "integrity_check_startup_delay_seconds",
                &self.integrity_check_startup_delay.as_secs(),
            )
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

    let master_key_ring = load_master_key_ring(dotenv, get_process_var)?;

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
    let health_readiness_poll_interval = parse_health_readiness_poll_interval(optional_var(
        ENV_HEALTH_READINESS_POLL_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let outbound_http_connect_timeout = parse_outbound_http_connect_timeout(optional_var(
        ENV_OUTBOUND_HTTP_CONNECT_TIMEOUT_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let outbound_http_request_timeout = parse_outbound_http_request_timeout(optional_var(
        ENV_OUTBOUND_HTTP_REQUEST_TIMEOUT_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let http_handler_timeout = parse_http_handler_timeout(
        optional_var(ENV_HTTP_HANDLER_TIMEOUT_SECONDS, dotenv, get_process_var),
        outbound_http_request_timeout,
    )?;
    let http_rate_limit_requests = parse_http_rate_limit_requests(optional_var(
        ENV_HTTP_RATE_LIMIT_REQUESTS,
        dotenv,
        get_process_var,
    ))?;
    let http_rate_limit_window = parse_http_rate_limit_window(optional_var(
        ENV_HTTP_RATE_LIMIT_WINDOW_SECONDS,
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
    let restore_test_startup_delay = parse_restore_test_startup_delay(optional_var(
        ENV_RESTORE_TEST_STARTUP_DELAY_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let restore_test_sample_limit = parse_restore_test_sample_limit(optional_var(
        ENV_RESTORE_TEST_SAMPLE_LIMIT,
        dotenv,
        get_process_var,
    ))?;
    let integrity_check_interval = parse_integrity_check_interval(optional_var(
        ENV_INTEGRITY_CHECK_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let integrity_check_startup_delay = parse_integrity_check_startup_delay(optional_var(
        ENV_INTEGRITY_CHECK_STARTUP_DELAY_SECONDS,
        dotenv,
        get_process_var,
    ))?;

    Ok(AppConfig {
        listen_addr,
        master_key_ring,
        supabase_url,
        supabase_service_role_key,
        supabase_publishable_key,
        jwt_issuer,
        jwt_audience,
        jwks_url,
        jwks_refresh_interval,
        health_readiness_poll_interval,
        outbound_http_connect_timeout,
        outbound_http_request_timeout,
        http_handler_timeout,
        http_rate_limit_requests,
        http_rate_limit_window,
        audit_fallback_path,
        audit_resend_interval,
        audit_fallback_alert_threshold_bytes,
        audit_fallback_rotate_size_bytes,
        audit_fallback_archive_dir,
        audit_fallback_archive_auto_delete_enabled,
        audit_fallback_archive_retention,
        restore_test_interval,
        restore_test_startup_delay,
        restore_test_sample_limit,
        integrity_check_interval,
        integrity_check_startup_delay,
    })
}

fn load_master_key_ring<F>(
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

pub fn parse_restore_test_startup_delay(value: Option<String>) -> Result<Duration, ConfigError> {
    parse_non_negative_u64_config(
        value,
        ENV_RESTORE_TEST_STARTUP_DELAY_SECONDS,
        DEFAULT_RESTORE_TEST_STARTUP_DELAY_SECONDS,
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

pub fn parse_integrity_check_interval(value: Option<String>) -> Result<Duration, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_INTEGRITY_CHECK_INTERVAL_SECONDS,
        DEFAULT_INTEGRITY_CHECK_INTERVAL_SECONDS,
    )
    .map(Duration::from_secs)
}

pub fn parse_integrity_check_startup_delay(value: Option<String>) -> Result<Duration, ConfigError> {
    parse_non_negative_u64_config(
        value,
        ENV_INTEGRITY_CHECK_STARTUP_DELAY_SECONDS,
        DEFAULT_INTEGRITY_CHECK_STARTUP_DELAY_SECONDS,
    )
    .map(Duration::from_secs)
}

pub fn parse_jwks_refresh_interval(value: Option<String>) -> Result<Duration, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_JWKS_REFRESH_INTERVAL_SECONDS,
        DEFAULT_JWKS_REFRESH_INTERVAL_SECONDS,
    )
    .map(Duration::from_secs)
}

pub fn parse_health_readiness_poll_interval(
    value: Option<String>,
) -> Result<Duration, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_HEALTH_READINESS_POLL_INTERVAL_SECONDS,
        DEFAULT_HEALTH_READINESS_POLL_INTERVAL_SECONDS,
    )
    .map(Duration::from_secs)
}

pub fn parse_outbound_http_connect_timeout(value: Option<String>) -> Result<Duration, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_OUTBOUND_HTTP_CONNECT_TIMEOUT_SECONDS,
        DEFAULT_OUTBOUND_HTTP_CONNECT_TIMEOUT_SECONDS,
    )
    .map(Duration::from_secs)
}

pub fn parse_outbound_http_request_timeout(value: Option<String>) -> Result<Duration, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_OUTBOUND_HTTP_REQUEST_TIMEOUT_SECONDS,
        DEFAULT_OUTBOUND_HTTP_REQUEST_TIMEOUT_SECONDS,
    )
    .map(Duration::from_secs)
}

pub fn parse_http_handler_timeout(
    value: Option<String>,
    outbound_http_request_timeout: Duration,
) -> Result<Duration, ConfigError> {
    let timeout = parse_positive_u64_config(
        value,
        ENV_HTTP_HANDLER_TIMEOUT_SECONDS,
        DEFAULT_HTTP_HANDLER_TIMEOUT_SECONDS,
    )
    .map(Duration::from_secs)?;
    let minimum = minimum_http_handler_timeout(outbound_http_request_timeout)?;

    if timeout < minimum {
        return Err(ConfigError::InvalidValue {
            name: ENV_HTTP_HANDLER_TIMEOUT_SECONDS,
            reason: format!(
                "value must be at least {} seconds for the configured outbound request timeout",
                minimum.as_secs()
            ),
        });
    }

    Ok(timeout)
}

pub fn parse_http_rate_limit_requests(value: Option<String>) -> Result<u64, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_HTTP_RATE_LIMIT_REQUESTS,
        DEFAULT_HTTP_RATE_LIMIT_REQUESTS,
    )
}

pub fn parse_http_rate_limit_window(value: Option<String>) -> Result<Duration, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_HTTP_RATE_LIMIT_WINDOW_SECONDS,
        DEFAULT_HTTP_RATE_LIMIT_WINDOW_SECONDS,
    )
    .map(Duration::from_secs)
}

pub fn build_outbound_http_client(config: &AppConfig) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .connect_timeout(config.outbound_http_connect_timeout)
        .timeout(config.outbound_http_request_timeout)
        .build()
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

fn parse_non_negative_u64_config(
    value: Option<String>,
    name: &'static str,
    default_value: u64,
) -> Result<u64, ConfigError> {
    let Some(value) = value else {
        return Ok(default_value);
    };

    value
        .parse::<u64>()
        .map_err(|error| ConfigError::InvalidValue {
            name,
            reason: error.to_string(),
        })
}

fn minimum_http_handler_timeout(
    outbound_http_request_timeout: Duration,
) -> Result<Duration, ConfigError> {
    let seconds = outbound_http_request_timeout
        .as_secs()
        .checked_mul(3)
        .and_then(|seconds| seconds.checked_add(15))
        .ok_or_else(|| ConfigError::InvalidValue {
            name: ENV_OUTBOUND_HTTP_REQUEST_TIMEOUT_SECONDS,
            reason: "value is too large".to_owned(),
        })?;

    Ok(Duration::from_secs(seconds))
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

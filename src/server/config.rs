use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::types::{KeyVersion, MasterKey};

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_AUDIT_FALLBACK_PATH: &str = "/var/lib/mipsorcu/audit_fallback.jsonl";
const DEFAULT_AUDIT_RESEND_INTERVAL_SECONDS: u64 = 60;
const DEFAULT_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;

const ENV_LISTEN_ADDR: &str = "MIPSORCU_LISTEN_ADDR";
const ENV_MASTER_KEY: &str = "MIPSORCU_MASTER_KEY";
const ENV_KEY_VERSION: &str = "MIPSORCU_KEY_VERSION";
const ENV_SUPABASE_URL: &str = "MIPSORCU_SUPABASE_URL";
const ENV_SUPABASE_SERVICE_ROLE_KEY: &str = "MIPSORCU_SUPABASE_SERVICE_ROLE_KEY";
const ENV_SUPABASE_PUBLISHABLE_KEY: &str = "MIPSORCU_SUPABASE_PUBLISHABLE_KEY";
const ENV_JWT_ISSUER: &str = "MIPSORCU_JWT_ISSUER";
const ENV_JWT_AUDIENCE: &str = "MIPSORCU_JWT_AUDIENCE";
const ENV_JWKS_JSON: &str = "MIPSORCU_JWKS_JSON";
const ENV_AUDIT_FALLBACK_PATH: &str = "MIPSORCU_AUDIT_FALLBACK_PATH";
const ENV_AUDIT_RESEND_INTERVAL_SECONDS: &str = "MIPSORCU_AUDIT_RESEND_INTERVAL_SECONDS";
const ENV_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES: &str =
    "MIPSORCU_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES";

pub struct AppConfig {
    pub listen_addr: SocketAddr,
    pub master_key: MasterKey,
    pub key_version: KeyVersion,
    pub supabase_url: String,
    pub supabase_service_role_key: String,
    pub supabase_publishable_key: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwks_json: String,
    pub audit_fallback_path: PathBuf,
    pub audit_resend_interval: Duration,
    pub audit_fallback_alert_threshold_bytes: u64,
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
            .field("jwks_json", &"<redacted>")
            .field("audit_fallback_path", &self.audit_fallback_path)
            .field(
                "audit_resend_interval_seconds",
                &self.audit_resend_interval.as_secs(),
            )
            .field(
                "audit_fallback_alert_threshold_bytes",
                &self.audit_fallback_alert_threshold_bytes,
            )
            .finish()
    }
}

#[derive(Debug)]
pub enum ConfigError {
    MissingVar { name: &'static str },
    InvalidValue { name: &'static str, reason: String },
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
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn load_config() -> Result<AppConfig, ConfigError> {
    let listen_addr = optional_var(ENV_LISTEN_ADDR)
        .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_owned())
        .parse::<SocketAddr>()
        .map_err(|error| ConfigError::InvalidValue {
            name: ENV_LISTEN_ADDR,
            reason: error.to_string(),
        })?;

    let master_key_hex = required_var(ENV_MASTER_KEY)?;
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

    let key_version_str = required_var(ENV_KEY_VERSION)?;
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

    let supabase_url = required_var(ENV_SUPABASE_URL)?;
    let supabase_service_role_key = required_var(ENV_SUPABASE_SERVICE_ROLE_KEY)?;
    let supabase_publishable_key = required_var(ENV_SUPABASE_PUBLISHABLE_KEY)?;
    let jwt_issuer = required_var(ENV_JWT_ISSUER)?;
    let jwt_audience = required_var(ENV_JWT_AUDIENCE)?;
    let jwks_json = required_var(ENV_JWKS_JSON)?;

    let audit_fallback_path = PathBuf::from(
        optional_var(ENV_AUDIT_FALLBACK_PATH)
            .unwrap_or_else(|| DEFAULT_AUDIT_FALLBACK_PATH.to_owned()),
    );
    let audit_resend_interval =
        parse_audit_resend_interval(std::env::var(ENV_AUDIT_RESEND_INTERVAL_SECONDS).ok())?;
    let audit_fallback_alert_threshold_bytes = parse_audit_fallback_alert_threshold(
        std::env::var(ENV_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES).ok(),
    )?;

    Ok(AppConfig {
        listen_addr,
        master_key,
        key_version,
        supabase_url,
        supabase_service_role_key,
        supabase_publishable_key,
        jwt_issuer,
        jwt_audience,
        jwks_json,
        audit_fallback_path,
        audit_resend_interval,
        audit_fallback_alert_threshold_bytes,
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

fn required_var(name: &'static str) -> Result<String, ConfigError> {
    let value = std::env::var(name).map_err(|_| ConfigError::MissingVar { name })?;
    if value.trim().is_empty() {
        return Err(ConfigError::InvalidValue {
            name,
            reason: "value must not be empty".to_owned(),
        });
    }
    Ok(value)
}

fn optional_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

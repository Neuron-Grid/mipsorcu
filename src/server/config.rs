use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use mipsorcu::types::{KeyVersion, MasterKey};

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_AUDIT_FALLBACK_PATH: &str = "/var/lib/mipsorcu/audit_fallback.jsonl";
const DEFAULT_AUDIT_RESEND_INTERVAL_SECONDS: u64 = 60;

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
    })
}

fn parse_audit_resend_interval(value: Option<String>) -> Result<Duration, ConfigError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_resend_interval_defaults_to_sixty_seconds() {
        let interval = parse_audit_resend_interval(None).expect("default interval should be valid");

        assert_eq!(interval, Duration::from_secs(60));
    }

    #[test]
    fn audit_resend_interval_accepts_positive_seconds() {
        let interval = parse_audit_resend_interval(Some("30".to_owned()))
            .expect("positive interval should be valid");

        assert_eq!(interval, Duration::from_secs(30));
    }

    #[test]
    fn audit_resend_interval_rejects_zero_empty_and_non_numeric_values() {
        assert!(matches!(
            parse_audit_resend_interval(Some("0".to_owned())),
            Err(ConfigError::InvalidValue { .. })
        ));
        assert!(matches!(
            parse_audit_resend_interval(Some(String::new())),
            Err(ConfigError::InvalidValue { .. })
        ));
        assert!(matches!(
            parse_audit_resend_interval(Some("not-a-number".to_owned())),
            Err(ConfigError::InvalidValue { .. })
        ));
    }
}

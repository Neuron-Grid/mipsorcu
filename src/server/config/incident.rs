//! Incident notification 関連の env 解析。

use std::time::Duration;

use http::Uri;

use crate::types::SecretString;

use super::constants::{
    DEFAULT_INCIDENT_WEBHOOK_REQUEST_TIMEOUT_SECONDS, ENV_INCIDENT_NOTIFIER,
    ENV_INCIDENT_WEBHOOK_REQUEST_TIMEOUT_SECONDS, ENV_INCIDENT_WEBHOOK_SECRET,
    ENV_INCIDENT_WEBHOOK_URL, INCIDENT_WEBHOOK_SECRET_MIN_BYTES,
};
use super::env::{DotenvVars, optional_var};
use super::error::ConfigError;

/// runtime で選択される incident notification sink の種類。
///
/// `MIPSORCU_INCIDENT_NOTIFIER` が `none` または未設定のとき `Disabled`
/// （`DummyNotificationSink` への fallback）。`webhook` のとき URL と secret を
/// 含めて `Webhook` を構築する。
#[derive(Debug, Clone)]
pub enum IncidentNotifierConfig {
    None,
    Dummy,
    Webhook {
        endpoint: String,
        secret: SecretString,
        request_timeout: Duration,
    },
}

impl IncidentNotifierConfig {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Dummy => "dummy",
            Self::Webhook { .. } => "webhook",
        }
    }
}

pub fn parse_incident_notifier_config<F>(
    dotenv: &DotenvVars,
    get_process_var: &F,
) -> Result<IncidentNotifierConfig, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let notifier = optional_var(ENV_INCIDENT_NOTIFIER, dotenv, get_process_var)
        .map(|value| value.trim().to_ascii_lowercase());
    match notifier.as_deref() {
        None | Some("none") | Some("") => Ok(IncidentNotifierConfig::None),
        Some("dummy") => Ok(IncidentNotifierConfig::Dummy),
        Some("webhook") => {
            let endpoint = optional_var(ENV_INCIDENT_WEBHOOK_URL, dotenv, get_process_var).ok_or(
                ConfigError::InvalidValue {
                    name: ENV_INCIDENT_WEBHOOK_URL,
                    reason: "must be set when MIPSORCU_INCIDENT_NOTIFIER=webhook".to_owned(),
                },
            )?;
            let secret_str = optional_var(ENV_INCIDENT_WEBHOOK_SECRET, dotenv, get_process_var)
                .ok_or(ConfigError::InvalidValue {
                    name: ENV_INCIDENT_WEBHOOK_SECRET,
                    reason: "must be set when MIPSORCU_INCIDENT_NOTIFIER=webhook".to_owned(),
                })?;
            let secret =
                SecretString::new(&secret_str).map_err(|error| ConfigError::InvalidValue {
                    name: ENV_INCIDENT_WEBHOOK_SECRET,
                    reason: error.to_string(),
                })?;
            if secret.len() < INCIDENT_WEBHOOK_SECRET_MIN_BYTES {
                return Err(ConfigError::InvalidValue {
                    name: ENV_INCIDENT_WEBHOOK_SECRET,
                    reason: format!(
                        "secret must be at least {INCIDENT_WEBHOOK_SECRET_MIN_BYTES} bytes",
                    ),
                });
            }
            validate_webhook_endpoint(&endpoint)?;
            let request_timeout = parse_incident_webhook_request_timeout(optional_var(
                ENV_INCIDENT_WEBHOOK_REQUEST_TIMEOUT_SECONDS,
                dotenv,
                get_process_var,
            ))?;
            Ok(IncidentNotifierConfig::Webhook {
                endpoint,
                secret,
                request_timeout,
            })
        }
        Some(other) => Err(ConfigError::InvalidValue {
            name: ENV_INCIDENT_NOTIFIER,
            reason: format!("unknown notifier '{other}'; expected none|dummy|webhook"),
        }),
    }
}

pub fn parse_incident_webhook_request_timeout(
    value: Option<String>,
) -> Result<Duration, ConfigError> {
    let seconds = match value {
        Some(value) => value
            .trim()
            .parse::<u64>()
            .map_err(|error| ConfigError::InvalidValue {
                name: ENV_INCIDENT_WEBHOOK_REQUEST_TIMEOUT_SECONDS,
                reason: error.to_string(),
            })?,
        None => DEFAULT_INCIDENT_WEBHOOK_REQUEST_TIMEOUT_SECONDS,
    };
    if seconds == 0 || seconds > 30 {
        return Err(ConfigError::InvalidValue {
            name: ENV_INCIDENT_WEBHOOK_REQUEST_TIMEOUT_SECONDS,
            reason: "must be between 1 and 30 seconds".to_owned(),
        });
    }
    Ok(Duration::from_secs(seconds))
}

fn validate_webhook_endpoint(endpoint: &str) -> Result<(), ConfigError> {
    let url = endpoint
        .parse::<Uri>()
        .map_err(|error| ConfigError::InvalidValue {
            name: ENV_INCIDENT_WEBHOOK_URL,
            reason: error.to_string(),
        })?;
    match url.scheme_str() {
        Some("https") => Ok(()),
        Some("http") if is_local_http_endpoint(&url) => Ok(()),
        Some("http") => Err(ConfigError::InvalidValue {
            name: ENV_INCIDENT_WEBHOOK_URL,
            reason: "http is allowed only for localhost, 127.0.0.1, or [::1]".to_owned(),
        }),
        _ => Err(ConfigError::InvalidValue {
            name: ENV_INCIDENT_WEBHOOK_URL,
            reason: "scheme must be https, or local http for tests".to_owned(),
        }),
    }
}

fn is_local_http_endpoint(url: &Uri) -> bool {
    let Some(authority) = url.authority().map(|authority| authority.as_str()) else {
        return false;
    };
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        match rest.split_once(']') {
            Some((host, _rest)) => host,
            None => return false,
        }
    } else {
        host_port
            .split_once(':')
            .map_or(host_port, |(host, _port)| host)
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

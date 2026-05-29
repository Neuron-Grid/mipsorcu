//! Incident notification 関連の env 解析。

use crate::types::SecretString;

use super::constants::{
    ENV_INCIDENT_NOTIFIER, ENV_INCIDENT_WEBHOOK_SECRET, ENV_INCIDENT_WEBHOOK_URL,
    INCIDENT_WEBHOOK_SECRET_MIN_BYTES,
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
    Disabled,
    Webhook {
        endpoint: String,
        secret: SecretString,
    },
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
        None | Some("none") | Some("") | Some("dummy") => Ok(IncidentNotifierConfig::Disabled),
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
            Ok(IncidentNotifierConfig::Webhook { endpoint, secret })
        }
        Some(other) => Err(ConfigError::InvalidValue {
            name: ENV_INCIDENT_NOTIFIER,
            reason: format!("unknown notifier '{other}'; expected none|dummy|webhook"),
        }),
    }
}

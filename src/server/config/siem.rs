use std::time::Duration;

use crate::types::SecretString;

use super::constants::{
    DEFAULT_SIEM_BUFFER_MAX_BYTES, DEFAULT_SIEM_LONG_FAILURE_THRESHOLD_SECONDS,
    DEFAULT_SIEM_RESEND_INTERVAL_SECONDS, ENV_SIEM_BUFFER_MAX_BYTES, ENV_SIEM_EXPORTER,
    ENV_SIEM_LONG_FAILURE_THRESHOLD_SECONDS, ENV_SIEM_OTLP_AUTH_TOKEN, ENV_SIEM_OTLP_ENDPOINT,
    ENV_SIEM_RESEND_INTERVAL_SECONDS, ENV_SIEM_SPLUNK_HEC_TOKEN, ENV_SIEM_SPLUNK_HEC_URL,
    SIEM_BUFFER_MAX_BYTES_LIMIT,
};
use super::env::{DotenvVars, optional_var};
use super::error::ConfigError;
use super::parse::parse_positive_u64_config;

pub fn parse_siem_resend_interval(value: Option<String>) -> Result<Duration, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_SIEM_RESEND_INTERVAL_SECONDS,
        DEFAULT_SIEM_RESEND_INTERVAL_SECONDS,
    )
    .map(Duration::from_secs)
}

pub fn parse_siem_long_failure_threshold(value: Option<String>) -> Result<Duration, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_SIEM_LONG_FAILURE_THRESHOLD_SECONDS,
        DEFAULT_SIEM_LONG_FAILURE_THRESHOLD_SECONDS,
    )
    .map(Duration::from_secs)
}

pub fn parse_siem_buffer_max_bytes(value: Option<String>) -> Result<u64, ConfigError> {
    let parsed = parse_positive_u64_config(
        value,
        ENV_SIEM_BUFFER_MAX_BYTES,
        DEFAULT_SIEM_BUFFER_MAX_BYTES,
    )?;
    if parsed > SIEM_BUFFER_MAX_BYTES_LIMIT {
        return Err(ConfigError::InvalidValue {
            name: ENV_SIEM_BUFFER_MAX_BYTES,
            reason: format!("value must be <= {SIEM_BUFFER_MAX_BYTES_LIMIT}"),
        });
    }
    Ok(parsed)
}

/// runtime で選択される SIEM exporter の種類。
///
/// `MIPSORCU_SIEM_EXPORTER` が `none` のとき `Disabled`、`otlp` のとき OTLP、
/// `splunk_hec` のとき Splunk HEC を組み立てる。`Disabled` は `InMemorySiemSink`
/// に fallback する（buffer ファイルのみが残り、外部 SIEM へ送信しない）。
#[derive(Debug, Clone)]
pub enum SiemExporterConfig {
    Disabled,
    Otlp {
        endpoint: String,
        auth_token: Option<SecretString>,
    },
    SplunkHec {
        endpoint: String,
        token: SecretString,
    },
}

/// `MIPSORCU_SIEM_*` 系の env を読み取り、排他バリデーション後の構成を返す。
///
/// otlp 選択時は `MIPSORCU_SIEM_OTLP_ENDPOINT` が必須。
/// splunk_hec 選択時は `MIPSORCU_SIEM_SPLUNK_HEC_URL` と
/// `MIPSORCU_SIEM_SPLUNK_HEC_TOKEN` が必須。
pub fn parse_siem_exporter_config<F>(
    dotenv: &DotenvVars,
    get_process_var: &F,
) -> Result<SiemExporterConfig, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let exporter = optional_var(ENV_SIEM_EXPORTER, dotenv, get_process_var)
        .map(|value| value.trim().to_ascii_lowercase());
    match exporter.as_deref() {
        None | Some("none") | Some("") => Ok(SiemExporterConfig::Disabled),
        Some("otlp") => {
            let endpoint = optional_var(ENV_SIEM_OTLP_ENDPOINT, dotenv, get_process_var).ok_or(
                ConfigError::InvalidValue {
                    name: ENV_SIEM_OTLP_ENDPOINT,
                    reason: "must be set when MIPSORCU_SIEM_EXPORTER=otlp".to_owned(),
                },
            )?;
            let auth_token = optional_var(ENV_SIEM_OTLP_AUTH_TOKEN, dotenv, get_process_var)
                .map(|value| {
                    SecretString::new(&value).map_err(|error| ConfigError::InvalidValue {
                        name: ENV_SIEM_OTLP_AUTH_TOKEN,
                        reason: error.to_string(),
                    })
                })
                .transpose()?;
            Ok(SiemExporterConfig::Otlp {
                endpoint,
                auth_token,
            })
        }
        Some("splunk_hec") => {
            let endpoint = optional_var(ENV_SIEM_SPLUNK_HEC_URL, dotenv, get_process_var).ok_or(
                ConfigError::InvalidValue {
                    name: ENV_SIEM_SPLUNK_HEC_URL,
                    reason: "must be set when MIPSORCU_SIEM_EXPORTER=splunk_hec".to_owned(),
                },
            )?;
            let token_str = optional_var(ENV_SIEM_SPLUNK_HEC_TOKEN, dotenv, get_process_var)
                .ok_or(ConfigError::InvalidValue {
                    name: ENV_SIEM_SPLUNK_HEC_TOKEN,
                    reason: "must be set when MIPSORCU_SIEM_EXPORTER=splunk_hec".to_owned(),
                })?;
            let token =
                SecretString::new(&token_str).map_err(|error| ConfigError::InvalidValue {
                    name: ENV_SIEM_SPLUNK_HEC_TOKEN,
                    reason: error.to_string(),
                })?;
            Ok(SiemExporterConfig::SplunkHec { endpoint, token })
        }
        Some(other) => Err(ConfigError::InvalidValue {
            name: ENV_SIEM_EXPORTER,
            reason: format!("unknown SIEM exporter '{other}'; expected none|otlp|splunk_hec"),
        }),
    }
}

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::constants::{
    DEFAULT_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES, DEFAULT_AUDIT_FALLBACK_ARCHIVE_RETENTION_DAYS,
    DEFAULT_AUDIT_FALLBACK_ROTATE_SIZE_BYTES, DEFAULT_AUDIT_RESEND_INTERVAL_SECONDS,
    ENV_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES, ENV_AUDIT_FALLBACK_ARCHIVE_AUTO_DELETE_ENABLED,
    ENV_AUDIT_FALLBACK_ARCHIVE_RETENTION_DAYS, ENV_AUDIT_FALLBACK_ROTATE_SIZE_BYTES,
    ENV_AUDIT_RESEND_INTERVAL_SECONDS, SECONDS_PER_DAY,
};
use super::error::ConfigError;
use super::parse::parse_positive_u64_config;

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

pub(super) fn default_audit_fallback_archive_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("archive")
}

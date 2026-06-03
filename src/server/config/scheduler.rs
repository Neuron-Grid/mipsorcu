use std::time::Duration;

use super::constants::{
    DEFAULT_SCHEDULER_DAILY_HOUR_UTC, DEFAULT_SCHEDULER_ENVELOPE_MIGRATION_BATCH_SIZE,
    DEFAULT_SCHEDULER_ENVELOPE_MIGRATION_MAX_BATCHES, DEFAULT_SCHEDULER_MONTHLY_DAY,
    DEFAULT_SCHEDULER_MONTHLY_HOUR_UTC, DEFAULT_SCHEDULER_POLL_INTERVAL_SECONDS,
    DEFAULT_SCHEDULER_QUARTERLY_HOUR_UTC, DEFAULT_SCHEDULER_STARTUP_DELAY_SECONDS,
    ENV_SCHEDULER_DAILY_HOUR_UTC, ENV_SCHEDULER_ENABLED,
    ENV_SCHEDULER_ENVELOPE_MIGRATION_BATCH_SIZE, ENV_SCHEDULER_ENVELOPE_MIGRATION_MAX_BATCHES,
    ENV_SCHEDULER_MONTHLY_DAY, ENV_SCHEDULER_MONTHLY_HOUR_UTC, ENV_SCHEDULER_POLL_INTERVAL_SECONDS,
    ENV_SCHEDULER_QUARTERLY_HOUR_UTC, ENV_SCHEDULER_STARTUP_DELAY_SECONDS,
    SCHEDULER_ENVELOPE_MIGRATION_BATCH_SIZE_MAX,
};
use super::error::ConfigError;
use super::parse::{parse_non_negative_u64_config, parse_positive_u64_config};

pub fn parse_scheduler_enabled(value: Option<String>) -> Result<bool, ConfigError> {
    let Some(value) = value else {
        return Ok(false);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(ConfigError::InvalidValue {
            name: ENV_SCHEDULER_ENABLED,
            reason: "value must be true or false".to_owned(),
        }),
    }
}

pub fn scheduler_startup_delay_value(
    seconds_value: Option<String>,
    legacy_sec_value: Option<String>,
) -> Option<String> {
    seconds_value.or(legacy_sec_value)
}

pub fn parse_scheduler_startup_delay(value: Option<String>) -> Result<Duration, ConfigError> {
    parse_non_negative_u64_config(
        value,
        ENV_SCHEDULER_STARTUP_DELAY_SECONDS,
        DEFAULT_SCHEDULER_STARTUP_DELAY_SECONDS,
    )
    .map(Duration::from_secs)
}

pub fn parse_scheduler_poll_interval(value: Option<String>) -> Result<Duration, ConfigError> {
    parse_positive_u64_config(
        value,
        ENV_SCHEDULER_POLL_INTERVAL_SECONDS,
        DEFAULT_SCHEDULER_POLL_INTERVAL_SECONDS,
    )
    .map(Duration::from_secs)
}

pub fn parse_scheduler_monthly_day(value: Option<String>) -> Result<u8, ConfigError> {
    parse_u8_range(
        value,
        ENV_SCHEDULER_MONTHLY_DAY,
        DEFAULT_SCHEDULER_MONTHLY_DAY,
        1,
        28,
    )
}

pub fn parse_scheduler_monthly_hour_utc(value: Option<String>) -> Result<u8, ConfigError> {
    parse_u8_range(
        value,
        ENV_SCHEDULER_MONTHLY_HOUR_UTC,
        DEFAULT_SCHEDULER_MONTHLY_HOUR_UTC,
        0,
        23,
    )
}

pub fn parse_scheduler_quarterly_hour_utc(value: Option<String>) -> Result<u8, ConfigError> {
    parse_u8_range(
        value,
        ENV_SCHEDULER_QUARTERLY_HOUR_UTC,
        DEFAULT_SCHEDULER_QUARTERLY_HOUR_UTC,
        0,
        23,
    )
}

pub fn parse_scheduler_daily_hour_utc(value: Option<String>) -> Result<u8, ConfigError> {
    parse_u8_range(
        value,
        ENV_SCHEDULER_DAILY_HOUR_UTC,
        DEFAULT_SCHEDULER_DAILY_HOUR_UTC,
        0,
        23,
    )
}

pub fn parse_scheduler_envelope_migration_batch_size(
    value: Option<String>,
) -> Result<u32, ConfigError> {
    parse_u32_range(
        value,
        ENV_SCHEDULER_ENVELOPE_MIGRATION_BATCH_SIZE,
        DEFAULT_SCHEDULER_ENVELOPE_MIGRATION_BATCH_SIZE,
        1,
        SCHEDULER_ENVELOPE_MIGRATION_BATCH_SIZE_MAX,
    )
}

pub fn parse_scheduler_envelope_migration_max_batches(
    value: Option<String>,
) -> Result<u32, ConfigError> {
    parse_u32_range(
        value,
        ENV_SCHEDULER_ENVELOPE_MIGRATION_MAX_BATCHES,
        DEFAULT_SCHEDULER_ENVELOPE_MIGRATION_MAX_BATCHES,
        1,
        u32::MAX,
    )
}

fn parse_u8_range(
    value: Option<String>,
    name: &'static str,
    default_value: u8,
    min: u8,
    max: u8,
) -> Result<u8, ConfigError> {
    let Some(value) = value else {
        return Ok(default_value);
    };
    let parsed = value
        .parse::<u8>()
        .map_err(|error| ConfigError::InvalidValue {
            name,
            reason: error.to_string(),
        })?;
    if parsed < min || parsed > max {
        return Err(ConfigError::InvalidValue {
            name,
            reason: format!("value must be between {min} and {max}"),
        });
    }
    Ok(parsed)
}

fn parse_u32_range(
    value: Option<String>,
    name: &'static str,
    default_value: u32,
    min: u32,
    max: u32,
) -> Result<u32, ConfigError> {
    let Some(value) = value else {
        return Ok(default_value);
    };
    let parsed = value
        .parse::<u32>()
        .map_err(|error| ConfigError::InvalidValue {
            name,
            reason: error.to_string(),
        })?;
    if parsed < min || parsed > max {
        return Err(ConfigError::InvalidValue {
            name,
            reason: format!("value must be between {min} and {max}"),
        });
    }
    Ok(parsed)
}

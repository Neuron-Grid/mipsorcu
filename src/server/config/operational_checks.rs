use std::time::Duration;

use super::constants::{
    DEFAULT_INTEGRITY_CHECK_INTERVAL_SECONDS, DEFAULT_INTEGRITY_CHECK_STARTUP_DELAY_SECONDS,
    DEFAULT_RESTORE_TEST_INTERVAL_SECONDS, DEFAULT_RESTORE_TEST_SAMPLE_LIMIT,
    DEFAULT_RESTORE_TEST_STARTUP_DELAY_SECONDS, ENV_INTEGRITY_CHECK_INTERVAL_SECONDS,
    ENV_INTEGRITY_CHECK_STARTUP_DELAY_SECONDS, ENV_RESTORE_TEST_INTERVAL_SECONDS,
    ENV_RESTORE_TEST_SAMPLE_LIMIT, ENV_RESTORE_TEST_STARTUP_DELAY_SECONDS,
};
use super::error::ConfigError;
use super::parse::{parse_non_negative_u64_config, parse_positive_u64_config};

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

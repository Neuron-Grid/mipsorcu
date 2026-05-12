use std::time::Duration;

use super::constants::{
    DEFAULT_SIEM_LONG_FAILURE_THRESHOLD_SECONDS, DEFAULT_SIEM_RESEND_INTERVAL_SECONDS,
    ENV_SIEM_LONG_FAILURE_THRESHOLD_SECONDS, ENV_SIEM_RESEND_INTERVAL_SECONDS,
};
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

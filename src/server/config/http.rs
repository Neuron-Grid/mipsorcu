use std::time::Duration;

use super::constants::{
    DEFAULT_HEALTH_READINESS_POLL_INTERVAL_SECONDS, DEFAULT_HTTP_HANDLER_TIMEOUT_SECONDS,
    DEFAULT_HTTP_RATE_LIMIT_REQUESTS, DEFAULT_HTTP_RATE_LIMIT_WINDOW_SECONDS,
    DEFAULT_JWKS_REFRESH_INTERVAL_SECONDS, DEFAULT_OUTBOUND_HTTP_CONNECT_TIMEOUT_SECONDS,
    DEFAULT_OUTBOUND_HTTP_REQUEST_TIMEOUT_SECONDS, ENV_HEALTH_READINESS_POLL_INTERVAL_SECONDS,
    ENV_HTTP_HANDLER_TIMEOUT_SECONDS, ENV_HTTP_RATE_LIMIT_REQUESTS,
    ENV_HTTP_RATE_LIMIT_WINDOW_SECONDS, ENV_JWKS_REFRESH_INTERVAL_SECONDS,
    ENV_OUTBOUND_HTTP_CONNECT_TIMEOUT_SECONDS, ENV_OUTBOUND_HTTP_REQUEST_TIMEOUT_SECONDS,
};
use super::error::ConfigError;
use super::model::AppConfig;
use super::parse::parse_positive_u64_config;

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

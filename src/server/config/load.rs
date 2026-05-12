use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use super::audit_fallback::{
    default_audit_fallback_archive_dir, parse_audit_fallback_alert_threshold,
    parse_audit_fallback_archive_auto_delete_enabled, parse_audit_fallback_archive_retention_days,
    parse_audit_fallback_rotate_size, parse_audit_resend_interval,
};
use super::constants::{
    DEFAULT_AUDIT_FALLBACK_PATH, DEFAULT_DOTENV_PATH, DEFAULT_LISTEN_ADDR,
    DEFAULT_SCHEDULER_LOCAL_ARCHIVE_DIR, DEFAULT_SIEM_BUFFER_PATH,
    ENV_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES, ENV_AUDIT_FALLBACK_ARCHIVE_AUTO_DELETE_ENABLED,
    ENV_AUDIT_FALLBACK_ARCHIVE_DIR, ENV_AUDIT_FALLBACK_ARCHIVE_RETENTION_DAYS,
    ENV_AUDIT_FALLBACK_PATH, ENV_AUDIT_FALLBACK_ROTATE_SIZE_BYTES,
    ENV_AUDIT_RESEND_INTERVAL_SECONDS, ENV_HEALTH_READINESS_POLL_INTERVAL_SECONDS,
    ENV_HTTP_HANDLER_TIMEOUT_SECONDS, ENV_HTTP_RATE_LIMIT_REQUESTS,
    ENV_HTTP_RATE_LIMIT_WINDOW_SECONDS, ENV_INTEGRITY_CHECK_INTERVAL_SECONDS,
    ENV_INTEGRITY_CHECK_STARTUP_DELAY_SECONDS, ENV_JWKS_REFRESH_INTERVAL_SECONDS, ENV_JWKS_URL,
    ENV_JWT_AUDIENCE, ENV_JWT_ISSUER, ENV_LISTEN_ADDR, ENV_OUTBOUND_HTTP_CONNECT_TIMEOUT_SECONDS,
    ENV_OUTBOUND_HTTP_REQUEST_TIMEOUT_SECONDS, ENV_RESTORE_TEST_INTERVAL_SECONDS,
    ENV_RESTORE_TEST_SAMPLE_LIMIT, ENV_RESTORE_TEST_STARTUP_DELAY_SECONDS, ENV_SCHEDULER_ENABLED,
    ENV_SCHEDULER_LOCAL_ARCHIVE_DIR, ENV_SCHEDULER_MONTHLY_DAY, ENV_SCHEDULER_MONTHLY_HOUR_UTC,
    ENV_SCHEDULER_POLL_INTERVAL_SECONDS, ENV_SCHEDULER_QUARTERLY_HOUR_UTC,
    ENV_SCHEDULER_STARTUP_DELAY_SECONDS, ENV_SIEM_BUFFER_PATH,
    ENV_SIEM_LONG_FAILURE_THRESHOLD_SECONDS, ENV_SIEM_RESEND_INTERVAL_SECONDS,
    ENV_SUPABASE_PUBLISHABLE_KEY, ENV_SUPABASE_SERVICE_ROLE_KEY, ENV_SUPABASE_URL,
};
use super::env::{DotenvVars, current_process_var, load_dotenv_file, optional_var, required_var};
use super::error::ConfigError;
use super::http::{
    parse_health_readiness_poll_interval, parse_http_handler_timeout,
    parse_http_rate_limit_requests, parse_http_rate_limit_window, parse_jwks_refresh_interval,
    parse_outbound_http_connect_timeout, parse_outbound_http_request_timeout,
};
use super::keyring::load_master_key_ring;
use super::ledger_signing::load_ledger_signing_key;
use super::model::AppConfig;
use super::operational_checks::{
    parse_integrity_check_interval, parse_integrity_check_startup_delay,
    parse_restore_test_interval, parse_restore_test_sample_limit, parse_restore_test_startup_delay,
};
use super::scheduler::{
    parse_scheduler_enabled, parse_scheduler_monthly_day, parse_scheduler_monthly_hour_utc,
    parse_scheduler_poll_interval, parse_scheduler_quarterly_hour_utc,
    parse_scheduler_startup_delay,
};
use super::siem::{parse_siem_long_failure_threshold, parse_siem_resend_interval};

pub fn load_config() -> Result<AppConfig, ConfigError> {
    let dotenv = load_dotenv_file(Path::new(DEFAULT_DOTENV_PATH))?;
    load_config_from_sources(&current_process_var, &dotenv)
}

#[doc(hidden)]
pub fn load_config_from_sources<F>(
    get_process_var: &F,
    dotenv: &DotenvVars,
) -> Result<AppConfig, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let listen_addr = optional_var(ENV_LISTEN_ADDR, dotenv, get_process_var)
        .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_owned())
        .parse::<SocketAddr>()
        .map_err(|error| ConfigError::InvalidValue {
            name: ENV_LISTEN_ADDR,
            reason: error.to_string(),
        })?;

    let master_key_ring = load_master_key_ring(dotenv, get_process_var)?;

    let supabase_url = required_var(ENV_SUPABASE_URL, dotenv, get_process_var)?;
    let supabase_service_role_key =
        required_var(ENV_SUPABASE_SERVICE_ROLE_KEY, dotenv, get_process_var)?;
    let supabase_publishable_key =
        required_var(ENV_SUPABASE_PUBLISHABLE_KEY, dotenv, get_process_var)?;
    let ledger_signing_key = load_ledger_signing_key(dotenv, get_process_var)?;
    let jwt_issuer = required_var(ENV_JWT_ISSUER, dotenv, get_process_var)?;
    let jwt_audience = required_var(ENV_JWT_AUDIENCE, dotenv, get_process_var)?;
    let jwks_url = required_var(ENV_JWKS_URL, dotenv, get_process_var)?;
    let jwks_refresh_interval = parse_jwks_refresh_interval(optional_var(
        ENV_JWKS_REFRESH_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let health_readiness_poll_interval = parse_health_readiness_poll_interval(optional_var(
        ENV_HEALTH_READINESS_POLL_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let outbound_http_connect_timeout = parse_outbound_http_connect_timeout(optional_var(
        ENV_OUTBOUND_HTTP_CONNECT_TIMEOUT_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let outbound_http_request_timeout = parse_outbound_http_request_timeout(optional_var(
        ENV_OUTBOUND_HTTP_REQUEST_TIMEOUT_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let http_handler_timeout = parse_http_handler_timeout(
        optional_var(ENV_HTTP_HANDLER_TIMEOUT_SECONDS, dotenv, get_process_var),
        outbound_http_request_timeout,
    )?;
    let http_rate_limit_requests = parse_http_rate_limit_requests(optional_var(
        ENV_HTTP_RATE_LIMIT_REQUESTS,
        dotenv,
        get_process_var,
    ))?;
    let http_rate_limit_window = parse_http_rate_limit_window(optional_var(
        ENV_HTTP_RATE_LIMIT_WINDOW_SECONDS,
        dotenv,
        get_process_var,
    ))?;

    let audit_fallback_path = PathBuf::from(
        optional_var(ENV_AUDIT_FALLBACK_PATH, dotenv, get_process_var)
            .unwrap_or_else(|| DEFAULT_AUDIT_FALLBACK_PATH.to_owned()),
    );
    let siem_buffer_path = PathBuf::from(
        optional_var(ENV_SIEM_BUFFER_PATH, dotenv, get_process_var)
            .unwrap_or_else(|| DEFAULT_SIEM_BUFFER_PATH.to_owned()),
    );
    let audit_fallback_archive_dir =
        optional_var(ENV_AUDIT_FALLBACK_ARCHIVE_DIR, dotenv, get_process_var)
            .map(PathBuf::from)
            .unwrap_or_else(|| default_audit_fallback_archive_dir(&audit_fallback_path));
    let audit_resend_interval = parse_audit_resend_interval(optional_var(
        ENV_AUDIT_RESEND_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let siem_resend_interval = parse_siem_resend_interval(optional_var(
        ENV_SIEM_RESEND_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let siem_long_failure_threshold = parse_siem_long_failure_threshold(optional_var(
        ENV_SIEM_LONG_FAILURE_THRESHOLD_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let audit_fallback_alert_threshold_bytes = parse_audit_fallback_alert_threshold(optional_var(
        ENV_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES,
        dotenv,
        get_process_var,
    ))?;
    let audit_fallback_rotate_size_bytes = parse_audit_fallback_rotate_size(optional_var(
        ENV_AUDIT_FALLBACK_ROTATE_SIZE_BYTES,
        dotenv,
        get_process_var,
    ))?;
    let audit_fallback_archive_auto_delete_enabled =
        parse_audit_fallback_archive_auto_delete_enabled(optional_var(
            ENV_AUDIT_FALLBACK_ARCHIVE_AUTO_DELETE_ENABLED,
            dotenv,
            get_process_var,
        ))?;
    let audit_fallback_archive_retention =
        parse_audit_fallback_archive_retention_days(optional_var(
            ENV_AUDIT_FALLBACK_ARCHIVE_RETENTION_DAYS,
            dotenv,
            get_process_var,
        ))?;
    let restore_test_interval = parse_restore_test_interval(optional_var(
        ENV_RESTORE_TEST_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let restore_test_startup_delay = parse_restore_test_startup_delay(optional_var(
        ENV_RESTORE_TEST_STARTUP_DELAY_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let restore_test_sample_limit = parse_restore_test_sample_limit(optional_var(
        ENV_RESTORE_TEST_SAMPLE_LIMIT,
        dotenv,
        get_process_var,
    ))?;
    let integrity_check_interval = parse_integrity_check_interval(optional_var(
        ENV_INTEGRITY_CHECK_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let integrity_check_startup_delay = parse_integrity_check_startup_delay(optional_var(
        ENV_INTEGRITY_CHECK_STARTUP_DELAY_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let scheduler_enabled =
        parse_scheduler_enabled(optional_var(ENV_SCHEDULER_ENABLED, dotenv, get_process_var))?;
    let scheduler_startup_delay = parse_scheduler_startup_delay(optional_var(
        ENV_SCHEDULER_STARTUP_DELAY_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let scheduler_poll_interval = parse_scheduler_poll_interval(optional_var(
        ENV_SCHEDULER_POLL_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let scheduler_monthly_day = parse_scheduler_monthly_day(optional_var(
        ENV_SCHEDULER_MONTHLY_DAY,
        dotenv,
        get_process_var,
    ))?;
    let scheduler_monthly_hour_utc = parse_scheduler_monthly_hour_utc(optional_var(
        ENV_SCHEDULER_MONTHLY_HOUR_UTC,
        dotenv,
        get_process_var,
    ))?;
    let scheduler_quarterly_hour_utc = parse_scheduler_quarterly_hour_utc(optional_var(
        ENV_SCHEDULER_QUARTERLY_HOUR_UTC,
        dotenv,
        get_process_var,
    ))?;
    let scheduler_local_archive_dir = PathBuf::from(
        optional_var(ENV_SCHEDULER_LOCAL_ARCHIVE_DIR, dotenv, get_process_var)
            .unwrap_or_else(|| DEFAULT_SCHEDULER_LOCAL_ARCHIVE_DIR.to_owned()),
    );

    Ok(AppConfig {
        listen_addr,
        master_key_ring,
        supabase_url,
        supabase_service_role_key,
        supabase_publishable_key,
        ledger_signing_key,
        jwt_issuer,
        jwt_audience,
        jwks_url,
        jwks_refresh_interval,
        health_readiness_poll_interval,
        outbound_http_connect_timeout,
        outbound_http_request_timeout,
        http_handler_timeout,
        http_rate_limit_requests,
        http_rate_limit_window,
        audit_fallback_path,
        siem_buffer_path,
        audit_resend_interval,
        siem_resend_interval,
        siem_long_failure_threshold,
        audit_fallback_alert_threshold_bytes,
        audit_fallback_rotate_size_bytes,
        audit_fallback_archive_dir,
        audit_fallback_archive_auto_delete_enabled,
        audit_fallback_archive_retention,
        restore_test_interval,
        restore_test_startup_delay,
        restore_test_sample_limit,
        integrity_check_interval,
        integrity_check_startup_delay,
        scheduler_enabled,
        scheduler_startup_delay,
        scheduler_poll_interval,
        scheduler_monthly_day,
        scheduler_monthly_hour_utc,
        scheduler_quarterly_hour_utc,
        scheduler_local_archive_dir,
    })
}

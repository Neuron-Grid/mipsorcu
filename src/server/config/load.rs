use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::audit_fallback::{
    default_audit_fallback_archive_dir, parse_audit_fallback_alert_threshold,
    parse_audit_fallback_archive_auto_delete_enabled, parse_audit_fallback_archive_retention_days,
    parse_audit_fallback_rotate_size, parse_audit_resend_interval,
};
use super::constants::{
    DEFAULT_AUDIT_FALLBACK_PATH, DEFAULT_DOTENV_PATH, DEFAULT_LISTEN_ADDR,
    DEFAULT_SCHEDULER_LOCAL_ARCHIVE_DIR, DEFAULT_SIEM_BUFFER_PATH, ENV_ALIAS_ENCRYPTION_KEY,
    ENV_ALIAS_ENCRYPTION_KEY_VERSION, ENV_ALIAS_FINGERPRINT_KEY, ENV_ALIAS_FINGERPRINT_KEY_VERSION,
    ENV_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES, ENV_AUDIT_FALLBACK_ARCHIVE_AUTO_DELETE_ENABLED,
    ENV_AUDIT_FALLBACK_ARCHIVE_DIR, ENV_AUDIT_FALLBACK_ARCHIVE_RETENTION_DAYS,
    ENV_AUDIT_FALLBACK_PATH, ENV_AUDIT_FALLBACK_ROTATE_SIZE_BYTES,
    ENV_AUDIT_RESEND_INTERVAL_SECONDS, ENV_HEALTH_READINESS_POLL_INTERVAL_SECONDS,
    ENV_HTTP_HANDLER_TIMEOUT_SECONDS, ENV_HTTP_RATE_LIMIT_REQUESTS,
    ENV_HTTP_RATE_LIMIT_WINDOW_SECONDS, ENV_INTEGRITY_CHECK_INTERVAL_SECONDS,
    ENV_INTEGRITY_CHECK_STARTUP_DELAY_SECONDS, ENV_JWKS_REFRESH_INTERVAL_SECONDS, ENV_JWKS_URL,
    ENV_JWT_AUDIENCE, ENV_JWT_ISSUER, ENV_LISTEN_ADDR, ENV_OUTBOUND_HTTP_CONNECT_TIMEOUT_SECONDS,
    ENV_OUTBOUND_HTTP_REQUEST_TIMEOUT_SECONDS, ENV_RESTORE_TEST_INTERVAL_SECONDS,
    ENV_RESTORE_TEST_SAMPLE_LIMIT, ENV_RESTORE_TEST_STARTUP_DELAY_SECONDS,
    ENV_SCHEDULER_DAILY_HOUR_UTC, ENV_SCHEDULER_ENABLED,
    ENV_SCHEDULER_ENVELOPE_MIGRATION_BATCH_SIZE, ENV_SCHEDULER_ENVELOPE_MIGRATION_MAX_BATCHES,
    ENV_SCHEDULER_LOCAL_ARCHIVE_DIR, ENV_SCHEDULER_MONTHLY_DAY, ENV_SCHEDULER_MONTHLY_HOUR_UTC,
    ENV_SCHEDULER_POLL_INTERVAL_SECONDS, ENV_SCHEDULER_QUARTERLY_HOUR_UTC,
    ENV_SCHEDULER_STARTUP_DELAY_SEC, ENV_SCHEDULER_STARTUP_DELAY_SECONDS, ENV_SIEM_BUFFER_PATH,
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
use super::keyring::{load_master_key_ring, parse_fixed_length_key_hex, parse_key_version_config};
use super::ledger_signing::load_ledger_signing_key;
use super::model::AppConfig;
use super::operational_checks::{
    parse_integrity_check_interval, parse_integrity_check_startup_delay,
    parse_restore_test_interval, parse_restore_test_sample_limit, parse_restore_test_startup_delay,
};
use super::scheduler::{
    parse_scheduler_daily_hour_utc, parse_scheduler_enabled,
    parse_scheduler_envelope_migration_batch_size, parse_scheduler_envelope_migration_max_batches,
    parse_scheduler_monthly_day, parse_scheduler_monthly_hour_utc, parse_scheduler_poll_interval,
    parse_scheduler_quarterly_hour_utc, parse_scheduler_startup_delay,
    scheduler_startup_delay_value,
};
use super::siem::SiemExporterConfig;
use super::siem::{
    parse_siem_exporter_config, parse_siem_long_failure_threshold, parse_siem_resend_interval,
};
use crate::{AliasEncryptionKey, AliasFingerprintKey, KeyVersion};

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
    let alias_keys = load_alias_keys(dotenv, get_process_var)?;

    let supabase_url = required_var(ENV_SUPABASE_URL, dotenv, get_process_var)?;
    let supabase_service_role_key =
        required_var(ENV_SUPABASE_SERVICE_ROLE_KEY, dotenv, get_process_var)?;
    let supabase_publishable_key =
        required_var(ENV_SUPABASE_PUBLISHABLE_KEY, dotenv, get_process_var)?;
    let ledger_signing_key = load_ledger_signing_key(dotenv, get_process_var)?;
    let jwt_issuer = required_var(ENV_JWT_ISSUER, dotenv, get_process_var)?;
    let jwt_audience = required_var(ENV_JWT_AUDIENCE, dotenv, get_process_var)?;
    let jwks_url = required_var(ENV_JWKS_URL, dotenv, get_process_var)?;
    let incident_notifier =
        super::incident::parse_incident_notifier_config(dotenv, get_process_var)?;

    let http = load_http_config(dotenv, get_process_var)?;
    let audit_fallback = load_audit_fallback_config(dotenv, get_process_var)?;
    let siem = load_siem_config(dotenv, get_process_var)?;
    let operational = load_operational_checks_config(dotenv, get_process_var)?;
    let scheduler = load_scheduler_config(dotenv, get_process_var)?;

    Ok(AppConfig {
        listen_addr,
        master_key_ring,
        alias_encryption_key: alias_keys.encryption_key,
        alias_encryption_key_version: alias_keys.encryption_key_version,
        alias_fingerprint_key: alias_keys.fingerprint_key,
        alias_fingerprint_key_version: alias_keys.fingerprint_key_version,
        supabase_url,
        supabase_service_role_key,
        supabase_publishable_key,
        ledger_signing_key,
        jwt_issuer,
        jwt_audience,
        jwks_url,
        jwks_refresh_interval: http.jwks_refresh_interval,
        health_readiness_poll_interval: http.health_readiness_poll_interval,
        outbound_http_connect_timeout: http.outbound_http_connect_timeout,
        outbound_http_request_timeout: http.outbound_http_request_timeout,
        http_handler_timeout: http.http_handler_timeout,
        http_rate_limit_requests: http.http_rate_limit_requests,
        http_rate_limit_window: http.http_rate_limit_window,
        audit_fallback_path: audit_fallback.path,
        siem_buffer_path: siem.buffer_path,
        siem_exporter: siem.exporter,
        incident_notifier,
        audit_resend_interval: audit_fallback.resend_interval,
        siem_resend_interval: siem.resend_interval,
        siem_long_failure_threshold: siem.long_failure_threshold,
        audit_fallback_alert_threshold_bytes: audit_fallback.alert_threshold_bytes,
        audit_fallback_rotate_size_bytes: audit_fallback.rotate_size_bytes,
        audit_fallback_archive_dir: audit_fallback.archive_dir,
        audit_fallback_archive_auto_delete_enabled: audit_fallback.archive_auto_delete_enabled,
        audit_fallback_archive_retention: audit_fallback.archive_retention,
        restore_test_interval: operational.restore_test_interval,
        restore_test_startup_delay: operational.restore_test_startup_delay,
        restore_test_sample_limit: operational.restore_test_sample_limit,
        integrity_check_interval: operational.integrity_check_interval,
        integrity_check_startup_delay: operational.integrity_check_startup_delay,
        scheduler_enabled: scheduler.enabled,
        scheduler_startup_delay: scheduler.startup_delay,
        scheduler_poll_interval: scheduler.poll_interval,
        scheduler_monthly_day: scheduler.monthly_day,
        scheduler_monthly_hour_utc: scheduler.monthly_hour_utc,
        scheduler_quarterly_hour_utc: scheduler.quarterly_hour_utc,
        scheduler_daily_hour_utc: scheduler.daily_hour_utc,
        scheduler_envelope_migration_batch_size: scheduler.envelope_migration_batch_size,
        scheduler_envelope_migration_max_batches: scheduler.envelope_migration_max_batches,
        scheduler_local_archive_dir: scheduler.local_archive_dir,
    })
}

/// alias 暗号化・フィンガープリント鍵とそのバージョン。
struct AliasKeys {
    encryption_key: AliasEncryptionKey,
    encryption_key_version: KeyVersion,
    fingerprint_key: AliasFingerprintKey,
    fingerprint_key_version: KeyVersion,
}

fn load_alias_keys<F>(dotenv: &DotenvVars, get_process_var: &F) -> Result<AliasKeys, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let encryption_key = AliasEncryptionKey::from_bytes(parse_fixed_length_key_hex(
        ENV_ALIAS_ENCRYPTION_KEY,
        &required_var(ENV_ALIAS_ENCRYPTION_KEY, dotenv, get_process_var)?,
    )?);
    let encryption_key_version = parse_key_version_config(
        ENV_ALIAS_ENCRYPTION_KEY_VERSION,
        &required_var(ENV_ALIAS_ENCRYPTION_KEY_VERSION, dotenv, get_process_var)?,
    )?;
    let fingerprint_key = AliasFingerprintKey::from_bytes(parse_fixed_length_key_hex(
        ENV_ALIAS_FINGERPRINT_KEY,
        &required_var(ENV_ALIAS_FINGERPRINT_KEY, dotenv, get_process_var)?,
    )?);
    let fingerprint_key_version = parse_key_version_config(
        ENV_ALIAS_FINGERPRINT_KEY_VERSION,
        &required_var(ENV_ALIAS_FINGERPRINT_KEY_VERSION, dotenv, get_process_var)?,
    )?;

    Ok(AliasKeys {
        encryption_key,
        encryption_key_version,
        fingerprint_key,
        fingerprint_key_version,
    })
}

/// HTTP / JWKS まわりのタイムアウト・レート制限設定。
struct HttpConfig {
    jwks_refresh_interval: Duration,
    health_readiness_poll_interval: Duration,
    outbound_http_connect_timeout: Duration,
    outbound_http_request_timeout: Duration,
    http_handler_timeout: Duration,
    http_rate_limit_requests: u64,
    http_rate_limit_window: Duration,
}

fn load_http_config<F>(dotenv: &DotenvVars, get_process_var: &F) -> Result<HttpConfig, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
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
    // http_handler_timeout は outbound_http_request_timeout に依存するため同一グループ内で解決する。
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

    Ok(HttpConfig {
        jwks_refresh_interval,
        health_readiness_poll_interval,
        outbound_http_connect_timeout,
        outbound_http_request_timeout,
        http_handler_timeout,
        http_rate_limit_requests,
        http_rate_limit_window,
    })
}

/// 監査フォールバックファイルとそのアーカイブ・再送に関する設定。
struct AuditFallbackConfig {
    path: PathBuf,
    archive_dir: PathBuf,
    resend_interval: Duration,
    alert_threshold_bytes: u64,
    rotate_size_bytes: u64,
    archive_auto_delete_enabled: bool,
    archive_retention: Duration,
}

fn load_audit_fallback_config<F>(
    dotenv: &DotenvVars,
    get_process_var: &F,
) -> Result<AuditFallbackConfig, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let path = PathBuf::from(
        optional_var(ENV_AUDIT_FALLBACK_PATH, dotenv, get_process_var)
            .unwrap_or_else(|| DEFAULT_AUDIT_FALLBACK_PATH.to_owned()),
    );
    // archive_dir は path を既定値の基準に使うため同一グループ内で解決する。
    let archive_dir = optional_var(ENV_AUDIT_FALLBACK_ARCHIVE_DIR, dotenv, get_process_var)
        .map(PathBuf::from)
        .unwrap_or_else(|| default_audit_fallback_archive_dir(&path));
    let resend_interval = parse_audit_resend_interval(optional_var(
        ENV_AUDIT_RESEND_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let alert_threshold_bytes = parse_audit_fallback_alert_threshold(optional_var(
        ENV_AUDIT_FALLBACK_ALERT_THRESHOLD_BYTES,
        dotenv,
        get_process_var,
    ))?;
    let rotate_size_bytes = parse_audit_fallback_rotate_size(optional_var(
        ENV_AUDIT_FALLBACK_ROTATE_SIZE_BYTES,
        dotenv,
        get_process_var,
    ))?;
    let archive_auto_delete_enabled =
        parse_audit_fallback_archive_auto_delete_enabled(optional_var(
            ENV_AUDIT_FALLBACK_ARCHIVE_AUTO_DELETE_ENABLED,
            dotenv,
            get_process_var,
        ))?;
    let archive_retention = parse_audit_fallback_archive_retention_days(optional_var(
        ENV_AUDIT_FALLBACK_ARCHIVE_RETENTION_DAYS,
        dotenv,
        get_process_var,
    ))?;

    Ok(AuditFallbackConfig {
        path,
        archive_dir,
        resend_interval,
        alert_threshold_bytes,
        rotate_size_bytes,
        archive_auto_delete_enabled,
        archive_retention,
    })
}

/// SIEM エクスポータとバッファ・再送に関する設定。
struct SiemConfig {
    buffer_path: PathBuf,
    exporter: SiemExporterConfig,
    resend_interval: Duration,
    long_failure_threshold: Duration,
}

fn load_siem_config<F>(dotenv: &DotenvVars, get_process_var: &F) -> Result<SiemConfig, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let buffer_path = PathBuf::from(
        optional_var(ENV_SIEM_BUFFER_PATH, dotenv, get_process_var)
            .unwrap_or_else(|| DEFAULT_SIEM_BUFFER_PATH.to_owned()),
    );
    let exporter = parse_siem_exporter_config(dotenv, get_process_var)?;
    let resend_interval = parse_siem_resend_interval(optional_var(
        ENV_SIEM_RESEND_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let long_failure_threshold = parse_siem_long_failure_threshold(optional_var(
        ENV_SIEM_LONG_FAILURE_THRESHOLD_SECONDS,
        dotenv,
        get_process_var,
    ))?;

    Ok(SiemConfig {
        buffer_path,
        exporter,
        resend_interval,
        long_failure_threshold,
    })
}

/// リストアテスト・整合性チェックの運用ジョブ設定。
struct OperationalChecksConfig {
    restore_test_interval: Duration,
    restore_test_startup_delay: Duration,
    restore_test_sample_limit: u32,
    integrity_check_interval: Duration,
    integrity_check_startup_delay: Duration,
}

fn load_operational_checks_config<F>(
    dotenv: &DotenvVars,
    get_process_var: &F,
) -> Result<OperationalChecksConfig, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
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

    Ok(OperationalChecksConfig {
        restore_test_interval,
        restore_test_startup_delay,
        restore_test_sample_limit,
        integrity_check_interval,
        integrity_check_startup_delay,
    })
}

/// スケジューラの有効化・周期・実行時刻・envelope マイグレーション設定。
struct SchedulerConfig {
    enabled: bool,
    startup_delay: Duration,
    poll_interval: Duration,
    monthly_day: u8,
    monthly_hour_utc: u8,
    quarterly_hour_utc: u8,
    daily_hour_utc: u8,
    envelope_migration_batch_size: u32,
    envelope_migration_max_batches: u32,
    local_archive_dir: PathBuf,
}

fn load_scheduler_config<F>(
    dotenv: &DotenvVars,
    get_process_var: &F,
) -> Result<SchedulerConfig, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let enabled =
        parse_scheduler_enabled(optional_var(ENV_SCHEDULER_ENABLED, dotenv, get_process_var))?;
    let startup_delay = parse_scheduler_startup_delay(scheduler_startup_delay_value(
        optional_var(ENV_SCHEDULER_STARTUP_DELAY_SECONDS, dotenv, get_process_var),
        optional_var(ENV_SCHEDULER_STARTUP_DELAY_SEC, dotenv, get_process_var),
    ))?;
    let poll_interval = parse_scheduler_poll_interval(optional_var(
        ENV_SCHEDULER_POLL_INTERVAL_SECONDS,
        dotenv,
        get_process_var,
    ))?;
    let monthly_day = parse_scheduler_monthly_day(optional_var(
        ENV_SCHEDULER_MONTHLY_DAY,
        dotenv,
        get_process_var,
    ))?;
    let monthly_hour_utc = parse_scheduler_monthly_hour_utc(optional_var(
        ENV_SCHEDULER_MONTHLY_HOUR_UTC,
        dotenv,
        get_process_var,
    ))?;
    let quarterly_hour_utc = parse_scheduler_quarterly_hour_utc(optional_var(
        ENV_SCHEDULER_QUARTERLY_HOUR_UTC,
        dotenv,
        get_process_var,
    ))?;
    let daily_hour_utc = parse_scheduler_daily_hour_utc(optional_var(
        ENV_SCHEDULER_DAILY_HOUR_UTC,
        dotenv,
        get_process_var,
    ))?;
    let envelope_migration_batch_size =
        parse_scheduler_envelope_migration_batch_size(optional_var(
            ENV_SCHEDULER_ENVELOPE_MIGRATION_BATCH_SIZE,
            dotenv,
            get_process_var,
        ))?;
    let envelope_migration_max_batches =
        parse_scheduler_envelope_migration_max_batches(optional_var(
            ENV_SCHEDULER_ENVELOPE_MIGRATION_MAX_BATCHES,
            dotenv,
            get_process_var,
        ))?;
    let local_archive_dir = PathBuf::from(
        optional_var(ENV_SCHEDULER_LOCAL_ARCHIVE_DIR, dotenv, get_process_var)
            .unwrap_or_else(|| DEFAULT_SCHEDULER_LOCAL_ARCHIVE_DIR.to_owned()),
    );

    Ok(SchedulerConfig {
        enabled,
        startup_delay,
        poll_interval,
        monthly_day,
        monthly_hour_utc,
        quarterly_hour_utc,
        daily_hour_utc,
        envelope_migration_batch_size,
        envelope_migration_max_batches,
        local_archive_dir,
    })
}

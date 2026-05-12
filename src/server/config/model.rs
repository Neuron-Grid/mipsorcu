use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::MasterKeyRing;
use crate::ledger::LedgerSigningKey;

use super::constants::SECONDS_PER_DAY;

pub struct AppConfig {
    pub listen_addr: SocketAddr,
    pub master_key_ring: MasterKeyRing,
    pub supabase_url: String,
    pub supabase_service_role_key: String,
    pub supabase_publishable_key: String,
    pub ledger_signing_key: LedgerSigningKey,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwks_url: String,
    pub jwks_refresh_interval: Duration,
    pub health_readiness_poll_interval: Duration,
    pub outbound_http_connect_timeout: Duration,
    pub outbound_http_request_timeout: Duration,
    pub http_handler_timeout: Duration,
    pub http_rate_limit_requests: u64,
    pub http_rate_limit_window: Duration,
    pub audit_fallback_path: PathBuf,
    pub siem_buffer_path: PathBuf,
    pub audit_resend_interval: Duration,
    pub siem_resend_interval: Duration,
    pub siem_long_failure_threshold: Duration,
    pub audit_fallback_alert_threshold_bytes: u64,
    pub audit_fallback_rotate_size_bytes: u64,
    pub audit_fallback_archive_dir: PathBuf,
    pub audit_fallback_archive_auto_delete_enabled: bool,
    pub audit_fallback_archive_retention: Duration,
    pub restore_test_interval: Duration,
    pub restore_test_startup_delay: Duration,
    pub restore_test_sample_limit: u32,
    pub integrity_check_interval: Duration,
    pub integrity_check_startup_delay: Duration,
    pub scheduler_enabled: bool,
    pub scheduler_startup_delay: Duration,
    pub scheduler_poll_interval: Duration,
    pub scheduler_monthly_day: u8,
    pub scheduler_monthly_hour_utc: u8,
    pub scheduler_quarterly_hour_utc: u8,
    pub scheduler_local_archive_dir: PathBuf,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppConfig")
            .field("listen_addr", &self.listen_addr)
            .field("master_key_ring", &self.master_key_ring)
            .field("supabase_url", &self.supabase_url)
            .field("supabase_service_role_key", &"<redacted>")
            .field("supabase_publishable_key", &"<redacted>")
            .field("ledger_signing_key", &self.ledger_signing_key)
            .field("jwt_issuer", &self.jwt_issuer)
            .field("jwt_audience", &self.jwt_audience)
            .field("jwks_url", &self.jwks_url)
            .field(
                "jwks_refresh_interval_seconds",
                &self.jwks_refresh_interval.as_secs(),
            )
            .field(
                "health_readiness_poll_interval_seconds",
                &self.health_readiness_poll_interval.as_secs(),
            )
            .field(
                "outbound_http_connect_timeout_seconds",
                &self.outbound_http_connect_timeout.as_secs(),
            )
            .field(
                "outbound_http_request_timeout_seconds",
                &self.outbound_http_request_timeout.as_secs(),
            )
            .field(
                "http_handler_timeout_seconds",
                &self.http_handler_timeout.as_secs(),
            )
            .field("http_rate_limit_requests", &self.http_rate_limit_requests)
            .field(
                "http_rate_limit_window_seconds",
                &self.http_rate_limit_window.as_secs(),
            )
            .field("audit_fallback_path", &self.audit_fallback_path)
            .field("siem_buffer_path", &self.siem_buffer_path)
            .field(
                "audit_resend_interval_seconds",
                &self.audit_resend_interval.as_secs(),
            )
            .field(
                "siem_resend_interval_seconds",
                &self.siem_resend_interval.as_secs(),
            )
            .field(
                "siem_long_failure_threshold_seconds",
                &self.siem_long_failure_threshold.as_secs(),
            )
            .field(
                "audit_fallback_alert_threshold_bytes",
                &self.audit_fallback_alert_threshold_bytes,
            )
            .field(
                "audit_fallback_rotate_size_bytes",
                &self.audit_fallback_rotate_size_bytes,
            )
            .field(
                "audit_fallback_archive_dir",
                &self.audit_fallback_archive_dir,
            )
            .field(
                "audit_fallback_archive_auto_delete_enabled",
                &self.audit_fallback_archive_auto_delete_enabled,
            )
            .field(
                "audit_fallback_archive_retention_days",
                &(self.audit_fallback_archive_retention.as_secs() / SECONDS_PER_DAY),
            )
            .field(
                "restore_test_interval_seconds",
                &self.restore_test_interval.as_secs(),
            )
            .field(
                "restore_test_startup_delay_seconds",
                &self.restore_test_startup_delay.as_secs(),
            )
            .field("restore_test_sample_limit", &self.restore_test_sample_limit)
            .field(
                "integrity_check_interval_seconds",
                &self.integrity_check_interval.as_secs(),
            )
            .field(
                "integrity_check_startup_delay_seconds",
                &self.integrity_check_startup_delay.as_secs(),
            )
            .field("scheduler_enabled", &self.scheduler_enabled)
            .field(
                "scheduler_startup_delay_seconds",
                &self.scheduler_startup_delay.as_secs(),
            )
            .field(
                "scheduler_poll_interval_seconds",
                &self.scheduler_poll_interval.as_secs(),
            )
            .field("scheduler_monthly_day", &self.scheduler_monthly_day)
            .field(
                "scheduler_monthly_hour_utc",
                &self.scheduler_monthly_hour_utc,
            )
            .field(
                "scheduler_quarterly_hour_utc",
                &self.scheduler_quarterly_hour_utc,
            )
            .field(
                "scheduler_local_archive_dir",
                &self.scheduler_local_archive_dir,
            )
            .finish()
    }
}

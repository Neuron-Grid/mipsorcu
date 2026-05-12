use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::audit::{
    ArchiveSweepOutcome, AuditRecordError, AuditRecorder, AuditTrigger, LocalAuditFallbackStore,
    LocalAuditStoreError, ResendAuditSummary, RolloverOutcome,
};
use crate::auth::{JwksCache, JwksFetchError, JwtVerifier, JwtVerifierConfig, fetch_jwks};
use crate::server::siem_forwarding::SiemForwardingService;
use crate::server::state::{AppState, ReadinessState};
use crate::server::supabase::{SupabaseAuditAppender, SupabaseClient};
use crate::server::{integrity_check, restore_test};
use crate::siem::InMemorySiemSink;

const AUDIT_ARCHIVE_SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

pub async fn initialize_jwt_verifier_from_jwks_url(
    http_client: &reqwest::Client,
    jwks_url: &str,
    jwt_issuer: &str,
    jwt_audience: &str,
) -> Result<JwtVerifier, JwtVerifierInitError> {
    let jwks = fetch_jwks(http_client, jwks_url)
        .await
        .map_err(JwtVerifierInitError::Fetch)?;
    let jwt_config =
        JwtVerifierConfig::new(jwt_issuer, jwt_audience).map_err(JwtVerifierInitError::Config)?;

    Ok(JwtVerifier::with_cache(jwt_config, JwksCache::new(jwks)))
}

#[derive(Debug)]
pub enum JwtVerifierInitError {
    Fetch(JwksFetchError),
    Config(crate::JwtVerificationError),
}

impl std::fmt::Display for JwtVerifierInitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fetch(error) => write!(formatter, "JWKS loading failed: {error}"),
            Self::Config(error) => write!(formatter, "JWT verifier config is invalid: {error}"),
        }
    }
}

impl std::error::Error for JwtVerifierInitError {}

pub async fn refresh_jwks_cache_once(
    cache: &JwksCache,
    http_client: &reqwest::Client,
    jwks_url: &str,
) -> Result<(), JwksFetchError> {
    let jwks = fetch_jwks(http_client, jwks_url).await?;
    cache.replace(jwks).map_err(JwksFetchError::InvalidJwks)
}

pub(crate) async fn run_jwks_refresh_loop(
    cache: JwksCache,
    http_client: reqwest::Client,
    jwks_url: String,
    interval_duration: Duration,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(interval_duration);
    interval.tick().await;

    loop {
        tokio::select! {
            result = shutdown_receiver.changed() => {
                if result.is_err() || *shutdown_receiver.borrow() {
                    tracing::info!("JWKS refresh loop stopped");
                    break;
                }
            }
            _ = interval.tick() => {
                match refresh_jwks_cache_once(&cache, &http_client, &jwks_url).await {
                    Ok(()) => {
                        tracing::info!(jwks_url = %jwks_url, "JWKS cache refreshed");
                    }
                    Err(error) => {
                        tracing::error!(
                            jwks_url = %jwks_url,
                            error_kind = jwks_fetch_error_kind(&error),
                            "JWKS cache refresh failed"
                        );
                    }
                }
            }
        }
    }
}

pub(crate) async fn run_supabase_readiness_poll_loop(
    readiness_state: ReadinessState,
    supabase_client: Arc<SupabaseClient>,
    interval_duration: Duration,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    run_supabase_readiness_probe_once(&readiness_state, &supabase_client).await;

    let mut interval = tokio::time::interval(interval_duration);
    interval.tick().await;

    loop {
        tokio::select! {
            result = shutdown_receiver.changed() => {
                if result.is_err() || *shutdown_receiver.borrow() {
                    tracing::info!("Supabase readiness poll loop stopped");
                    break;
                }
            }
            _ = interval.tick() => {
                run_supabase_readiness_probe_once(&readiness_state, &supabase_client).await;
            }
        }
    }
}

pub(crate) async fn run_restore_test_loop(
    state: AppState,
    interval_duration: Duration,
    startup_delay: Duration,
    sample_limit: u32,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    if sleep_until_first_run(startup_delay, &mut shutdown_receiver, "restore test").await {
        return;
    }

    restore_test::run_restore_test_once(&state, sample_limit, AuditTrigger::Startup).await;

    let mut interval = tokio::time::interval(interval_duration);
    interval.tick().await;

    loop {
        tokio::select! {
            result = shutdown_receiver.changed() => {
                if result.is_err() || *shutdown_receiver.borrow() {
                    tracing::info!("restore test loop stopped");
                    break;
                }
            }
            _ = interval.tick() => {
                restore_test::run_restore_test_once(&state, sample_limit, AuditTrigger::Background).await;
            }
        }
    }
}

pub(crate) async fn run_integrity_check_loop(
    state: AppState,
    interval_duration: Duration,
    startup_delay: Duration,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    if sleep_until_first_run(startup_delay, &mut shutdown_receiver, "integrity check").await {
        return;
    }

    let _ = integrity_check::run_integrity_check_once(&state, AuditTrigger::Startup).await;

    let mut interval = tokio::time::interval(interval_duration);
    interval.tick().await;

    loop {
        tokio::select! {
            result = shutdown_receiver.changed() => {
                if result.is_err() || *shutdown_receiver.borrow() {
                    tracing::info!("integrity check loop stopped");
                    break;
                }
            }
            _ = interval.tick() => {
                let _ = integrity_check::run_integrity_check_once(&state, AuditTrigger::Background).await;
            }
        }
    }
}

pub(crate) async fn run_audit_resend_loop(
    audit_recorder: Arc<AuditRecorder<SupabaseAuditAppender>>,
    fallback_store: LocalAuditFallbackStore,
    interval_duration: Duration,
    audit_fallback_alert_threshold_bytes: u64,
    audit_fallback_archive_auto_delete_enabled: bool,
    audit_fallback_archive_retention: Duration,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    let mut last_archive_sweep = None;

    record_audit_resend_result(resend_pending_once(audit_recorder.clone()).await);
    record_audit_fallback_post_resend_tasks(
        &fallback_store,
        audit_fallback_alert_threshold_bytes,
        audit_fallback_archive_auto_delete_enabled,
        audit_fallback_archive_retention,
        &mut last_archive_sweep,
    )
    .await;

    let mut interval = tokio::time::interval(interval_duration);
    interval.tick().await;

    loop {
        tokio::select! {
            result = shutdown_receiver.changed() => {
                if result.is_err() || *shutdown_receiver.borrow() {
                    tracing::info!("audit fallback resend loop stopped");
                    break;
                }
            }
            _ = interval.tick() => {
                record_audit_resend_result(resend_pending_once(audit_recorder.clone()).await);
                record_audit_fallback_post_resend_tasks(
                    &fallback_store,
                    audit_fallback_alert_threshold_bytes,
                    audit_fallback_archive_auto_delete_enabled,
                    audit_fallback_archive_retention,
                    &mut last_archive_sweep,
                )
                .await;
            }
        }
    }
}

pub(crate) async fn run_siem_resend_loop(
    siem_forwarding: Arc<SiemForwardingService<InMemorySiemSink>>,
    interval_duration: Duration,
    long_failure_threshold: Duration,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    record_siem_resend_result(
        siem_forwarding.resend_pending().await,
        &siem_forwarding,
        long_failure_threshold,
    );

    let mut interval = tokio::time::interval(interval_duration);
    interval.tick().await;

    loop {
        tokio::select! {
            result = shutdown_receiver.changed() => {
                if result.is_err() || *shutdown_receiver.borrow() {
                    tracing::info!("SIEM resend loop stopped");
                    break;
                }
            }
            _ = interval.tick() => {
                record_siem_resend_result(
                    siem_forwarding.resend_pending().await,
                    &siem_forwarding,
                    long_failure_threshold,
                );
            }
        }
    }
}

fn record_siem_resend_result(
    summary: crate::siem::SiemResendSummary,
    siem_forwarding: &SiemForwardingService<InMemorySiemSink>,
    long_failure_threshold: Duration,
) {
    if summary.attempted > 0 {
        tracing::info!(
            attempted = summary.attempted,
            sent = summary.sent,
            failed = summary.failed,
            "SIEM pending event resend completed"
        );
    }

    let now = time::OffsetDateTime::now_utc();
    if siem_forwarding
        .status()
        .is_long_failure(now, long_failure_threshold)
    {
        tracing::warn!(
            threshold_seconds = long_failure_threshold.as_secs(),
            "SIEM forwarding has been failing longer than threshold"
        );
    }
}

pub async fn run_audit_fallback_rollover_once(
    fallback_store: LocalAuditFallbackStore,
) -> Result<RolloverOutcome, LocalAuditStoreError> {
    tokio::task::spawn_blocking(move || fallback_store.rollover())
        .await
        .map_err(|_| LocalAuditStoreError::Io(std::io::Error::other("join failed")))?
}

pub async fn sweep_audit_fallback_archive_once(
    fallback_store: LocalAuditFallbackStore,
    audit_fallback_archive_retention: Duration,
) -> Result<ArchiveSweepOutcome, LocalAuditStoreError> {
    tokio::task::spawn_blocking(move || {
        fallback_store.sweep_archive(audit_fallback_archive_retention)
    })
    .await
    .map_err(|_| LocalAuditStoreError::Io(std::io::Error::other("join failed")))?
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditFallbackSizeAlert {
    pub size_bytes: u64,
    pub threshold_bytes: u64,
}

pub fn audit_fallback_size_alert(
    path: &Path,
    threshold_bytes: u64,
) -> Result<Option<AuditFallbackSizeAlert>, std::io::Error> {
    let Some(size_bytes) = audit_fallback_file_size(path)? else {
        return Ok(None);
    };

    if size_bytes >= threshold_bytes {
        Ok(Some(AuditFallbackSizeAlert {
            size_bytes,
            threshold_bytes,
        }))
    } else {
        Ok(None)
    }
}

pub fn audit_fallback_file_size(path: &Path) -> Result<Option<u64>, std::io::Error> {
    match std::fs::metadata(path) {
        Ok(metadata) => {
            if metadata.is_file() {
                Ok(Some(metadata.len()))
            } else {
                Ok(None)
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

async fn run_supabase_readiness_probe_once(
    readiness_state: &ReadinessState,
    supabase_client: &Arc<SupabaseClient>,
) {
    let reachable = supabase_client.probe_readiness().await;
    readiness_state.record_supabase_probe_result(reachable);
}

async fn sleep_until_first_run(
    startup_delay: Duration,
    shutdown_receiver: &mut watch::Receiver<bool>,
    loop_name: &'static str,
) -> bool {
    if startup_delay.is_zero() {
        return false;
    }

    tokio::select! {
        result = shutdown_receiver.changed() => {
            if result.is_err() || *shutdown_receiver.borrow() {
                tracing::info!("{loop_name} loop stopped before first run");
                true
            } else {
                false
            }
        }
        _ = tokio::time::sleep(startup_delay) => false,
    }
}

pub(crate) fn jwks_fetch_error_kind(error: &JwksFetchError) -> &'static str {
    match error {
        JwksFetchError::Network(_) => "network",
        JwksFetchError::NonSuccessStatus { .. } => "non_success_status",
        JwksFetchError::InvalidResponse(_) => "invalid_response",
        JwksFetchError::InvalidJwks(_) => "invalid_jwks",
    }
}

async fn record_audit_fallback_post_resend_tasks(
    fallback_store: &LocalAuditFallbackStore,
    audit_fallback_alert_threshold_bytes: u64,
    audit_fallback_archive_auto_delete_enabled: bool,
    audit_fallback_archive_retention: Duration,
    last_archive_sweep: &mut Option<Instant>,
) {
    record_audit_fallback_size_alert(fallback_store.path(), audit_fallback_alert_threshold_bytes);
    record_audit_fallback_rollover_result(
        fallback_store.path(),
        run_audit_fallback_rollover_once(fallback_store.clone()).await,
    );

    if audit_fallback_archive_auto_delete_enabled && should_sweep_archive(last_archive_sweep) {
        record_audit_fallback_archive_sweep_result(
            fallback_store.archive_dir(),
            audit_fallback_archive_retention,
            sweep_audit_fallback_archive_once(
                fallback_store.clone(),
                audit_fallback_archive_retention,
            )
            .await,
        );
    }
}

async fn resend_pending_once(
    audit_recorder: Arc<AuditRecorder<SupabaseAuditAppender>>,
) -> Result<ResendAuditSummary, AuditRecordError> {
    audit_recorder.resend_pending().await
}

fn record_audit_resend_result(result: Result<ResendAuditSummary, AuditRecordError>) {
    match result {
        Ok(summary) => {
            tracing::info!(
                attempted = summary.attempted,
                sent = summary.sent,
                failed = summary.failed,
                "audit fallback resend completed"
            );
        }
        Err(error) => {
            tracing::error!(
                error_kind = resend_audit_error_kind(&error),
                "audit fallback resend failed"
            );
        }
    }
}

fn resend_audit_error_kind(error: &AuditRecordError) -> &'static str {
    match error {
        AuditRecordError::EventConstructionFailed(_) => "event_construction_failed",
        AuditRecordError::LedgerAppendFailed => "ledger_append_failed",
        AuditRecordError::PrimaryAndFallbackFailed { .. } => "primary_and_fallback_failed",
        AuditRecordError::IdempotencyConflict => "idempotency_conflict",
        AuditRecordError::ResendReadFailed(_) => "resend_read_failed",
        AuditRecordError::ResendMarkSentFailed(_) => "resend_mark_sent_failed",
    }
}

fn record_audit_fallback_size_alert(path: &Path, threshold_bytes: u64) {
    match audit_fallback_size_alert(path, threshold_bytes) {
        Ok(Some(alert)) => {
            tracing::warn!(
                path = %path.display(),
                size_bytes = alert.size_bytes,
                threshold_bytes = alert.threshold_bytes,
                "audit fallback log size threshold exceeded"
            );
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!(
                path = %path.display(),
                error_kind = ?error.kind(),
                "audit fallback log size check failed"
            );
        }
    }
}

fn record_audit_fallback_rollover_result(
    path: &Path,
    result: Result<RolloverOutcome, LocalAuditStoreError>,
) {
    match result {
        Ok(RolloverOutcome::Skipped) => {}
        Ok(RolloverOutcome::Sealed(archive)) => {
            tracing::info!(
                path = %path.display(),
                archive_path = %archive.archive_path.display(),
                sha256_hex = %archive.sha256_hex,
                line_count = archive.line_count,
                first_occurred_at = archive.first_occurred_at.as_deref(),
                last_occurred_at = archive.last_occurred_at.as_deref(),
                size_bytes = archive.size_bytes,
                "audit fallback log rolled over"
            );
        }
        Err(error) => {
            tracing::error!(
                path = %path.display(),
                error_kind = local_audit_store_error_kind(&error),
                "audit fallback rollover failed"
            );
        }
    }
}

fn record_audit_fallback_archive_sweep_result(
    archive_dir: &Path,
    retention: Duration,
    result: Result<ArchiveSweepOutcome, LocalAuditStoreError>,
) {
    match result {
        Ok(outcome) => {
            for archive in outcome.deleted_archives {
                tracing::info!(
                    archive_dir = %archive_dir.display(),
                    archive_path = %archive.archive_path.display(),
                    sha256_hex = archive.sha256_hex.as_deref(),
                    line_count = ?archive.line_count,
                    size_bytes = archive.size_bytes,
                    retention_days = retention.as_secs() / (24 * 60 * 60),
                    "audit fallback archive deleted"
                );
            }
        }
        Err(error) => {
            tracing::error!(
                archive_dir = %archive_dir.display(),
                error_kind = local_audit_store_error_kind(&error),
                "audit fallback archive sweep failed"
            );
        }
    }
}

fn should_sweep_archive(last_archive_sweep: &mut Option<Instant>) -> bool {
    let now = Instant::now();

    match last_archive_sweep {
        Some(last_sweep) if now.duration_since(*last_sweep) < AUDIT_ARCHIVE_SWEEP_INTERVAL => false,
        _ => {
            *last_archive_sweep = Some(now);
            true
        }
    }
}

fn local_audit_store_error_kind(error: &LocalAuditStoreError) -> &'static str {
    match error {
        LocalAuditStoreError::Io(_) => "io",
        LocalAuditStoreError::Json(_) => "json",
        LocalAuditStoreError::TimestampFormat(_) => "timestamp_format",
        LocalAuditStoreError::ArchivePathUnavailable { .. } => "archive_path_unavailable",
        LocalAuditStoreError::GzipWriteFailed { .. } => "gzip_write_failed",
        LocalAuditStoreError::HashReadFailed { .. } => "hash_read_failed",
        LocalAuditStoreError::CurrentFileRemoveFailed { .. } => "current_file_remove_failed",
        LocalAuditStoreError::ArchiveDeleteFailed { .. } => "archive_delete_failed",
        LocalAuditStoreError::LockPoisoned => "lock_poisoned",
        LocalAuditStoreError::InvalidLine { .. } => "invalid_line",
        LocalAuditStoreError::Event(_) => "event",
    }
}

#[cfg(test)]
#[path = "../../tests_internal/server_background.rs"]
mod tests;

use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use crate::audit::{
    AuditEventError, AuditMetadata, AuditRecordError, AuditRecordOutcome, AuditResult,
    AuditTrigger, IntegrityCheckMetadata, RequestId,
};
use crate::incident::{DummyNotificationSink, IncidentRecorder};
use crate::server::audit_reporter::{self, IntegrityCheckAudit};
use crate::server::config::AppConfig;
use crate::server::state::{AppState, ReadinessState};
use crate::server::supabase::{SupabaseAuditAppender, SupabaseClient};
use crate::siem::{AnySiemSink, InMemorySiemSink, LocalSiemFallbackBuffer, SiemForwarder};
use crate::types::supabase::IntegrityCheckSummary;
use crate::{AuditRecorder, LocalAuditFallbackStore};

pub type IntegrityCheckTrigger = AuditTrigger;

#[derive(Debug)]
pub enum IntegrityCheckError {
    Usage(String),
    Config(String),
    RequestId(AuditEventError),
    Metadata(AuditEventError),
    RpcFailed,
    ViolationDetected { violation_count: u64 },
    AuditRecordFailed(AuditRecordError),
}

impl fmt::Display for IntegrityCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::Config(message) => write!(formatter, "integrity check config error: {message}"),
            Self::RequestId(error) => write!(formatter, "integrity check setup failed: {error}"),
            Self::Metadata(error) => write!(formatter, "integrity check metadata failed: {error}"),
            Self::RpcFailed => write!(formatter, "integrity check RPC failed"),
            Self::ViolationDetected { violation_count } => {
                write!(
                    formatter,
                    "integrity check detected {violation_count} violation(s)"
                )
            }
            Self::AuditRecordFailed(error) => {
                write!(formatter, "integrity check audit record failed: {error}")
            }
        }
    }
}

impl std::error::Error for IntegrityCheckError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityCheckOutcome {
    pub request_id: RequestId,
    pub summary: IntegrityCheckSummary,
    pub audit_result: AuditResult,
    pub audit_record_outcome: AuditRecordOutcome,
}

pub async fn run_integrity_check_once(
    state: &AppState,
    trigger: IntegrityCheckTrigger,
) -> Result<IntegrityCheckOutcome, IntegrityCheckError> {
    let request_id = RequestId::generate().map_err(IntegrityCheckError::RequestId)?;
    let started_at = Instant::now();

    let summary = match state.supabase_client.call_integrity_check().await {
        Ok(summary) => summary,
        Err(error) => {
            let summary = IntegrityCheckSummary::zero();
            let audit_record_outcome = record_integrity_check_audit(
                state,
                &request_id,
                AuditResult::Failure,
                &summary,
                trigger,
                Some("rpc_failed"),
                elapsed_ms(started_at),
            )
            .await?;
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "integrity_check",
                result = "failure",
                error_code = "rpc_failed",
                audit_record_outcome = audit_record_outcome_label(audit_record_outcome),
                "integrity check RPC failed"
            );
            return Err(IntegrityCheckError::RpcFailed);
        }
    };

    if summary.violation_count == 0 {
        let audit_record_outcome = record_integrity_check_audit(
            state,
            &request_id,
            AuditResult::Success,
            &summary,
            trigger,
            None,
            elapsed_ms(started_at),
        )
        .await?;
        tracing::info!(
            request_id = %request_id.as_canonical_string(),
            action = "integrity_check",
            result = "success",
            checked_secret_count = summary.checked_secret_count,
            checked_secret_version_count = summary.checked_secret_version_count,
            checked_audit_event_count = summary.checked_audit_event_count,
            violation_count = summary.violation_count,
            audit_record_outcome = audit_record_outcome_label(audit_record_outcome),
            "integrity check completed"
        );
        return Ok(IntegrityCheckOutcome {
            request_id,
            summary,
            audit_result: AuditResult::Success,
            audit_record_outcome,
        });
    }

    let audit_record_outcome = record_integrity_check_audit(
        state,
        &request_id,
        AuditResult::Failure,
        &summary,
        trigger,
        Some("integrity_violation_detected"),
        elapsed_ms(started_at),
    )
    .await?;
    tracing::error!(
        request_id = %request_id.as_canonical_string(),
        action = "integrity_check",
        result = "failure",
        error_code = "integrity_violation_detected",
        checked_secret_count = summary.checked_secret_count,
        checked_secret_version_count = summary.checked_secret_version_count,
        checked_audit_event_count = summary.checked_audit_event_count,
        violation_count = summary.violation_count,
        audit_record_outcome = audit_record_outcome_label(audit_record_outcome),
        "integrity check detected violations"
    );

    Err(IntegrityCheckError::ViolationDetected {
        violation_count: summary.violation_count,
    })
}

pub async fn run_cli(config: AppConfig, args: &[String]) -> Result<(), IntegrityCheckError> {
    match args {
        [command] if command == "once" => {
            let state = build_cli_state(config).await?;
            match run_integrity_check_once(&state, IntegrityCheckTrigger::Cli).await {
                Ok(outcome) => {
                    println!(
                        "integrity_check result=success request_id={} checked_secret_count={} checked_secret_version_count={} checked_audit_event_count={} violation_count={}",
                        outcome.request_id.as_canonical_string(),
                        outcome.summary.checked_secret_count,
                        outcome.summary.checked_secret_version_count,
                        outcome.summary.checked_audit_event_count,
                        outcome.summary.violation_count
                    );
                    Ok(())
                }
                Err(error) => Err(error),
            }
        }
        _ => Err(IntegrityCheckError::Usage(usage())),
    }
}

pub fn usage() -> String {
    ["usage:", "  mipsorcu integrity-check once"].join("\n")
}

pub fn build_integrity_check_metadata(
    summary: &IntegrityCheckSummary,
    trigger: IntegrityCheckTrigger,
    error_code: Option<&'static str>,
) -> Result<AuditMetadata, AuditEventError> {
    build_integrity_check_metadata_with_duration(summary, trigger, error_code, 0)
}

fn build_integrity_check_metadata_with_duration(
    summary: &IntegrityCheckSummary,
    trigger: IntegrityCheckTrigger,
    error_code: Option<&'static str>,
    duration_ms: u64,
) -> Result<AuditMetadata, AuditEventError> {
    IntegrityCheckMetadata::new(
        summary.checked_secret_count,
        summary.checked_secret_version_count,
        summary.checked_audit_event_count,
        summary.violation_count,
        summary.violation_summary.clone(),
        trigger,
    )
    .with_duration_ms(duration_ms)
    .with_error_code_opt(error_code)
    .build()
}

async fn record_integrity_check_audit(
    state: &AppState,
    request_id: &RequestId,
    result: AuditResult,
    summary: &IntegrityCheckSummary,
    trigger: IntegrityCheckTrigger,
    error_code: Option<&'static str>,
    duration_ms: u64,
) -> Result<AuditRecordOutcome, IntegrityCheckError> {
    let metadata =
        build_integrity_check_metadata_with_duration(summary, trigger, error_code, duration_ms)
            .map_err(IntegrityCheckError::Metadata)?;
    audit_reporter::record_integrity_check_audit(
        state,
        request_id,
        IntegrityCheckAudit {
            result,
            metadata,
            error_code,
        },
    )
    .await
    .map_err(IntegrityCheckError::AuditRecordFailed)
}

fn elapsed_ms(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

async fn build_cli_state(config: AppConfig) -> Result<AppState, IntegrityCheckError> {
    let http_client = crate::server::config::build_outbound_http_client(&config)
        .map_err(|error| IntegrityCheckError::Config(error.to_string()))?;
    let jwt_verifier = crate::server::background::initialize_jwt_verifier_from_jwks_url(
        &http_client,
        &config.jwks_url,
        &config.jwt_issuer,
        &config.jwt_audience,
    )
    .await
    .map_err(|error| IntegrityCheckError::Config(error.to_string()))?;
    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url,
        config.supabase_service_role_key,
        config.supabase_publishable_key,
    ));
    supabase_client
        .ensure_active_ledger_signing_public_key(&config.ledger_signing_key.verification_key())
        .await
        .map_err(|error| IntegrityCheckError::Config(error.to_string()))?;
    let audit_appender = SupabaseAuditAppender::new(supabase_client.clone());
    let audit_fallback_store = LocalAuditFallbackStore::with_rollover_config(
        &config.audit_fallback_path,
        &config.audit_fallback_archive_dir,
        config.audit_fallback_rotate_size_bytes,
    );
    let audit_recorder = Arc::new(AuditRecorder::new(
        audit_appender,
        audit_fallback_store.clone(),
    ));
    let ledger_appender = Arc::new(crate::server::ledger_appender::LedgerAppender::new(
        supabase_client.clone(),
        config.ledger_signing_key.clone(),
    ));
    let incident_recorder = Arc::new(IncidentRecorder::new(
        supabase_client.clone(),
        ledger_appender.clone(),
        crate::incident::AnyNotificationSink::Dummy(DummyNotificationSink::new()),
    ));
    let readiness_state = ReadinessState::new();
    let siem_forwarder = SiemForwarder::new(
        AnySiemSink::InMemory(InMemorySiemSink::new()),
        LocalSiemFallbackBuffer::new(config.siem_buffer_path.clone()),
    );
    let siem_forwarding = Arc::new(crate::server::siem_forwarding::SiemForwardingService::new(
        siem_forwarder,
        audit_recorder.clone(),
        readiness_state.clone(),
    ));

    Ok(AppState {
        master_key_ring: Arc::new(config.master_key_ring),
        alias_encryption_key: Arc::new(config.alias_encryption_key),
        alias_encryption_key_version: config.alias_encryption_key_version,
        alias_fingerprint_key: Arc::new(config.alias_fingerprint_key),
        alias_fingerprint_key_version: config.alias_fingerprint_key_version,
        jwt_verifier: Arc::new(jwt_verifier),
        supabase_client,
        audit_recorder,
        ledger_appender,
        incident_recorder,
        siem_forwarding,
        audit_fallback_store,
        readiness_state,
        health_readiness_poll_interval: config.health_readiness_poll_interval,
        siem_long_failure_threshold: config.siem_long_failure_threshold,
        http_handler_timeout: config.http_handler_timeout,
        http_rate_limit_requests: config.http_rate_limit_requests,
        http_rate_limit_window: config.http_rate_limit_window,
    })
}

fn audit_record_outcome_label(outcome: AuditRecordOutcome) -> &'static str {
    match outcome {
        AuditRecordOutcome::PrimarySucceeded => "primary_succeeded",
        AuditRecordOutcome::FallbackSucceeded => "fallback_succeeded",
    }
}

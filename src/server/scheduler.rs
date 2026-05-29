use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(test)]
use time::{Date, Time};
use time::{Month, OffsetDateTime};
use tokio::sync::watch;

use crate::archive::LocalFileArchiveBackend;
use crate::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditResult, AuditTrigger, RequestId,
    SchedulerJobMetadata,
};
use crate::incident::{
    IncidentRecordInput, IncidentType, dedupe_key, ledger_payload_contains_forbidden_key,
    scheduler_incident_type, severity_for_incident,
};
use crate::ledger::{
    DigestHash, LedgerChainHead, LedgerEntryId, LedgerEntryType, LedgerPayload, LedgerResult,
    LedgerSequenceNo, MonthlyDigestPeriod, SignedLedgerEntry, SignedMonthlyDigest,
    build_monthly_digest_canonical_form,
};
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts};
use crate::server::state::AppState;
use crate::server::supabase::{
    LedgerVerificationMaterialRow, MonthlyDigestVerificationMaterials, SupabaseClient,
};
use crate::server::use_cases::export_digest_to_archive::export_digest_to_archive_with_incident;
use crate::server::use_cases::generate_monthly_digest::{
    GenerateMonthlyDigestInput, generate_monthly_digest, record_monthly_digest_failure_audit,
};
use crate::server::use_cases::request_timestamping_for_digest::request_timestamping_for_digest_with_incident;
use crate::timestamping::InMemoryTimestampingService;
use crate::types::SourceEventAt;

use super::key_rotation::envelope_migration::run_scheduled_envelope_migration;
use super::restore_test;

#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    pub startup_delay: Duration,
    pub poll_interval: Duration,
    pub monthly_day: u8,
    pub monthly_hour_utc: u8,
    pub quarterly_hour_utc: u8,
    pub daily_hour_utc: u8,
    pub envelope_migration_batch_size: u32,
    pub envelope_migration_max_batches: u32,
    pub restore_test_sample_limit: u32,
    pub local_archive_dir: std::path::PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ScheduledJobName {
    LedgerHashChainFullVerify,
    LedgerSignatureFullVerify,
    MonthlyDigestGenerate,
    ArchiveExport,
    MonthlyTimestampingObtain,
    DailyEnvelopeLazyMigration,
    RestoreTest,
    SignatureKeyReviewReminder,
    AuditorPermissionReviewReminder,
}

impl ScheduledJobName {
    fn as_str(self) -> &'static str {
        match self {
            Self::LedgerHashChainFullVerify => "ledger_hash_chain_full_verify",
            Self::LedgerSignatureFullVerify => "ledger_signature_full_verify",
            Self::MonthlyDigestGenerate => "monthly_digest_generate",
            Self::ArchiveExport => "archive_export",
            Self::MonthlyTimestampingObtain => "monthly_timestamping_obtain",
            Self::DailyEnvelopeLazyMigration => "daily_envelope_lazy_migration",
            Self::RestoreTest => "restore_test",
            Self::SignatureKeyReviewReminder => "signature_key_review_reminder",
            Self::AuditorPermissionReviewReminder => "auditor_permission_review_reminder",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct JobRunKey {
    job_name: ScheduledJobName,
    period_key: String,
}

#[derive(Debug)]
struct JobLock {
    running: AtomicBool,
}

impl JobLock {
    fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
        }
    }

    fn try_enter(&self) -> Option<JobLockGuard<'_>> {
        self.running
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| JobLockGuard { lock: self })
    }
}

struct JobLockGuard<'a> {
    lock: &'a JobLock,
}

impl Drop for JobLockGuard<'_> {
    fn drop(&mut self) {
        self.lock.running.store(false, Ordering::Release);
    }
}

struct SchedulerRuntimeState {
    completed: HashSet<JobRunKey>,
    hash_chain_lock: JobLock,
    signature_lock: JobLock,
    digest_lock: JobLock,
    archive_lock: JobLock,
    timestamping_lock: JobLock,
    envelope_migration_lock: JobLock,
    restore_lock: JobLock,
    signature_review_lock: JobLock,
    auditor_review_lock: JobLock,
}

impl SchedulerRuntimeState {
    fn new() -> Self {
        Self {
            completed: HashSet::new(),
            hash_chain_lock: JobLock::new(),
            signature_lock: JobLock::new(),
            digest_lock: JobLock::new(),
            archive_lock: JobLock::new(),
            timestamping_lock: JobLock::new(),
            envelope_migration_lock: JobLock::new(),
            restore_lock: JobLock::new(),
            signature_review_lock: JobLock::new(),
            auditor_review_lock: JobLock::new(),
        }
    }

    fn lock_for(&self, job_name: ScheduledJobName) -> &JobLock {
        match job_name {
            ScheduledJobName::LedgerHashChainFullVerify => &self.hash_chain_lock,
            ScheduledJobName::LedgerSignatureFullVerify => &self.signature_lock,
            ScheduledJobName::MonthlyDigestGenerate => &self.digest_lock,
            ScheduledJobName::ArchiveExport => &self.archive_lock,
            ScheduledJobName::MonthlyTimestampingObtain => &self.timestamping_lock,
            ScheduledJobName::DailyEnvelopeLazyMigration => &self.envelope_migration_lock,
            ScheduledJobName::RestoreTest => &self.restore_lock,
            ScheduledJobName::SignatureKeyReviewReminder => &self.signature_review_lock,
            ScheduledJobName::AuditorPermissionReviewReminder => &self.auditor_review_lock,
        }
    }
}

pub async fn run_scheduler_loop(
    state: AppState,
    config: SchedulerConfig,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    if sleep_until_first_run(config.startup_delay, &mut shutdown_receiver).await {
        return;
    }

    let mut runtime_state = SchedulerRuntimeState::new();
    run_due_jobs(
        &state,
        &config,
        &mut runtime_state,
        OffsetDateTime::now_utc(),
    )
    .await;

    let mut interval = tokio::time::interval(config.poll_interval);
    interval.tick().await;

    loop {
        tokio::select! {
            result = shutdown_receiver.changed() => {
                if result.is_err() || *shutdown_receiver.borrow() {
                    tracing::info!("scheduler loop stopped");
                    break;
                }
            }
            _ = interval.tick() => {
                run_due_jobs(&state, &config, &mut runtime_state, OffsetDateTime::now_utc()).await;
            }
        }
    }
}

async fn sleep_until_first_run(
    startup_delay: Duration,
    shutdown_receiver: &mut watch::Receiver<bool>,
) -> bool {
    if startup_delay.is_zero() {
        return false;
    }

    tokio::select! {
        result = shutdown_receiver.changed() => {
            if result.is_err() || *shutdown_receiver.borrow() {
                tracing::info!("scheduler loop stopped before first run");
                true
            } else {
                false
            }
        }
        _ = tokio::time::sleep(startup_delay) => false,
    }
}

async fn run_due_jobs(
    state: &AppState,
    config: &SchedulerConfig,
    runtime_state: &mut SchedulerRuntimeState,
    now: OffsetDateTime,
) {
    if monthly_due(now, config.monthly_day, config.monthly_hour_utc) {
        let Ok(period) = previous_month_period(now) else {
            tracing::error!("scheduler failed to compute previous monthly digest period");
            return;
        };
        let key = JobRunKey {
            job_name: ScheduledJobName::LedgerHashChainFullVerify,
            period_key: period.as_str().to_owned(),
        };
        let hash_period = period.clone();
        let hash_result = run_once_per_period(
            runtime_state,
            key,
            run_full_ledger_hash_chain_verify_job(
                state,
                ScheduledJobName::LedgerHashChainFullVerify,
                Some(hash_period),
            ),
        )
        .await;

        let key = JobRunKey {
            job_name: ScheduledJobName::LedgerSignatureFullVerify,
            period_key: period.as_str().to_owned(),
        };
        let signature_period = period.clone();
        let signature_result = run_once_per_period(
            runtime_state,
            key,
            run_full_ledger_signature_verify_job(
                state,
                ScheduledJobName::LedgerSignatureFullVerify,
                Some(signature_period),
            ),
        )
        .await;

        if hash_result.is_err() || signature_result.is_err() {
            let digest_period = period.clone();
            let key = JobRunKey {
                job_name: ScheduledJobName::MonthlyDigestGenerate,
                period_key: digest_period.as_str().to_owned(),
            };
            let _ = run_once_per_period(
                runtime_state,
                key,
                record_precondition_failure_job(
                    state,
                    ScheduledJobName::MonthlyDigestGenerate,
                    Some(digest_period),
                    "ledger_verification_precondition_failed",
                ),
            )
            .await;

            let archive_period = period.clone();
            let key = JobRunKey {
                job_name: ScheduledJobName::ArchiveExport,
                period_key: archive_period.as_str().to_owned(),
            };
            let _ = run_once_per_period(
                runtime_state,
                key,
                record_precondition_failure_job(
                    state,
                    ScheduledJobName::ArchiveExport,
                    Some(archive_period),
                    "ledger_verification_precondition_failed",
                ),
            )
            .await;

            return;
        }

        let key = JobRunKey {
            job_name: ScheduledJobName::MonthlyDigestGenerate,
            period_key: period.as_str().to_owned(),
        };
        let digest_result = run_once_per_period(
            runtime_state,
            key,
            run_monthly_digest_generate_job(state, period.clone()),
        )
        .await;

        let signed_digest = match digest_result {
            Ok(Some(digest)) => digest,
            Ok(None) => match fetch_signed_digest(state.supabase_client.as_ref(), &period).await {
                Ok(digest) => digest,
                Err(error_code) => {
                    let key = JobRunKey {
                        job_name: ScheduledJobName::ArchiveExport,
                        period_key: period.as_str().to_owned(),
                    };
                    let _ = run_once_per_period(
                        runtime_state,
                        key,
                        record_precondition_failure_job(
                            state,
                            ScheduledJobName::ArchiveExport,
                            Some(period),
                            error_code,
                        ),
                    )
                    .await;
                    return;
                }
            },
            Err(_) => {
                let key = JobRunKey {
                    job_name: ScheduledJobName::ArchiveExport,
                    period_key: period.as_str().to_owned(),
                };
                let _ = run_once_per_period(
                    runtime_state,
                    key,
                    record_precondition_failure_job(
                        state,
                        ScheduledJobName::ArchiveExport,
                        Some(period),
                        "monthly_digest_generate_failed",
                    ),
                )
                .await;
                return;
            }
        };

        let archive_period = signed_digest.period.clone();
        let key = JobRunKey {
            job_name: ScheduledJobName::ArchiveExport,
            period_key: archive_period.as_str().to_owned(),
        };
        let timestamping_digest = signed_digest.clone();
        let _ = run_once_per_period(
            runtime_state,
            key,
            run_archive_export_job(state, config, signed_digest),
        )
        .await;

        let timestamping_period = timestamping_digest.period.clone();
        let key = JobRunKey {
            job_name: ScheduledJobName::MonthlyTimestampingObtain,
            period_key: timestamping_period.as_str().to_owned(),
        };
        let _ = run_once_per_period(
            runtime_state,
            key,
            run_monthly_timestamping_obtain_job(state, timestamping_digest),
        )
        .await;
    }

    if daily_due(now, config.daily_hour_utc) {
        let daily_key = daily_period_key(now);
        let key = JobRunKey {
            job_name: ScheduledJobName::DailyEnvelopeLazyMigration,
            period_key: daily_key,
        };
        let _ = run_once_per_period(
            runtime_state,
            key,
            run_daily_envelope_lazy_migration_job(state, config),
        )
        .await;
    }

    if quarterly_due(now, config.monthly_day, config.quarterly_hour_utc) {
        let quarter_key = quarter_period_key(now);
        for job_name in [
            ScheduledJobName::RestoreTest,
            ScheduledJobName::SignatureKeyReviewReminder,
            ScheduledJobName::AuditorPermissionReviewReminder,
        ] {
            let key = JobRunKey {
                job_name,
                period_key: quarter_key.clone(),
            };
            let _ = run_once_per_period(
                runtime_state,
                key,
                run_quarterly_job(state, config, job_name),
            )
            .await;
        }
    }
}

async fn run_once_per_period<Fut, T>(
    runtime_state: &mut SchedulerRuntimeState,
    key: JobRunKey,
    run: Fut,
) -> Result<Option<T>, &'static str>
where
    Fut: std::future::Future<Output = Result<T, &'static str>>,
{
    if runtime_state.completed.contains(&key) {
        return Ok(None);
    }

    let result = {
        let Some(guard) = runtime_state.lock_for(key.job_name).try_enter() else {
            tracing::info!(
                job_name = key.job_name.as_str(),
                "scheduled job already running; skipped"
            );
            return Err("scheduler_job_already_running");
        };
        let result = run.await;
        drop(guard);
        result
    };

    match result {
        Ok(output) => {
            runtime_state.completed.insert(key);
            Ok(Some(output))
        }
        Err(error_code) => {
            tracing::error!(
                job_name = key.job_name.as_str(),
                error_code,
                "scheduled job failed"
            );
            Err(error_code)
        }
    }
}

async fn run_quarterly_job(
    state: &AppState,
    config: &SchedulerConfig,
    job_name: ScheduledJobName,
) -> Result<(), &'static str> {
    match job_name {
        ScheduledJobName::RestoreTest => {
            match restore_test::run_restore_test_once(
                state,
                config.restore_test_sample_limit,
                AuditTrigger::Background,
            )
            .await
            {
                restore_test::RestoreTestOutcome::Success => {
                    record_scheduler_job_result(
                        state,
                        job_name,
                        AuditResult::Success,
                        None,
                        None,
                        0,
                    )
                    .await
                }
                restore_test::RestoreTestOutcome::Failure { error_code } => {
                    record_scheduler_job_result(
                        state,
                        job_name,
                        AuditResult::Failure,
                        Some(error_code),
                        None,
                        0,
                    )
                    .await
                    .and(Err(error_code))
                }
            }
        }
        ScheduledJobName::SignatureKeyReviewReminder
        | ScheduledJobName::AuditorPermissionReviewReminder => {
            record_scheduler_job_result(state, job_name, AuditResult::Success, None, None, 0).await
        }
        _ => Ok(()),
    }
}

async fn record_precondition_failure_job(
    state: &AppState,
    job_name: ScheduledJobName,
    period: Option<MonthlyDigestPeriod>,
    error_code: &'static str,
) -> Result<(), &'static str> {
    record_scheduler_job_result(
        state,
        job_name,
        AuditResult::Failure,
        Some(error_code),
        period,
        0,
    )
    .await?;
    Err(error_code)
}

async fn record_mapped_scheduler_incident(
    state: &AppState,
    job_name: ScheduledJobName,
    error_code: Option<&'static str>,
    period: Option<MonthlyDigestPeriod>,
) {
    let Some(error_code) = error_code else {
        return;
    };
    let Some(incident_type) = scheduler_incident_type(error_code) else {
        return;
    };

    record_scheduler_incident(state, job_name, incident_type, error_code, period).await;
}

async fn record_scheduler_incident(
    state: &AppState,
    job_name: ScheduledJobName,
    incident_type: IncidentType,
    error_code: &'static str,
    period: Option<MonthlyDigestPeriod>,
) {
    let detection_source = job_name.as_str();
    let mut input = IncidentRecordInput::new(
        incident_type,
        severity_for_incident(incident_type),
        detection_source,
        dedupe_key(incident_type, detection_source, period.as_ref()),
        error_code,
    );
    if let Some(period) = period {
        input = input.with_target_year_month(period);
    }

    match state.incident_recorder.record(input).await {
        Ok(result) => {
            tracing::info!(
                job_name = detection_source,
                incident_type = incident_type.as_str(),
                notification_result = result.notification_result.as_str(),
                suppressed = result.suppressed,
                "scheduler incident recorded"
            );
        }
        Err(error) => {
            tracing::error!(
                job_name = detection_source,
                incident_type = incident_type.as_str(),
                error = %error,
                "scheduler incident recording failed"
            );
        }
    }
}

async fn run_full_ledger_hash_chain_verify_job(
    state: &AppState,
    job_name: ScheduledJobName,
    period: Option<MonthlyDigestPeriod>,
) -> Result<(), &'static str> {
    let started_at = Instant::now();
    let outcome = verify_full_ledger_hash_chain(state.supabase_client.as_ref()).await;
    let (result, error_code) = match outcome {
        Ok(summary) if summary.valid => {
            tracing::info!(
                job_name = job_name.as_str(),
                checked_count = summary.checked_count,
                "full ledger hash chain verification completed"
            );
            (AuditResult::Success, None)
        }
        Ok(summary) => {
            tracing::error!(
                job_name = job_name.as_str(),
                checked_count = summary.checked_count,
                error_code = summary.error_code.unwrap_or("ledger_verification_failed"),
                "full ledger hash chain verification detected an anomaly without auto-repair"
            );
            (
                AuditResult::Failure,
                summary.error_code.or(Some("ledger_verification_failed")),
            )
        }
        Err(error_code) => (AuditResult::Failure, Some(error_code)),
    };
    let incident_period = period.clone();
    record_scheduler_job_result(
        state,
        job_name,
        result,
        error_code,
        period,
        elapsed_ms(started_at),
    )
    .await?;

    if result == AuditResult::Failure {
        record_mapped_scheduler_incident(state, job_name, error_code, incident_period).await;
    }

    if result == AuditResult::Success {
        Ok(())
    } else {
        Err(error_code.unwrap_or("ledger_verification_failed"))
    }
}

async fn run_full_ledger_signature_verify_job(
    state: &AppState,
    job_name: ScheduledJobName,
    period: Option<MonthlyDigestPeriod>,
) -> Result<(), &'static str> {
    let started_at = Instant::now();
    let outcome = verify_full_ledger_signatures(state.supabase_client.as_ref()).await;
    let (result, error_code) = match outcome {
        Ok(summary) if summary.valid => {
            tracing::info!(
                job_name = job_name.as_str(),
                checked_count = summary.checked_count,
                "full ledger signature verification completed"
            );
            (AuditResult::Success, None)
        }
        Ok(summary) => {
            tracing::error!(
                job_name = job_name.as_str(),
                checked_count = summary.checked_count,
                error_code = summary
                    .error_code
                    .unwrap_or("ledger_signature_verification_failed"),
                "full ledger signature verification detected an anomaly without auto-repair"
            );
            (
                AuditResult::Failure,
                summary
                    .error_code
                    .or(Some("ledger_signature_verification_failed")),
            )
        }
        Err(error_code) => (AuditResult::Failure, Some(error_code)),
    };
    let incident_period = period.clone();
    record_scheduler_job_result(
        state,
        job_name,
        result,
        error_code,
        period,
        elapsed_ms(started_at),
    )
    .await?;

    if result == AuditResult::Failure {
        record_mapped_scheduler_incident(state, job_name, error_code, incident_period).await;
    }

    if result == AuditResult::Success {
        Ok(())
    } else {
        Err(error_code.unwrap_or("ledger_signature_verification_failed"))
    }
}

async fn run_monthly_digest_generate_job(
    state: &AppState,
    period: MonthlyDigestPeriod,
) -> Result<SignedMonthlyDigest, &'static str> {
    let started_at = Instant::now();
    let request_id = RequestId::generate().map_err(|_| "scheduler_request_id_failed")?;
    let source_event_at =
        SourceEventAt::now_utc().map_err(|_| "scheduler_source_event_at_failed")?;
    let input = GenerateMonthlyDigestInput {
        period: period.clone(),
        generated_at: source_event_at.clone(),
        request_id: request_id.clone(),
    };

    let signed_digest = match generate_monthly_digest(
        &state.supabase_client,
        &state.ledger_appender,
        &state.audit_recorder,
        input,
    )
    .await
    {
        Ok(digest) => digest,
        Err(error) => {
            if error.as_error_code() == "monthly_digest_duplicate" {
                match fetch_signed_digest(state.supabase_client.as_ref(), &period).await {
                    Ok(digest) => digest,
                    Err(_) => {
                        record_scheduler_job_result(
                            state,
                            ScheduledJobName::MonthlyDigestGenerate,
                            AuditResult::Failure,
                            Some("monthly_digest_existing_fetch_failed"),
                            Some(period),
                            elapsed_ms(started_at),
                        )
                        .await?;
                        return Err("monthly_digest_existing_fetch_failed");
                    }
                }
            } else {
                record_monthly_digest_failure_audit(
                    &state.audit_recorder,
                    &request_id,
                    &period,
                    &error,
                    &source_event_at,
                )
                .await;
                record_scheduler_job_result(
                    state,
                    ScheduledJobName::MonthlyDigestGenerate,
                    AuditResult::Failure,
                    Some("monthly_digest_generate_failed"),
                    Some(period),
                    elapsed_ms(started_at),
                )
                .await?;
                return Err("monthly_digest_generate_failed");
            }
        }
    };

    record_scheduler_job_result(
        state,
        ScheduledJobName::MonthlyDigestGenerate,
        AuditResult::Success,
        None,
        Some(period),
        elapsed_ms(started_at),
    )
    .await?;
    Ok(signed_digest)
}

async fn run_archive_export_job(
    state: &AppState,
    config: &SchedulerConfig,
    signed_digest: SignedMonthlyDigest,
) -> Result<(), &'static str> {
    let started_at = Instant::now();
    let period = signed_digest.period.clone();
    let archive_request_id = RequestId::generate().map_err(|_| "scheduler_request_id_failed")?;
    let archived_at = SourceEventAt::now_utc().map_err(|_| "scheduler_source_event_at_failed")?;
    let archive_backend = LocalFileArchiveBackend::new(config.local_archive_dir.clone());
    if export_digest_to_archive_with_incident(
        &archive_backend,
        &state.audit_recorder,
        &state.ledger_appender,
        state.incident_recorder.as_ref(),
        &signed_digest,
        archive_request_id,
        archived_at,
    )
    .await
    .is_err()
    {
        record_scheduler_job_result(
            state,
            ScheduledJobName::ArchiveExport,
            AuditResult::Failure,
            Some("archive_export_failed"),
            Some(period),
            elapsed_ms(started_at),
        )
        .await?;
        return Err("archive_export_failed");
    }

    record_scheduler_job_result(
        state,
        ScheduledJobName::ArchiveExport,
        AuditResult::Success,
        None,
        Some(period),
        elapsed_ms(started_at),
    )
    .await?;
    Ok(())
}

async fn run_monthly_timestamping_obtain_job(
    state: &AppState,
    signed_digest: SignedMonthlyDigest,
) -> Result<(), &'static str> {
    let started_at = Instant::now();
    let period = signed_digest.period.clone();
    let request_id = RequestId::generate().map_err(|_| "scheduler_request_id_failed")?;
    let requested_at = SourceEventAt::now_utc().map_err(|_| "scheduler_source_event_at_failed")?;
    let service = InMemoryTimestampingService::new();
    let outcome = request_timestamping_for_digest_with_incident(
        &service,
        &state.audit_recorder,
        &state.ledger_appender,
        state.incident_recorder.as_ref(),
        &signed_digest,
        request_id,
        requested_at,
    )
    .await;
    let (result, error_code): (AuditResult, Option<&'static str>) = match outcome {
        Ok(_) => (AuditResult::Success, None),
        Err(_) => (
            AuditResult::Failure,
            Some("monthly_timestamping_obtain_failed"),
        ),
    };
    record_scheduler_job_result(
        state,
        ScheduledJobName::MonthlyTimestampingObtain,
        result,
        error_code,
        Some(period),
        elapsed_ms(started_at),
    )
    .await?;
    if result == AuditResult::Success {
        Ok(())
    } else {
        Err(error_code.unwrap_or("monthly_timestamping_obtain_failed"))
    }
}

async fn run_daily_envelope_lazy_migration_job(
    state: &AppState,
    config: &SchedulerConfig,
) -> Result<(), &'static str> {
    let started_at = Instant::now();
    let outcome = run_scheduled_envelope_migration(
        state.supabase_client.clone(),
        state.ledger_appender.clone(),
        state.master_key_ring.clone(),
        config.envelope_migration_batch_size,
        config.envelope_migration_max_batches,
    )
    .await;

    let (result, error_code): (AuditResult, Option<&'static str>) = match &outcome {
        Ok(summary) => {
            tracing::info!(
                job_name = ScheduledJobName::DailyEnvelopeLazyMigration.as_str(),
                selected_count = summary.selected_count,
                success_count = summary.success_count,
                failure_count = summary.failure_count,
                remaining_legacy_rows = summary.remaining_legacy_rows,
                batches_executed = summary.batches_executed,
                "daily envelope lazy migration completed"
            );
            if summary.failure_count == 0 {
                (AuditResult::Success, None)
            } else {
                (
                    AuditResult::Failure,
                    Some("envelope_migration_partial_failure"),
                )
            }
        }
        Err(error) => {
            tracing::error!(
                job_name = ScheduledJobName::DailyEnvelopeLazyMigration.as_str(),
                error = %error,
                "daily envelope lazy migration failed"
            );
            (
                AuditResult::Failure,
                Some(map_envelope_migration_error(error)),
            )
        }
    };

    let _ = outcome;
    record_scheduler_job_result(
        state,
        ScheduledJobName::DailyEnvelopeLazyMigration,
        result,
        error_code,
        None,
        elapsed_ms(started_at),
    )
    .await?;
    if result == AuditResult::Success {
        Ok(())
    } else {
        Err(error_code.unwrap_or("envelope_migration_failed"))
    }
}

fn map_envelope_migration_error(error: &super::key_rotation::KeyRotationCliError) -> &'static str {
    use super::key_rotation::KeyRotationCliError;
    match error {
        KeyRotationCliError::Config(_) => "envelope_migration_config_invalid",
        KeyRotationCliError::Supabase(_) => "envelope_migration_supabase_failed",
        KeyRotationCliError::Audit(_) => "envelope_migration_audit_failed",
        KeyRotationCliError::Crypto(_) => "envelope_migration_crypto_failed",
        KeyRotationCliError::Usage(_) => "envelope_migration_failed",
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LedgerVerificationSummary {
    pub(crate) valid: bool,
    pub(crate) checked_count: u64,
    pub(crate) error_code: Option<&'static str>,
}

async fn verify_full_ledger_hash_chain(
    client: &SupabaseClient,
) -> Result<LedgerVerificationSummary, &'static str> {
    let (chain_head, rows) = fetch_full_ledger_material_rows(client).await?;

    tokio::task::spawn_blocking(move || verify_hash_chain_rows(chain_head, rows))
        .await
        .map_err(|_| "ledger_verification_join_failed")?
}

pub(crate) async fn verify_full_ledger_signatures(
    client: &SupabaseClient,
) -> Result<LedgerVerificationSummary, &'static str> {
    let (_chain_head, rows) = fetch_full_ledger_material_rows(client).await?;

    tokio::task::spawn_blocking(move || verify_signature_rows(rows))
        .await
        .map_err(|_| "ledger_verification_join_failed")?
}

async fn fetch_full_ledger_material_rows(
    client: &SupabaseClient,
) -> Result<(LedgerChainHead, Vec<LedgerVerificationMaterialRow>), &'static str> {
    let chain_head = client
        .fetch_ledger_chain_head()
        .await
        .map_err(|_| "ledger_chain_head_fetch_failed")?;
    if chain_head.last_sequence_no() == 0 {
        return Ok((chain_head, Vec::new()));
    }

    let end = LedgerSequenceNo::new(chain_head.last_sequence_no())
        .map_err(|_| "ledger_sequence_invalid")?;
    let start = LedgerSequenceNo::new(1).map_err(|_| "ledger_sequence_invalid")?;
    let rows = client
        .export_ledger_verification_materials(start, end)
        .await
        .map_err(|_| "ledger_export_failed")?;

    Ok((chain_head, rows))
}

fn verify_hash_chain_rows(
    chain_head: LedgerChainHead,
    rows: Vec<LedgerVerificationMaterialRow>,
) -> Result<LedgerVerificationSummary, &'static str> {
    let mut entries: Vec<SignedLedgerEntry> = Vec::with_capacity(rows.len());
    for row in &rows {
        if ledger_payload_contains_forbidden_key(&row.payload) {
            return Ok(LedgerVerificationSummary {
                valid: false,
                checked_count: entry_count(entries.len()),
                error_code: Some("ledger_payload_forbidden_key"),
            });
        }

        let entry = row
            .try_restore_signed_ledger_entry()
            .map_err(|_| "ledger_entry_restore_failed")?;
        entries.push(entry);
    }

    let mut previous_sequence_no = LedgerChainHead::genesis().last_sequence_no();
    let mut previous_hash = LedgerChainHead::genesis().last_entry_hash();
    for entry in &entries {
        let expected_sequence_no = previous_sequence_no
            .checked_add(1)
            .ok_or("ledger_sequence_overflow")?;
        let actual_sequence_no = entry.sequence_no().get();

        if actual_sequence_no != expected_sequence_no {
            return Ok(LedgerVerificationSummary {
                valid: false,
                checked_count: entry_count(entries.len()),
                error_code: Some("ledger_sequence_gap"),
            });
        }

        if entry.previous_entry_hash() != previous_hash {
            return Ok(LedgerVerificationSummary {
                valid: false,
                checked_count: entry_count(entries.len()),
                error_code: Some("ledger_previous_hash_mismatch"),
            });
        }

        if entry.recompute_entry_hash() != entry.entry_hash() {
            return Ok(LedgerVerificationSummary {
                valid: false,
                checked_count: entry_count(entries.len()),
                error_code: Some("ledger_entry_hash_mismatch"),
            });
        }

        previous_sequence_no = actual_sequence_no;
        previous_hash = entry.entry_hash();
    }

    if previous_sequence_no != chain_head.last_sequence_no()
        || previous_hash != chain_head.last_entry_hash()
    {
        return Ok(LedgerVerificationSummary {
            valid: false,
            checked_count: entry_count(entries.len()),
            error_code: Some("ledger_chain_head_mismatch"),
        });
    }

    Ok(LedgerVerificationSummary {
        valid: true,
        checked_count: entry_count(entries.len()),
        error_code: None,
    })
}

fn verify_signature_rows(
    rows: Vec<LedgerVerificationMaterialRow>,
) -> Result<LedgerVerificationSummary, &'static str> {
    let mut checked_count = 0;
    for row in &rows {
        if ledger_payload_contains_forbidden_key(&row.payload) {
            return Ok(LedgerVerificationSummary {
                valid: false,
                checked_count,
                error_code: Some("ledger_payload_forbidden_key"),
            });
        }

        let entry = row
            .try_restore_signed_ledger_entry()
            .map_err(|_| "ledger_entry_restore_failed")?;
        let Some(key) = row
            .try_restore_verifying_key()
            .map_err(|_| "ledger_key_restore_failed")?
        else {
            return Ok(LedgerVerificationSummary {
                valid: false,
                checked_count: entry_count(rows.len()),
                error_code: Some("ledger_signature_key_missing"),
            });
        };

        if entry.verify_signature(&key).is_err() {
            return Ok(LedgerVerificationSummary {
                valid: false,
                checked_count: entry_count(rows.len()),
                error_code: Some("ledger_signature_invalid"),
            });
        }

        checked_count += 1;
    }

    Ok(LedgerVerificationSummary {
        valid: true,
        checked_count,
        error_code: None,
    })
}

fn entry_count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

async fn fetch_signed_digest(
    client: &SupabaseClient,
    period: &MonthlyDigestPeriod,
) -> Result<SignedMonthlyDigest, &'static str> {
    let materials = client
        .fetch_monthly_digest_for_verification(period.as_str())
        .await
        .map_err(|_| "monthly_digest_fetch_failed")?
        .ok_or("monthly_digest_not_found")?;
    signed_digest_from_materials(materials)
}

fn signed_digest_from_materials(
    materials: MonthlyDigestVerificationMaterials,
) -> Result<SignedMonthlyDigest, &'static str> {
    let canonical_bytes = build_monthly_digest_canonical_form(
        &materials.target_year_month,
        materials.start_sequence_no,
        materials.end_sequence_no,
        materials.start_entry_hash,
        materials.end_entry_hash,
        materials.stored_entry_count,
        &materials.digest_generated_at,
        materials.signature_key_version,
    )
    .map_err(|_| "monthly_digest_canonical_build_failed")?;
    let digest_hash = DigestHash::from_canonical_bytes(&canonical_bytes);

    Ok(SignedMonthlyDigest {
        period: materials.target_year_month,
        start_sequence_no: materials.start_sequence_no,
        end_sequence_no: materials.end_sequence_no,
        start_entry_hash: materials.start_entry_hash,
        end_entry_hash: materials.end_entry_hash,
        entry_count: materials.stored_entry_count,
        digest_generated_at: materials.digest_generated_at,
        signature_key_version: materials.signature_key_version,
        canonical_bytes,
        digest_hash,
        sbc_signature: materials.sbc_signature,
    })
}

async fn record_scheduler_job_result(
    state: &AppState,
    job_name: ScheduledJobName,
    result: AuditResult,
    error_code: Option<&'static str>,
    period: Option<MonthlyDigestPeriod>,
    duration_ms: u64,
) -> Result<(), &'static str> {
    let request_id = match RequestId::generate() {
        Ok(request_id) => request_id,
        Err(error) => {
            tracing::error!(error = %error, job_name = job_name.as_str(), "scheduler audit request id generation failed");
            return Err("scheduler_request_id_failed");
        }
    };
    let source_event_at = match SourceEventAt::now_utc() {
        Ok(source_event_at) => source_event_at,
        Err(error) => {
            tracing::error!(error = %error, job_name = job_name.as_str(), "scheduler source_event_at generation failed");
            return Err("scheduler_source_event_at_failed");
        }
    };

    let mut metadata_builder = SchedulerJobMetadata::new(
        job_name.as_str(),
        AuditTrigger::Background,
        source_event_at.clone(),
    )
    .with_duration_ms(duration_ms);
    if let Some(error_code) = error_code {
        metadata_builder = metadata_builder.with_error_code(error_code);
    }
    if let Some(period) = &period {
        metadata_builder = metadata_builder.with_target_year_month(period.as_str());
    }
    let metadata = match metadata_builder.build() {
        Ok(metadata) => metadata,
        Err(error) => {
            tracing::error!(error = %error, job_name = job_name.as_str(), "scheduler audit metadata build failed");
            return Err("scheduler_audit_metadata_failed");
        }
    };

    let audit_event_id = match AuditEventId::generate() {
        Ok(audit_event_id) => audit_event_id,
        Err(error) => {
            tracing::error!(error = %error, job_name = job_name.as_str(), "scheduler audit event id generation failed");
            return Err("scheduler_audit_event_id_failed");
        }
    };
    let event = match AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::SchedulerJob,
        target_secret_id: None,
        result,
        key_version: None,
        metadata_json: metadata,
    }) {
        Ok(event) => event,
        Err(error) => {
            tracing::error!(error = %error, job_name = job_name.as_str(), "scheduler audit event build failed");
            return Err("scheduler_audit_event_failed");
        }
    };

    if let Err(error) = state.audit_recorder.record(&event).await {
        tracing::error!(
            error = %error,
            job_name = job_name.as_str(),
            result = result.as_str(),
            "scheduler audit primary and fallback recording failed"
        );
        return Err("scheduler_audit_record_failed");
    }
    append_scheduler_ledger_entry(
        job_name,
        SchedulerLedgerEntryRecord {
            state,
            result,
            error_code,
            period,
            duration_ms,
            request_id,
            source_event_at,
            source_event_id: Some(event.audit_event_id().clone()),
        },
    )
    .await
    .inspect_err(|&error_code| {
        tracing::error!(
            job_name = job_name.as_str(),
            result = result.as_str(),
            error_code,
            "scheduler ledger recording failed"
        );
    })?;

    Ok(())
}

struct SchedulerLedgerEntryRecord<'a> {
    state: &'a AppState,
    result: AuditResult,
    error_code: Option<&'static str>,
    period: Option<MonthlyDigestPeriod>,
    duration_ms: u64,
    request_id: RequestId,
    source_event_at: SourceEventAt,
    source_event_id: Option<AuditEventId>,
}

async fn append_scheduler_ledger_entry(
    job_name: ScheduledJobName,
    record: SchedulerLedgerEntryRecord<'_>,
) -> Result<(), &'static str> {
    let SchedulerLedgerEntryRecord {
        state,
        result,
        error_code,
        period,
        duration_ms,
        request_id,
        source_event_at,
        source_event_id,
    } = record;

    let entry_type = LedgerEntryType::SchedulerJobCompleted;
    let mut payload_value = serde_json::json!({
        "duration_ms": duration_ms,
        "job_name": job_name.as_str(),
        "trigger": AuditTrigger::Background.as_str(),
    });
    if let (Some(period), Some(object)) = (period.as_ref(), payload_value.as_object_mut()) {
        object.insert(
            "target_year_month".to_owned(),
            serde_json::Value::String(period.as_str().to_owned()),
        );
    }
    let payload = LedgerPayload::new(entry_type, payload_value)
        .map_err(|_| "scheduler_ledger_payload_failed")?;
    let ledger_result = match result {
        AuditResult::Success => LedgerResult::Success,
        AuditResult::Failure => LedgerResult::Failure,
    };
    let draft = LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::generate().map_err(|_| "scheduler_ledger_id_failed")?,
        entry_type,
        source_event_at,
        request_id,
        source_event_id,
        target_secret_id: None,
        target_secret_version_id: None,
        actor_user_id: None,
        actor_device_id: None,
        result: ledger_result,
        error_code: error_code.map(str::to_owned),
        payload,
    })
    .map_err(|_| "scheduler_ledger_draft_failed")?;
    state
        .ledger_appender
        .append(&draft)
        .await
        .map_err(|_| "scheduler_ledger_append_failed")?;
    Ok(())
}

fn monthly_due(now: OffsetDateTime, monthly_day: u8, monthly_hour_utc: u8) -> bool {
    now.day() == monthly_day && now.hour() >= monthly_hour_utc
}

fn quarterly_due(now: OffsetDateTime, monthly_day: u8, quarterly_hour_utc: u8) -> bool {
    matches!(
        now.month(),
        Month::January | Month::April | Month::July | Month::October
    ) && now.day() == monthly_day
        && now.hour() >= quarterly_hour_utc
}

fn daily_due(now: OffsetDateTime, daily_hour_utc: u8) -> bool {
    now.hour() >= daily_hour_utc
}

fn daily_period_key(now: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
    )
}

fn previous_month_period(
    now: OffsetDateTime,
) -> Result<MonthlyDigestPeriod, crate::ledger::LedgerError> {
    let mut year = now.year();
    let mut month = u8::from(now.month()) - 1;
    if month == 0 {
        year -= 1;
        month = 12;
    }
    MonthlyDigestPeriod::parse(&format!("{year:04}-{month:02}"))
}

fn quarter_period_key(now: OffsetDateTime) -> String {
    let quarter = match now.month() {
        Month::January | Month::February | Month::March => 1,
        Month::April | Month::May | Month::June => 2,
        Month::July | Month::August | Month::September => 3,
        Month::October | Month::November | Month::December => 4,
    };
    format!("{:04}-Q{quarter}", now.year())
}

fn elapsed_ms(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(year: i32, month: Month, day: u8, hour: u8) -> OffsetDateTime {
        let date = Date::from_calendar_date(year, month, day).expect("valid test date");
        let time = Time::from_hms(hour, 0, 0).expect("valid test time");
        date.with_time(time).assume_utc()
    }

    #[test]
    fn monthly_due_respects_day_and_hour() {
        assert!(monthly_due(dt(2026, Month::June, 1, 3), 1, 3));
        assert!(monthly_due(dt(2026, Month::June, 1, 4), 1, 3));
        assert!(!monthly_due(dt(2026, Month::June, 1, 2), 1, 3));
        assert!(!monthly_due(dt(2026, Month::June, 2, 3), 1, 3));
    }

    #[test]
    fn quarterly_due_only_runs_on_quarter_boundary_months() {
        assert!(quarterly_due(dt(2026, Month::April, 1, 4), 1, 4));
        assert!(!quarterly_due(dt(2026, Month::May, 1, 4), 1, 4));
        assert!(!quarterly_due(dt(2026, Month::April, 1, 3), 1, 4));
    }

    #[test]
    fn daily_due_respects_hour_boundary() {
        assert!(!daily_due(dt(2026, Month::June, 1, 3), 4));
        assert!(daily_due(dt(2026, Month::June, 1, 4), 4));
        assert!(daily_due(dt(2026, Month::June, 1, 5), 4));
        assert!(daily_due(dt(2026, Month::June, 1, 23), 4));
    }

    #[test]
    fn daily_period_key_encodes_year_month_day() {
        assert_eq!(daily_period_key(dt(2026, Month::June, 1, 4)), "2026-06-01");
        assert_eq!(
            daily_period_key(dt(2025, Month::December, 31, 23)),
            "2025-12-31"
        );
    }

    #[test]
    fn scheduled_job_name_includes_new_v02_jobs() {
        assert_eq!(
            ScheduledJobName::MonthlyTimestampingObtain.as_str(),
            "monthly_timestamping_obtain"
        );
        assert_eq!(
            ScheduledJobName::DailyEnvelopeLazyMigration.as_str(),
            "daily_envelope_lazy_migration"
        );
    }

    #[test]
    fn scheduler_runtime_state_assigns_distinct_locks_for_new_jobs() {
        let runtime_state = SchedulerRuntimeState::new();
        let timestamping_lock_ptr = std::ptr::from_ref::<JobLock>(
            runtime_state.lock_for(ScheduledJobName::MonthlyTimestampingObtain),
        );
        let envelope_lock_ptr = std::ptr::from_ref::<JobLock>(
            runtime_state.lock_for(ScheduledJobName::DailyEnvelopeLazyMigration),
        );
        let archive_lock_ptr =
            std::ptr::from_ref::<JobLock>(runtime_state.lock_for(ScheduledJobName::ArchiveExport));
        assert_ne!(timestamping_lock_ptr, envelope_lock_ptr);
        assert_ne!(timestamping_lock_ptr, archive_lock_ptr);
        assert_ne!(envelope_lock_ptr, archive_lock_ptr);
    }

    #[tokio::test]
    async fn run_once_per_period_marks_new_jobs_distinctly() {
        let mut runtime_state = SchedulerRuntimeState::new();
        let timestamping_key = JobRunKey {
            job_name: ScheduledJobName::MonthlyTimestampingObtain,
            period_key: "2026-05".to_owned(),
        };
        let envelope_key = JobRunKey {
            job_name: ScheduledJobName::DailyEnvelopeLazyMigration,
            period_key: "2026-05-29".to_owned(),
        };

        let first = run_once_per_period(&mut runtime_state, timestamping_key.clone(), async {
            Ok::<_, &str>("ok")
        })
        .await;
        let second = run_once_per_period(&mut runtime_state, envelope_key.clone(), async {
            Ok::<_, &str>("ok")
        })
        .await;
        let third = run_once_per_period(&mut runtime_state, timestamping_key.clone(), async {
            Ok::<_, &str>("ok")
        })
        .await;

        assert_eq!(first, Ok(Some("ok")));
        assert_eq!(second, Ok(Some("ok")));
        assert_eq!(third, Ok(None));
        assert!(runtime_state.completed.contains(&timestamping_key));
        assert!(runtime_state.completed.contains(&envelope_key));
    }

    #[test]
    fn previous_month_period_wraps_year() {
        assert_eq!(
            previous_month_period(dt(2026, Month::June, 1, 3))
                .unwrap()
                .as_str(),
            "2026-05"
        );
        assert_eq!(
            previous_month_period(dt(2026, Month::January, 1, 3))
                .unwrap()
                .as_str(),
            "2025-12"
        );
    }

    #[test]
    fn job_lock_prevents_reentry_until_guard_drops() {
        let lock = JobLock::new();
        let first = lock.try_enter();
        assert!(first.is_some());
        assert!(lock.try_enter().is_none());
        drop(first);
        assert!(lock.try_enter().is_some());
    }

    #[tokio::test]
    async fn run_once_per_period_does_not_complete_failed_job() {
        let mut runtime_state = SchedulerRuntimeState::new();
        let key = JobRunKey {
            job_name: ScheduledJobName::MonthlyDigestGenerate,
            period_key: "2026-05".to_owned(),
        };

        let result = run_once_per_period(&mut runtime_state, key.clone(), async {
            Err::<(), _>("synthetic_failure")
        })
        .await;

        assert_eq!(result, Err("synthetic_failure"));
        assert!(!runtime_state.completed.contains(&key));
    }

    #[tokio::test]
    async fn run_once_per_period_returns_none_for_completed_job() {
        let mut runtime_state = SchedulerRuntimeState::new();
        let key = JobRunKey {
            job_name: ScheduledJobName::ArchiveExport,
            period_key: "2026-05".to_owned(),
        };

        let first =
            run_once_per_period(&mut runtime_state, key.clone(), async { Ok::<_, &str>(7) }).await;
        let second =
            run_once_per_period(&mut runtime_state, key, async { Ok::<_, &str>(11) }).await;

        assert_eq!(first, Ok(Some(7)));
        assert_eq!(second, Ok(None));
    }
}

use std::collections::HashSet;
use std::future::Future;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use time::{Month, OffsetDateTime};

use crate::audit::{
    AuditAction, AuditEvent, AuditResult, AuditTrigger, RequestId, SchedulerJobMetadata,
};
use crate::incident::{
    IncidentRecordInput, IncidentType, dedupe_key, scheduler_incident_type, severity_for_incident,
};
use crate::ledger::{MonthlyDigestPeriod, SignedMonthlyDigest};
use crate::server::state::AppState;
use crate::types::SourceEventAt;

use super::SchedulerConfig;
use super::audit::{SchedulerLedgerEntryRecord, append_scheduler_ledger_entry};
use super::catalog::ScheduledJobName;
use super::jobs::{
    elapsed_ms, fetch_signed_digest, previous_month_period, run_archive_export_job,
    run_daily_envelope_lazy_migration_job, run_monthly_digest_generate_job,
    run_monthly_timestamping_obtain_job, run_quarterly_job, verify_full_ledger_hash_chain,
    verify_full_ledger_signatures,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct JobRunKey {
    pub(crate) job_name: ScheduledJobName,
    pub(crate) period_key: String,
}

#[derive(Debug)]
pub(crate) struct JobLock {
    running: AtomicBool,
}

impl JobLock {
    pub(crate) fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
        }
    }

    pub(crate) fn try_enter(&self) -> Option<JobLockGuard<'_>> {
        self.running
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| JobLockGuard { lock: self })
    }
}

pub(crate) struct JobLockGuard<'a> {
    lock: &'a JobLock,
}

impl Drop for JobLockGuard<'_> {
    fn drop(&mut self) {
        self.lock.running.store(false, Ordering::Release);
    }
}

pub(crate) struct SchedulerRuntimeState {
    pub(crate) completed: HashSet<JobRunKey>,
    hash_chain_lock: JobLock,
    signature_lock: JobLock,
    digest_lock: JobLock,
    archive_lock: JobLock,
    timestamping_lock: JobLock,
    envelope_migration_lock: JobLock,
    restore_lock: JobLock,
    signature_review_lock: JobLock,
    auditor_review_lock: JobLock,
    siem_buffer_flush_lock: JobLock,
}

impl SchedulerRuntimeState {
    pub(crate) fn new() -> Self {
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
            siem_buffer_flush_lock: JobLock::new(),
        }
    }

    pub(crate) fn lock_for(&self, job_name: ScheduledJobName) -> &JobLock {
        match job_name {
            ScheduledJobName::MonthlyHashChainVerify => &self.hash_chain_lock,
            ScheduledJobName::MonthlySignatureVerify => &self.signature_lock,
            ScheduledJobName::MonthlyDigestGenerate => &self.digest_lock,
            ScheduledJobName::MonthlyArchiveUpload => &self.archive_lock,
            ScheduledJobName::MonthlyTimestampingObtain => &self.timestamping_lock,
            ScheduledJobName::DailyEnvelopeLazyMigration => &self.envelope_migration_lock,
            ScheduledJobName::QuarterlyRestoreDrillReminder => &self.restore_lock,
            ScheduledJobName::QuarterlySigningKeyReviewReminder => &self.signature_review_lock,
            ScheduledJobName::QuarterlyAuditorPrivilegeReviewReminder => &self.auditor_review_lock,
            ScheduledJobName::SiemBufferFlush => &self.siem_buffer_flush_lock,
        }
    }
}

#[allow(dead_code)]
pub(crate) async fn run_due_jobs(
    state: &AppState,
    config: &SchedulerConfig,
    runtime_state: &mut SchedulerRuntimeState,
    now: OffsetDateTime,
) {
    if monthly_due(now, config.monthly_day, config.monthly_hour_utc)
        && run_monthly_due_jobs(state, config, runtime_state, now)
            .await
            .is_break()
    {
        return;
    }

    if daily_due(now, config.daily_hour_utc) {
        run_daily_due_jobs(state, config, runtime_state, now).await;
    }

    if quarterly_due(now, config.monthly_day, config.quarterly_hour_utc) {
        run_quarterly_due_jobs(state, config, runtime_state, now).await;
    }
}

#[allow(dead_code)]
async fn run_monthly_due_jobs(
    state: &AppState,
    config: &SchedulerConfig,
    runtime_state: &mut SchedulerRuntimeState,
    now: OffsetDateTime,
) -> ControlFlow<()> {
    let Ok(period) = previous_month_period(now) else {
        tracing::error!("scheduler failed to compute previous monthly digest period");
        return ControlFlow::Break(());
    };

    if !run_monthly_ledger_verification(state, runtime_state, &period).await {
        record_monthly_precondition_failures(
            state,
            runtime_state,
            &period,
            &[
                ScheduledJobName::MonthlyDigestGenerate,
                ScheduledJobName::MonthlyArchiveUpload,
            ],
            "ledger_verification_precondition_failed",
        )
        .await;
        return ControlFlow::Break(());
    }

    let signed_digest = match resolve_monthly_signed_digest(state, runtime_state, &period).await {
        Ok(digest) => digest,
        Err(error_code) => {
            record_monthly_precondition_failures(
                state,
                runtime_state,
                &period,
                &[ScheduledJobName::MonthlyArchiveUpload],
                error_code,
            )
            .await;
            return ControlFlow::Break(());
        }
    };

    run_monthly_archive_export(state, config, runtime_state, signed_digest.clone()).await;
    run_monthly_timestamping(state, config, runtime_state, signed_digest).await;
    ControlFlow::Continue(())
}

#[allow(dead_code)]
async fn run_monthly_ledger_verification(
    state: &AppState,
    runtime_state: &mut SchedulerRuntimeState,
    period: &MonthlyDigestPeriod,
) -> bool {
    let key = JobRunKey {
        job_name: ScheduledJobName::MonthlyHashChainVerify,
        period_key: period.as_str().to_owned(),
    };
    let hash_result = run_once_per_period(
        runtime_state,
        key,
        run_full_ledger_hash_chain_verify_job(
            state,
            ScheduledJobName::MonthlyHashChainVerify,
            Some(period.clone()),
        ),
    )
    .await;

    let key = JobRunKey {
        job_name: ScheduledJobName::MonthlySignatureVerify,
        period_key: period.as_str().to_owned(),
    };
    let signature_result = run_once_per_period(
        runtime_state,
        key,
        run_full_ledger_signature_verify_job(
            state,
            ScheduledJobName::MonthlySignatureVerify,
            Some(period.clone()),
        ),
    )
    .await;

    hash_result.is_ok() && signature_result.is_ok()
}

#[allow(dead_code)]
async fn resolve_monthly_signed_digest(
    state: &AppState,
    runtime_state: &mut SchedulerRuntimeState,
    period: &MonthlyDigestPeriod,
) -> Result<SignedMonthlyDigest, &'static str> {
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

    match digest_result {
        Ok(Some(digest)) => Ok(digest),
        Ok(None) => fetch_signed_digest(state.supabase_client.as_ref(), period).await,
        Err(_) => Err("monthly_digest_generate_failed"),
    }
}

#[allow(dead_code)]
async fn record_monthly_precondition_failures(
    state: &AppState,
    runtime_state: &mut SchedulerRuntimeState,
    period: &MonthlyDigestPeriod,
    job_names: &[ScheduledJobName],
    error_code: &'static str,
) {
    for &job_name in job_names {
        let key = JobRunKey {
            job_name,
            period_key: period.as_str().to_owned(),
        };
        let _ = run_once_per_period(
            runtime_state,
            key,
            record_precondition_failure_job(state, job_name, Some(period.clone()), error_code),
        )
        .await;
    }
}

#[allow(dead_code)]
async fn run_monthly_archive_export(
    state: &AppState,
    config: &SchedulerConfig,
    runtime_state: &mut SchedulerRuntimeState,
    signed_digest: SignedMonthlyDigest,
) {
    let key = JobRunKey {
        job_name: ScheduledJobName::MonthlyArchiveUpload,
        period_key: signed_digest.period.as_str().to_owned(),
    };
    let _ = run_once_per_period(
        runtime_state,
        key,
        run_archive_export_job(state, config, signed_digest),
    )
    .await;
}

#[allow(dead_code)]
async fn run_monthly_timestamping(
    state: &AppState,
    config: &SchedulerConfig,
    runtime_state: &mut SchedulerRuntimeState,
    signed_digest: SignedMonthlyDigest,
) {
    let key = JobRunKey {
        job_name: ScheduledJobName::MonthlyTimestampingObtain,
        period_key: signed_digest.period.as_str().to_owned(),
    };
    let _ = run_once_per_period(
        runtime_state,
        key,
        run_monthly_timestamping_obtain_job(state, config, signed_digest),
    )
    .await;
}

#[allow(dead_code)]
async fn run_daily_due_jobs(
    state: &AppState,
    config: &SchedulerConfig,
    runtime_state: &mut SchedulerRuntimeState,
    now: OffsetDateTime,
) {
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

#[allow(dead_code)]
async fn run_quarterly_due_jobs(
    state: &AppState,
    config: &SchedulerConfig,
    runtime_state: &mut SchedulerRuntimeState,
    now: OffsetDateTime,
) {
    let quarter_key = quarter_period_key(now);
    for job_name in [
        ScheduledJobName::QuarterlyRestoreDrillReminder,
        ScheduledJobName::QuarterlySigningKeyReviewReminder,
        ScheduledJobName::QuarterlyAuditorPrivilegeReviewReminder,
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

pub(crate) async fn run_once_per_period<Fut, T>(
    runtime_state: &mut SchedulerRuntimeState,
    key: JobRunKey,
    run: Fut,
) -> Result<Option<T>, &'static str>
where
    Fut: Future<Output = Result<T, &'static str>>,
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
            tracing::error!(
                error = %error,
                job_name = job_name.as_str(),
                "scheduler audit request id generation failed"
            );
            return Err("scheduler_request_id_failed");
        }
    };
    let source_event_at = match SourceEventAt::now_utc() {
        Ok(source_event_at) => source_event_at,
        Err(error) => {
            tracing::error!(
                error = %error,
                job_name = job_name.as_str(),
                "scheduler source_event_at generation failed"
            );
            return Err("scheduler_source_event_at_failed");
        }
    };

    let metadata = build_scheduler_job_metadata(
        job_name,
        source_event_at.clone(),
        duration_ms,
        error_code,
        period.as_ref(),
    )?;
    let event = AuditEvent::build_with_current_source_event_at(
        request_id.clone(),
        None,
        None,
        AuditAction::SchedulerJob,
        None,
        result,
        None,
        metadata,
    )
    .map_err(|_| "scheduler_audit_event_build_failed")?;

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

#[allow(dead_code)]
fn build_scheduler_job_metadata(
    job_name: ScheduledJobName,
    source_event_at: SourceEventAt,
    duration_ms: u64,
    error_code: Option<&'static str>,
    period: Option<&MonthlyDigestPeriod>,
) -> Result<crate::audit::AuditMetadata, &'static str> {
    let mut metadata_builder =
        SchedulerJobMetadata::new(job_name.as_str(), AuditTrigger::Background, source_event_at)
            .with_duration_ms(duration_ms);
    if let Some(code) = error_code {
        metadata_builder = metadata_builder.with_error_code(code);
    }
    if let Some(p) = period {
        metadata_builder = metadata_builder.with_target_year_month(p.as_str());
    }
    metadata_builder
        .build()
        .map_err(|_| "scheduler_metadata_build_failed")
}

pub(crate) fn monthly_due(now: OffsetDateTime, monthly_day: u8, monthly_hour_utc: u8) -> bool {
    now.day() == monthly_day && now.hour() >= monthly_hour_utc
}

pub(crate) fn quarterly_due(now: OffsetDateTime, monthly_day: u8, quarterly_hour_utc: u8) -> bool {
    matches!(
        now.month(),
        Month::January | Month::April | Month::July | Month::October
    ) && now.day() == monthly_day
        && now.hour() >= quarterly_hour_utc
}

pub(crate) fn daily_due(now: OffsetDateTime, daily_hour_utc: u8) -> bool {
    now.hour() >= daily_hour_utc
}

pub(crate) fn daily_period_key(now: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
    )
}

#[allow(dead_code)]
pub(crate) fn quarter_period_key(now: OffsetDateTime) -> String {
    let quarter = match now.month() {
        Month::January | Month::February | Month::March => 1,
        Month::April | Month::May | Month::June => 2,
        Month::July | Month::August | Month::September => 3,
        Month::October | Month::November | Month::December => 4,
    };
    format!("{:04}-Q{quarter}", now.year())
}

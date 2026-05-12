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
use crate::ledger::{
    DigestHash, LedgerChainHead, LedgerEntryId, LedgerEntryType, LedgerPayload, LedgerResult,
    LedgerSequenceNo, MonthlyDigestPeriod, SignedLedgerEntry, SignedMonthlyDigest,
    build_monthly_digest_canonical_form, verify_ledger_chain,
};
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts};
use crate::server::state::AppState;
use crate::server::supabase::{MonthlyDigestVerificationMaterials, SupabaseClient};
use crate::server::use_cases::export_digest_to_archive::export_digest_to_archive;
use crate::server::use_cases::generate_monthly_digest::{
    GenerateMonthlyDigestInput, generate_monthly_digest, record_monthly_digest_failure_audit,
};
use crate::server::use_cases::request_timestamping_for_digest::request_timestamping_for_digest;
use crate::server::use_cases::verify_monthly_digest::{
    VerifyMonthlyDigestInput, record_monthly_digest_verify_failure_audit, verify_monthly_digest,
};
use crate::timestamping::InMemoryTimestampingService;
use crate::types::SourceEventAt;

use super::restore_test;

#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    pub startup_delay: Duration,
    pub poll_interval: Duration,
    pub monthly_day: u8,
    pub monthly_hour_utc: u8,
    pub quarterly_hour_utc: u8,
    pub restore_test_sample_limit: u32,
    pub local_archive_dir: std::path::PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ScheduledJobName {
    LedgerHashChainFullVerify,
    LedgerSignatureFullVerify,
    MonthlyDigestPipeline,
    RestoreTest,
    SignatureKeyReviewReminder,
    AuditorPermissionReviewReminder,
}

impl ScheduledJobName {
    fn as_str(self) -> &'static str {
        match self {
            Self::LedgerHashChainFullVerify => "ledger_hash_chain_full_verify",
            Self::LedgerSignatureFullVerify => "ledger_signature_full_verify",
            Self::MonthlyDigestPipeline => "monthly_digest_pipeline",
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
            restore_lock: JobLock::new(),
            signature_review_lock: JobLock::new(),
            auditor_review_lock: JobLock::new(),
        }
    }

    fn lock_for(&self, job_name: ScheduledJobName) -> &JobLock {
        match job_name {
            ScheduledJobName::LedgerHashChainFullVerify => &self.hash_chain_lock,
            ScheduledJobName::LedgerSignatureFullVerify => &self.signature_lock,
            ScheduledJobName::MonthlyDigestPipeline => &self.digest_lock,
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
        run_once_per_period(
            runtime_state,
            key,
            run_full_ledger_verify_job(
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
        run_once_per_period(
            runtime_state,
            key,
            run_full_ledger_verify_job(
                state,
                ScheduledJobName::LedgerSignatureFullVerify,
                Some(signature_period),
            ),
        )
        .await;

        let key = JobRunKey {
            job_name: ScheduledJobName::MonthlyDigestPipeline,
            period_key: period.as_str().to_owned(),
        };
        run_once_per_period(
            runtime_state,
            key,
            run_monthly_digest_pipeline_job(state, config, period),
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
            run_once_per_period(
                runtime_state,
                key,
                run_quarterly_job(state, config, job_name),
            )
            .await;
        }
    }
}

async fn run_once_per_period<Fut>(
    runtime_state: &mut SchedulerRuntimeState,
    key: JobRunKey,
    run: Fut,
) where
    Fut: std::future::Future<Output = Result<(), &'static str>>,
{
    if runtime_state.completed.contains(&key) {
        return;
    }

    let result = {
        let Some(guard) = runtime_state.lock_for(key.job_name).try_enter() else {
            tracing::info!(
                job_name = key.job_name.as_str(),
                "scheduled job already running; skipped"
            );
            return;
        };
        let result = run.await;
        drop(guard);
        result
    };

    match result {
        Ok(()) => {
            runtime_state.completed.insert(key);
        }
        Err(error_code) => {
            tracing::error!(
                job_name = key.job_name.as_str(),
                error_code,
                "scheduled job failed"
            );
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
            restore_test::run_restore_test_once(
                state,
                config.restore_test_sample_limit,
                AuditTrigger::Background,
            )
            .await;
            Ok(())
        }
        ScheduledJobName::SignatureKeyReviewReminder
        | ScheduledJobName::AuditorPermissionReviewReminder => {
            record_scheduler_job_result(state, job_name, AuditResult::Success, None, None, 0).await;
            Ok(())
        }
        _ => Ok(()),
    }
}

async fn run_full_ledger_verify_job(
    state: &AppState,
    job_name: ScheduledJobName,
    period: Option<MonthlyDigestPeriod>,
) -> Result<(), &'static str> {
    let started_at = Instant::now();
    let outcome = verify_full_ledger(state.supabase_client.as_ref()).await;
    let (result, error_code) = match outcome {
        Ok(summary) if summary.valid => {
            tracing::info!(
                job_name = job_name.as_str(),
                checked_count = summary.checked_count,
                "full ledger verification completed"
            );
            (AuditResult::Success, None)
        }
        Ok(summary) => {
            tracing::error!(
                job_name = job_name.as_str(),
                checked_count = summary.checked_count,
                error_code = summary.error_code.unwrap_or("ledger_verification_failed"),
                "full ledger verification detected an anomaly without auto-repair"
            );
            (
                AuditResult::Failure,
                summary.error_code.or(Some("ledger_verification_failed")),
            )
        }
        Err(error_code) => (AuditResult::Failure, Some(error_code)),
    };
    record_scheduler_job_result(
        state,
        job_name,
        result,
        error_code,
        period,
        elapsed_ms(started_at),
    )
    .await;

    if result == AuditResult::Success {
        Ok(())
    } else {
        Err(error_code.unwrap_or("ledger_verification_failed"))
    }
}

async fn run_monthly_digest_pipeline_job(
    state: &AppState,
    config: &SchedulerConfig,
    period: MonthlyDigestPeriod,
) -> Result<(), &'static str> {
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
        input,
    )
    .await
    {
        Ok(digest) => digest,
        Err(error) => {
            record_monthly_digest_failure_audit(
                &state.audit_recorder,
                &request_id,
                &period,
                &error,
                &source_event_at,
            )
            .await;
            if error.as_error_code() == "monthly_digest_duplicate" {
                fetch_signed_digest(state.supabase_client.as_ref(), &period)
                    .await
                    .map_err(|_| "monthly_digest_existing_fetch_failed")?
            } else {
                record_scheduler_job_result(
                    state,
                    ScheduledJobName::MonthlyDigestPipeline,
                    AuditResult::Failure,
                    Some("monthly_digest_generate_failed"),
                    Some(period),
                    elapsed_ms(started_at),
                )
                .await;
                return Err("monthly_digest_generate_failed");
            }
        }
    };

    let verify_request_id = RequestId::generate().map_err(|_| "scheduler_request_id_failed")?;
    let verify_input = VerifyMonthlyDigestInput {
        period: period.clone(),
        request_id: verify_request_id.clone(),
    };
    if let Err(error) = verify_monthly_digest(&state.supabase_client, &verify_input).await {
        let verified_at =
            SourceEventAt::now_utc().map_err(|_| "scheduler_source_event_at_failed")?;
        record_monthly_digest_verify_failure_audit(
            &state.audit_recorder,
            &verify_request_id,
            &period,
            &error,
            &verified_at,
        )
        .await;
        record_scheduler_job_result(
            state,
            ScheduledJobName::MonthlyDigestPipeline,
            AuditResult::Failure,
            Some("monthly_digest_verify_failed"),
            Some(period),
            elapsed_ms(started_at),
        )
        .await;
        return Err("monthly_digest_verify_failed");
    }

    let timestamp_request_id = RequestId::generate().map_err(|_| "scheduler_request_id_failed")?;
    let timestamped_at =
        SourceEventAt::now_utc().map_err(|_| "scheduler_source_event_at_failed")?;
    let timestamping_service = InMemoryTimestampingService::new();
    let _ = request_timestamping_for_digest(
        &timestamping_service,
        &state.audit_recorder,
        &state.ledger_appender,
        &signed_digest,
        timestamp_request_id,
        timestamped_at,
    )
    .await;

    let archive_request_id = RequestId::generate().map_err(|_| "scheduler_request_id_failed")?;
    let archived_at = SourceEventAt::now_utc().map_err(|_| "scheduler_source_event_at_failed")?;
    let archive_backend = LocalFileArchiveBackend::new(config.local_archive_dir.clone());
    if export_digest_to_archive(
        &archive_backend,
        &state.audit_recorder,
        &state.ledger_appender,
        &signed_digest,
        archive_request_id,
        archived_at,
    )
    .await
    .is_err()
    {
        record_scheduler_job_result(
            state,
            ScheduledJobName::MonthlyDigestPipeline,
            AuditResult::Failure,
            Some("archive_export_failed"),
            Some(period),
            elapsed_ms(started_at),
        )
        .await;
        return Err("archive_export_failed");
    }

    record_scheduler_job_result(
        state,
        ScheduledJobName::MonthlyDigestPipeline,
        AuditResult::Success,
        None,
        Some(period),
        elapsed_ms(started_at),
    )
    .await;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct LedgerVerificationSummary {
    valid: bool,
    checked_count: u64,
    error_code: Option<&'static str>,
}

async fn verify_full_ledger(
    client: &SupabaseClient,
) -> Result<LedgerVerificationSummary, &'static str> {
    let chain_head = client
        .fetch_ledger_chain_head()
        .await
        .map_err(|_| "ledger_chain_head_fetch_failed")?;
    if chain_head.last_sequence_no() == 0 {
        return Ok(LedgerVerificationSummary {
            valid: true,
            checked_count: 0,
            error_code: None,
        });
    }

    let end = LedgerSequenceNo::new(chain_head.last_sequence_no())
        .map_err(|_| "ledger_sequence_invalid")?;
    let start = LedgerSequenceNo::new(1).map_err(|_| "ledger_sequence_invalid")?;
    let rows = client
        .export_ledger_verification_materials(start, end)
        .await
        .map_err(|_| "ledger_export_failed")?;

    let mut entries: Vec<SignedLedgerEntry> = Vec::with_capacity(rows.len());
    let mut verification_keys = Vec::new();
    for row in &rows {
        let entry = row
            .try_restore_signed_ledger_entry()
            .map_err(|_| "ledger_entry_restore_failed")?;
        entries.push(entry);
        let maybe_key = row
            .try_restore_verifying_key()
            .map_err(|_| "ledger_key_restore_failed")?;
        if let Some(key) = maybe_key
            && !verification_keys
                .iter()
                .any(|existing: &crate::ledger::LedgerVerifyingKey| {
                    existing.key_version() == key.key_version()
                })
        {
            verification_keys.push(key);
        }
    }

    match verify_ledger_chain(&entries, LedgerChainHead::genesis(), &verification_keys) {
        Ok(final_head) if final_head.last_entry_hash() == chain_head.last_entry_hash() => {
            Ok(LedgerVerificationSummary {
                valid: true,
                checked_count: entries.len() as u64,
                error_code: None,
            })
        }
        Ok(_) => Ok(LedgerVerificationSummary {
            valid: false,
            checked_count: entries.len() as u64,
            error_code: Some("ledger_chain_head_mismatch"),
        }),
        Err(_) => Ok(LedgerVerificationSummary {
            valid: false,
            checked_count: entries.len() as u64,
            error_code: Some("ledger_chain_verification_failed"),
        }),
    }
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
        sbc_signature: materials.signature,
    })
}

async fn record_scheduler_job_result(
    state: &AppState,
    job_name: ScheduledJobName,
    result: AuditResult,
    error_code: Option<&'static str>,
    period: Option<MonthlyDigestPeriod>,
    duration_ms: u64,
) {
    let request_id = match RequestId::generate() {
        Ok(request_id) => request_id,
        Err(error) => {
            tracing::error!(error = %error, job_name = job_name.as_str(), "scheduler audit request id generation failed");
            return;
        }
    };
    let source_event_at = match SourceEventAt::now_utc() {
        Ok(source_event_at) => source_event_at,
        Err(error) => {
            tracing::error!(error = %error, job_name = job_name.as_str(), "scheduler source_event_at generation failed");
            return;
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
            return;
        }
    };

    let audit_event_id = match AuditEventId::generate() {
        Ok(audit_event_id) => audit_event_id,
        Err(error) => {
            tracing::error!(error = %error, job_name = job_name.as_str(), "scheduler audit event id generation failed");
            return;
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
            return;
        }
    };

    if let Err(error) = state.audit_recorder.record(&event).await {
        tracing::error!(
            error = %error,
            job_name = job_name.as_str(),
            result = result.as_str(),
            "scheduler audit primary and fallback recording failed"
        );
    }
    if let Err(error_code) = append_scheduler_ledger_entry(
        state,
        job_name,
        result,
        error_code,
        period,
        duration_ms,
        request_id,
        source_event_at,
        Some(event.audit_event_id().clone()),
    )
    .await
    {
        tracing::error!(
            job_name = job_name.as_str(),
            result = result.as_str(),
            error_code,
            "scheduler ledger recording failed"
        );
    }
}

async fn append_scheduler_ledger_entry(
    state: &AppState,
    job_name: ScheduledJobName,
    result: AuditResult,
    error_code: Option<&'static str>,
    period: Option<MonthlyDigestPeriod>,
    duration_ms: u64,
    request_id: RequestId,
    source_event_at: SourceEventAt,
    source_event_id: Option<AuditEventId>,
) -> Result<(), &'static str> {
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
}

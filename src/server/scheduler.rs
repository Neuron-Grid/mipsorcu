use std::collections::HashSet;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use time::{Month, OffsetDateTime};
use tokio::sync::watch;

use crate::archive::LocalFileArchiveBackend;
use crate::audit::{
    AuditEvent, AuditEventId, AuditMetadata, AuditResult, AuditTrigger, RequestId,
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
    record_monthly_digest_success_audit,
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

// 月次パイプライン（連鎖検証 → 署名検証 → ダイジェスト生成 → アーカイブ →
// タイムスタンプ）を統括する。早期中断は元の `run_due_jobs` 月次ブロックの
// 早期 `return` を再現するもので、`ControlFlow::Break` は呼び出し側で日次・
// 四半期ジョブをスキップさせる意味を持つ。末尾到達時のみ `Continue` を返す。
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
                ScheduledJobName::ArchiveExport,
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
                &[ScheduledJobName::ArchiveExport],
                error_code,
            )
            .await;
            return ControlFlow::Break(());
        }
    };

    run_monthly_archive_export(state, config, runtime_state, signed_digest.clone()).await;
    run_monthly_timestamping(state, runtime_state, signed_digest).await;
    ControlFlow::Continue(())
}

// 台帳のハッシュ連鎖検証と署名検証を両方実行し、いずれも成功したかを返す。
// 署名検証を短絡させず、常に両方のジョブを実行する。
async fn run_monthly_ledger_verification(
    state: &AppState,
    runtime_state: &mut SchedulerRuntimeState,
    period: &MonthlyDigestPeriod,
) -> bool {
    let key = JobRunKey {
        job_name: ScheduledJobName::LedgerHashChainFullVerify,
        period_key: period.as_str().to_owned(),
    };
    let hash_result = run_once_per_period(
        runtime_state,
        key,
        run_full_ledger_hash_chain_verify_job(
            state,
            ScheduledJobName::LedgerHashChainFullVerify,
            Some(period.clone()),
        ),
    )
    .await;

    let key = JobRunKey {
        job_name: ScheduledJobName::LedgerSignatureFullVerify,
        period_key: period.as_str().to_owned(),
    };
    let signature_result = run_once_per_period(
        runtime_state,
        key,
        run_full_ledger_signature_verify_job(
            state,
            ScheduledJobName::LedgerSignatureFullVerify,
            Some(period.clone()),
        ),
    )
    .await;

    hash_result.is_ok() && signature_result.is_ok()
}

// 月次ダイジェストを取得する。生成ジョブが成功すればその結果を、既に生成済み
// （`Ok(None)`）であれば Supabase からフォールバック取得する。失敗時は、後続の
// アーカイブ前提失敗として記録すべき `error_code` を `Err` で返す（記録は呼び出し側）。
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

// 指定したジョブ群について前提条件の失敗を監査へ記録する。
// `job_names` に渡した順序で記録する（記録順序は監査上の意味を持つため厳守）。
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

// 署名済みダイジェストのアーカイブ書き出しジョブを実行する。
async fn run_monthly_archive_export(
    state: &AppState,
    config: &SchedulerConfig,
    runtime_state: &mut SchedulerRuntimeState,
    signed_digest: SignedMonthlyDigest,
) {
    let key = JobRunKey {
        job_name: ScheduledJobName::ArchiveExport,
        period_key: signed_digest.period.as_str().to_owned(),
    };
    let _ = run_once_per_period(
        runtime_state,
        key,
        run_archive_export_job(state, config, signed_digest),
    )
    .await;
}

// 署名済みダイジェストの外部タイムスタンプ取得ジョブを実行する。
async fn run_monthly_timestamping(
    state: &AppState,
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
        run_monthly_timestamping_obtain_job(state, signed_digest),
    )
    .await;
}

// 日次スケジュールのジョブ（envelope の遅延マイグレーション）を実行する。
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

// 四半期スケジュールのジョブ（リストアテスト・各種レビュー督促）を順に実行する。
async fn run_quarterly_due_jobs(
    state: &AppState,
    config: &SchedulerConfig,
    runtime_state: &mut SchedulerRuntimeState,
    now: OffsetDateTime,
) {
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
        input,
    )
    .await
    {
        Ok(digest) => {
            // 新規生成成功を audit_events に同期記録する
            // （重複時の既存 digest 再取得では記録しない）。
            record_monthly_digest_success_audit(&state.audit_recorder, &request_id, &digest).await;
            digest
        }
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
    let entries = match restore_entries_checking_forbidden_keys(&rows)? {
        RestoreResult::Restored(entries) => entries,
        RestoreResult::ForbiddenKey(summary) => return Ok(summary),
    };
    verify_chain_links(&entries, chain_head)
}

/// export 行を署名済みエントリへ復元する。禁止キー検出時は失敗サマリを返す。
enum RestoreResult {
    Restored(Vec<SignedLedgerEntry>),
    ForbiddenKey(LedgerVerificationSummary),
}

fn restore_entries_checking_forbidden_keys(
    rows: &[LedgerVerificationMaterialRow],
) -> Result<RestoreResult, &'static str> {
    let mut entries: Vec<SignedLedgerEntry> = Vec::with_capacity(rows.len());
    for row in rows {
        if ledger_payload_contains_forbidden_key(&row.payload) {
            return Ok(RestoreResult::ForbiddenKey(LedgerVerificationSummary {
                valid: false,
                checked_count: entry_count(entries.len()),
                error_code: Some("ledger_payload_forbidden_key"),
            }));
        }

        let entry = row
            .try_restore_signed_ledger_entry()
            .map_err(|_| "ledger_entry_restore_failed")?;
        entries.push(entry);
    }

    Ok(RestoreResult::Restored(entries))
}

/// 復元済みエントリのハッシュ連鎖（順序・前ハッシュ・自己ハッシュ・チェーンヘッド）を検証する。
fn verify_chain_links(
    entries: &[SignedLedgerEntry],
    chain_head: LedgerChainHead,
) -> Result<LedgerVerificationSummary, &'static str> {
    let mut previous_sequence_no = LedgerChainHead::genesis().last_sequence_no();
    let mut previous_hash = LedgerChainHead::genesis().last_entry_hash();
    for entry in entries {
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
        crate::audit::AuditAction::SchedulerJob,
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

/// scheduler ジョブ結果の監査メタデータを組み立てる（純粋なビルダ呼び出し）。
fn build_scheduler_job_metadata(
    job_name: ScheduledJobName,
    source_event_at: SourceEventAt,
    duration_ms: u64,
    error_code: Option<&'static str>,
    period: Option<&MonthlyDigestPeriod>,
) -> Result<AuditMetadata, &'static str> {
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
#[path = "../../tests/unit/server/scheduler/tests.rs"]
mod tests;

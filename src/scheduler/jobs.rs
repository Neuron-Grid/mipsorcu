use std::time::Instant;

use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::archive::{
    ArchiveBackend, ArchiveObjectKey, ArchiveOpaqueObject, LocalFileArchiveBackend,
};
use crate::audit::{AuditTrigger, RequestId};
use crate::incident::ledger_payload_contains_forbidden_key;
use crate::ledger::{
    DigestHash, LedgerChainHead, LedgerHash, LedgerSequenceNo, MonthlyDigestPeriod,
    SignedLedgerEntry, SignedMonthlyDigest, build_monthly_digest_canonical_form,
};
use crate::server::key_rotation::{
    KeyRotationCliError, envelope_migration::run_scheduled_envelope_migration,
};
use crate::server::restore_test;
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
use crate::siem::SIEM_MAX_BATCH_SIZE;
use crate::timestamping::{InMemoryTimestampingService, TimestampingToken, TimestampingTokenHash};
use crate::types::SourceEventAt;

use super::SchedulerConfig;
use super::catalog::{ScheduledJobName, ScheduledJobSpec};

pub(crate) struct JobExecutionSummary {
    pub(crate) result_summary: Value,
    pub(crate) target_year_month: Option<MonthlyDigestPeriod>,
    pub(crate) duration_ms: u64,
}

impl JobExecutionSummary {
    fn new(
        result_summary: Value,
        target_year_month: Option<MonthlyDigestPeriod>,
        started: Instant,
    ) -> Self {
        Self {
            result_summary,
            target_year_month,
            duration_ms: elapsed_ms(started),
        }
    }
}

pub(crate) async fn run_job_body(
    state: &AppState,
    config: &SchedulerConfig,
    spec: ScheduledJobSpec,
) -> Result<JobExecutionSummary, &'static str> {
    let started = Instant::now();
    match spec.name {
        ScheduledJobName::MonthlyHashChainVerify => run_hash_chain_verify_job(state, started).await,
        ScheduledJobName::MonthlySignatureVerify => run_signature_verify_job(state, started).await,
        ScheduledJobName::MonthlyDigestGenerate => {
            run_monthly_digest_scheduler_job(state, started).await
        }
        ScheduledJobName::MonthlyArchiveUpload => {
            run_monthly_archive_scheduler_job(state, config, started).await
        }
        ScheduledJobName::MonthlyTimestampingObtain => {
            run_monthly_timestamping_scheduler_job(state, config, started).await
        }
        ScheduledJobName::DailyEnvelopeLazyMigration => {
            run_daily_envelope_scheduler_job(state, config, started).await
        }
        ScheduledJobName::QuarterlyRestoreDrillReminder
        | ScheduledJobName::QuarterlySigningKeyReviewReminder
        | ScheduledJobName::QuarterlyAuditorPrivilegeReviewReminder => {
            run_quarterly_scheduler_job(state, config, spec.name, started).await
        }
        ScheduledJobName::SiemBufferFlush => run_siem_buffer_flush_job(state, started).await,
    }
}

async fn run_hash_chain_verify_job(
    state: &AppState,
    started: Instant,
) -> Result<JobExecutionSummary, &'static str> {
    let summary = verify_full_ledger_hash_chain(state.supabase_client.as_ref()).await?;
    ledger_verification_job_summary(summary, "ledger_verification_failed", started)
}

async fn run_signature_verify_job(
    state: &AppState,
    started: Instant,
) -> Result<JobExecutionSummary, &'static str> {
    let summary = verify_full_ledger_signatures(state.supabase_client.as_ref()).await?;
    ledger_verification_job_summary(summary, "ledger_signature_verification_failed", started)
}

async fn run_monthly_digest_scheduler_job(
    state: &AppState,
    started: Instant,
) -> Result<JobExecutionSummary, &'static str> {
    let period = previous_month_period_from_now()?;
    ensure_monthly_verification_preconditions(state).await?;
    let digest = run_monthly_digest_generate_job(state, period.clone()).await?;
    Ok(monthly_digest_summary(digest, period, started))
}

async fn run_monthly_archive_scheduler_job(
    state: &AppState,
    config: &SchedulerConfig,
    started: Instant,
) -> Result<JobExecutionSummary, &'static str> {
    let period = previous_month_period_from_now()?;
    let digest = fetch_required_signed_digest(state.supabase_client.as_ref(), &period).await?;
    run_archive_export_job(state, config, digest).await?;
    Ok(monthly_archive_summary(period, started))
}

async fn run_monthly_timestamping_scheduler_job(
    state: &AppState,
    config: &SchedulerConfig,
    started: Instant,
) -> Result<JobExecutionSummary, &'static str> {
    let period = previous_month_period_from_now()?;
    let digest = fetch_required_signed_digest(state.supabase_client.as_ref(), &period).await?;
    let token = run_monthly_timestamping_obtain_job(state, config, digest).await?;
    Ok(monthly_timestamping_summary(period, &token, started))
}

async fn run_daily_envelope_scheduler_job(
    state: &AppState,
    config: &SchedulerConfig,
    started: Instant,
) -> Result<JobExecutionSummary, &'static str> {
    run_daily_envelope_lazy_migration_job(state, config).await?;
    Ok(daily_envelope_summary(config, started))
}

async fn run_quarterly_scheduler_job(
    state: &AppState,
    config: &SchedulerConfig,
    job_name: ScheduledJobName,
    started: Instant,
) -> Result<JobExecutionSummary, &'static str> {
    run_quarterly_job(state, config, job_name).await?;
    Ok(quarterly_reminder_summary(job_name, started))
}

async fn run_siem_buffer_flush_job(
    state: &AppState,
    started: Instant,
) -> Result<JobExecutionSummary, &'static str> {
    let summary = state
        .siem_forwarding
        .resend_pending_batch(SIEM_MAX_BATCH_SIZE)
        .await;
    Ok(siem_buffer_flush_summary(summary, started))
}

fn ledger_verification_job_summary(
    summary: LedgerVerificationSummary,
    default_error_code: &'static str,
    started: Instant,
) -> Result<JobExecutionSummary, &'static str> {
    if summary.valid {
        Ok(JobExecutionSummary::new(
            json!({ "checked_count": summary.checked_count, "valid": true }),
            None,
            started,
        ))
    } else {
        Err(summary.error_code.unwrap_or(default_error_code))
    }
}

fn monthly_digest_summary(
    digest: SignedMonthlyDigest,
    period: MonthlyDigestPeriod,
    started: Instant,
) -> JobExecutionSummary {
    JobExecutionSummary::new(
        json!({
            "digest_hash": digest.digest_hash.to_hex(),
            "target_year_month": period.as_str()
        }),
        Some(period),
        started,
    )
}

fn monthly_archive_summary(period: MonthlyDigestPeriod, started: Instant) -> JobExecutionSummary {
    JobExecutionSummary::new(
        json!({ "target_year_month": period.as_str() }),
        Some(period),
        started,
    )
}

fn monthly_timestamping_summary(
    period: MonthlyDigestPeriod,
    token: &TimestampingToken,
    started: Instant,
) -> JobExecutionSummary {
    JobExecutionSummary::new(
        json!({
            "target_year_month": period.as_str(),
            "timestamp_token_hash": TimestampingTokenHash::from_token(token).to_hex()
        }),
        Some(period),
        started,
    )
}

fn daily_envelope_summary(config: &SchedulerConfig, started: Instant) -> JobExecutionSummary {
    JobExecutionSummary::new(
        json!({
            "batch_size": config.envelope_migration_batch_size,
            "max_batches": config.envelope_migration_max_batches
        }),
        None,
        started,
    )
}

fn quarterly_reminder_summary(job_name: ScheduledJobName, started: Instant) -> JobExecutionSummary {
    JobExecutionSummary::new(json!({ "reminder": job_name.as_str() }), None, started)
}

fn siem_buffer_flush_summary(
    summary: crate::siem::SiemResendSummary,
    started: Instant,
) -> JobExecutionSummary {
    JobExecutionSummary::new(
        json!({
            "attempted": summary.attempted,
            "sent": summary.sent,
            "failed": summary.failed
        }),
        None,
        started,
    )
}

fn previous_month_period_from_now() -> Result<MonthlyDigestPeriod, &'static str> {
    previous_month_period(OffsetDateTime::now_utc()).map_err(|_| "scheduler_previous_month_failed")
}

async fn fetch_required_signed_digest(
    client: &SupabaseClient,
    period: &MonthlyDigestPeriod,
) -> Result<SignedMonthlyDigest, &'static str> {
    fetch_signed_digest(client, period)
        .await
        .map_err(|_| "scheduler_precondition_monthly_digest_missing")
}

async fn ensure_monthly_verification_preconditions(state: &AppState) -> Result<(), &'static str> {
    let hash = verify_full_ledger_hash_chain(state.supabase_client.as_ref()).await?;
    if !hash.valid {
        return Err(hash
            .error_code
            .unwrap_or("scheduler_precondition_hash_verify_failed"));
    }
    let signatures = verify_full_ledger_signatures(state.supabase_client.as_ref()).await?;
    if !signatures.valid {
        return Err(signatures
            .error_code
            .unwrap_or("scheduler_precondition_signature_verify_failed"));
    }
    Ok(())
}

pub(crate) async fn run_monthly_digest_generate_job(
    state: &AppState,
    period: MonthlyDigestPeriod,
) -> Result<SignedMonthlyDigest, &'static str> {
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
            record_monthly_digest_success_audit(&state.audit_recorder, &request_id, &digest).await;
            digest
        }
        Err(error) => {
            if error.as_error_code() == "monthly_digest_duplicate" {
                match fetch_signed_digest(state.supabase_client.as_ref(), &period).await {
                    Ok(digest) => digest,
                    Err(_) => return Err("monthly_digest_existing_fetch_failed"),
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
                return Err("monthly_digest_generate_failed");
            }
        }
    };

    Ok(signed_digest)
}

pub(crate) async fn run_archive_export_job(
    state: &AppState,
    config: &SchedulerConfig,
    signed_digest: SignedMonthlyDigest,
) -> Result<(), &'static str> {
    let archive_request_id = RequestId::generate().map_err(|_| "scheduler_request_id_failed")?;
    let archived_at = SourceEventAt::now_utc().map_err(|_| "scheduler_source_event_at_failed")?;
    let export_result = if let Some(archive_backend) = config.archive_backend.as_deref() {
        export_digest_to_archive_with_incident(
            archive_backend,
            &state.audit_recorder,
            &state.ledger_appender,
            state.incident_recorder.as_ref(),
            &signed_digest,
            archive_request_id,
            archived_at,
        )
        .await
    } else {
        let archive_backend = LocalFileArchiveBackend::new(config.local_archive_dir.clone());
        export_digest_to_archive_with_incident(
            &archive_backend,
            &state.audit_recorder,
            &state.ledger_appender,
            state.incident_recorder.as_ref(),
            &signed_digest,
            archive_request_id,
            archived_at,
        )
        .await
    };

    export_result
        .map(|_| ())
        .map_err(|_| "archive_export_failed")
}

pub(crate) async fn run_monthly_timestamping_obtain_job(
    state: &AppState,
    config: &SchedulerConfig,
    signed_digest: SignedMonthlyDigest,
) -> Result<TimestampingToken, &'static str> {
    let period = signed_digest.period.clone();
    let request_id = RequestId::generate().map_err(|_| "scheduler_request_id_failed")?;
    let requested_at = SourceEventAt::now_utc().map_err(|_| "scheduler_source_event_at_failed")?;
    let outcome = if let Some(service) = config.timestamping_provider.as_deref() {
        request_timestamping_for_digest_with_incident(
            service,
            &state.audit_recorder,
            &state.ledger_appender,
            state.incident_recorder.as_ref(),
            &signed_digest,
            request_id,
            requested_at,
        )
        .await
    } else {
        let service = InMemoryTimestampingService::new();
        request_timestamping_for_digest_with_incident(
            &service,
            &state.audit_recorder,
            &state.ledger_appender,
            state.incident_recorder.as_ref(),
            &signed_digest,
            request_id,
            requested_at,
        )
        .await
    };
    match outcome {
        Ok(token) => {
            if let Some(backend) = config.archive_backend.as_deref() {
                let object_key = ArchiveObjectKey::for_timestamping_token(&period)
                    .map_err(|_| "timestamping_token_archive_key_failed")?;
                let object = ArchiveOpaqueObject::from_timestamping_token(&token);
                backend
                    .put_opaque_object(&object_key, &object)
                    .await
                    .map_err(|_| "timestamping_token_archive_persist_failed")?;
            }
            Ok(token)
        }
        Err(_) => Err("monthly_timestamping_obtain_failed"),
    }
}

pub(crate) async fn run_daily_envelope_lazy_migration_job(
    state: &AppState,
    config: &SchedulerConfig,
) -> Result<(), &'static str> {
    let outcome = run_scheduled_envelope_migration(
        state.supabase_client.clone(),
        state.ledger_appender.clone(),
        state.master_key_ring.clone(),
        config.envelope_migration_batch_size,
        config.envelope_migration_max_batches,
    )
    .await;

    match &outcome {
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
                Ok(())
            } else {
                Err("envelope_migration_partial_failure")
            }
        }
        Err(error) => {
            tracing::error!(
                job_name = ScheduledJobName::DailyEnvelopeLazyMigration.as_str(),
                error = %error,
                "daily envelope lazy migration failed"
            );
            Err(map_envelope_migration_error(error))
        }
    }
}

fn map_envelope_migration_error(error: &KeyRotationCliError) -> &'static str {
    match error {
        KeyRotationCliError::Config(_) => "envelope_migration_config_invalid",
        KeyRotationCliError::Supabase(_) => "envelope_migration_supabase_failed",
        KeyRotationCliError::Audit(_) => "envelope_migration_audit_failed",
        KeyRotationCliError::Crypto(_) => "envelope_migration_crypto_failed",
        KeyRotationCliError::Usage(_) => "envelope_migration_failed",
    }
}

pub(crate) async fn run_quarterly_job(
    state: &AppState,
    config: &SchedulerConfig,
    job_name: ScheduledJobName,
) -> Result<(), &'static str> {
    match job_name {
        ScheduledJobName::QuarterlyRestoreDrillReminder => {
            match restore_test::run_restore_test_once(
                state,
                config.restore_test_sample_limit,
                AuditTrigger::Background,
            )
            .await
            {
                restore_test::RestoreTestOutcome::Success => Ok(()),
                restore_test::RestoreTestOutcome::Failure { error_code } => Err(error_code),
            }
        }
        ScheduledJobName::QuarterlySigningKeyReviewReminder
        | ScheduledJobName::QuarterlyAuditorPrivilegeReviewReminder => Ok(()),
        _ => Ok(()),
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LedgerVerificationSummary {
    pub(crate) valid: bool,
    pub(crate) checked_count: u64,
    pub(crate) error_code: Option<&'static str>,
}

impl LedgerVerificationSummary {
    fn valid(checked_count: u64) -> Self {
        Self {
            valid: true,
            checked_count,
            error_code: None,
        }
    }

    fn invalid(checked_count: u64, error_code: &'static str) -> Self {
        Self {
            valid: false,
            checked_count,
            error_code: Some(error_code),
        }
    }
}

pub(crate) async fn verify_full_ledger_hash_chain(
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
            return Ok(RestoreResult::ForbiddenKey(
                LedgerVerificationSummary::invalid(
                    entry_count(entries.len()),
                    "ledger_payload_forbidden_key",
                ),
            ));
        }

        let entry = row
            .try_restore_signed_ledger_entry()
            .map_err(|_| "ledger_entry_restore_failed")?;
        entries.push(entry);
    }

    Ok(RestoreResult::Restored(entries))
}

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

        if let Some(error_code) = chain_link_error(entry, expected_sequence_no, previous_hash) {
            return Ok(ledger_chain_failure_summary(entries, error_code));
        }

        previous_sequence_no = entry.sequence_no().get();
        previous_hash = entry.entry_hash();
    }

    if previous_sequence_no != chain_head.last_sequence_no()
        || previous_hash != chain_head.last_entry_hash()
    {
        return Ok(ledger_chain_failure_summary(
            entries,
            "ledger_chain_head_mismatch",
        ));
    }

    Ok(LedgerVerificationSummary::valid(entry_count(entries.len())))
}

fn chain_link_error(
    entry: &SignedLedgerEntry,
    expected_sequence_no: u64,
    previous_hash: LedgerHash,
) -> Option<&'static str> {
    if entry.sequence_no().get() != expected_sequence_no {
        Some("ledger_sequence_gap")
    } else if entry.previous_entry_hash() != previous_hash {
        Some("ledger_previous_hash_mismatch")
    } else if entry.recompute_entry_hash() != entry.entry_hash() {
        Some("ledger_entry_hash_mismatch")
    } else {
        None
    }
}

fn ledger_chain_failure_summary(
    entries: &[SignedLedgerEntry],
    error_code: &'static str,
) -> LedgerVerificationSummary {
    LedgerVerificationSummary::invalid(entry_count(entries.len()), error_code)
}

fn verify_signature_rows(
    rows: Vec<LedgerVerificationMaterialRow>,
) -> Result<LedgerVerificationSummary, &'static str> {
    let mut checked_count = 0;
    for row in &rows {
        if ledger_payload_contains_forbidden_key(&row.payload) {
            return Ok(LedgerVerificationSummary::invalid(
                checked_count,
                "ledger_payload_forbidden_key",
            ));
        }

        let entry = row
            .try_restore_signed_ledger_entry()
            .map_err(|_| "ledger_entry_restore_failed")?;
        let Some(key) = row
            .try_restore_verifying_key()
            .map_err(|_| "ledger_key_restore_failed")?
        else {
            return Ok(LedgerVerificationSummary::invalid(
                entry_count(rows.len()),
                "ledger_signature_key_missing",
            ));
        };

        if entry.verify_signature(&key).is_err() {
            return Ok(LedgerVerificationSummary::invalid(
                entry_count(rows.len()),
                "ledger_signature_invalid",
            ));
        }

        checked_count += 1;
    }

    Ok(LedgerVerificationSummary::valid(checked_count))
}

fn entry_count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

pub(crate) async fn fetch_signed_digest(
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

pub(crate) fn previous_month_period(
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

pub(crate) fn elapsed_ms(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

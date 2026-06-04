use serde_json::json;

use crate::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditMetadata, AuditResult, AuditTrigger, RequestId,
};
use crate::ledger::{
    LedgerEntryId, LedgerEntryType, LedgerPayload, LedgerResult, MonthlyDigestPeriod,
};
use crate::server::incident::{DetectedIncident, record_and_dispatch_incident};
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts};
use crate::server::state::AppState;
use crate::types::SourceEventAt;

use super::catalog::{ScheduledJobName, ScheduledJobSpec};
use super::jobs::JobExecutionSummary;

pub(crate) async fn record_scheduler_started(
    state: &AppState,
    spec: ScheduledJobSpec,
    scheduled_at: &SourceEventAt,
    started_at: &SourceEventAt,
) -> Result<(), &'static str> {
    let metadata = AuditMetadata::new(json!({
        "job_name": spec.name.as_str(),
        "scheduled_at": scheduled_at.as_str(),
        "started_at": started_at.as_str(),
        "source_event_at": started_at.as_str(),
    }))
    .map_err(|_| "scheduler_metadata_build_failed")?;
    record_scheduler_audit_event(
        state,
        AuditAction::SchedulerJobStarted,
        AuditResult::Success,
        metadata,
    )
    .await
    .map(|_| ())
}

pub(crate) async fn record_scheduler_completed(
    state: &AppState,
    spec: ScheduledJobSpec,
    started_at: &SourceEventAt,
    completed_at: &SourceEventAt,
    summary: &JobExecutionSummary,
) -> Result<(), &'static str> {
    let metadata = AuditMetadata::new(json!({
        "job_name": spec.name.as_str(),
        "started_at": started_at.as_str(),
        "completed_at": completed_at.as_str(),
        "duration_ms": summary.duration_ms,
        "result_summary": summary.result_summary,
        "source_event_at": completed_at.as_str(),
    }))
    .map_err(|_| "scheduler_metadata_build_failed")?;
    let (request_id, source_event_id) = record_scheduler_audit_event(
        state,
        AuditAction::SchedulerJobCompleted,
        AuditResult::Success,
        metadata,
    )
    .await?;
    append_scheduler_ledger_entry(
        spec.name,
        SchedulerLedgerEntryRecord {
            state,
            result: AuditResult::Success,
            error_code: None,
            period: summary.target_year_month.clone(),
            duration_ms: summary.duration_ms,
            request_id,
            source_event_at: completed_at.clone(),
            source_event_id: Some(source_event_id),
        },
    )
    .await
}

pub(crate) async fn record_scheduler_failed(
    state: &AppState,
    spec: ScheduledJobSpec,
    started_at: &SourceEventAt,
    failed_at: &SourceEventAt,
    error_code: &'static str,
) -> Result<(), &'static str> {
    let metadata = AuditMetadata::new(json!({
        "job_name": spec.name.as_str(),
        "started_at": started_at.as_str(),
        "failed_at": failed_at.as_str(),
        "error_code": error_code,
        "retry_count": 0,
        "source_event_at": failed_at.as_str(),
    }))
    .map_err(|_| "scheduler_metadata_build_failed")?;
    record_scheduler_audit_event(
        state,
        AuditAction::SchedulerJobFailed,
        AuditResult::Failure,
        metadata,
    )
    .await
    .map(|_| ())
}

pub(crate) async fn record_scheduler_skipped(
    state: &AppState,
    spec: ScheduledJobSpec,
    skipped_at: &SourceEventAt,
    reason: &'static str,
) -> Result<(), &'static str> {
    let metadata = AuditMetadata::new(json!({
        "job_name": spec.name.as_str(),
        "skipped_at": skipped_at.as_str(),
        "reason": reason,
        "source_event_at": skipped_at.as_str(),
    }))
    .map_err(|_| "scheduler_metadata_build_failed")?;
    record_scheduler_audit_event(
        state,
        AuditAction::SchedulerJobSkipped,
        AuditResult::Success,
        metadata,
    )
    .await
    .map(|_| ())
}

pub(crate) async fn record_scheduler_failure_incident(
    state: &AppState,
    spec: ScheduledJobSpec,
    failure_streak: u32,
    error_code: &'static str,
) {
    match state
        .incident_detector
        .scheduler_failure(spec.name.as_str(), failure_streak, error_code)
    {
        Ok(Some(notification)) => {
            let detected =
                DetectedIncident::from_notification(notification, spec.name.as_str(), error_code);
            record_and_dispatch_incident(state, detected).await;
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!(
                job_name = spec.name.as_str(),
                error = %error,
                "scheduler failure incident detection failed"
            );
        }
    }
}

async fn record_scheduler_audit_event(
    state: &AppState,
    action: AuditAction,
    result: AuditResult,
    metadata: AuditMetadata,
) -> Result<(RequestId, AuditEventId), &'static str> {
    let request_id = RequestId::generate().map_err(|_| "scheduler_request_id_failed")?;
    let event = AuditEvent::build_with_current_source_event_at(
        request_id.clone(),
        None,
        None,
        action,
        None,
        result,
        None,
        metadata,
    )
    .map_err(|_| "scheduler_audit_event_build_failed")?;
    let audit_event_id = event.audit_event_id().clone();
    state
        .audit_recorder
        .record(&event)
        .await
        .map_err(|_| "scheduler_audit_record_failed")?;
    Ok((request_id, audit_event_id))
}

pub(crate) struct SchedulerLedgerEntryRecord<'a> {
    pub(crate) state: &'a AppState,
    pub(crate) result: AuditResult,
    pub(crate) error_code: Option<&'static str>,
    pub(crate) period: Option<MonthlyDigestPeriod>,
    pub(crate) duration_ms: u64,
    pub(crate) request_id: RequestId,
    pub(crate) source_event_at: SourceEventAt,
    pub(crate) source_event_id: Option<AuditEventId>,
}

pub(crate) async fn append_scheduler_ledger_entry(
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

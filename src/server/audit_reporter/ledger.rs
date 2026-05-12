use serde_json::Value;

use crate::audit::{AuditEvent, AuditRecordError, AuditRecordOutcome, AuditResult, RequestId};
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts};
use crate::server::state::AppState;
use crate::{LedgerEntryId, LedgerEntryType, LedgerPayload, LedgerResult};

pub(super) async fn record_audit_with_ledger(
    state: &AppState,
    request_id: &RequestId,
    event: &AuditEvent,
    ledger_draft: LedgerAppendDraft,
    action: &'static str,
) -> Result<AuditRecordOutcome, AuditRecordError> {
    let signed_entries = state
        .ledger_appender
        .sign_entries(&[ledger_draft])
        .await
        .map_err(|error| {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action,
                result = event.result().as_str(),
                audit_record_outcome = "ledger_sign_failed",
                "audit and ledger recording failed"
            );
            AuditRecordError::LedgerAppendFailed
        })?;
    let Some(signed_entry) = signed_entries.first() else {
        tracing::error!(
            request_id = %request_id.as_canonical_string(),
            action,
            result = event.result().as_str(),
            audit_record_outcome = "ledger_entry_missing",
            "audit and ledger recording failed"
        );
        return Err(AuditRecordError::LedgerAppendFailed);
    };

    match state
        .supabase_client
        .call_append_audit_event_with_ledger(event, signed_entry)
        .await
    {
        Ok(_) => {
            let _ = state.siem_forwarding.forward_audit_event(event).await;
            let _ = state
                .siem_forwarding
                .forward_ledger_entry(signed_entry)
                .await;
            Ok(AuditRecordOutcome::PrimarySucceeded)
        }
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action,
                result = event.result().as_str(),
                audit_record_outcome = "ledger_append_failed",
                "audit and ledger recording failed"
            );
            Err(AuditRecordError::LedgerAppendFailed)
        }
    }
}

fn ledger_result_from_audit(result: AuditResult) -> Result<LedgerResult, crate::LedgerError> {
    LedgerResult::parse(result.as_str())
}

fn ledger_error_code_from_metadata(
    event: &AuditEvent,
    default_code: &'static str,
) -> Option<String> {
    if event.result() == AuditResult::Success {
        return None;
    }

    metadata_str(event.metadata_json().as_value(), "error_code")
        .map(str::to_owned)
        .or_else(|| Some(default_code.to_owned()))
}

fn metadata_u64(value: &Value, key: &'static str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn metadata_str<'a>(value: &'a Value, key: &'static str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn event_source_event_at(event: &AuditEvent) -> Result<crate::SourceEventAt, crate::LedgerError> {
    event
        .source_event_at()
        .map_err(|_| crate::LedgerError::InvalidUuid {
            field: "source_event_at",
        })
}

pub(super) fn build_restore_test_ledger_draft(
    event: &AuditEvent,
) -> Result<LedgerAppendDraft, crate::LedgerError> {
    let entry_type = LedgerEntryType::RestoreTestCompleted;
    let metadata = event.metadata_json().as_value();
    let sample_count = metadata_u64(metadata, "sample_count");
    let duration_ms = metadata_u64(metadata, "duration_ms");
    let trigger = metadata_str(metadata, "trigger").unwrap_or("scheduled");
    let (success_count, failure_count) = match event.result() {
        AuditResult::Success => (sample_count, 0),
        AuditResult::Failure => (0, metadata_u64(metadata, "failure_count").max(1)),
    };
    let payload = LedgerPayload::new(
        entry_type,
        serde_json::json!({
            "duration_ms": duration_ms,
            "failure_count": failure_count,
            "sample_count": sample_count,
            "success_count": success_count,
            "trigger": trigger,
        }),
    )?;

    LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::generate()?,
        entry_type,
        source_event_at: event_source_event_at(event)?,
        request_id: event.request_id().clone(),
        source_event_id: Some(event.audit_event_id().clone()),
        target_secret_id: event.target_secret_id().cloned(),
        target_secret_version_id: None,
        actor_user_id: event.actor_user_id().cloned(),
        actor_device_id: event.actor_device_id().cloned(),
        result: ledger_result_from_audit(event.result())?,
        error_code: ledger_error_code_from_metadata(event, "restore_test_failed"),
        payload,
    })
}

pub(super) fn build_integrity_check_ledger_draft(
    event: &AuditEvent,
) -> Result<LedgerAppendDraft, crate::LedgerError> {
    let entry_type = LedgerEntryType::IntegrityCheckCompleted;
    let metadata = event.metadata_json().as_value();
    let payload = LedgerPayload::new(
        entry_type,
        serde_json::json!({
            "checked_audit_event_count": metadata_u64(metadata, "checked_audit_event_count"),
            "checked_secret_count": metadata_u64(metadata, "checked_secret_count"),
            "checked_secret_version_count": metadata_u64(metadata, "checked_secret_version_count"),
            "duration_ms": metadata_u64(metadata, "duration_ms"),
            "violation_count": metadata_u64(metadata, "violation_count"),
        }),
    )?;

    LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::generate()?,
        entry_type,
        source_event_at: event_source_event_at(event)?,
        request_id: event.request_id().clone(),
        source_event_id: Some(event.audit_event_id().clone()),
        target_secret_id: None,
        target_secret_version_id: None,
        actor_user_id: None,
        actor_device_id: None,
        result: ledger_result_from_audit(event.result())?,
        error_code: ledger_error_code_from_metadata(event, "integrity_check_failed"),
        payload,
    })
}

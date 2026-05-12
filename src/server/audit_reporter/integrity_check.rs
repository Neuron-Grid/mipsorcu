use crate::audit::{
    AuditAction, AuditEvent, AuditMetadata, AuditRecordError, AuditRecordOutcome, AuditResult,
    RequestId,
};
use crate::server::state::AppState;

use super::ledger::{build_integrity_check_ledger_draft, record_audit_with_ledger};

pub struct IntegrityCheckAudit {
    pub result: AuditResult,
    pub metadata: AuditMetadata,
    pub error_code: Option<&'static str>,
}

pub async fn record_integrity_check_audit(
    state: &AppState,
    request_id: &RequestId,
    audit: IntegrityCheckAudit,
) -> Result<AuditRecordOutcome, AuditRecordError> {
    let IntegrityCheckAudit {
        result,
        metadata,
        error_code,
    } = audit;
    let event = match AuditEvent::build_with_current_source_event_at(
        request_id.clone(),
        None,
        None,
        AuditAction::IntegrityCheck,
        None,
        result,
        None,
        metadata,
    ) {
        Ok(event) => event,
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "integrity_check",
                result = "failure",
                error_code = "audit_event_build_failed",
                "integrity check audit setup failed"
            );
            return Err(AuditRecordError::EventConstructionFailed(error));
        }
    };

    if error_code != Some("rpc_failed") {
        let ledger_draft = build_integrity_check_ledger_draft(&event).map_err(|error| {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "integrity_check",
                result = event.result().as_str(),
                error_code = "ledger_entry_build_failed",
                "integrity check ledger entry setup failed"
            );
            AuditRecordError::LedgerAppendFailed
        })?;

        let outcome =
            record_audit_with_ledger(state, request_id, &event, ledger_draft, "integrity_check")
                .await?;
        tracing::debug!(
            request_id = %request_id.as_canonical_string(),
            action = "integrity_check",
            audit_record_outcome = "primary_succeeded",
            "integrity check audit and ledger recorded"
        );
        return Ok(outcome);
    }

    let recorder = state.audit_recorder.clone();
    match recorder.record(&event).await {
        Ok(AuditRecordOutcome::PrimarySucceeded) => {
            let _ = state.siem_forwarding.forward_audit_event(&event).await;
            tracing::debug!(
                request_id = %request_id.as_canonical_string(),
                action = "integrity_check",
                audit_record_outcome = "primary_succeeded",
                "integrity check audit recorded"
            );
            Ok(AuditRecordOutcome::PrimarySucceeded)
        }
        Ok(AuditRecordOutcome::FallbackSucceeded) => {
            let _ = state.siem_forwarding.forward_audit_event(&event).await;
            tracing::warn!(
                request_id = %request_id.as_canonical_string(),
                action = "integrity_check",
                audit_record_outcome = "fallback_succeeded",
                "integrity check audit recorded to local fallback"
            );
            Ok(AuditRecordOutcome::FallbackSucceeded)
        }
        Err(error @ AuditRecordError::PrimaryAndFallbackFailed { .. }) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "integrity_check",
                result = "failure",
                error_code = error_code.unwrap_or("audit_record_failed"),
                audit_record_outcome = "both_failed",
                "integrity check audit recording failed"
            );
            Err(error)
        }
        Err(error @ AuditRecordError::IdempotencyConflict) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "integrity_check",
                result = "failure",
                error_code = "audit_idempotency_conflict",
                audit_record_outcome = "idempotency_conflict",
                "integrity check audit recording failed"
            );
            Err(error)
        }
        Err(
            error @ (AuditRecordError::ResendReadFailed(_)
            | AuditRecordError::ResendMarkSentFailed(_)
            | AuditRecordError::EventConstructionFailed(_)
            | AuditRecordError::LedgerAppendFailed),
        ) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "integrity_check",
                result = "failure",
                error_code = error_code.unwrap_or("audit_record_failed"),
                audit_record_outcome = "unexpected_resend_error",
                "integrity check audit recording failed"
            );
            Err(error)
        }
    }
}

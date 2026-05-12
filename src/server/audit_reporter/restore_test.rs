use crate::audit::{
    AuditAction, AuditEvent, AuditMetadata, AuditRecordError, AuditRecordOutcome, AuditResult,
    RequestId,
};
use crate::server::state::AppState;
use crate::{KeyVersion, SecretId};

use super::ledger::{build_restore_test_ledger_draft, record_audit_with_ledger};

pub struct RestoreTestAudit {
    pub result: AuditResult,
    pub target_secret_id: Option<SecretId>,
    pub key_version: Option<KeyVersion>,
    pub metadata: AuditMetadata,
    pub error_code: Option<&'static str>,
}

pub async fn record_restore_test_audit(
    state: &AppState,
    request_id: &RequestId,
    audit: RestoreTestAudit,
) -> Result<AuditRecordOutcome, AuditRecordError> {
    let RestoreTestAudit {
        result,
        target_secret_id,
        key_version,
        metadata,
        error_code,
    } = audit;
    let event = match AuditEvent::build_with_current_source_event_at(
        request_id.clone(),
        None,
        None,
        AuditAction::RestoreTest,
        target_secret_id,
        result,
        key_version,
        metadata,
    ) {
        Ok(event) => event,
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "restore_test",
                result = "failure",
                error_code = "audit_event_build_failed",
                "restore test audit setup failed"
            );
            return Err(AuditRecordError::EventConstructionFailed(error));
        }
    };

    if event.result() == AuditResult::Success {
        let ledger_draft = build_restore_test_ledger_draft(&event).map_err(|error| {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "restore_test",
                result = "success",
                error_code = "ledger_entry_build_failed",
                "restore test ledger entry setup failed"
            );
            AuditRecordError::LedgerAppendFailed
        })?;

        let outcome =
            record_audit_with_ledger(state, request_id, &event, ledger_draft, "restore_test")
                .await?;
        tracing::debug!(
            request_id = %request_id.as_canonical_string(),
            action = "restore_test",
            audit_record_outcome = "primary_succeeded",
            "restore test audit and ledger recorded"
        );
        return Ok(outcome);
    }

    let recorder = state.audit_recorder.clone();
    match recorder.record(&event).await {
        Ok(AuditRecordOutcome::PrimarySucceeded) => {
            let _ = state.siem_forwarding.forward_audit_event(&event).await;
            tracing::debug!(
                request_id = %request_id.as_canonical_string(),
                action = "restore_test",
                audit_record_outcome = "primary_succeeded",
                "restore test audit recorded"
            );
            Ok(AuditRecordOutcome::PrimarySucceeded)
        }
        Ok(AuditRecordOutcome::FallbackSucceeded) => {
            let _ = state.siem_forwarding.forward_audit_event(&event).await;
            tracing::warn!(
                request_id = %request_id.as_canonical_string(),
                action = "restore_test",
                audit_record_outcome = "fallback_succeeded",
                "restore test audit recorded to local fallback"
            );
            Ok(AuditRecordOutcome::FallbackSucceeded)
        }
        Err(error @ AuditRecordError::PrimaryAndFallbackFailed { .. }) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "restore_test",
                result = "failure",
                error_code = error_code.unwrap_or("audit_record_failed"),
                audit_record_outcome = "both_failed",
                "restore test audit recording failed"
            );
            Err(error)
        }
        Err(error @ AuditRecordError::IdempotencyConflict) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "restore_test",
                result = "failure",
                error_code = "audit_idempotency_conflict",
                audit_record_outcome = "idempotency_conflict",
                "restore test audit recording failed"
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
                action = "restore_test",
                result = "failure",
                error_code = error_code.unwrap_or("audit_record_failed"),
                audit_record_outcome = "unexpected_resend_error",
                "restore test audit recording failed"
            );
            Err(error)
        }
    }
}

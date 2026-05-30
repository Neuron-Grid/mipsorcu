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

/// restore test の監査イベントを構築する。構築失敗時はログ出力して `Err` を返す。
///
/// 記録経路（ledger / fallback）から「イベント構築」の責務を分離する。他の
/// audit_reporter（decrypt_success 等）の `build_*_event` と同じ役割を担う。
fn build_restore_test_event(
    request_id: &RequestId,
    result: AuditResult,
    target_secret_id: Option<SecretId>,
    key_version: Option<KeyVersion>,
    metadata: AuditMetadata,
) -> Result<AuditEvent, AuditRecordError> {
    AuditEvent::build_with_current_source_event_at(
        request_id.clone(),
        None,
        None,
        AuditAction::RestoreTest,
        target_secret_id,
        result,
        key_version,
        metadata,
    )
    .map_err(|error| {
        tracing::error!(
            request_id = %request_id.as_canonical_string(),
            error = %error,
            action = "restore_test",
            result = "failure",
            error_code = "audit_event_build_failed",
            "restore test audit setup failed"
        );
        AuditRecordError::EventConstructionFailed(error)
    })
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
    let event =
        build_restore_test_event(request_id, result, target_secret_id, key_version, metadata)?;

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

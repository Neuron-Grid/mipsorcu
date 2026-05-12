use crate::audit::{
    AuditAction, AuditEvent, AuditMetadata, AuditRecordError, AuditRecordOutcome, AuditResult,
    EncryptCreateMetadata, EncryptRotateMetadata, RequestId,
};
use crate::server::state::AppState;
use crate::{OwnerUserId, PreparedSecretVersion, SecretId};

pub fn write_failure_audit_metadata_for_prepared_secret(
    prepared: &PreparedSecretVersion,
) -> AuditMetadata {
    let result = match prepared.write_action() {
        crate::SecretWriteAction::EncryptCreate => {
            EncryptCreateMetadata::new(prepared.version(), prepared.secret_version_id().clone())
                .build()
        }
        crate::SecretWriteAction::EncryptRotate => {
            EncryptRotateMetadata::new(prepared.version(), prepared.secret_version_id().clone())
                .build()
        }
    };

    result.unwrap_or_else(|error| {
        tracing::error!(
            error = %error,
            "failed to construct write failure audit metadata"
        );
        AuditMetadata::empty()
    })
}

pub(super) async fn record_failure_audit_with_metadata(
    state: &AppState,
    request_id: &RequestId,
    actor_user_id: Option<&OwnerUserId>,
    target_secret_id: Option<&SecretId>,
    action: AuditAction,
    metadata_json: AuditMetadata,
) -> Result<AuditRecordOutcome, AuditRecordError> {
    let event = match AuditEvent::build_with_current_source_event_at(
        request_id.clone(),
        actor_user_id.cloned(),
        None,
        action,
        target_secret_id.cloned(),
        AuditResult::Failure,
        None,
        metadata_json,
    ) {
        Ok(event) => event,
        Err(error) => {
            state.readiness_state.mark_failure_audit_both_failed();
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = action.as_str(),
                result = "failure",
                error_code = "audit_event_build_failed",
                "failed to construct failure audit event"
            );
            return Err(AuditRecordError::EventConstructionFailed(error));
        }
    };

    let recorder = state.audit_recorder.clone();
    let readiness_state = state.readiness_state.clone();
    match recorder.record(&event).await {
        Ok(AuditRecordOutcome::PrimarySucceeded) => {
            let _ = state.siem_forwarding.forward_audit_event(&event).await;
            tracing::debug!(
                request_id = %request_id.as_canonical_string(),
                action = action.as_str(),
                result = "failure",
                audit_record_outcome = "primary_succeeded",
                "failure audit recorded"
            );
            Ok(AuditRecordOutcome::PrimarySucceeded)
        }
        Ok(AuditRecordOutcome::FallbackSucceeded) => {
            let _ = state.siem_forwarding.forward_audit_event(&event).await;
            tracing::warn!(
                request_id = %request_id.as_canonical_string(),
                action = action.as_str(),
                result = "failure",
                audit_record_outcome = "fallback_succeeded",
                "failure audit recorded to local fallback"
            );
            Ok(AuditRecordOutcome::FallbackSucceeded)
        }
        Err(error @ AuditRecordError::PrimaryAndFallbackFailed { .. }) => {
            readiness_state.mark_failure_audit_both_failed();
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = action.as_str(),
                result = "failure",
                audit_record_outcome = "both_failed",
                "audit recording failed (including fallback)"
            );
            Err(error)
        }
        Err(error @ AuditRecordError::IdempotencyConflict) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = action.as_str(),
                result = "failure",
                error_code = "audit_idempotency_conflict",
                audit_record_outcome = "idempotency_conflict",
                "audit recording failed"
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
                action = action.as_str(),
                result = "failure",
                audit_record_outcome = "unexpected_resend_error",
                "audit recording failed"
            );
            Err(error)
        }
    }
}

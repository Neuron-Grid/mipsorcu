use crate::audit::{
    AuditAction, AuditEvent, AuditEventError, AuditEventId, AuditEventParts, AuditMetadata,
    AuditRecordError, AuditRecordOutcome, AuditResult, RequestId,
};
use crate::server::state::AppState;
use crate::{OwnerUserId, SecretId};

pub fn build_failure_audit_event(
    audit_event_id: AuditEventId,
    request_id: &RequestId,
    actor_user_id: Option<&OwnerUserId>,
    target_secret_id: Option<&SecretId>,
    action: AuditAction,
    metadata_json: AuditMetadata,
) -> Result<AuditEvent, AuditEventError> {
    let metadata_json = metadata_json.with_current_source_event_at()?;

    AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: actor_user_id.cloned(),
        actor_device_id: None,
        action,
        target_secret_id: target_secret_id.cloned(),
        result: AuditResult::Failure,
        key_version: None,
        metadata_json,
    })
}

pub fn failure_audit_metadata_for_attempted_secret(secret_id: &SecretId) -> AuditMetadata {
    AuditMetadata::empty()
        .with_attempted_secret_id(secret_id)
        .unwrap_or_else(|error| {
            tracing::error!(
                error = %error,
                "failed to construct attempted secret audit metadata"
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
    let audit_event_id = match AuditEventId::generate() {
        Ok(id) => id,
        Err(error) => {
            state.readiness_state.mark_failure_audit_both_failed();
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = action.as_str(),
                result = "failure",
                error_code = "audit_event_id_generation_failed",
                "failed to generate failure audit event id"
            );
            return Err(AuditRecordError::EventConstructionFailed(error));
        }
    };

    let event = match build_failure_audit_event(
        audit_event_id,
        request_id,
        actor_user_id,
        target_secret_id,
        action,
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

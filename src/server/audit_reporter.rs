use std::fmt::Display;

use crate::audit::{
    AuditAction, AuditEvent, AuditEventError, AuditEventId, AuditEventParts, AuditMetadata,
    AuditRecordError, AuditRecordOutcome, AuditResult, RequestId,
};
use crate::server::errors::ApiError;
use crate::server::state::AppState;
use crate::server::supabase::SupabaseRpcError;
use crate::{KeyVersion, OwnerUserId, SecretId};

pub struct FailureAuditContext<'a> {
    state: &'a AppState,
    request_id: &'a RequestId,
    actor_user_id: Option<&'a OwnerUserId>,
    target_secret_id: Option<&'a SecretId>,
    action: AuditAction,
}

impl<'a> FailureAuditContext<'a> {
    pub fn new(
        state: &'a AppState,
        request_id: &'a RequestId,
        actor_user_id: Option<&'a OwnerUserId>,
        target_secret_id: Option<&'a SecretId>,
        action: AuditAction,
    ) -> Self {
        Self {
            state,
            request_id,
            actor_user_id,
            target_secret_id,
            action,
        }
    }

    pub fn log(&self, error: &impl Display, stage: &'static str) {
        match self.target_secret_id {
            Some(secret_id) => {
                tracing::error!(
                    request_id = %self.request_id.as_canonical_string(),
                    secret_id = %secret_id.as_canonical_string(),
                    error = %error,
                    action = self.action.as_str(),
                    result = "failure",
                    stage,
                    "request handling failed"
                );
            }
            None => {
                tracing::error!(
                    request_id = %self.request_id.as_canonical_string(),
                    error = %error,
                    action = self.action.as_str(),
                    result = "failure",
                    stage,
                    "request handling failed"
                );
            }
        }
    }

    pub async fn record(&self) -> Result<AuditRecordOutcome, AuditRecordError> {
        record_failure_audit_with_metadata(
            self.state,
            self.request_id,
            self.actor_user_id,
            self.target_secret_id,
            self.action,
            AuditMetadata::empty(),
        )
        .await
    }

    pub async fn record_with_metadata(
        &self,
        metadata_json: AuditMetadata,
    ) -> Result<AuditRecordOutcome, AuditRecordError> {
        record_failure_audit_with_metadata(
            self.state,
            self.request_id,
            self.actor_user_id,
            self.target_secret_id,
            self.action,
            metadata_json,
        )
        .await
    }

    pub async fn log_and_record(
        &self,
        error: &impl Display,
        stage: &'static str,
    ) -> Result<AuditRecordOutcome, AuditRecordError> {
        self.log(error, stage);
        self.record().await
    }

    pub fn log_upstream_failure(&self, error: &SupabaseRpcError, stage: &'static str) {
        match (self.target_secret_id, error.upstream_status()) {
            (Some(secret_id), Some(upstream_status)) => {
                tracing::error!(
                    request_id = %self.request_id.as_canonical_string(),
                    secret_id = %secret_id.as_canonical_string(),
                    error = %error,
                    action = self.action.as_str(),
                    result = "failure",
                    error_code = "upstream_dependency_failed",
                    upstream_status,
                    stage,
                    "request handling failed"
                );
            }
            (Some(secret_id), None) => {
                tracing::error!(
                    request_id = %self.request_id.as_canonical_string(),
                    secret_id = %secret_id.as_canonical_string(),
                    error = %error,
                    action = self.action.as_str(),
                    result = "failure",
                    error_code = "upstream_dependency_failed",
                    stage,
                    "request handling failed"
                );
            }
            (None, Some(upstream_status)) => {
                tracing::error!(
                    request_id = %self.request_id.as_canonical_string(),
                    error = %error,
                    action = self.action.as_str(),
                    result = "failure",
                    error_code = "upstream_dependency_failed",
                    upstream_status,
                    stage,
                    "request handling failed"
                );
            }
            (None, None) => {
                tracing::error!(
                    request_id = %self.request_id.as_canonical_string(),
                    error = %error,
                    action = self.action.as_str(),
                    result = "failure",
                    error_code = "upstream_dependency_failed",
                    stage,
                    "request handling failed"
                );
            }
        }
    }
}

pub async fn record_success_audit(
    state: &AppState,
    request_id: &RequestId,
    actor_user_id: &OwnerUserId,
    target_secret_id: &SecretId,
    key_version: KeyVersion,
) -> Result<AuditRecordOutcome, ApiError> {
    let event = match build_success_decrypt_audit_event(
        request_id,
        actor_user_id,
        target_secret_id,
        key_version,
    ) {
        Ok(event) => event,
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                error = %error,
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                "failed to construct decrypt success audit event"
            );
            return Err(audit_recording_failed());
        }
    };

    let recorder = state.audit_recorder.clone();
    match recorder.record(&event).await {
        Ok(AuditRecordOutcome::PrimarySucceeded) => {
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                audit_record_outcome = "primary_succeeded",
                "decrypt success audit recorded"
            );
            Ok(AuditRecordOutcome::PrimarySucceeded)
        }
        Ok(AuditRecordOutcome::FallbackSucceeded) => {
            tracing::warn!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                audit_record_outcome = "fallback_succeeded",
                "decrypt success audit recorded to local fallback"
            );
            Ok(AuditRecordOutcome::FallbackSucceeded)
        }
        Err(error @ AuditRecordError::PrimaryAndFallbackFailed { .. }) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                error = %error,
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                audit_record_outcome = "both_failed",
                "decrypt success audit recording failed"
            );
            Err(audit_recording_failed())
        }
        Err(error @ AuditRecordError::IdempotencyConflict) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                error = %error,
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                error_code = "audit_idempotency_conflict",
                audit_record_outcome = "idempotency_conflict",
                "decrypt success audit recording failed"
            );
            Err(audit_recording_failed())
        }
        Err(
            error @ (AuditRecordError::ResendReadFailed(_)
            | AuditRecordError::ResendMarkSentFailed(_)
            | AuditRecordError::EventConstructionFailed(_)),
        ) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                error = %error,
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                audit_record_outcome = "unexpected_resend_error",
                "decrypt success audit recording failed"
            );
            Err(audit_recording_failed())
        }
    }
}

fn audit_recording_failed() -> ApiError {
    ApiError::AuditRecordFailed
}

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
    let audit_event_id = match AuditEventId::generate() {
        Ok(audit_event_id) => audit_event_id,
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "restore_test",
                result = "failure",
                error_code = "audit_event_id_generation_failed",
                "restore test audit setup failed"
            );
            return Err(AuditRecordError::EventConstructionFailed(error));
        }
    };
    let metadata_json = match metadata.with_current_source_event_at() {
        Ok(metadata_json) => metadata_json,
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "restore_test",
                result = "failure",
                error_code = "audit_metadata_build_failed",
                "restore test audit metadata setup failed"
            );
            return Err(AuditRecordError::EventConstructionFailed(error));
        }
    };
    let event = match AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::RestoreTest,
        target_secret_id,
        result,
        key_version,
        metadata_json,
    }) {
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

    let recorder = state.audit_recorder.clone();
    match recorder.record(&event).await {
        Ok(AuditRecordOutcome::PrimarySucceeded) => {
            tracing::debug!(
                request_id = %request_id.as_canonical_string(),
                action = "restore_test",
                audit_record_outcome = "primary_succeeded",
                "restore test audit recorded"
            );
            Ok(AuditRecordOutcome::PrimarySucceeded)
        }
        Ok(AuditRecordOutcome::FallbackSucceeded) => {
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
            | AuditRecordError::EventConstructionFailed(_)),
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

fn build_success_decrypt_audit_event(
    request_id: &RequestId,
    actor_user_id: &OwnerUserId,
    target_secret_id: &SecretId,
    key_version: KeyVersion,
) -> Result<AuditEvent, AuditEventError> {
    let metadata_json = AuditMetadata::empty().with_current_source_event_at()?;

    AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::generate()?,
        request_id: request_id.clone(),
        actor_user_id: Some(actor_user_id.clone()),
        actor_device_id: None,
        action: AuditAction::Decrypt,
        target_secret_id: Some(target_secret_id.clone()),
        result: AuditResult::Success,
        key_version: Some(key_version),
        metadata_json,
    })
}

async fn record_failure_audit_with_metadata(
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
            | AuditRecordError::EventConstructionFailed(_)),
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

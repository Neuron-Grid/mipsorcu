use std::fmt::Display;

use crate::audit::{
    AuditAction, AuditEvent, AuditEventError, AuditEventId, AuditEventParts, AuditMetadata,
    AuditRecordError, AuditRecordOutcome, AuditResult, RequestId,
};
use crate::server::state::AppState;
use crate::server::supabase::SupabaseRpcError;
use crate::{KeyVersion, OwnerUserId, SecretId};

pub(super) struct FailureAuditContext<'a> {
    state: &'a AppState,
    request_id: &'a RequestId,
    actor_user_id: Option<&'a OwnerUserId>,
    target_secret_id: Option<&'a SecretId>,
    action: AuditAction,
}

impl<'a> FailureAuditContext<'a> {
    pub(super) fn new(
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

    pub(super) fn log(&self, error: &impl Display, stage: &'static str) {
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

    pub(super) fn record(&self) {
        record_failure_audit_nonblocking(
            self.state,
            self.request_id,
            self.actor_user_id,
            self.target_secret_id,
            self.action,
        );
    }

    pub(super) fn record_with_metadata(&self, metadata_json: AuditMetadata) {
        record_failure_audit_nonblocking_with_metadata(
            self.state,
            self.request_id,
            self.actor_user_id,
            self.target_secret_id,
            self.action,
            metadata_json,
        );
    }

    pub(super) fn log_and_record(&self, error: &impl Display, stage: &'static str) {
        self.log(error, stage);
        self.record();
    }

    pub(super) fn log_upstream_failure(&self, error: &SupabaseRpcError, stage: &'static str) {
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

pub(super) async fn record_success_audit(
    state: &AppState,
    request_id: &RequestId,
    actor_user_id: &OwnerUserId,
    target_secret_id: &SecretId,
    key_version: KeyVersion,
) {
    let audit_event_id = match AuditEventId::generate() {
        Ok(id) => id,
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                error = %error,
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                "failed to generate decrypt success audit event id"
            );
            return;
        }
    };
    let event = match AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: Some(actor_user_id.clone()),
        actor_device_id: None,
        action: AuditAction::Decrypt,
        target_secret_id: Some(target_secret_id.clone()),
        result: AuditResult::Success,
        key_version: Some(key_version),
        metadata_json: AuditMetadata::empty(),
    }) {
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
            return;
        }
    };

    let recorder = state.audit_recorder.clone();
    match tokio::task::spawn_blocking(move || recorder.record(&event)).await {
        Ok(Ok(AuditRecordOutcome::PrimarySucceeded)) => {
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                audit_record_outcome = "primary_succeeded",
                "decrypt success audit recorded"
            );
        }
        Ok(Ok(AuditRecordOutcome::FallbackSucceeded)) => {
            tracing::warn!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                audit_record_outcome = "fallback_succeeded",
                "decrypt success audit recorded to local fallback"
            );
        }
        Ok(Err(error @ AuditRecordError::PrimaryAndFallbackFailed { .. })) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                error = %error,
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                audit_record_outcome = "both_failed",
                "decrypt success audit recording failed"
            );
        }
        Ok(Err(
            error @ (AuditRecordError::ResendReadFailed(_)
            | AuditRecordError::ResendMarkSentFailed(_)),
        )) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                error = %error,
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                audit_record_outcome = "unexpected_resend_error",
                "decrypt success audit recording failed"
            );
        }
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                error = %error,
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                audit_record_outcome = "spawn_failed",
                "decrypt success audit task failed"
            );
        }
    }
}

fn record_failure_audit_nonblocking(
    state: &AppState,
    request_id: &RequestId,
    actor_user_id: Option<&OwnerUserId>,
    target_secret_id: Option<&SecretId>,
    action: AuditAction,
) {
    record_failure_audit_nonblocking_with_metadata(
        state,
        request_id,
        actor_user_id,
        target_secret_id,
        action,
        AuditMetadata::empty(),
    );
}

fn record_failure_audit_nonblocking_with_metadata(
    state: &AppState,
    request_id: &RequestId,
    actor_user_id: Option<&OwnerUserId>,
    target_secret_id: Option<&SecretId>,
    action: AuditAction,
    metadata_json: AuditMetadata,
) {
    let audit_event_id = match AuditEventId::generate() {
        Ok(id) => id,
        Err(error) => {
            tracing::error!(error = %error, "failed to generate audit event id");
            return;
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
            tracing::error!(error = %error, "failed to construct audit event");
            return;
        }
    };

    let recorder = state.audit_recorder.clone();
    let readiness_state = state.readiness_state.clone();
    tokio::task::spawn_blocking(move || match recorder.record(&event) {
        Ok(AuditRecordOutcome::PrimarySucceeded) => {
            tracing::debug!(
                audit_record_outcome = "primary_succeeded",
                "failure audit recorded"
            );
        }
        Ok(AuditRecordOutcome::FallbackSucceeded) => {
            tracing::warn!(
                audit_record_outcome = "fallback_succeeded",
                "failure audit recorded to local fallback"
            );
        }
        Err(error) => {
            readiness_state.mark_failure_audit_both_failed();
            tracing::error!(
                error = %error,
                audit_record_outcome = "both_failed",
                "audit recording failed (including fallback)"
            );
        }
    });
}

pub(super) fn build_failure_audit_event(
    audit_event_id: AuditEventId,
    request_id: &RequestId,
    actor_user_id: Option<&OwnerUserId>,
    target_secret_id: Option<&SecretId>,
    action: AuditAction,
    metadata_json: AuditMetadata,
) -> Result<AuditEvent, AuditEventError> {
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

pub(super) fn failure_audit_metadata_for_attempted_secret(secret_id: &SecretId) -> AuditMetadata {
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

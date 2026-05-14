use std::fmt::Display;

use crate::audit::{AuditAction, AuditMetadata, AuditRecordError, AuditRecordOutcome, RequestId};
use crate::server::state::AppState;
use crate::server::supabase::SupabaseRpcError;
use crate::{OwnerUserId, SecretId};

use super::failure::record_failure_audit_with_metadata;

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

    pub fn log_upstream_failure_without_error_value(
        &self,
        error: &SupabaseRpcError,
        stage: &'static str,
    ) {
        match (self.target_secret_id, error.upstream_status()) {
            (Some(secret_id), Some(upstream_status)) => {
                tracing::error!(
                    request_id = %self.request_id.as_canonical_string(),
                    secret_id = %secret_id.as_canonical_string(),
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

use std::fmt::Display;

use serde_json::Value;

use crate::audit::{
    AuditAction, AuditEvent, AuditEventError, AuditEventId, AuditEventParts, AuditMetadata,
    AuditRecordError, AuditRecordOutcome, AuditResult, RequestId,
};
use crate::server::errors::ApiError;
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts};
use crate::server::state::AppState;
use crate::server::supabase::SupabaseRpcError;
use crate::{
    ALGORITHM_XCHACHA20_POLY1305, KeyVersion, LedgerEntryId, LedgerEntryType, LedgerPayload,
    LedgerResult, LedgerTargetSecretVersionId, OwnerUserId, SecretId, SecretVersion,
    SecretVersionId,
};

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
    target_secret_version_id: &SecretVersionId,
    version: SecretVersion,
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

    let ledger_draft = match build_success_decrypt_ledger_draft(
        &event,
        target_secret_version_id,
        version,
        key_version,
    ) {
        Ok(draft) => draft,
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                error = %error,
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                "failed to construct decrypt success ledger entry"
            );
            return Err(audit_recording_failed());
        }
    };
    let signed_entries = state
        .ledger_appender
        .sign_entries(&[ledger_draft])
        .await
        .map_err(|error| {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                error = %error,
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                "failed to sign decrypt success ledger entry"
            );
            ApiError::LedgerAppendFailed
        })?;
    let Some(signed_entry) = signed_entries.first() else {
        tracing::error!(
            request_id = %request_id.as_canonical_string(),
            secret_id = %target_secret_id.as_canonical_string(),
            action = AuditAction::Decrypt.as_str(),
            result = "success",
            "missing decrypt success ledger entry"
        );
        return Err(ApiError::LedgerAppendFailed);
    };

    match state
        .supabase_client
        .call_append_audit_event_with_ledger(&event, signed_entry)
        .await
    {
        Ok(_) => {
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                audit_record_outcome = "primary_succeeded",
                "decrypt success audit and ledger recorded"
            );
            Ok(AuditRecordOutcome::PrimarySucceeded)
        }
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %target_secret_id.as_canonical_string(),
                error = %error,
                action = AuditAction::Decrypt.as_str(),
                result = "success",
                audit_record_outcome = "primary_failed",
                "decrypt success audit and ledger recording failed"
            );
            Err(ApiError::LedgerAppendFailed)
        }
    }
}

fn build_success_decrypt_ledger_draft(
    event: &AuditEvent,
    target_secret_version_id: &SecretVersionId,
    version: SecretVersion,
    key_version: KeyVersion,
) -> Result<LedgerAppendDraft, crate::LedgerError> {
    let entry_type = LedgerEntryType::SecretDecrypted;
    let payload = LedgerPayload::new(
        entry_type,
        serde_json::json!({
            "algorithm": ALGORITHM_XCHACHA20_POLY1305,
            "key_version": key_version.get(),
            "version": version.get(),
        }),
    )?;
    let target_secret_version_id =
        LedgerTargetSecretVersionId::from_secret_version_id(target_secret_version_id)?;

    LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::generate()?,
        entry_type,
        source_event_at: event
            .source_event_at()
            .map_err(|_| crate::LedgerError::InvalidUuid {
                field: "source_event_at",
            })?,
        request_id: event.request_id().clone(),
        source_event_id: Some(event.audit_event_id().clone()),
        target_secret_id: event.target_secret_id().cloned(),
        target_secret_version_id: Some(target_secret_version_id),
        actor_user_id: event.actor_user_id().cloned(),
        actor_device_id: event.actor_device_id().cloned(),
        result: LedgerResult::Success,
        error_code: None,
        payload,
    })
}

async fn record_audit_with_ledger(
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
        Ok(_) => Ok(AuditRecordOutcome::PrimarySucceeded),
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

fn build_restore_test_ledger_draft(
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

fn build_integrity_check_ledger_draft(
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
    let audit_event_id = match AuditEventId::generate() {
        Ok(audit_event_id) => audit_event_id,
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "integrity_check",
                result = "failure",
                error_code = "audit_event_id_generation_failed",
                "integrity check audit setup failed"
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
                action = "integrity_check",
                result = "failure",
                error_code = "audit_metadata_build_failed",
                "integrity check audit metadata setup failed"
            );
            return Err(AuditRecordError::EventConstructionFailed(error));
        }
    };
    let event = match AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::IntegrityCheck,
        target_secret_id: None,
        result,
        key_version: None,
        metadata_json,
    }) {
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
            tracing::debug!(
                request_id = %request_id.as_canonical_string(),
                action = "integrity_check",
                audit_record_outcome = "primary_succeeded",
                "integrity check audit recorded"
            );
            Ok(AuditRecordOutcome::PrimarySucceeded)
        }
        Ok(AuditRecordOutcome::FallbackSucceeded) => {
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

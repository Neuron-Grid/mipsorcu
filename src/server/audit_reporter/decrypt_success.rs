use crate::audit::{
    AuditAction, AuditEvent, AuditEventError, AuditMetadata, AuditRecordOutcome, AuditResult,
    RequestId,
};
use crate::server::errors::ApiError;
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts};
use crate::server::state::AppState;
use crate::{
    ALGORITHM_XCHACHA20_POLY1305, KeyVersion, LedgerEntryId, LedgerEntryType, LedgerPayload,
    LedgerResult, LedgerTargetSecretVersionId, OwnerUserId, SecretId, SecretVersion,
    SecretVersionId,
};

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

fn build_success_decrypt_audit_event(
    request_id: &RequestId,
    actor_user_id: &OwnerUserId,
    target_secret_id: &SecretId,
    key_version: KeyVersion,
) -> Result<AuditEvent, AuditEventError> {
    AuditEvent::build_with_current_source_event_at(
        request_id.clone(),
        Some(actor_user_id.clone()),
        None,
        AuditAction::Decrypt,
        Some(target_secret_id.clone()),
        AuditResult::Success,
        Some(key_version),
        AuditMetadata::empty(),
    )
}

fn audit_recording_failed() -> ApiError {
    ApiError::AuditRecordFailed
}

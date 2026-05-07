use crate::audit::AuditEvent;
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts, LedgerAppender};
use crate::{LedgerEntryId, LedgerEntryType, LedgerPayload, LedgerResult, SignedLedgerEntry};

use super::KeyRotationCliError;

pub(super) fn build_key_rotation_ledger_draft(
    event: &AuditEvent,
    entry_type: LedgerEntryType,
    payload_value: serde_json::Value,
) -> Result<LedgerAppendDraft, KeyRotationCliError> {
    let payload = LedgerPayload::new(entry_type, payload_value)
        .map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;
    let source_event_at = event
        .source_event_at()
        .map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;

    LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::generate()
            .map_err(|error| KeyRotationCliError::Audit(error.to_string()))?,
        entry_type,
        source_event_at,
        request_id: event.request_id().clone(),
        source_event_id: Some(event.audit_event_id().clone()),
        target_secret_id: None,
        target_secret_version_id: None,
        actor_user_id: None,
        actor_device_id: None,
        result: LedgerResult::Success,
        error_code: None,
        payload,
    })
    .map_err(|error| KeyRotationCliError::Audit(error.to_string()))
}

pub(super) async fn sign_single_ledger_entry(
    ledger_appender: &LedgerAppender,
    ledger_draft: &LedgerAppendDraft,
) -> Result<SignedLedgerEntry, KeyRotationCliError> {
    let signed_entries = ledger_appender
        .sign_entries(std::slice::from_ref(ledger_draft))
        .await
        .map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;

    signed_entries.into_iter().next().ok_or_else(|| {
        KeyRotationCliError::Audit("ledger entry signing returned no entry".to_owned())
    })
}

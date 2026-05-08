use serde::{Deserialize, Serialize};

use crate::KeyVersion;
use crate::audit::AuditEvent;
use crate::ledger::SignedLedgerEntry;
use crate::types::supabase::{
    KeyRotationApplyOutcome, KeyRotationApplyRow, KeyRotationBatchRow, KeyRotationCompleteOutcome,
    KeyRotationStatus, LedgerEntryRpcParams,
};

use super::response::ensure_success;
use super::{SupabaseClient, SupabaseRpcError};

impl SupabaseClient {
    pub async fn call_key_rotation_status(
        &self,
        key_version: KeyVersion,
    ) -> Result<KeyRotationStatus, SupabaseRpcError> {
        let params = KeyRotationStatusParams {
            p_key_version: key_version.get(),
        };
        let response = self.post_rpc("rpc_key_rotation_status", &params).await?;
        let rows: Vec<KeyRotationStatusResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .map(KeyRotationStatus::from)
    }

    pub async fn call_list_key_rotation_batch(
        &self,
        old_key_version: KeyVersion,
        batch_limit: u32,
    ) -> Result<Vec<KeyRotationBatchRow>, SupabaseRpcError> {
        let params = KeyRotationBatchParams {
            p_old_key_version: old_key_version.get(),
            p_limit: batch_limit,
        };
        let response = self
            .post_rpc("rpc_list_key_rotation_batch", &params)
            .await?;

        ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))
    }

    pub async fn call_apply_key_rotation_batch(
        &self,
        event: &AuditEvent,
        ledger_entry: &SignedLedgerEntry,
        old_key_version: KeyVersion,
        new_key_version: KeyVersion,
        rows: Vec<KeyRotationApplyRow>,
    ) -> Result<KeyRotationApplyOutcome, SupabaseRpcError> {
        let source_event_at = event.source_event_at().map_err(|error| {
            SupabaseRpcError::InvalidResponse(format!(
                "key rotation audit event source_event_at is invalid: {error}"
            ))
        })?;
        let params = ApplyKeyRotationBatchParams {
            p_request_id: event.request_id().as_canonical_string(),
            p_old_key_version: old_key_version.get(),
            p_new_key_version: new_key_version.get(),
            p_rows: rows,
            p_audit_event_id: event.audit_event_id().as_canonical_string(),
            p_source_event_at: source_event_at.as_str().to_owned(),
            p_ledger_entry: LedgerEntryRpcParams::from_signed_entry(ledger_entry),
        };
        let response = self
            .post_rpc("rpc_apply_key_rotation_batch", &params)
            .await?;
        let rows: Vec<KeyRotationApplyResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .map(KeyRotationApplyOutcome::from)
    }

    pub async fn call_complete_key_rotation(
        &self,
        event: &AuditEvent,
        ledger_entry: &SignedLedgerEntry,
        old_key_version: KeyVersion,
        new_key_version: KeyVersion,
    ) -> Result<KeyRotationCompleteOutcome, SupabaseRpcError> {
        let source_event_at = event.source_event_at().map_err(|error| {
            SupabaseRpcError::InvalidResponse(format!(
                "key rotation audit event source_event_at is invalid: {error}"
            ))
        })?;
        let params = CompleteKeyRotationParams {
            p_request_id: event.request_id().as_canonical_string(),
            p_old_key_version: old_key_version.get(),
            p_new_key_version: new_key_version.get(),
            p_audit_event_id: event.audit_event_id().as_canonical_string(),
            p_source_event_at: source_event_at.as_str().to_owned(),
            p_ledger_entry: LedgerEntryRpcParams::from_signed_entry(ledger_entry),
        };
        let response = self.post_rpc("rpc_complete_key_rotation", &params).await?;
        let rows: Vec<KeyRotationCompleteResponse> =
            ensure_success(response)
                .await?
                .json()
                .await
                .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .map(KeyRotationCompleteOutcome::from)
    }
}

#[derive(Serialize)]
struct KeyRotationStatusParams {
    p_key_version: u32,
}

#[derive(Serialize)]
struct KeyRotationBatchParams {
    p_old_key_version: u32,
    p_limit: u32,
}

#[derive(Serialize)]
struct ApplyKeyRotationBatchParams {
    p_request_id: String,
    p_old_key_version: u32,
    p_new_key_version: u32,
    p_rows: Vec<KeyRotationApplyRow>,
    p_audit_event_id: String,
    p_source_event_at: String,
    p_ledger_entry: LedgerEntryRpcParams,
}

#[derive(Serialize)]
struct CompleteKeyRotationParams {
    p_request_id: String,
    p_old_key_version: u32,
    p_new_key_version: u32,
    p_audit_event_id: String,
    p_source_event_at: String,
    p_ledger_entry: LedgerEntryRpcParams,
}

#[derive(Debug, Deserialize)]
struct KeyRotationStatusResponse {
    key_version: i32,
    remaining_count: i64,
}

impl From<KeyRotationStatusResponse> for KeyRotationStatus {
    fn from(response: KeyRotationStatusResponse) -> Self {
        Self::new(response.key_version, response.remaining_count)
    }
}

#[derive(Debug, Deserialize)]
struct KeyRotationApplyResponse {
    processed_count: i64,
    remaining_count: i64,
}

impl From<KeyRotationApplyResponse> for KeyRotationApplyOutcome {
    fn from(response: KeyRotationApplyResponse) -> Self {
        Self::new(response.processed_count, response.remaining_count)
    }
}

#[derive(Debug, Deserialize)]
struct KeyRotationCompleteResponse {
    remaining_count: i64,
}

impl From<KeyRotationCompleteResponse> for KeyRotationCompleteOutcome {
    fn from(response: KeyRotationCompleteResponse) -> Self {
        Self::new(response.remaining_count)
    }
}

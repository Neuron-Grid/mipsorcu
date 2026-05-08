use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::AuditEvent;
use crate::ledger::{LedgerChainHead, LedgerHash, LedgerSequenceNo, SignedLedgerEntry};
use crate::types::supabase::{
    AppendLedgerEntryOutcome, LedgerAppendRpcFailure, LedgerEntryRpcParams,
};

use super::response::{ensure_success, response_contains_marker};
use super::{SupabaseClient, SupabaseRpcError};

const LEDGER_CHAIN_STATE_READ_COLUMNS: &str = "last_sequence_no,last_entry_hash";
const LEDGER_ENTRY_ID_CONFLICT_MARKER: &str = "ledger_entry_id_conflict";
const LEDGER_ENTRY_HASH_CONFLICT_MARKER: &str = "ledger_entry_hash_conflict";
const LEDGER_SEQUENCE_MISMATCH_MARKER: &str = "ledger_sequence_mismatch";
const LEDGER_PREVIOUS_HASH_MISMATCH_MARKER: &str = "ledger_previous_hash_mismatch";
const LEDGER_CHAIN_STATE_MISSING_MARKER: &str = "ledger_chain_state_missing";
const LEDGER_INVALID_RPC_INPUT_MARKER: &str = "invalid_rpc_input";
const LEDGER_PAYLOAD_SCHEMA_MARKERS: &[&str] = &[
    "ledger_payload_schema_violation",
    "ledger_entries_payload_valid",
    "ledger_payload_is_valid",
];

impl SupabaseClient {
    pub async fn call_append_ledger_entry(
        &self,
        entry: &SignedLedgerEntry,
    ) -> Result<AppendLedgerEntryOutcome, SupabaseRpcError> {
        let params = LedgerEntryRpcParams::from_signed_entry(entry);
        let response = self.post_rpc("rpc_append_ledger_entry", &params).await?;
        let rows: Vec<AppendLedgerEntryResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(AppendLedgerEntryOutcome::try_from)
    }

    pub async fn call_append_audit_event_with_ledger(
        &self,
        event: &AuditEvent,
        entry: &SignedLedgerEntry,
    ) -> Result<AppendLedgerEntryOutcome, SupabaseRpcError> {
        let params = AppendAuditEventWithLedgerParams::from_event_and_entry(event, entry);
        let response = self
            .post_rpc("rpc_append_audit_event_with_ledger", &params)
            .await?;
        let rows: Vec<AppendLedgerEntryResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(AppendLedgerEntryOutcome::try_from)
    }

    pub async fn fetch_ledger_chain_head(&self) -> Result<LedgerChainHead, SupabaseRpcError> {
        let url = format!(
            "{}/rest/v1/ledger_chain_state?select={LEDGER_CHAIN_STATE_READ_COLUMNS}&chain_id=eq.global&limit=1",
            self.base_url
        );
        let response = self
            .http_client
            .get(&url)
            .header("apikey", &self.service_role_key)
            .bearer_auth(&self.service_role_key)
            .send()
            .await
            .map_err(SupabaseRpcError::Network)?;

        let rows: Vec<LedgerChainStateResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(LedgerChainHead::try_from)
    }
}

#[derive(Serialize)]
struct AppendAuditEventWithLedgerParams {
    p_audit_event_id: String,
    p_request_id: String,
    p_actor_user_id: Option<String>,
    p_actor_device_id: Option<String>,
    p_action: String,
    p_target_secret_id: Option<String>,
    p_result: String,
    p_key_version: Option<u32>,
    p_metadata_json: Value,
    p_ledger_entry_id: String,
    p_sequence_no: u64,
    p_entry_type: String,
    p_source_event_at: String,
    p_source_event_id: Option<String>,
    p_target_secret_version_id: Option<String>,
    p_error_code: Option<String>,
    p_payload: Value,
    p_canonicalization_version: u8,
    p_previous_entry_hash: String,
    p_entry_hash: String,
    p_hash_algorithm: String,
    p_signature: String,
    p_signature_algorithm: String,
    p_signature_key_version: u32,
}

impl AppendAuditEventWithLedgerParams {
    fn from_event_and_entry(event: &AuditEvent, entry: &SignedLedgerEntry) -> Self {
        let ledger_entry = LedgerEntryRpcParams::from_signed_entry(entry);

        Self {
            p_audit_event_id: event.audit_event_id().as_canonical_string(),
            p_request_id: event.request_id().as_canonical_string(),
            p_actor_user_id: event.actor_user_id().map(|u| u.as_canonical_string()),
            p_actor_device_id: event.actor_device_id().map(|d| d.as_str().to_owned()),
            p_action: event.action().as_str().to_owned(),
            p_target_secret_id: event.target_secret_id().map(|s| s.as_canonical_string()),
            p_result: event.result().as_str().to_owned(),
            p_key_version: event.key_version().map(|kv| kv.get()),
            p_metadata_json: event.metadata_json().as_value().clone(),
            p_ledger_entry_id: ledger_entry.p_ledger_entry_id,
            p_sequence_no: ledger_entry.p_sequence_no,
            p_entry_type: ledger_entry.p_entry_type,
            p_source_event_at: ledger_entry.p_source_event_at,
            p_source_event_id: ledger_entry.p_source_event_id,
            p_target_secret_version_id: ledger_entry.p_target_secret_version_id,
            p_error_code: ledger_entry.p_error_code,
            p_payload: ledger_entry.p_payload,
            p_canonicalization_version: ledger_entry.p_canonicalization_version,
            p_previous_entry_hash: ledger_entry.p_previous_entry_hash,
            p_entry_hash: ledger_entry.p_entry_hash,
            p_hash_algorithm: ledger_entry.p_hash_algorithm,
            p_signature: ledger_entry.p_signature,
            p_signature_algorithm: ledger_entry.p_signature_algorithm,
            p_signature_key_version: ledger_entry.p_signature_key_version,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppendLedgerEntryResponse {
    ledger_entry_id: String,
    sequence_no: i64,
    entry_hash: String,
    chain_last_sequence_no: i64,
    chain_last_entry_hash: String,
    replayed: bool,
}

impl TryFrom<AppendLedgerEntryResponse> for AppendLedgerEntryOutcome {
    type Error = SupabaseRpcError;

    fn try_from(response: AppendLedgerEntryResponse) -> Result<Self, Self::Error> {
        let ledger_entry_id =
            crate::LedgerEntryId::parse(&response.ledger_entry_id).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "ledger RPC returned invalid ledger_entry_id".to_owned(),
                )
            })?;
        let sequence_no = LedgerSequenceNo::from_i64(response.sequence_no).map_err(|_| {
            SupabaseRpcError::InvalidResponse("ledger RPC returned invalid sequence_no".to_owned())
        })?;
        let entry_hash = LedgerHash::from_bytea_hex(&response.entry_hash).map_err(|_| {
            SupabaseRpcError::InvalidResponse("ledger RPC returned invalid entry_hash".to_owned())
        })?;
        let chain_last_entry_hash = LedgerHash::from_bytea_hex(&response.chain_last_entry_hash)
            .map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "ledger RPC returned invalid chain_last_entry_hash".to_owned(),
                )
            })?;
        let chain_head =
            LedgerChainHead::from_i64(response.chain_last_sequence_no, chain_last_entry_hash)
                .map_err(|_| {
                    SupabaseRpcError::InvalidResponse(
                        "ledger RPC returned invalid chain_last_sequence_no".to_owned(),
                    )
                })?;

        Ok(Self::new(
            ledger_entry_id,
            sequence_no,
            entry_hash,
            chain_head,
            response.replayed,
        ))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerChainStateResponse {
    last_sequence_no: i64,
    last_entry_hash: String,
}

impl TryFrom<LedgerChainStateResponse> for LedgerChainHead {
    type Error = SupabaseRpcError;

    fn try_from(response: LedgerChainStateResponse) -> Result<Self, Self::Error> {
        let last_entry_hash =
            LedgerHash::from_bytea_hex(&response.last_entry_hash).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "ledger chain state returned invalid last_entry_hash".to_owned(),
                )
            })?;

        LedgerChainHead::from_i64(response.last_sequence_no, last_entry_hash).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "ledger chain state returned invalid last_sequence_no".to_owned(),
            )
        })
    }
}

pub fn classify_append_ledger_error(error: &SupabaseRpcError) -> LedgerAppendRpcFailure {
    let SupabaseRpcError::NonSuccessStatus { body, .. } = error else {
        return LedgerAppendRpcFailure::AppendFailed;
    };

    if response_contains_marker(body, LEDGER_ENTRY_ID_CONFLICT_MARKER) {
        LedgerAppendRpcFailure::EntryIdConflict
    } else if response_contains_marker(body, LEDGER_ENTRY_HASH_CONFLICT_MARKER) {
        LedgerAppendRpcFailure::EntryHashConflict
    } else if response_contains_marker(body, LEDGER_SEQUENCE_MISMATCH_MARKER) {
        LedgerAppendRpcFailure::SequenceMismatch
    } else if response_contains_marker(body, LEDGER_PREVIOUS_HASH_MISMATCH_MARKER) {
        LedgerAppendRpcFailure::PreviousHashMismatch
    } else if LEDGER_PAYLOAD_SCHEMA_MARKERS
        .iter()
        .any(|marker| response_contains_marker(body, marker))
    {
        LedgerAppendRpcFailure::PayloadSchemaViolation
    } else if response_contains_marker(body, LEDGER_CHAIN_STATE_MISSING_MARKER) {
        LedgerAppendRpcFailure::ChainStateMissing
    } else if response_contains_marker(body, LEDGER_INVALID_RPC_INPUT_MARKER) {
        LedgerAppendRpcFailure::InvalidRpcInput
    } else {
        LedgerAppendRpcFailure::AppendFailed
    }
}

//! Read-only Supabase RPC client for auditor UI backend endpoints.
//!
//! The RPCs exposed here return non-secret metadata and verification material only.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ledger::LedgerSequenceNo;

use super::response::ensure_success;
use super::{SupabaseClient, SupabaseRpcError};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditUiSecretInventoryRow {
    pub secret_id: String,
    pub owner_user_id: String,
    pub classification: String,
    pub current_version_id: Option<String>,
    pub secret_created_at: String,
    pub secret_updated_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditUiAuditEventRow {
    pub audit_event_id: String,
    pub request_id: String,
    pub actor_user_id: Option<String>,
    pub actor_device_id: Option<String>,
    pub action: String,
    pub target_secret_id: Option<String>,
    pub result: String,
    pub key_version: Option<i32>,
    pub metadata_json: Value,
    pub occurred_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditUiLedgerEntryRow {
    pub ledger_entry_id: String,
    pub sequence_no: i64,
    pub entry_type: String,
    pub source_event_at: String,
    pub request_id: String,
    pub source_event_id: Option<String>,
    pub target_secret_id: Option<String>,
    pub target_secret_version_id: Option<String>,
    pub actor_user_id: Option<String>,
    pub actor_device_id: Option<String>,
    pub result: String,
    pub error_code: Option<String>,
    pub payload: Value,
    pub canonicalization_version: i32,
    pub previous_entry_hash: String,
    pub entry_hash: String,
    pub hash_algorithm: String,
    pub signature: String,
    pub signature_algorithm: String,
    pub signature_key_version: i32,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditUiIntegrityStatusRow {
    pub chain_id: String,
    pub last_sequence_no: i64,
    pub last_entry_hash: String,
    pub chain_state_updated_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditUiVerificationFailureRow {
    pub code: String,
    pub occurred_at: String,
    pub sequence_no: Option<i64>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditUiHashChainVerification {
    pub chain_valid: bool,
    pub entries_checked: u64,
    pub first_gap_sequence_no: Option<u64>,
    pub first_gap_detail: Option<String>,
    pub first_hash_mismatch_sequence_no: Option<u64>,
    pub first_hash_mismatch_detail: Option<String>,
    pub chain_head_sequence_no: Option<u64>,
    pub chain_head_entry_hash: Option<String>,
}

impl SupabaseClient {
    pub async fn fetch_audit_ui_secret_inventory(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditUiSecretInventoryRow>, SupabaseRpcError> {
        let response = self
            .post_rpc(
                "rpc_audit_ui_secret_inventory",
                &PageRpcParams::new(limit, offset),
            )
            .await?;
        decode_rows(response).await
    }

    pub async fn fetch_audit_ui_audit_events(
        &self,
        params: AuditUiAuditEventsParams,
    ) -> Result<Vec<AuditUiAuditEventRow>, SupabaseRpcError> {
        let response = self.post_rpc("rpc_audit_ui_audit_events", &params).await?;
        decode_rows(response).await
    }

    pub async fn fetch_audit_ui_ledger_entries(
        &self,
        params: AuditUiLedgerEntriesParams,
    ) -> Result<Vec<AuditUiLedgerEntryRow>, SupabaseRpcError> {
        let response = self
            .post_rpc("rpc_audit_ui_ledger_entries", &params)
            .await?;
        decode_rows(response).await
    }

    pub async fn fetch_audit_ui_integrity_status(
        &self,
    ) -> Result<Vec<AuditUiIntegrityStatusRow>, SupabaseRpcError> {
        let response = self
            .post_rpc("rpc_audit_ui_integrity_status", &EmptyRpcParams {})
            .await?;
        decode_rows(response).await
    }

    pub async fn fetch_audit_ui_verification_failures(
        &self,
        params: AuditUiVerificationFailuresParams,
    ) -> Result<Vec<AuditUiVerificationFailureRow>, SupabaseRpcError> {
        let response = self
            .post_rpc("rpc_audit_ui_verification_failures", &params)
            .await?;
        decode_rows(response).await
    }

    pub async fn verify_audit_ui_ledger_hash_chain(
        &self,
        start_sequence_no: Option<LedgerSequenceNo>,
        end_sequence_no: Option<LedgerSequenceNo>,
    ) -> Result<AuditUiHashChainVerification, SupabaseRpcError> {
        let params = AuditUiHashChainParams::new(start_sequence_no, end_sequence_no)?;
        let response = self
            .post_rpc("rpc_verify_ledger_hash_chain", &params)
            .await?;
        let rows: Vec<AuditUiHashChainVerificationResponse> = decode_rows(response).await?;
        let row = rows
            .into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)?;

        AuditUiHashChainVerification::try_from(row)
    }
}

#[derive(Serialize)]
struct EmptyRpcParams {}

#[derive(Serialize)]
struct PageRpcParams {
    p_limit: u32,
    p_offset: u32,
}

impl PageRpcParams {
    fn new(limit: u32, offset: u32) -> Self {
        Self {
            p_limit: limit,
            p_offset: offset,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditUiAuditEventsParams {
    pub p_limit: u32,
    pub p_offset: u32,
    pub p_period_start: Option<String>,
    pub p_period_end: Option<String>,
    pub p_action: Option<String>,
    pub p_result: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditUiLedgerEntriesParams {
    pub p_limit: u32,
    pub p_offset: u32,
    pub p_start_sequence_no: Option<i64>,
    pub p_end_sequence_no: Option<i64>,
    pub p_entry_type: Option<String>,
    pub p_result: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditUiVerificationFailuresParams {
    pub p_limit: u32,
    pub p_offset: u32,
    pub p_period_start: String,
    pub p_period_end: String,
}

#[derive(Serialize)]
struct AuditUiHashChainParams {
    p_start_sequence_no: Option<i64>,
    p_end_sequence_no: Option<i64>,
}

impl AuditUiHashChainParams {
    fn new(
        start_sequence_no: Option<LedgerSequenceNo>,
        end_sequence_no: Option<LedgerSequenceNo>,
    ) -> Result<Self, SupabaseRpcError> {
        Ok(Self {
            p_start_sequence_no: sequence_to_i64(start_sequence_no)?,
            p_end_sequence_no: sequence_to_i64(end_sequence_no)?,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditUiHashChainVerificationResponse {
    chain_valid: bool,
    entries_checked: i64,
    first_gap_sequence_no: Option<i64>,
    first_gap_detail: Option<String>,
    first_hash_mismatch_sequence_no: Option<i64>,
    first_hash_mismatch_detail: Option<String>,
    chain_head_sequence_no: Option<i64>,
    chain_head_entry_hash: Option<String>,
}

impl TryFrom<AuditUiHashChainVerificationResponse> for AuditUiHashChainVerification {
    type Error = SupabaseRpcError;

    fn try_from(row: AuditUiHashChainVerificationResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            chain_valid: row.chain_valid,
            entries_checked: i64_to_u64(row.entries_checked, "entries_checked")?,
            first_gap_sequence_no: optional_i64_to_u64(
                row.first_gap_sequence_no,
                "first_gap_sequence_no",
            )?,
            first_gap_detail: row.first_gap_detail,
            first_hash_mismatch_sequence_no: optional_i64_to_u64(
                row.first_hash_mismatch_sequence_no,
                "first_hash_mismatch_sequence_no",
            )?,
            first_hash_mismatch_detail: row.first_hash_mismatch_detail,
            chain_head_sequence_no: optional_i64_to_u64(
                row.chain_head_sequence_no,
                "chain_head_sequence_no",
            )?,
            chain_head_entry_hash: row
                .chain_head_entry_hash
                .map(|hash| strip_bytea_prefix(&hash)),
        })
    }
}

async fn decode_rows<T>(response: reqwest::Response) -> Result<Vec<T>, SupabaseRpcError>
where
    T: for<'de> Deserialize<'de>,
{
    ensure_success(response)
        .await?
        .json()
        .await
        .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))
}

fn sequence_to_i64(value: Option<LedgerSequenceNo>) -> Result<Option<i64>, SupabaseRpcError> {
    value
        .map(|sequence| {
            sequence.as_i64().map_err(|_| {
                SupabaseRpcError::InvalidResponse("sequence_no is outside i64 range".to_owned())
            })
        })
        .transpose()
}

fn i64_to_u64(value: i64, field: &'static str) -> Result<u64, SupabaseRpcError> {
    u64::try_from(value).map_err(|_| {
        SupabaseRpcError::InvalidResponse(format!("{field} returned a negative value"))
    })
}

fn optional_i64_to_u64(
    value: Option<i64>,
    field: &'static str,
) -> Result<Option<u64>, SupabaseRpcError> {
    value.map(|inner| i64_to_u64(inner, field)).transpose()
}

fn strip_bytea_prefix(value: &str) -> String {
    value.strip_prefix("\\x").unwrap_or(value).to_owned()
}

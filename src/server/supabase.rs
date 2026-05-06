use std::fmt;
use std::sync::Arc;

use http::StatusCode;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::{AuditAppendError, AuditEvent, AuditEventAppender, RequestId};
use crate::auth::RawJwt;
use crate::ledger::{
    LedgerChainHead, LedgerEntryId, LedgerHash, LedgerSequenceNo, SignedLedgerEntry,
};
use crate::{KeyVersion, SecretId, SecretVersion};

const CURRENT_SECRET_VERSION_READ_COLUMNS: &str = "\
id,secret_id,version,ciphertext,encrypted_data_key,key_version,\
algorithm,classification,nonce_or_iv,aad_context,created_by_user_id,\
created_at,secrets!inner(current_version_id,owner_user_id,classification)";
const AUDIT_EVENT_ID_CONFLICT_MARKER: &str = "audit_event_id_conflict";
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

pub enum SupabaseRpcError {
    Network(reqwest::Error),
    NonSuccessStatus { status: u16, body: String },
    InvalidResponse(String),
    EmptyResult,
}

impl fmt::Display for SupabaseRpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(error) => write!(formatter, "supabase network error: {error}"),
            Self::NonSuccessStatus { status, body } => {
                write!(
                    formatter,
                    "supabase returned status {status} with response body length {}",
                    body.len()
                )
            }
            Self::InvalidResponse(message) => {
                write!(formatter, "supabase invalid response: {message}")
            }
            Self::EmptyResult => write!(formatter, "supabase RPC returned no rows"),
        }
    }
}

impl std::error::Error for SupabaseRpcError {}

impl SupabaseRpcError {
    pub fn upstream_status(&self) -> Option<u16> {
        match self {
            Self::NonSuccessStatus { status, .. } => Some(*status),
            _ => None,
        }
    }
}

impl fmt::Debug for SupabaseRpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(error) => formatter
                .debug_struct("Network")
                .field("error", &error.to_string())
                .finish(),
            Self::NonSuccessStatus { status, body } => formatter
                .debug_struct("NonSuccessStatus")
                .field("status", status)
                .field("body_len", &body.len())
                .finish(),
            Self::InvalidResponse(message) => formatter
                .debug_struct("InvalidResponse")
                .field("message", message)
                .finish(),
            Self::EmptyResult => formatter.write_str("EmptyResult"),
        }
    }
}

pub struct SupabaseClient {
    http_client: reqwest::Client,
    base_url: String,
    service_role_key: String,
    publishable_key: String,
}

impl SupabaseClient {
    pub fn new(
        http_client: reqwest::Client,
        base_url: impl Into<String>,
        service_role_key: impl Into<String>,
        publishable_key: impl Into<String>,
    ) -> Self {
        Self {
            http_client,
            base_url: base_url.into(),
            service_role_key: service_role_key.into(),
            publishable_key: publishable_key.into(),
        }
    }

    pub async fn call_write_secret_version(
        &self,
        params: &WriteSecretVersionParams,
    ) -> Result<WriteSecretVersionOutcome, SupabaseRpcError> {
        let response = self.post_rpc("rpc_write_secret_version", params).await?;
        let rows: Vec<WriteSecretVersionResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(WriteSecretVersionOutcome::try_from)
    }

    pub async fn call_append_audit_event(
        &self,
        event: &AuditEvent,
    ) -> Result<(), SupabaseRpcError> {
        let params = AppendAuditEventParams::from_event(event);
        let response = self.post_rpc("rpc_append_audit_event", &params).await?;
        ensure_success(response).await.map(|_| ())
    }

    pub async fn call_append_ledger_entry(
        &self,
        entry: &SignedLedgerEntry,
    ) -> Result<AppendLedgerEntryOutcome, SupabaseRpcError> {
        let params = AppendLedgerEntryParams::from_signed_entry(entry);
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

    pub async fn fetch_current_secret_version_for_user(
        &self,
        secret_id: &SecretId,
        raw_jwt: &RawJwt,
    ) -> Result<Vec<SecretVersionReadRow>, SupabaseRpcError> {
        let secret_id = secret_id.as_canonical_string();
        let url = format!(
            "{}/rest/v1/secret_versions?select={CURRENT_SECRET_VERSION_READ_COLUMNS}&secret_id=eq.{secret_id}",
            self.base_url
        );
        let response = self
            .http_client
            .get(&url)
            .header("apikey", &self.publishable_key)
            .bearer_auth(raw_jwt.as_str())
            .send()
            .await
            .map_err(SupabaseRpcError::Network)?;

        let rows: Vec<SecretVersionReadRow> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        Ok(rows)
    }

    pub async fn call_sample_restore_test(
        &self,
        limit: u32,
    ) -> Result<Vec<RestoreTestSampleRow>, SupabaseRpcError> {
        let params = SampleRestoreTestParams { p_limit: limit };
        let response = self.post_rpc("rpc_sample_restore_test", &params).await?;
        ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))
    }

    pub async fn call_integrity_check(&self) -> Result<IntegrityCheckSummary, SupabaseRpcError> {
        let params = serde_json::json!({});
        let response = self.post_rpc("rpc_integrity_check", &params).await?;
        let rows: Vec<IntegrityCheckResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .map(IntegrityCheckSummary::from)
    }

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
        request_id: &RequestId,
        old_key_version: KeyVersion,
        new_key_version: KeyVersion,
        rows: Vec<KeyRotationApplyRow>,
    ) -> Result<KeyRotationApplyOutcome, SupabaseRpcError> {
        let params = ApplyKeyRotationBatchParams {
            p_request_id: request_id.as_canonical_string(),
            p_old_key_version: old_key_version.get(),
            p_new_key_version: new_key_version.get(),
            p_rows: rows,
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
        request_id: &RequestId,
        old_key_version: KeyVersion,
        new_key_version: KeyVersion,
    ) -> Result<KeyRotationCompleteOutcome, SupabaseRpcError> {
        let params = CompleteKeyRotationParams {
            p_request_id: request_id.as_canonical_string(),
            p_old_key_version: old_key_version.get(),
            p_new_key_version: new_key_version.get(),
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

    pub async fn probe_readiness(&self) -> bool {
        let url = format!("{}/rest/v1/", self.base_url);

        match self.readiness_probe_status(&url, None).await {
            Ok(status) if status.is_success() => true,
            Ok(StatusCode::UNAUTHORIZED) | Ok(StatusCode::FORBIDDEN) => self
                .readiness_probe_status(&url, Some(&self.publishable_key))
                .await
                .is_ok_and(|status| status.is_success()),
            Ok(_) | Err(_) => false,
        }
    }

    async fn post_rpc<T: Serialize + ?Sized>(
        &self,
        rpc_name: &str,
        params: &T,
    ) -> Result<Response, SupabaseRpcError> {
        let url = format!("{}/rest/v1/rpc/{rpc_name}", self.base_url);

        self.http_client
            .post(&url)
            .header("apikey", &self.service_role_key)
            .bearer_auth(&self.service_role_key)
            .json(params)
            .send()
            .await
            .map_err(SupabaseRpcError::Network)
    }

    async fn readiness_probe_status(
        &self,
        url: &str,
        api_key: Option<&str>,
    ) -> Result<StatusCode, reqwest::Error> {
        let request = self.http_client.head(url);
        let request = match api_key {
            Some(api_key) => request.header("apikey", api_key),
            None => request,
        };

        request.send().await.map(|response| response.status())
    }
}

async fn ensure_success(response: Response) -> Result<Response, SupabaseRpcError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }

    let body = response.text().await.unwrap_or_else(|_| String::new());
    Err(SupabaseRpcError::NonSuccessStatus {
        status: status.as_u16(),
        body,
    })
}

impl fmt::Debug for SupabaseClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupabaseClient")
            .field("base_url", &self.base_url)
            .field("service_role_key", &"<redacted>")
            .field("publishable_key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
pub struct SecretVersionReadRow {
    pub id: String,
    pub secret_id: String,
    pub version: i32,
    pub ciphertext: String,
    pub encrypted_data_key: String,
    pub key_version: i32,
    pub algorithm: String,
    pub classification: String,
    pub nonce_or_iv: String,
    pub aad_context: Value,
    pub created_by_user_id: String,
    pub created_at: String,
    pub secrets: SecretReadJoin,
}

#[derive(Debug, Deserialize)]
pub struct SecretReadJoin {
    pub current_version_id: String,
    pub owner_user_id: String,
    pub classification: String,
}

#[derive(Debug, Deserialize)]
pub struct RestoreTestSampleRow {
    pub id: String,
    pub secret_id: String,
    pub version: i32,
    pub ciphertext: String,
    pub encrypted_data_key: String,
    pub key_version: i32,
    pub nonce_or_iv: String,
    pub aad_context: Value,
    pub classification: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegrityCheckSummary {
    pub checked_secret_count: u64,
    pub checked_secret_version_count: u64,
    pub checked_audit_event_count: u64,
    pub violation_count: u64,
    pub violation_summary: IntegrityCheckViolationSummary,
}

impl IntegrityCheckSummary {
    pub fn zero() -> Self {
        Self {
            checked_secret_count: 0,
            checked_secret_version_count: 0,
            checked_audit_event_count: 0,
            violation_count: 0,
            violation_summary: IntegrityCheckViolationSummary::zero(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityCheckViolationSummary {
    pub current_version_invalid: u64,
    pub version_invalid: u64,
    pub retention_exceeded: u64,
    pub ciphertext_empty: u64,
    pub encrypted_data_key_empty: u64,
    pub nonce_length_invalid: u64,
    pub algorithm_invalid: u64,
    pub nonce_duplicate: u64,
    pub aad_keys_invalid: u64,
    pub aad_row_mismatch: u64,
    pub created_at_mismatch: u64,
    pub audit_action_invalid: u64,
    pub audit_result_invalid: u64,
    pub audit_metadata_not_object: u64,
    pub audit_metadata_forbidden_key: u64,
    pub audit_source_event_at_invalid: u64,
}

impl IntegrityCheckViolationSummary {
    pub fn zero() -> Self {
        Self {
            current_version_invalid: 0,
            version_invalid: 0,
            retention_exceeded: 0,
            ciphertext_empty: 0,
            encrypted_data_key_empty: 0,
            nonce_length_invalid: 0,
            algorithm_invalid: 0,
            nonce_duplicate: 0,
            aad_keys_invalid: 0,
            aad_row_mismatch: 0,
            created_at_mismatch: 0,
            audit_action_invalid: 0,
            audit_result_invalid: 0,
            audit_metadata_not_object: 0,
            audit_metadata_forbidden_key: 0,
            audit_source_event_at_invalid: 0,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntegrityCheckResponse {
    checked_secret_count: u64,
    checked_secret_version_count: u64,
    checked_audit_event_count: u64,
    violation_count: u64,
    violation_summary: IntegrityCheckViolationSummary,
}

impl From<IntegrityCheckResponse> for IntegrityCheckSummary {
    fn from(response: IntegrityCheckResponse) -> Self {
        Self {
            checked_secret_count: response.checked_secret_count,
            checked_secret_version_count: response.checked_secret_version_count,
            checked_audit_event_count: response.checked_audit_event_count,
            violation_count: response.violation_count,
            violation_summary: response.violation_summary,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct KeyRotationBatchRow {
    pub id: String,
    pub secret_id: String,
    pub version: i32,
    pub encrypted_data_key: String,
    pub key_version: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyRotationApplyRow {
    pub id: String,
    pub encrypted_data_key: String,
}

#[derive(Debug)]
pub struct KeyRotationStatus {
    pub key_version: i32,
    pub remaining_count: i64,
}

impl From<KeyRotationStatusResponse> for KeyRotationStatus {
    fn from(response: KeyRotationStatusResponse) -> Self {
        Self {
            key_version: response.key_version,
            remaining_count: response.remaining_count,
        }
    }
}

#[derive(Debug)]
pub struct KeyRotationApplyOutcome {
    pub processed_count: i64,
    pub remaining_count: i64,
}

impl From<KeyRotationApplyResponse> for KeyRotationApplyOutcome {
    fn from(response: KeyRotationApplyResponse) -> Self {
        Self {
            processed_count: response.processed_count,
            remaining_count: response.remaining_count,
        }
    }
}

#[derive(Debug)]
pub struct KeyRotationCompleteOutcome {
    pub remaining_count: i64,
}

impl From<KeyRotationCompleteResponse> for KeyRotationCompleteOutcome {
    fn from(response: KeyRotationCompleteResponse) -> Self {
        Self {
            remaining_count: response.remaining_count,
        }
    }
}

#[derive(Serialize)]
struct AppendLedgerEntryParams {
    p_ledger_entry_id: String,
    p_sequence_no: u64,
    p_entry_type: String,
    p_source_event_at: String,
    p_request_id: String,
    p_source_event_id: Option<String>,
    p_target_secret_id: Option<String>,
    p_target_secret_version_id: Option<String>,
    p_actor_user_id: Option<String>,
    p_actor_device_id: Option<String>,
    p_result: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendLedgerEntryOutcome {
    ledger_entry_id: LedgerEntryId,
    sequence_no: LedgerSequenceNo,
    entry_hash: LedgerHash,
    chain_head: LedgerChainHead,
    replayed: bool,
}

impl AppendLedgerEntryOutcome {
    pub fn ledger_entry_id(&self) -> &LedgerEntryId {
        &self.ledger_entry_id
    }

    pub fn sequence_no(&self) -> LedgerSequenceNo {
        self.sequence_no
    }

    pub fn entry_hash(&self) -> LedgerHash {
        self.entry_hash
    }

    pub fn chain_head(&self) -> LedgerChainHead {
        self.chain_head
    }

    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

impl TryFrom<AppendLedgerEntryResponse> for AppendLedgerEntryOutcome {
    type Error = SupabaseRpcError;

    fn try_from(response: AppendLedgerEntryResponse) -> Result<Self, Self::Error> {
        let ledger_entry_id = LedgerEntryId::parse(&response.ledger_entry_id).map_err(|_| {
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

        Ok(Self {
            ledger_entry_id,
            sequence_no,
            entry_hash,
            chain_head,
            replayed: response.replayed,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerAppendRpcFailure {
    EntryIdConflict,
    EntryHashConflict,
    SequenceMismatch,
    PreviousHashMismatch,
    PayloadSchemaViolation,
    ChainStateMissing,
    InvalidRpcInput,
    AppendFailed,
}

impl LedgerAppendRpcFailure {
    pub fn as_error_code(self) -> &'static str {
        match self {
            Self::EntryIdConflict => "ledger_entry_id_conflict",
            Self::EntryHashConflict => "ledger_entry_hash_conflict",
            Self::SequenceMismatch => "ledger_sequence_mismatch",
            Self::PreviousHashMismatch => "ledger_previous_hash_mismatch",
            Self::PayloadSchemaViolation => "ledger_payload_schema_violation",
            Self::ChainStateMissing => "ledger_chain_state_mismatch",
            Self::InvalidRpcInput | Self::AppendFailed => "ledger_append_failed",
        }
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

impl AppendLedgerEntryParams {
    fn from_signed_entry(entry: &SignedLedgerEntry) -> Self {
        Self {
            p_ledger_entry_id: entry.ledger_entry_id().as_canonical_string(),
            p_sequence_no: entry.sequence_no().get(),
            p_entry_type: entry.entry_type().as_str().to_owned(),
            p_source_event_at: entry.source_event_at().as_str().to_owned(),
            p_request_id: entry.request_id().as_canonical_string(),
            p_source_event_id: entry
                .source_event_id()
                .map(|event_id| event_id.as_canonical_string()),
            p_target_secret_id: entry
                .target_secret_id()
                .map(|secret_id| secret_id.as_canonical_string()),
            p_target_secret_version_id: entry
                .target_secret_version_id()
                .map(|version_id| version_id.as_canonical_string()),
            p_actor_user_id: entry
                .actor_user_id()
                .map(|user_id| user_id.as_canonical_string()),
            p_actor_device_id: entry
                .actor_device_id()
                .map(|device_id| device_id.as_str().to_owned()),
            p_result: entry.result().as_str().to_owned(),
            p_error_code: entry.error_code().map(str::to_owned),
            p_payload: entry.payload().as_value(),
            p_canonicalization_version: crate::ledger::LEDGER_CANONICALIZATION_VERSION_V1,
            p_previous_entry_hash: entry.previous_entry_hash().to_bytea_hex(),
            p_entry_hash: entry.entry_hash().to_bytea_hex(),
            p_hash_algorithm: crate::ledger::LEDGER_HASH_ALGORITHM_SHA256.to_owned(),
            p_signature: entry.signature().to_bytea_hex(),
            p_signature_algorithm: crate::ledger::LEDGER_SIGNATURE_ALGORITHM_ED25519.to_owned(),
            p_signature_key_version: entry.signature_key_version().get(),
        }
    }
}

#[derive(Serialize)]
pub struct WriteSecretVersionParams {
    pub p_request_id: String,
    pub p_action: String,
    pub p_secret_id: String,
    pub p_owner_user_id: String,
    pub p_classification: String,
    pub p_created_by_device_id: String,
    pub p_created_at: String,
    pub p_version: u32,
    pub p_ciphertext: String,
    pub p_encrypted_data_key: String,
    pub p_key_version: u32,
    pub p_algorithm: String,
    pub p_nonce_or_iv: String,
    pub p_aad_context: Value,
}

#[derive(Debug, Deserialize)]
struct WriteSecretVersionResponse {
    secret_id: String,
    secret_version_id: String,
    version: i32,
    #[allow(dead_code)]
    purged_version_ids: Vec<String>,
}

#[derive(Debug)]
pub struct WriteSecretVersionOutcome {
    secret_id: SecretId,
    secret_version_id: String,
    version: SecretVersion,
    purged_version_ids: Vec<String>,
}

impl WriteSecretVersionOutcome {
    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    pub fn secret_version_id(&self) -> &str {
        &self.secret_version_id
    }

    pub fn version(&self) -> SecretVersion {
        self.version
    }

    #[allow(dead_code)]
    pub fn purged_version_ids(&self) -> &[String] {
        &self.purged_version_ids
    }
}

impl TryFrom<WriteSecretVersionResponse> for WriteSecretVersionOutcome {
    type Error = SupabaseRpcError;

    fn try_from(response: WriteSecretVersionResponse) -> Result<Self, Self::Error> {
        let version = u32::try_from(response.version)
            .ok()
            .and_then(|value| SecretVersion::new(value).ok())
            .ok_or_else(|| {
                SupabaseRpcError::InvalidResponse("write RPC returned invalid version".to_owned())
            })?;

        let secret_id = SecretId::parse(&response.secret_id).map_err(|_| {
            SupabaseRpcError::InvalidResponse("write RPC returned invalid secret_id".to_owned())
        })?;

        Ok(Self {
            secret_id,
            secret_version_id: response.secret_version_id,
            version,
            purged_version_ids: response.purged_version_ids,
        })
    }
}

#[derive(Serialize)]
struct AppendAuditEventParams {
    p_audit_event_id: String,
    p_request_id: String,
    p_actor_user_id: Option<String>,
    p_actor_device_id: Option<String>,
    p_action: String,
    p_target_secret_id: Option<String>,
    p_result: String,
    p_key_version: Option<u32>,
    p_metadata_json: Value,
}

#[derive(Serialize)]
struct SampleRestoreTestParams {
    p_limit: u32,
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
}

#[derive(Serialize)]
struct CompleteKeyRotationParams {
    p_request_id: String,
    p_old_key_version: u32,
    p_new_key_version: u32,
}

#[derive(Debug, Deserialize)]
struct KeyRotationStatusResponse {
    key_version: i32,
    remaining_count: i64,
}

#[derive(Debug, Deserialize)]
struct KeyRotationApplyResponse {
    processed_count: i64,
    remaining_count: i64,
}

#[derive(Debug, Deserialize)]
struct KeyRotationCompleteResponse {
    remaining_count: i64,
}

impl AppendAuditEventParams {
    fn from_event(event: &AuditEvent) -> Self {
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
        }
    }
}

pub struct SupabaseAuditAppender {
    client: Arc<SupabaseClient>,
}

impl SupabaseAuditAppender {
    /// Builds the Supabase-backed audit appender.
    pub fn new(client: Arc<SupabaseClient>) -> Self {
        Self { client }
    }
}

impl AuditEventAppender for SupabaseAuditAppender {
    async fn append_audit_event(&self, event: &AuditEvent) -> Result<(), AuditAppendError> {
        self.client
            .call_append_audit_event(event)
            .await
            .map_err(classify_append_audit_error)
    }
}

fn classify_append_audit_error(error: SupabaseRpcError) -> AuditAppendError {
    match error {
        SupabaseRpcError::NonSuccessStatus { status, body }
            if status == StatusCode::CONFLICT.as_u16()
                && response_contains_audit_event_id_conflict(&body) =>
        {
            AuditAppendError::IdempotencyConflict
        }
        SupabaseRpcError::Network(_)
        | SupabaseRpcError::NonSuccessStatus { .. }
        | SupabaseRpcError::InvalidResponse(_)
        | SupabaseRpcError::EmptyResult => AuditAppendError::ExternalDependencyFailed {
            code: "supabase_rpc_failed",
        },
    }
}

fn response_contains_audit_event_id_conflict(body: &str) -> bool {
    response_contains_marker(body, AUDIT_EVENT_ID_CONFLICT_MARKER)
}

fn response_contains_marker(body: &str, marker: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return body.contains(marker);
    };

    ["message", "details", "hint"].into_iter().any(|field| {
        value
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|text| text.contains(marker))
    })
}

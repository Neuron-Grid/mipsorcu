use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::AuditEvent;
use crate::ledger::{LedgerSignatureKeyVersion, LedgerVerifyingKey, SignedLedgerEntry};
use crate::types::supabase::{AppendLedgerEntryOutcome, LedgerEntryRpcParams};

use super::response::{ensure_success, response_contains_marker};
use super::{SupabaseClient, SupabaseRpcError};

const REGISTER_PUBLIC_KEY_CONFLICT_MARKER: &str = "ledger_signing_public_key_conflict";
const REGISTER_PUBLIC_KEY_RETIRED_MARKER: &str = "ledger_signing_public_key_retired";
const REGISTER_INVALID_RPC_INPUT_MARKER: &str = "invalid_rpc_input";

impl SupabaseClient {
    pub async fn register_ledger_signing_public_key(
        &self,
        verification_key: &LedgerVerifyingKey,
    ) -> Result<RegisterLedgerSigningPublicKeyOutcome, SupabaseRpcError> {
        let params = RegisterLedgerSigningPublicKeyParams::from_verifying_key(verification_key);
        let response = self
            .post_rpc("rpc_register_ledger_signing_public_key", &params)
            .await?;
        let rows: Vec<RegisterLedgerSigningPublicKeyResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(RegisterLedgerSigningPublicKeyOutcome::try_from)
    }

    pub async fn get_ledger_signing_public_key_status(
        &self,
        key_version: LedgerSignatureKeyVersion,
    ) -> Result<LedgerSigningPublicKeyStatus, SupabaseRpcError> {
        let params = LedgerSigningPublicKeyStatusParams {
            p_key_version: key_version.get(),
        };
        let response = self
            .post_rpc("rpc_get_ledger_signing_public_key_status", &params)
            .await?;
        let rows: Vec<LedgerSigningPublicKeyStatusResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(LedgerSigningPublicKeyStatus::try_from)
    }

    pub async fn ensure_active_ledger_signing_public_key(
        &self,
        verification_key: &LedgerVerifyingKey,
    ) -> Result<(), SupabaseRpcError> {
        let status = self
            .get_ledger_signing_public_key_status(verification_key.key_version())
            .await?;

        if status.status != "active" {
            return Err(SupabaseRpcError::InvalidResponse(
                "ledger signing public key is not active".to_owned(),
            ));
        }

        if status.public_key.as_bytes() != verification_key.as_bytes() {
            return Err(SupabaseRpcError::InvalidResponse(
                "ledger signing public key does not match configured signing key".to_owned(),
            ));
        }

        Ok(())
    }

    pub async fn create_ledger_signing_public_key_with_ledger(
        &self,
        verification_key: &LedgerVerifyingKey,
        event: &AuditEvent,
        entry: &SignedLedgerEntry,
    ) -> Result<AppendLedgerEntryOutcome, SupabaseRpcError> {
        let params =
            SignatureKeyLifecycleParams::from_event_and_entry(Some(verification_key), event, entry);
        let response = self
            .post_rpc("rpc_create_ledger_signing_public_key_with_ledger", &params)
            .await?;
        parse_lifecycle_outcome(response).await
    }

    pub async fn activate_ledger_signing_public_key_with_ledger(
        &self,
        event: &AuditEvent,
        entry: &SignedLedgerEntry,
    ) -> Result<AppendLedgerEntryOutcome, SupabaseRpcError> {
        let params = SignatureKeyLifecycleParams::from_event_and_entry(None, event, entry);
        let response = self
            .post_rpc(
                "rpc_activate_ledger_signing_public_key_with_ledger",
                &params,
            )
            .await?;
        parse_lifecycle_outcome(response).await
    }

    pub async fn retire_ledger_signing_public_key_with_ledger(
        &self,
        event: &AuditEvent,
        entry: &SignedLedgerEntry,
    ) -> Result<AppendLedgerEntryOutcome, SupabaseRpcError> {
        let params = SignatureKeyLifecycleParams::from_event_and_entry(None, event, entry);
        let response = self
            .post_rpc("rpc_retire_ledger_signing_public_key_with_ledger", &params)
            .await?;
        parse_lifecycle_outcome(response).await
    }
}

#[derive(Serialize)]
struct RegisterLedgerSigningPublicKeyParams {
    p_key_version: u32,
    p_public_key: String,
}

impl RegisterLedgerSigningPublicKeyParams {
    fn from_verifying_key(verification_key: &LedgerVerifyingKey) -> Self {
        Self {
            p_key_version: verification_key.key_version().get(),
            p_public_key: encode_public_key_as_bytea(verification_key.as_bytes()),
        }
    }
}

fn encode_public_key_as_bytea(bytes: [u8; 32]) -> String {
    format!("\\x{}", hex::encode(bytes))
}

#[derive(Serialize)]
struct LedgerSigningPublicKeyStatusParams {
    p_key_version: u32,
}

#[derive(Debug, Clone)]
pub struct LedgerSigningPublicKeyStatus {
    pub key_version: LedgerSignatureKeyVersion,
    pub public_key: LedgerVerifyingKey,
    pub public_key_fingerprint: String,
    pub algorithm: String,
    pub status: String,
    pub created_at: String,
    pub activated_at: Option<String>,
    pub retired_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerSigningPublicKeyStatusResponse {
    key_version: i32,
    public_key: String,
    public_key_fingerprint: String,
    algorithm: String,
    status: String,
    created_at: String,
    activated_at: Option<String>,
    retired_at: Option<String>,
}

impl TryFrom<LedgerSigningPublicKeyStatusResponse> for LedgerSigningPublicKeyStatus {
    type Error = SupabaseRpcError;

    fn try_from(response: LedgerSigningPublicKeyStatusResponse) -> Result<Self, Self::Error> {
        let key_version_raw = u32::try_from(response.key_version).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "ledger signing public key status returned invalid key_version".to_owned(),
            )
        })?;
        let key_version = LedgerSignatureKeyVersion::new(key_version_raw).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "ledger signing public key status returned invalid key_version".to_owned(),
            )
        })?;
        let public_key_bytes = decode_public_key_bytea(&response.public_key)?;
        let public_key = LedgerVerifyingKey::from_public_key_bytes(key_version, &public_key_bytes)
            .map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "ledger signing public key status returned invalid public_key".to_owned(),
                )
            })?;
        if response.algorithm != "ed25519" {
            return Err(SupabaseRpcError::InvalidResponse(
                "ledger signing public key status returned invalid algorithm".to_owned(),
            ));
        }

        Ok(Self {
            key_version,
            public_key,
            public_key_fingerprint: response.public_key_fingerprint,
            algorithm: response.algorithm,
            status: response.status,
            created_at: response.created_at,
            activated_at: response.activated_at,
            retired_at: response.retired_at,
        })
    }
}

fn decode_public_key_bytea(value: &str) -> Result<Vec<u8>, SupabaseRpcError> {
    let hex_value = value.strip_prefix("\\x").ok_or_else(|| {
        SupabaseRpcError::InvalidResponse(
            "ledger signing public key status returned public_key without bytea prefix".to_owned(),
        )
    })?;
    hex::decode(hex_value).map_err(|_| {
        SupabaseRpcError::InvalidResponse(
            "ledger signing public key status returned invalid public_key hex".to_owned(),
        )
    })
}

#[derive(Serialize)]
struct SignatureKeyLifecycleParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    p_key_version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p_public_key: Option<String>,
    p_audit_event_id: String,
    p_request_id: String,
    p_actor_user_id: Option<String>,
    p_actor_device_id: Option<String>,
    p_action: String,
    p_target_secret_id: Option<String>,
    p_result: String,
    p_key_version_audit: Option<u32>,
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

impl SignatureKeyLifecycleParams {
    fn from_event_and_entry(
        verification_key: Option<&LedgerVerifyingKey>,
        event: &AuditEvent,
        entry: &SignedLedgerEntry,
    ) -> Self {
        let ledger_entry = LedgerEntryRpcParams::from_signed_entry(entry);

        Self {
            p_key_version: verification_key.map(|key| key.key_version().get()),
            p_public_key: verification_key.map(|key| encode_public_key_as_bytea(key.as_bytes())),
            p_audit_event_id: event.audit_event_id().as_canonical_string(),
            p_request_id: event.request_id().as_canonical_string(),
            p_actor_user_id: event.actor_user_id().map(|u| u.as_canonical_string()),
            p_actor_device_id: event.actor_device_id().map(|d| d.as_str().to_owned()),
            p_action: event.action().as_str().to_owned(),
            p_target_secret_id: event.target_secret_id().map(|s| s.as_canonical_string()),
            p_result: event.result().as_str().to_owned(),
            p_key_version_audit: event.key_version().map(|kv| kv.get()),
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

async fn parse_lifecycle_outcome(
    response: reqwest::Response,
) -> Result<AppendLedgerEntryOutcome, SupabaseRpcError> {
    let rows: Vec<super::ledger_rpc::AppendLedgerEntryResponse> = ensure_success(response)
        .await?
        .json()
        .await
        .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

    rows.into_iter()
        .next()
        .ok_or(SupabaseRpcError::EmptyResult)
        .and_then(AppendLedgerEntryOutcome::try_from)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterLedgerSigningPublicKeyOutcome {
    replayed: bool,
}

impl RegisterLedgerSigningPublicKeyOutcome {
    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    dead_code,
    reason = "fields exist for serde(deny_unknown_fields) validation"
)]
struct RegisterLedgerSigningPublicKeyResponse {
    out_key_version: i32,
    public_key: String,
    algorithm: String,
    status: String,
    created_at: String,
    retired_at: Option<String>,
    replayed: bool,
}

impl TryFrom<RegisterLedgerSigningPublicKeyResponse> for RegisterLedgerSigningPublicKeyOutcome {
    type Error = SupabaseRpcError;

    fn try_from(response: RegisterLedgerSigningPublicKeyResponse) -> Result<Self, Self::Error> {
        if response.out_key_version <= 0 {
            return Err(SupabaseRpcError::InvalidResponse(
                "register ledger signing public key RPC returned invalid out_key_version"
                    .to_owned(),
            ));
        }

        Ok(Self {
            replayed: response.replayed,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterPublicKeyError {
    Conflict,
    Retired,
    InvalidRpcInput,
    RegisterFailed,
}

impl RegisterPublicKeyError {
    pub fn as_error_code(self) -> &'static str {
        match self {
            Self::Conflict => REGISTER_PUBLIC_KEY_CONFLICT_MARKER,
            Self::Retired => REGISTER_PUBLIC_KEY_RETIRED_MARKER,
            Self::InvalidRpcInput => REGISTER_INVALID_RPC_INPUT_MARKER,
            Self::RegisterFailed => "ledger_public_key_register_failed",
        }
    }
}

pub fn classify_register_public_key_error(error: &SupabaseRpcError) -> RegisterPublicKeyError {
    let SupabaseRpcError::NonSuccessStatus { body, .. } = error else {
        return RegisterPublicKeyError::RegisterFailed;
    };

    if response_contains_marker(body, REGISTER_PUBLIC_KEY_CONFLICT_MARKER) {
        RegisterPublicKeyError::Conflict
    } else if response_contains_marker(body, REGISTER_PUBLIC_KEY_RETIRED_MARKER) {
        RegisterPublicKeyError::Retired
    } else if response_contains_marker(body, REGISTER_INVALID_RPC_INPUT_MARKER) {
        RegisterPublicKeyError::InvalidRpcInput
    } else {
        RegisterPublicKeyError::RegisterFailed
    }
}

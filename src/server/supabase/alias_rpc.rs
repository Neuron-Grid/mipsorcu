use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::alias::AliasFingerprint;
use crate::server::supabase::response::{ensure_success, response_contains_marker};
use crate::types::supabase::{SecretAliasListRow, SecretAliasResolveRow};
use crate::{OwnerUserId, SecretAliasId, SecretId};

use super::{SupabaseClient, SupabaseRpcError};

const ALIAS_CONFLICT_MARKER: &str = "alias_conflict";
const INVALID_RPC_INPUT_MARKER: &str = "invalid_rpc_input";
const OWNER_MISMATCH_MARKER: &str = "owner_mismatch";
const ALIAS_NOT_FOUND_MARKER: &str = "alias_not_found";
const SECRET_NOT_FOUND_MARKER: &str = "secret_not_found";

impl SupabaseClient {
    pub async fn call_create_secret_alias(
        &self,
        params: &CreateSecretAliasParams,
    ) -> Result<SecretAliasId, SupabaseRpcError> {
        let response = self.post_rpc("rpc_create_secret_alias", params).await?;
        let rows: Vec<CreateSecretAliasResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(|row| {
                SecretAliasId::parse(&row.secret_alias_id).map_err(|_| {
                    SupabaseRpcError::InvalidResponse(
                        "create alias RPC returned invalid secret_alias_id".to_owned(),
                    )
                })
            })
    }

    pub async fn call_update_secret_alias(
        &self,
        params: &UpdateSecretAliasParams,
    ) -> Result<AliasFingerprint, SupabaseRpcError> {
        let response = self.post_rpc("rpc_update_secret_alias", params).await?;
        let rows: Vec<UpdateSecretAliasResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(|row| parse_alias_fingerprint_bytea(&row.old_alias_fingerprint))
    }

    pub async fn call_delete_secret_alias(
        &self,
        params: &DeleteSecretAliasParams,
    ) -> Result<AliasFingerprint, SupabaseRpcError> {
        let response = self.post_rpc("rpc_delete_secret_alias", params).await?;
        let rows: Vec<DeleteSecretAliasResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(|row| parse_alias_fingerprint_bytea(&row.alias_fingerprint))
    }

    pub async fn call_list_secret_aliases(
        &self,
        params: &ListSecretAliasesParams,
    ) -> Result<Vec<SecretAliasListRow>, SupabaseRpcError> {
        let response = self.post_rpc("rpc_list_secret_aliases", params).await?;
        ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))
    }

    pub async fn call_resolve_secret_alias(
        &self,
        owner_user_id: &OwnerUserId,
        fingerprint: &AliasFingerprint,
    ) -> Result<Option<SecretAliasResolveRow>, SupabaseRpcError> {
        let params = ResolveSecretAliasParams {
            p_owner_user_id: owner_user_id.as_canonical_string(),
            p_alias_fingerprint: encode_bytea(fingerprint.as_bytes()),
        };
        let response = self.post_rpc("rpc_resolve_secret_alias", &params).await?;
        let rows: Vec<SecretAliasResolveRow> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        match rows.len() {
            0 => Ok(None),
            1 => Ok(rows.into_iter().next()),
            count => Err(SupabaseRpcError::InvalidResponse(format!(
                "resolve alias RPC returned {count} rows"
            ))),
        }
    }

    pub async fn call_get_secret_alias_for_update(
        &self,
        owner_user_id: &OwnerUserId,
        secret_alias_id: &SecretAliasId,
    ) -> Result<SecretId, SupabaseRpcError> {
        let params = GetSecretAliasForUpdateParams {
            p_owner_user_id: owner_user_id.as_canonical_string(),
            p_secret_alias_id: secret_alias_id.as_canonical_string(),
        };
        let response = self
            .post_rpc("rpc_get_secret_alias_for_update", &params)
            .await?;
        let rows: Vec<GetSecretAliasForUpdateResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(|row| {
                SecretId::parse(&row.secret_id).map_err(|_| {
                    SupabaseRpcError::InvalidResponse(
                        "get alias update context RPC returned invalid secret_id".to_owned(),
                    )
                })
            })
    }
}

#[derive(Clone, Serialize)]
pub struct CreateSecretAliasParams {
    pub p_request_id: String,
    pub p_secret_alias_id: String,
    pub p_secret_id: String,
    pub p_owner_user_id: String,
    pub p_alias_ciphertext: String,
    pub p_alias_nonce: String,
    pub p_alias_key_version: u32,
    pub p_alias_fingerprint: String,
    pub p_alias_fingerprint_key_version: u32,
    pub p_alias_fingerprint_schema_version: u32,
    pub p_aad_context: Value,
    pub p_created_at: String,
    pub p_source_event_at: String,
}

#[derive(Clone, Serialize)]
pub struct UpdateSecretAliasParams {
    pub p_request_id: String,
    pub p_secret_alias_id: String,
    pub p_owner_user_id: String,
    pub p_alias_ciphertext: String,
    pub p_alias_nonce: String,
    pub p_alias_key_version: u32,
    pub p_new_alias_fingerprint: String,
    pub p_alias_fingerprint_key_version: u32,
    pub p_alias_fingerprint_schema_version: u32,
    pub p_aad_context: Value,
    pub p_source_event_at: String,
}

#[derive(Clone, Serialize)]
pub struct DeleteSecretAliasParams {
    pub p_request_id: String,
    pub p_secret_alias_id: String,
    pub p_owner_user_id: String,
    pub p_source_event_at: String,
}

#[derive(Clone, Serialize)]
pub struct ListSecretAliasesParams {
    pub p_request_id: String,
    pub p_owner_user_id: String,
    pub p_limit: u32,
    pub p_offset: u32,
}

#[derive(Serialize)]
struct ResolveSecretAliasParams {
    p_owner_user_id: String,
    p_alias_fingerprint: String,
}

#[derive(Serialize)]
struct GetSecretAliasForUpdateParams {
    p_owner_user_id: String,
    p_secret_alias_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSecretAliasResponse {
    secret_alias_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateSecretAliasResponse {
    old_alias_fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteSecretAliasResponse {
    alias_fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetSecretAliasForUpdateResponse {
    secret_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretAliasRpcError {
    AliasConflict,
    InvalidInput,
    OwnerMismatch,
    AliasNotFound,
    SecretNotFound,
    Failed,
}

pub fn classify_secret_alias_rpc_error(error: &SupabaseRpcError) -> SecretAliasRpcError {
    let SupabaseRpcError::NonSuccessStatus { body, .. } = error else {
        return SecretAliasRpcError::Failed;
    };

    if response_contains_marker(body, ALIAS_CONFLICT_MARKER) {
        SecretAliasRpcError::AliasConflict
    } else if response_contains_marker(body, INVALID_RPC_INPUT_MARKER) {
        SecretAliasRpcError::InvalidInput
    } else if response_contains_marker(body, OWNER_MISMATCH_MARKER) {
        SecretAliasRpcError::OwnerMismatch
    } else if response_contains_marker(body, ALIAS_NOT_FOUND_MARKER) {
        SecretAliasRpcError::AliasNotFound
    } else if response_contains_marker(body, SECRET_NOT_FOUND_MARKER) {
        SecretAliasRpcError::SecretNotFound
    } else {
        SecretAliasRpcError::Failed
    }
}

pub(crate) fn encode_bytea(bytes: &[u8]) -> String {
    format!("\\x{}", hex::encode(bytes))
}

pub(crate) fn decode_bytea(value: &str) -> Result<Vec<u8>, SupabaseRpcError> {
    let hex_value = value.strip_prefix("\\x").ok_or_else(|| {
        SupabaseRpcError::InvalidResponse("bytea value is not hex encoded".to_owned())
    })?;

    hex::decode(hex_value)
        .map_err(|_| SupabaseRpcError::InvalidResponse("bytea value is invalid".to_owned()))
}

fn parse_alias_fingerprint_bytea(value: &str) -> Result<AliasFingerprint, SupabaseRpcError> {
    let bytes = decode_bytea(value)?;
    AliasFingerprint::parse(&bytes).map_err(|_| {
        SupabaseRpcError::InvalidResponse("RPC returned invalid alias fingerprint".to_owned())
    })
}

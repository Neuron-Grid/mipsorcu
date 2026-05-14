use serde::{Deserialize, Serialize};

use crate::auth::RawJwt;
use crate::server::supabase::response::{ensure_success, response_contains_marker};
use crate::types::supabase::{CreateSecretAliasOutcome, SecretAliasReadRow};
use crate::{AliasNormalized, OwnerUserId, SecretAlias, SecretId};

use super::{SupabaseClient, SupabaseRpcError};

const SECRET_ALIAS_READ_COLUMNS: &str = "secret_id,owner_user_id,alias_normalized";
const SECRET_ALIAS_DUPLICATE_MARKER: &str = "secret_alias_duplicate";
const SECRET_ALIAS_INVALID_MARKER: &str = "secret_alias_invalid";
const SECRET_ALIAS_OWNER_MISMATCH_MARKER: &str = "secret_alias_owner_mismatch";
const SECRET_ALIAS_NOT_FOUND_MARKER: &str = "secret_alias_secret_not_found";

impl SupabaseClient {
    pub async fn resolve_secret_alias_for_user(
        &self,
        alias_normalized: &AliasNormalized,
        raw_jwt: &RawJwt,
    ) -> Result<Vec<SecretAliasReadRow>, SupabaseRpcError> {
        let url = format!(
            "{}/rest/v1/secret_aliases?select={SECRET_ALIAS_READ_COLUMNS}&alias_normalized=eq.{}",
            self.base_url,
            alias_normalized.as_str()
        );
        let response = self
            .http_client
            .get(&url)
            .header("apikey", &self.publishable_key)
            .bearer_auth(raw_jwt.as_str())
            .send()
            .await
            .map_err(SupabaseRpcError::Network)?;

        ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))
    }

    pub async fn call_create_secret_alias(
        &self,
        secret_id: &SecretId,
        owner_user_id: &OwnerUserId,
        alias: &SecretAlias,
    ) -> Result<CreateSecretAliasOutcome, SupabaseRpcError> {
        let alias_normalized = alias.normalized();
        let params = CreateSecretAliasParams {
            p_secret_id: secret_id.as_canonical_string(),
            p_owner_user_id: owner_user_id.as_canonical_string(),
            p_alias: alias.as_str().to_owned(),
            p_alias_normalized: alias_normalized.as_str().to_owned(),
        };
        let response = self.post_rpc("rpc_create_secret_alias", &params).await?;
        let rows: Vec<CreateSecretAliasResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(CreateSecretAliasOutcome::try_from)
    }
}

#[derive(Serialize)]
struct CreateSecretAliasParams {
    p_secret_id: String,
    p_owner_user_id: String,
    p_alias: String,
    p_alias_normalized: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSecretAliasResponse {
    secret_id: String,
    alias: String,
    alias_normalized: String,
}

impl TryFrom<CreateSecretAliasResponse> for CreateSecretAliasOutcome {
    type Error = SupabaseRpcError;

    fn try_from(response: CreateSecretAliasResponse) -> Result<Self, Self::Error> {
        let secret_id = SecretId::parse(&response.secret_id).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "create alias RPC returned invalid secret_id".to_owned(),
            )
        })?;
        let alias = SecretAlias::new(&response.alias).map_err(|_| {
            SupabaseRpcError::InvalidResponse("create alias RPC returned invalid alias".to_owned())
        })?;
        let alias_normalized = AliasNormalized::new(&response.alias_normalized).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "create alias RPC returned invalid alias_normalized".to_owned(),
            )
        })?;

        Ok(CreateSecretAliasOutcome::new(
            secret_id,
            alias,
            alias_normalized,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateSecretAliasRpcError {
    Duplicate,
    InvalidInput,
    OwnerMismatch,
    SecretNotFound,
    CreateFailed,
}

pub fn classify_create_secret_alias_error(error: &SupabaseRpcError) -> CreateSecretAliasRpcError {
    let SupabaseRpcError::NonSuccessStatus { body, .. } = error else {
        return CreateSecretAliasRpcError::CreateFailed;
    };

    if response_contains_marker(body, SECRET_ALIAS_DUPLICATE_MARKER) {
        CreateSecretAliasRpcError::Duplicate
    } else if response_contains_marker(body, SECRET_ALIAS_INVALID_MARKER) {
        CreateSecretAliasRpcError::InvalidInput
    } else if response_contains_marker(body, SECRET_ALIAS_OWNER_MISMATCH_MARKER) {
        CreateSecretAliasRpcError::OwnerMismatch
    } else if response_contains_marker(body, SECRET_ALIAS_NOT_FOUND_MARKER) {
        CreateSecretAliasRpcError::SecretNotFound
    } else {
        CreateSecretAliasRpcError::CreateFailed
    }
}

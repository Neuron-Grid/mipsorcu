use std::fmt;

use crate::audit::RequestId;
use crate::auth::{RawJwt, VerifiedJwtClaims};
use crate::server::errors::ApiError;
use crate::server::read_model::{
    FetchCurrentSecretVersionError, ResolveSecretRefError, fetch_current_secret_version,
    resolve_secret_ref,
};
use crate::server::state::AppState;
use crate::server::supabase::{CreateSecretAliasRpcError, classify_create_secret_alias_error};
use crate::{AliasNormalized, SecretAlias, SecretId, SecretRef};

pub(in crate::server) struct CreateSecretAliasCommand {
    requested_secret_ref: SecretRef,
    alias: SecretAlias,
}

impl CreateSecretAliasCommand {
    pub(in crate::server) fn new(requested_secret_ref: SecretRef, alias: SecretAlias) -> Self {
        Self {
            requested_secret_ref,
            alias,
        }
    }
}

impl fmt::Debug for CreateSecretAliasCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateSecretAliasCommand")
            .field("requested_secret_ref", &self.requested_secret_ref)
            .field("alias", &self.alias)
            .finish()
    }
}

pub(in crate::server) struct CreateSecretAliasOutput {
    secret_id: SecretId,
    alias: SecretAlias,
    alias_normalized: AliasNormalized,
}

impl CreateSecretAliasOutput {
    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    pub fn alias(&self) -> &SecretAlias {
        &self.alias
    }

    pub fn alias_normalized(&self) -> &AliasNormalized {
        &self.alias_normalized
    }
}

pub(in crate::server) async fn create_secret_alias(
    state: &AppState,
    request_id: &RequestId,
    raw_jwt: &RawJwt,
    claims: &VerifiedJwtClaims,
    command: CreateSecretAliasCommand,
) -> Result<CreateSecretAliasOutput, ApiError> {
    let actor_user_id = claims.subject_user_id().clone();
    let secret_id = resolve_secret_ref(state, command.requested_secret_ref, raw_jwt)
        .await
        .map_err(api_error_from_resolve_secret_ref)?;

    let current = fetch_current_secret_version(state, &secret_id, raw_jwt)
        .await
        .map_err(api_error_from_current_secret_version)?;
    if current.owner_user_id() != &actor_user_id {
        return Err(ApiError::Forbidden("forbidden".to_owned()));
    }

    let outcome = state
        .supabase_client
        .call_create_secret_alias(&secret_id, &actor_user_id, &command.alias)
        .await
        .map_err(api_error_from_create_alias_rpc)?;

    tracing::info!(
        request_id = %request_id.as_canonical_string(),
        secret_id = %outcome.secret_id().as_canonical_string(),
        action = "secret_alias_create",
        result = "success",
    );

    Ok(CreateSecretAliasOutput {
        secret_id: outcome.secret_id().clone(),
        alias: outcome.alias().clone(),
        alias_normalized: outcome.alias_normalized().clone(),
    })
}

fn api_error_from_resolve_secret_ref(error: ResolveSecretRefError) -> ApiError {
    match error {
        ResolveSecretRefError::Upstream(error) => ApiError::from(error),
        ResolveSecretRefError::Api(error) => error,
    }
}

fn api_error_from_current_secret_version(error: FetchCurrentSecretVersionError) -> ApiError {
    match error {
        FetchCurrentSecretVersionError::Upstream(error) => ApiError::from(error),
        FetchCurrentSecretVersionError::Api(error) => error,
    }
}

fn api_error_from_create_alias_rpc(error: crate::server::supabase::SupabaseRpcError) -> ApiError {
    match classify_create_secret_alias_error(&error) {
        CreateSecretAliasRpcError::Duplicate => {
            ApiError::Conflict("secret alias already exists".to_owned())
        }
        CreateSecretAliasRpcError::InvalidInput => {
            ApiError::BadRequest("invalid secret alias".to_owned())
        }
        CreateSecretAliasRpcError::OwnerMismatch => ApiError::Forbidden("forbidden".to_owned()),
        CreateSecretAliasRpcError::SecretNotFound => {
            ApiError::NotFound("secret not found".to_owned())
        }
        CreateSecretAliasRpcError::CreateFailed => ApiError::from(error),
    }
}

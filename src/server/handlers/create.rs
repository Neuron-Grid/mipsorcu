use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use crate::audit::AuditAction;
use crate::prepare_new_secret_version;
use crate::server::dto::{CreateSecretRequest, CreateSecretResponse};
use crate::server::errors::ApiError;
use crate::server::middleware::AuthenticatedUser;
use crate::server::state::AppState;
use crate::{
    NewSecretVersionInput, OwnerUserId, PreparedSecretVersion, authorize_new_secret_create,
};

use super::audit::{FailureAuditContext, failure_audit_metadata_for_attempted_secret};
use super::parsing::{ParsedCreateSecretRequest, parse_create_secret_request};
use super::shared::{build_rpc_params, generate_request_id};

pub async fn create_secret(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(body): Json<CreateSecretRequest>,
) -> Result<(StatusCode, Json<CreateSecretResponse>), ApiError> {
    let request_id = generate_request_id()?;
    let owner_user_id = auth.claims.subject_user_id().clone();
    let request = parse_create_secret_request(body)?;
    let failure = FailureAuditContext::new(
        &state,
        &request_id,
        Some(&owner_user_id),
        None,
        AuditAction::EncryptCreate,
    );
    authorize_new_secret_create(&auth.claims).map_err(|error| {
        failure.log_and_record(&error, "authorize_new_secret_create");
        ApiError::Forbidden("forbidden".to_owned())
    })?;

    let prepared = prepare_secret_version(&state, owner_user_id.clone(), request)
        .await
        .map_err(|error| {
            failure.log_and_record(&error, "prepare_secret_version");
            error
        })?;

    let rpc_params = build_rpc_params(&request_id, &prepared)?;
    let rpc_result = state
        .supabase_client
        .call_write_secret_version(&rpc_params)
        .await;

    match rpc_result {
        Ok(response) => {
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %response.secret_id().as_canonical_string(),
                version = response.version().get(),
                action = AuditAction::EncryptCreate.as_str(),
                result = "success",
            );

            Ok((
                StatusCode::CREATED,
                Json(CreateSecretResponse {
                    secret_id: response.secret_id().as_canonical_string(),
                    version: response.version().get(),
                    secret_version_id: response.secret_version_id().to_owned(),
                }),
            ))
        }
        Err(rpc_error) => {
            let metadata_json = failure_audit_metadata_for_attempted_secret(prepared.secret_id());
            failure.log_and_record_with_metadata(
                &rpc_error,
                "call_write_secret_version",
                metadata_json,
            );
            Err(ApiError::from(rpc_error))
        }
    }
}

async fn prepare_secret_version(
    state: &AppState,
    owner_user_id: OwnerUserId,
    request: ParsedCreateSecretRequest,
) -> Result<PreparedSecretVersion, ApiError> {
    let master_key = state.master_key.clone();
    let key_version = state.key_version;

    tokio::task::spawn_blocking(move || {
        prepare_new_secret_version(
            &master_key,
            NewSecretVersionInput::new(
                owner_user_id,
                request.classification,
                request.device_id,
                request.created_at,
                key_version,
                request.plaintext,
            ),
        )
    })
    .await
    .map_err(|error| ApiError::InternalError(error.to_string()))?
    .map_err(ApiError::from)
}

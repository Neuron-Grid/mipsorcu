use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;

use crate::audit::AuditAction;
use crate::authorize_existing_secret_version_write;
use crate::prepare_existing_secret_version;
use crate::server::dto::{RotateSecretRequest, RotateSecretResponse};
use crate::server::errors::ApiError;
use crate::server::middleware::AuthenticatedUser;
use crate::server::state::AppState;
use crate::{ExistingSecretVersionInput, PreparedSecretVersion};

use super::audit::FailureAuditContext;
use super::parsing::{ParsedRotateSecretRequest, parse_rotate_secret_request, parse_secret_id};
use super::read_row::fetch_single_current_secret_version;
use super::shared::{build_rpc_params, generate_request_id, parse_write_response_version};

pub async fn rotate_secret(
    State(state): State<AppState>,
    AxumPath(secret_id): AxumPath<String>,
    auth: AuthenticatedUser,
    Json(body): Json<RotateSecretRequest>,
) -> Result<(StatusCode, Json<RotateSecretResponse>), ApiError> {
    let request_id = generate_request_id()?;
    let requested_secret_id = parse_secret_id(&secret_id)?;
    let actor_user_id = auth.claims.subject_user_id().clone();
    let request = parse_rotate_secret_request(body)?;
    let failure = FailureAuditContext::new(
        &state,
        &request_id,
        Some(&actor_user_id),
        Some(&requested_secret_id),
        AuditAction::EncryptRotate,
    );

    let current = fetch_single_current_secret_version(&state, &requested_secret_id, &auth.raw_jwt)
        .await
        .inspect_err(|error| failure.log_and_record(error, "fetch_current_secret_version"))?;

    authorize_existing_secret_version_write(&auth.claims, current.owner_user_id()).map_err(
        |error| {
            failure.log_and_record(&error, "authorize_existing_secret_version_write");
            ApiError::Forbidden("forbidden".to_owned())
        },
    )?;

    let prepared = prepare_existing_secret_version_for_request(&state, current, request)
        .await
        .map_err(|error| {
            failure.log_and_record(&error, "prepare_existing_secret_version");
            error
        })?;

    let rpc_params = build_rpc_params(&request_id, &prepared)?;
    let rpc_result = state
        .supabase_client
        .call_write_secret_version(&rpc_params)
        .await;

    match rpc_result {
        Ok(response) => {
            let response_version = parse_write_response_version(response.version)?;
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %response.secret_id,
                version = response_version,
                action = AuditAction::EncryptRotate.as_str(),
                result = "success",
            );

            Ok((
                StatusCode::CREATED,
                Json(RotateSecretResponse {
                    secret_id: response.secret_id,
                    version: response_version,
                    secret_version_id: response.secret_version_id,
                }),
            ))
        }
        Err(rpc_error) => {
            failure.log_and_record(&rpc_error, "call_write_secret_version");
            Err(ApiError::from(rpc_error))
        }
    }
}

async fn prepare_existing_secret_version_for_request(
    state: &AppState,
    current: super::read_row::PreparedDecryptRow,
    request: ParsedRotateSecretRequest,
) -> Result<PreparedSecretVersion, ApiError> {
    let master_key = state.master_key.clone();
    let current_state = current.into_current_secret_version_state();

    tokio::task::spawn_blocking(move || {
        prepare_existing_secret_version(
            &master_key,
            ExistingSecretVersionInput::new(
                current_state,
                request.device_id,
                request.created_at,
                request.plaintext,
            ),
        )
    })
    .await
    .map_err(|error| ApiError::InternalError(error.to_string()))?
    .map_err(ApiError::from)
}

use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;

use crate::server::dto::{RotateSecretRequest, RotateSecretResponse};
use crate::server::errors::ServerResult;
use crate::server::middleware::{AuthenticatedUser, RequestContext, RequestJson};
use crate::server::state::AppState;
use crate::server::use_cases::write_secret_version::{self, RotateSecretCommand};

use super::parsing::{ParsedRotateSecretRequest, parse_rotate_secret_request, parse_secret_id};

pub async fn rotate_secret(
    State(state): State<AppState>,
    request_context: RequestContext,
    AxumPath(secret_id): AxumPath<String>,
    auth: AuthenticatedUser,
    RequestJson(body): RequestJson<RotateSecretRequest>,
) -> ServerResult<(StatusCode, Json<RotateSecretResponse>)> {
    let request_id = request_context.into_request_id();

    let requested_secret_id =
        parse_secret_id(&secret_id).map_err(|error| error.with_request_id(&request_id))?;
    let request =
        parse_rotate_secret_request(body).map_err(|error| error.with_request_id(&request_id))?;
    let command = rotate_secret_command(requested_secret_id, request);
    let output = write_secret_version::rotate_secret(
        &state,
        &request_id,
        &auth.raw_jwt,
        &auth.claims,
        command,
    )
    .await
    .map_err(|error| error.with_request_id(&request_id))?;

    Ok((
        StatusCode::CREATED,
        Json(RotateSecretResponse {
            secret_id: output.secret_id().as_canonical_string(),
            version: output.version().get(),
            secret_version_id: output.secret_version_id().to_owned(),
        }),
    ))
}

fn rotate_secret_command(
    requested_secret_id: crate::SecretId,
    request: ParsedRotateSecretRequest,
) -> RotateSecretCommand {
    RotateSecretCommand::new(
        requested_secret_id,
        request.device_id,
        request.plaintext,
        request.created_at,
    )
}

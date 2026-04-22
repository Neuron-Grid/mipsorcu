use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use crate::server::dto::{CreateSecretRequest, CreateSecretResponse};
use crate::server::errors::ServerResult;
use crate::server::middleware::{AuthenticatedUser, RequestContext, RequestJson};
use crate::server::state::AppState;
use crate::server::use_cases::write_secret_version::{self, CreateSecretCommand};

use super::parsing::{ParsedCreateSecretRequest, parse_create_secret_request};

pub async fn create_secret(
    State(state): State<AppState>,
    request_context: RequestContext,
    auth: AuthenticatedUser,
    RequestJson(body): RequestJson<CreateSecretRequest>,
) -> ServerResult<(StatusCode, Json<CreateSecretResponse>)> {
    let request_id = request_context.into_request_id();

    let request =
        parse_create_secret_request(body).map_err(|error| error.with_request_id(&request_id))?;
    let command = create_secret_command(request);
    let output = write_secret_version::create_secret(&state, &request_id, &auth.claims, command)
        .await
        .map_err(|error| error.with_request_id(&request_id))?;

    Ok((
        StatusCode::CREATED,
        Json(CreateSecretResponse {
            secret_id: output.secret_id().as_canonical_string(),
            version: output.version().get(),
            secret_version_id: output.secret_version_id().to_owned(),
        }),
    ))
}

fn create_secret_command(request: ParsedCreateSecretRequest) -> CreateSecretCommand {
    CreateSecretCommand::new(
        request.classification,
        request.device_id,
        request.plaintext,
        request.created_at,
    )
}

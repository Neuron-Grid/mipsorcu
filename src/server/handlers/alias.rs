use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;

use crate::server::dto::{CreateSecretAliasRequest, CreateSecretAliasResponse};
use crate::server::errors::ServerResult;
use crate::server::middleware::{AuthenticatedUser, RequestContext, RequestJson};
use crate::server::state::AppState;
use crate::server::use_cases::secret_alias::{self, CreateSecretAliasCommand};

use super::parsing::{
    ParsedCreateSecretAliasRequest, parse_create_secret_alias_request, parse_secret_id,
};

pub async fn create_secret_alias(
    State(state): State<AppState>,
    request_context: RequestContext,
    AxumPath(secret_ref): AxumPath<String>,
    auth: AuthenticatedUser,
    RequestJson(body): RequestJson<CreateSecretAliasRequest>,
) -> ServerResult<(StatusCode, Json<CreateSecretAliasResponse>)> {
    let request_id = request_context.into_request_id();

    let secret_id =
        parse_secret_id(&secret_ref).map_err(|error| error.with_request_id(&request_id))?;
    let request = parse_create_secret_alias_request(body)
        .map_err(|error| error.with_request_id(&request_id))?;
    let command = create_secret_alias_command(secret_id, request);
    let output = secret_alias::create_secret_alias(
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
        Json(CreateSecretAliasResponse {
            secret_alias_id: output.secret_alias_id().as_canonical_string(),
            secret_id: output.secret_id().as_canonical_string(),
        }),
    ))
}

fn create_secret_alias_command(
    secret_id: crate::SecretId,
    request: ParsedCreateSecretAliasRequest,
) -> CreateSecretAliasCommand {
    CreateSecretAliasCommand::new(secret_id, request.alias)
}

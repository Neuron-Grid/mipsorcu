use axum::Json;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};

use crate::server::dto::{
    CreateSecretAliasRequest, CreateSecretAliasResponse, ListSecretAliasesQuery,
    ListSecretAliasesResponse, ResolveSecretAliasRequest, ResolveSecretAliasResponse,
    SecretAliasSummary, UpdateSecretAliasRequest, UpdateSecretAliasResponse,
};
use crate::server::errors::ApiError;
use crate::server::errors::ServerResult;
use crate::server::middleware::{AuthenticatedUser, RequestContext, RequestJson};
use crate::server::state::AppState;
use crate::server::use_cases::secret_alias::{self, CreateSecretAliasCommand};

use super::parsing::{
    ParsedCreateSecretAliasRequest, parse_create_secret_alias_request, parse_secret_alias,
    parse_secret_alias_id, parse_secret_id,
};

pub async fn create_secret_alias(
    State(state): State<AppState>,
    request_context: RequestContext,
    AxumPath(secret_id_path): AxumPath<String>,
    auth: AuthenticatedUser,
    RequestJson(body): RequestJson<CreateSecretAliasRequest>,
) -> ServerResult<(StatusCode, Json<CreateSecretAliasResponse>)> {
    let request_id = request_context.into_request_id();

    let secret_id =
        parse_secret_id(&secret_id_path).map_err(|error| error.with_request_id(&request_id))?;
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

pub async fn update_secret_alias(
    State(state): State<AppState>,
    request_context: RequestContext,
    AxumPath(alias_id_path): AxumPath<String>,
    auth: AuthenticatedUser,
    RequestJson(body): RequestJson<UpdateSecretAliasRequest>,
) -> ServerResult<Json<UpdateSecretAliasResponse>> {
    let request_id = request_context.into_request_id();

    let secret_alias_id = parse_secret_alias_id(&alias_id_path)
        .map_err(|error| error.with_request_id(&request_id))?;
    let alias =
        parse_secret_alias(&body.alias).map_err(|error| error.with_request_id(&request_id))?;
    let output =
        secret_alias::update_alias(&state, &request_id, &auth.claims, secret_alias_id, alias)
            .await
            .map_err(|error| error.with_request_id(&request_id))?;

    Ok(Json(UpdateSecretAliasResponse {
        secret_alias_id: output.secret_alias_id().as_canonical_string(),
    }))
}

pub async fn delete_secret_alias(
    State(state): State<AppState>,
    request_context: RequestContext,
    AxumPath(alias_id_path): AxumPath<String>,
    auth: AuthenticatedUser,
) -> ServerResult<StatusCode> {
    let request_id = request_context.into_request_id();

    let secret_alias_id = parse_secret_alias_id(&alias_id_path)
        .map_err(|error| error.with_request_id(&request_id))?;
    secret_alias::delete_alias(&state, &request_id, &auth.claims, secret_alias_id)
        .await
        .map_err(|error| error.with_request_id(&request_id))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_secret_aliases(
    State(state): State<AppState>,
    request_context: RequestContext,
    Query(query): Query<ListSecretAliasesQuery>,
    auth: AuthenticatedUser,
) -> ServerResult<(HeaderMap, Json<ListSecretAliasesResponse>)> {
    let request_id = request_context.into_request_id();

    validate_list_query(&query).map_err(|error| error.with_request_id(&request_id))?;

    let output =
        secret_alias::list_aliases(&state, &request_id, &auth.claims, query.limit, query.offset)
            .await
            .map_err(|error| error.with_request_id(&request_id))?;
    let total_returned = u32::try_from(output.aliases.len())
        .map_err(|error| ApiError::InternalError(error.to_string()).with_request_id(&request_id))?;
    let aliases = output
        .aliases
        .into_iter()
        .map(|item| SecretAliasSummary {
            secret_alias_id: item.secret_alias_id.as_canonical_string(),
            secret_id: item.secret_id.as_canonical_string(),
            alias: item.alias.as_str().to_owned(),
            created_at: item.created_at,
            updated_at: item.updated_at,
        })
        .collect();

    Ok((
        no_store_headers(),
        Json(ListSecretAliasesResponse {
            aliases,
            limit: query.limit,
            offset: query.offset,
            total_returned,
        }),
    ))
}

pub async fn resolve_secret_alias(
    State(state): State<AppState>,
    request_context: RequestContext,
    auth: AuthenticatedUser,
    RequestJson(body): RequestJson<ResolveSecretAliasRequest>,
) -> ServerResult<(HeaderMap, Json<ResolveSecretAliasResponse>)> {
    let request_id = request_context.into_request_id();

    let alias =
        parse_secret_alias(&body.alias).map_err(|error| error.with_request_id(&request_id))?;
    let output = secret_alias::resolve_alias(&state, &request_id, &auth.claims, alias)
        .await
        .map_err(|error| error.with_request_id(&request_id))?;

    Ok((
        no_store_headers(),
        Json(ResolveSecretAliasResponse {
            secret_alias_id: output.secret_alias_id.as_canonical_string(),
            secret_id: output.secret_id.as_canonical_string(),
        }),
    ))
}

fn create_secret_alias_command(
    secret_id: crate::SecretId,
    request: ParsedCreateSecretAliasRequest,
) -> CreateSecretAliasCommand {
    CreateSecretAliasCommand::new(secret_id, request.alias)
}

fn validate_list_query(query: &ListSecretAliasesQuery) -> Result<(), ApiError> {
    if query.limit == 0 || query.limit > 1000 {
        return Err(ApiError::BadRequest(
            "limit must be between 1 and 1000".to_owned(),
        ));
    }

    Ok(())
}

fn no_store_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

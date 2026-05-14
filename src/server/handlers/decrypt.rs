use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, HeaderValue, header};

use crate::server::dto::DecryptSecretResponse;
use crate::server::errors::ServerResult;
use crate::server::middleware::{AuthenticatedUser, RequestContext};
use crate::server::state::AppState;
use crate::server::use_cases;

use super::parsing::parse_secret_ref;

pub async fn decrypt_secret(
    State(state): State<AppState>,
    request_context: RequestContext,
    AxumPath(secret_ref): AxumPath<String>,
    auth: AuthenticatedUser,
) -> ServerResult<(HeaderMap, Json<DecryptSecretResponse>)> {
    let request_id = request_context.into_request_id();

    let requested_secret_ref =
        parse_secret_ref(&secret_ref).map_err(|error| error.with_request_id(&request_id))?;
    let output = use_cases::decrypt_secret::decrypt_secret(
        &state,
        &request_id,
        requested_secret_ref,
        &auth.raw_jwt,
        auth.claims,
    )
    .await
    .map_err(|error| error.with_request_id(&request_id))?;

    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    Ok((
        headers,
        Json(DecryptSecretResponse::new(
            output.secret_id().as_canonical_string(),
            output.version().get(),
            output.plaintext().as_bytes(),
        )),
    ))
}

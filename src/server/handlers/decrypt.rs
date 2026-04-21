use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, HeaderValue, header};

use crate::audit::AuditAction;
use crate::decrypt_current_secret_version as decrypt_current_secret_version_with_master_key;
use crate::server::dto::DecryptSecretResponse;
use crate::server::errors::ApiError;
use crate::server::middleware::AuthenticatedUser;
use crate::server::state::AppState;
use crate::types::Plaintext;

use super::audit::{FailureAuditContext, record_success_audit};
use super::parsing::parse_secret_id;
use super::read_row::fetch_single_current_secret_version;
use super::shared::generate_request_id;

pub async fn decrypt_secret(
    State(state): State<AppState>,
    AxumPath(secret_id): AxumPath<String>,
    auth: AuthenticatedUser,
) -> Result<(HeaderMap, Json<DecryptSecretResponse>), ApiError> {
    let request_id = generate_request_id()?;
    let requested_secret_id = parse_secret_id(&secret_id)?;
    let actor_user_id = auth.claims.subject_user_id().clone();
    let failure = FailureAuditContext::new(
        &state,
        &request_id,
        Some(&actor_user_id),
        Some(&requested_secret_id),
        AuditAction::Decrypt,
    );

    let row = fetch_single_current_secret_version(&state, &requested_secret_id, &auth.raw_jwt)
        .await
        .inspect_err(|error| failure.log_and_record(error, "fetch_current_secret_version"))?;

    let key_version = row.key_version();
    let response_secret_id = row.secret_id().clone();
    let version = row.version();
    let input = row.into_decrypt_input(auth.claims);

    let plaintext = decrypt_prepared_input(&state, input)
        .await
        .inspect_err(|error| failure.log_and_record(error, "decrypt_current_secret_version"))?;

    record_success_audit(
        &state,
        &request_id,
        &actor_user_id,
        &response_secret_id,
        key_version,
    )
    .await;

    tracing::info!(
        request_id = %request_id.as_canonical_string(),
        secret_id = %response_secret_id.as_canonical_string(),
        version = version.get(),
        action = AuditAction::Decrypt.as_str(),
        result = "success",
    );

    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    Ok((
        headers,
        Json(DecryptSecretResponse::new(
            response_secret_id.as_canonical_string(),
            version.get(),
            plaintext.as_bytes(),
        )),
    ))
}

async fn decrypt_prepared_input(
    state: &AppState,
    input: crate::DecryptCurrentSecretVersionInput,
) -> Result<Plaintext, ApiError> {
    let master_key = state.master_key.clone();

    tokio::task::spawn_blocking(move || {
        decrypt_current_secret_version_with_master_key(&master_key, input)
    })
    .await
    .map_err(|error| ApiError::InternalError(error.to_string()))?
    .map_err(ApiError::from)
}

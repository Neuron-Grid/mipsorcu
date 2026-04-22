use crate::audit::{AuditAction, AuditMetadata, RequestId};
use crate::auth::{RawJwt, VerifiedJwtClaims};
use crate::server::audit_reporter::{
    FailureAuditContext, failure_audit_metadata_for_attempted_secret,
};
use crate::server::dto::{CreateSecretRequest, RotateSecretRequest};
use crate::server::errors::ApiError;
use crate::server::handlers::parsing::{
    ParsedCreateSecretRequest, ParsedRotateSecretRequest, parse_create_secret_request,
    parse_rotate_secret_request,
};
use crate::server::handlers::shared::build_rpc_params;
use crate::server::read_model::{self, FetchCurrentSecretVersionError};
use crate::server::state::AppState;
use crate::server::supabase::WriteSecretVersionOutcome;
use crate::{
    ExistingSecretVersionInput, NewSecretVersionInput, OwnerUserId, PreparedSecretVersion,
    SecretId, SecretVersion, SecretWriteAction, authorize_existing_secret_version_write,
    authorize_new_secret_create, prepare_existing_secret_version, prepare_new_secret_version,
};

#[derive(Debug)]
pub(in crate::server) struct WriteSecretVersionOutput {
    secret_id: SecretId,
    version: SecretVersion,
    secret_version_id: String,
}

impl WriteSecretVersionOutput {
    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    pub fn version(&self) -> SecretVersion {
        self.version
    }

    pub fn secret_version_id(&self) -> &str {
        &self.secret_version_id
    }
}

pub(in crate::server) async fn create_secret(
    state: &AppState,
    request_id: &RequestId,
    claims: &VerifiedJwtClaims,
    body: CreateSecretRequest,
) -> Result<WriteSecretVersionOutput, ApiError> {
    let owner_user_id = claims.subject_user_id().clone();
    let request = parse_create_secret_request(body)?;
    let failure = FailureAuditContext::new(
        state,
        request_id,
        Some(&owner_user_id),
        None,
        AuditAction::EncryptCreate,
    );

    authorize_new_secret_create(claims).map_err(|error| {
        failure.log_and_record(&error, "authorize_new_secret_create");
        ApiError::Forbidden("forbidden".to_owned())
    })?;

    let prepared = prepare_new_secret_version_for_request(state, owner_user_id.clone(), request)
        .await
        .inspect_err(|error| {
            failure.log_and_record(error, "prepare_secret_version");
        })?;
    let attempted_secret_metadata = Some(failure_audit_metadata_for_attempted_secret(
        prepared.secret_id(),
    ));

    submit_prepared_secret_version(
        state,
        request_id,
        &failure,
        prepared,
        attempted_secret_metadata,
    )
    .await
}

pub(in crate::server) async fn rotate_secret(
    state: &AppState,
    request_id: &RequestId,
    requested_secret_id: SecretId,
    raw_jwt: &RawJwt,
    claims: &VerifiedJwtClaims,
    body: RotateSecretRequest,
) -> Result<WriteSecretVersionOutput, ApiError> {
    let actor_user_id = claims.subject_user_id().clone();
    let request = parse_rotate_secret_request(body)?;
    let failure = FailureAuditContext::new(
        state,
        request_id,
        Some(&actor_user_id),
        Some(&requested_secret_id),
        AuditAction::EncryptRotate,
    );

    let current =
        read_model::fetch_single_current_secret_version(state, &requested_secret_id, raw_jwt)
            .await
            .map_err(|error| match error {
                FetchCurrentSecretVersionError::Upstream(rpc_error) => {
                    failure.log_upstream_failure(&rpc_error, "fetch_current_secret_version");
                    failure.record();
                    ApiError::from(rpc_error)
                }
                FetchCurrentSecretVersionError::Api(api_error) => {
                    failure.log_and_record(&api_error, "fetch_current_secret_version");
                    api_error
                }
            })?;

    authorize_existing_secret_version_write(claims, current.owner_user_id()).map_err(|error| {
        failure.log_and_record(&error, "authorize_existing_secret_version_write");
        ApiError::Forbidden("forbidden".to_owned())
    })?;

    let prepared = prepare_existing_secret_version_for_request(state, current, request)
        .await
        .inspect_err(|error| {
            failure.log_and_record(error, "prepare_existing_secret_version");
        })?;

    submit_prepared_secret_version(state, request_id, &failure, prepared, None).await
}

async fn submit_prepared_secret_version(
    state: &AppState,
    request_id: &RequestId,
    failure: &FailureAuditContext<'_>,
    prepared: PreparedSecretVersion,
    upstream_failure_metadata: Option<AuditMetadata>,
) -> Result<WriteSecretVersionOutput, ApiError> {
    let action = prepared.write_action();
    let rpc_params = build_rpc_params(request_id, &prepared)?;
    let rpc_result = state
        .supabase_client
        .call_write_secret_version(&rpc_params)
        .await;

    match rpc_result {
        Ok(response) => {
            log_write_success(request_id, action, &response);
            Ok(WriteSecretVersionOutput {
                secret_id: response.secret_id().clone(),
                version: response.version(),
                secret_version_id: response.secret_version_id().to_owned(),
            })
        }
        Err(rpc_error) => {
            failure.log_upstream_failure(&rpc_error, "call_write_secret_version");
            match upstream_failure_metadata {
                Some(metadata) => failure.record_with_metadata(metadata),
                None => failure.record(),
            }
            Err(ApiError::from(rpc_error))
        }
    }
}

async fn prepare_new_secret_version_for_request(
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

async fn prepare_existing_secret_version_for_request(
    state: &AppState,
    current: read_model::PreparedDecryptRow,
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

fn log_write_success(
    request_id: &RequestId,
    action: SecretWriteAction,
    response: &WriteSecretVersionOutcome,
) {
    tracing::info!(
        request_id = %request_id.as_canonical_string(),
        secret_id = %response.secret_id().as_canonical_string(),
        version = response.version().get(),
        action = action.as_str(),
        result = "success",
    );
}

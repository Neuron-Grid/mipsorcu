use crate::audit::{AuditAction, RequestId};
use crate::auth::{RawJwt, VerifiedJwtClaims};
use crate::server::audit_reporter::FailureAuditContext;
use crate::server::errors::ApiError;
use crate::server::read_model::{
    self, FetchCurrentSecretVersionError, ResolveSecretRefError, resolve_secret_ref,
};
use crate::server::state::AppState;
use crate::{authorize_existing_secret_version_write, authorize_new_secret_create};

use super::WriteSecretVersionOutput;
use super::command::{CreateSecretCommand, RotateSecretCommand};
use super::prepare::{
    prepare_existing_secret_version_for_request, prepare_new_secret_version_for_request,
};
use super::rpc::submit_prepared_secret_version;

pub(in crate::server) async fn create_secret(
    state: &AppState,
    request_id: &RequestId,
    claims: &VerifiedJwtClaims,
    command: CreateSecretCommand,
) -> Result<WriteSecretVersionOutput, ApiError> {
    let owner_user_id = claims.subject_user_id().clone();
    let failure = FailureAuditContext::new(
        state,
        request_id,
        Some(&owner_user_id),
        None,
        AuditAction::EncryptCreate,
    );

    if let Err(error) = authorize_new_secret_create(claims) {
        failure
            .record_and_warn(&error, "authorize_new_secret_create")
            .await;
        return Err(ApiError::Forbidden("forbidden".to_owned()));
    }

    let prepared =
        match prepare_new_secret_version_for_request(state, owner_user_id.clone(), command).await {
            Ok(prepared) => prepared,
            Err(error) => {
                failure.record_and_warn(&error, "prepare_secret_version").await;
                return Err(error);
            }
        };
    submit_prepared_secret_version(state, request_id, &failure, prepared, None).await
}

pub(in crate::server) async fn rotate_secret(
    state: &AppState,
    request_id: &RequestId,
    raw_jwt: &RawJwt,
    claims: &VerifiedJwtClaims,
    command: RotateSecretCommand,
) -> Result<WriteSecretVersionOutput, ApiError> {
    let actor_user_id = claims.subject_user_id().clone();
    let requested_secret_id =
        match resolve_secret_ref(state, command.requested_secret_ref.clone(), &actor_user_id).await
        {
            Ok(secret_id) => secret_id,
            Err(error) => {
                let failure = FailureAuditContext::new(
                    state,
                    request_id,
                    Some(&actor_user_id),
                    None,
                    AuditAction::EncryptRotate,
                );
                record_secret_ref_resolution_failure(&failure, &error).await?;
                return Err(ApiError::from(error));
            }
        };
    let failure = FailureAuditContext::new(
        state,
        request_id,
        Some(&actor_user_id),
        Some(&requested_secret_id),
        AuditAction::EncryptRotate,
    );

    let current =
        match read_model::fetch_current_secret_write_state(state, &requested_secret_id, raw_jwt)
            .await
        {
            Ok(current) => current,
            Err(FetchCurrentSecretVersionError::Upstream(rpc_error)) => {
                failure
                    .record_upstream_and_warn(&rpc_error, "fetch_current_secret_write_state")
                    .await;
                return Err(ApiError::from(rpc_error));
            }
            Err(FetchCurrentSecretVersionError::Api(api_error)) => {
                failure
                    .record_and_warn(&api_error, "fetch_current_secret_write_state")
                    .await;
                return Err(api_error);
            }
        };

    if let Err(error) = authorize_existing_secret_version_write(claims, current.owner_user_id()) {
        failure
            .record_and_warn(&error, "authorize_existing_secret_version_write")
            .await;
        return Err(ApiError::Forbidden("forbidden".to_owned()));
    }

    let retention_snapshot = match state
        .supabase_client
        .fetch_secret_version_retention_snapshot(&requested_secret_id)
        .await
    {
        Ok(snapshot) => snapshot,
        Err(rpc_error) => {
            failure
                .record_upstream_and_warn(&rpc_error, "fetch_secret_version_retention_snapshot")
                .await;
            return Err(ApiError::from(rpc_error));
        }
    };

    let prepared = match prepare_existing_secret_version_for_request(state, current, command).await
    {
        Ok(prepared) => prepared,
        Err(error) => {
            failure
                .record_and_warn(&error, "prepare_existing_secret_version")
                .await;
            return Err(error);
        }
    };

    submit_prepared_secret_version(
        state,
        request_id,
        &failure,
        prepared,
        Some(retention_snapshot),
    )
    .await
}

async fn record_secret_ref_resolution_failure(
    failure: &FailureAuditContext<'_>,
    error: &ResolveSecretRefError,
) -> Result<(), crate::server::errors::ApiError> {
    match error {
        ResolveSecretRefError::Upstream(rpc_error) => {
            failure.log_upstream_failure_without_error_value(rpc_error, "resolve_secret_ref");
            failure.record_and_warn_on_secondary_failure().await;
        }
        ResolveSecretRefError::Api(api_error) => {
            failure.record_and_warn(api_error, "resolve_secret_ref").await;
        }
    }

    Ok(())
}

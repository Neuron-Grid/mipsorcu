use crate::audit::{AuditAction, RequestId};
use crate::auth::{RawJwt, VerifiedJwtClaims};
use crate::server::audit_reporter::FailureAuditContext;
use crate::server::errors::ApiError;
use crate::server::read_model::{self, FetchCurrentSecretVersionError};
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
        if let Err(audit_err) = failure
            .log_and_record(&error, "authorize_new_secret_create")
            .await
        {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %audit_err,
                "failure audit recording also failed"
            );
        }
        return Err(ApiError::Forbidden("forbidden".to_owned()));
    }

    let prepared =
        match prepare_new_secret_version_for_request(state, owner_user_id.clone(), command).await {
            Ok(prepared) => prepared,
            Err(error) => {
                if let Err(audit_err) = failure
                    .log_and_record(&error, "prepare_secret_version")
                    .await
                {
                    tracing::error!(
                        request_id = %request_id.as_canonical_string(),
                        error = %audit_err,
                        "failure audit recording also failed"
                    );
                }
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
    let requested_secret_id = command.requested_secret_id.clone();
    let failure = FailureAuditContext::new(
        state,
        request_id,
        Some(&actor_user_id),
        Some(&requested_secret_id),
        AuditAction::EncryptRotate,
    );

    let current = match read_model::fetch_current_secret_version(
        state,
        &requested_secret_id,
        raw_jwt,
    )
    .await
    {
        Ok(current) => current,
        Err(FetchCurrentSecretVersionError::Upstream(rpc_error)) => {
            failure.log_upstream_failure(&rpc_error, "fetch_current_secret_version");
            if let Err(audit_err) = failure.record().await {
                tracing::error!(
                    request_id = %request_id.as_canonical_string(),
                    error = %audit_err,
                    "failure audit recording also failed"
                );
            }
            return Err(ApiError::from(rpc_error));
        }
        Err(FetchCurrentSecretVersionError::Api(api_error)) => {
            if let Err(audit_err) = failure
                .log_and_record(&api_error, "fetch_current_secret_version")
                .await
            {
                tracing::error!(
                    request_id = %request_id.as_canonical_string(),
                    error = %audit_err,
                    "failure audit recording also failed"
                );
            }
            return Err(api_error);
        }
    };

    if let Err(error) = authorize_existing_secret_version_write(claims, current.owner_user_id()) {
        if let Err(audit_err) = failure
            .log_and_record(&error, "authorize_existing_secret_version_write")
            .await
        {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %audit_err,
                "failure audit recording also failed"
            );
        }
        return Err(ApiError::Forbidden("forbidden".to_owned()));
    }

    let retention_snapshot = match state
        .supabase_client
        .fetch_secret_version_retention_snapshot(&requested_secret_id)
        .await
    {
        Ok(snapshot) => snapshot,
        Err(rpc_error) => {
            failure.log_upstream_failure(&rpc_error, "fetch_secret_version_retention_snapshot");
            if let Err(audit_err) = failure.record().await {
                tracing::error!(
                    request_id = %request_id.as_canonical_string(),
                    error = %audit_err,
                    "failure audit recording also failed"
                );
            }
            return Err(ApiError::from(rpc_error));
        }
    };

    let prepared = match prepare_existing_secret_version_for_request(state, current, command).await
    {
        Ok(prepared) => prepared,
        Err(error) => {
            if let Err(audit_err) = failure
                .log_and_record(&error, "prepare_existing_secret_version")
                .await
            {
                tracing::error!(
                    request_id = %request_id.as_canonical_string(),
                    error = %audit_err,
                    "failure audit recording also failed"
                );
            }
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

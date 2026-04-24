use crate::audit::{AuditAction, RequestId};
use crate::auth::{RawJwt, VerifiedJwtClaims};
use crate::decrypt_current_secret_version_with_keyring;
use crate::server::audit_reporter::{self, FailureAuditContext};
use crate::server::errors::ApiError;
use crate::server::read_model::{self, FetchCurrentSecretVersionError};
use crate::server::state::AppState;
use crate::types::Plaintext;
use crate::{SecretId, SecretVersion};

#[derive(Debug)]
pub(in crate::server) struct DecryptSecretOutput {
    secret_id: SecretId,
    version: SecretVersion,
    plaintext: Plaintext,
}

impl DecryptSecretOutput {
    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    pub fn version(&self) -> SecretVersion {
        self.version
    }

    pub fn plaintext(&self) -> &Plaintext {
        &self.plaintext
    }
}

pub(in crate::server) async fn decrypt_secret(
    state: &AppState,
    request_id: &RequestId,
    requested_secret_id: SecretId,
    raw_jwt: &RawJwt,
    claims: VerifiedJwtClaims,
) -> Result<DecryptSecretOutput, ApiError> {
    let actor_user_id = claims.subject_user_id().clone();
    let failure = FailureAuditContext::new(
        state,
        request_id,
        Some(&actor_user_id),
        Some(&requested_secret_id),
        AuditAction::Decrypt,
    );

    let row = match read_model::fetch_current_secret_version(state, &requested_secret_id, raw_jwt)
        .await
    {
        Ok(row) => row,
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

    let key_version = row.key_version();
    let response_secret_id = row.secret_id().clone();
    let version = row.version();
    let input = row.into_decrypt_input(claims);

    let plaintext = match decrypt_prepared_input(state, input).await {
        Ok(plaintext) => plaintext,
        Err(error) => {
            if let Err(audit_err) = failure
                .log_and_record(&error, "decrypt_current_secret_version")
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

    audit_reporter::record_success_audit(
        state,
        request_id,
        &actor_user_id,
        &response_secret_id,
        key_version,
    )
    .await?;

    tracing::info!(
        request_id = %request_id.as_canonical_string(),
        secret_id = %response_secret_id.as_canonical_string(),
        version = version.get(),
        action = AuditAction::Decrypt.as_str(),
        result = "success",
    );

    Ok(DecryptSecretOutput {
        secret_id: response_secret_id,
        version,
        plaintext,
    })
}

async fn decrypt_prepared_input(
    state: &AppState,
    input: crate::DecryptCurrentSecretVersionInput,
) -> Result<Plaintext, ApiError> {
    let master_key_ring = state.master_key_ring.clone();

    tokio::task::spawn_blocking(move || {
        decrypt_current_secret_version_with_keyring(&master_key_ring, input)
    })
    .await
    .map_err(|error| ApiError::InternalError(error.to_string()))?
    .map_err(ApiError::from)
}

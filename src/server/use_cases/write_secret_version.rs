use crate::audit::{AuditAction, AuditMetadata, RequestId};
use crate::auth::{RawJwt, VerifiedJwtClaims};
use crate::server::audit_reporter::{
    FailureAuditContext, failure_audit_metadata_for_attempted_secret,
};
use crate::server::errors::ApiError;
use crate::server::read_model::{self, FetchCurrentSecretVersionError};
use crate::server::state::AppState;
use crate::server::supabase::{WriteSecretVersionOutcome, WriteSecretVersionParams};
use crate::types::{Classification, CreatedAt, DeviceId, Plaintext};
use crate::{
    ExistingSecretVersionInput, NewSecretVersionInput, OwnerUserId, PreparedSecretVersion,
    SecretId, SecretVersion, SecretWriteAction, authorize_existing_secret_version_write,
    authorize_new_secret_create, prepare_existing_secret_version_with_keyring,
    prepare_new_secret_version_with_keyring,
};

#[derive(Debug)]
pub(in crate::server) struct CreateSecretCommand {
    classification: Classification,
    device_id: DeviceId,
    plaintext: Plaintext,
    created_at: CreatedAt,
}

impl CreateSecretCommand {
    pub(in crate::server) fn new(
        classification: Classification,
        device_id: DeviceId,
        plaintext: Plaintext,
        created_at: CreatedAt,
    ) -> Self {
        Self {
            classification,
            device_id,
            plaintext,
            created_at,
        }
    }
}

#[derive(Debug)]
pub(in crate::server) struct RotateSecretCommand {
    requested_secret_id: SecretId,
    device_id: DeviceId,
    plaintext: Plaintext,
    created_at: CreatedAt,
}

impl RotateSecretCommand {
    pub(in crate::server) fn new(
        requested_secret_id: SecretId,
        device_id: DeviceId,
        plaintext: Plaintext,
        created_at: CreatedAt,
    ) -> Self {
        Self {
            requested_secret_id,
            device_id,
            plaintext,
            created_at,
        }
    }
}

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
    let rpc_params = match build_rpc_params(request_id, &prepared) {
        Ok(rpc_params) => rpc_params,
        Err(error) => {
            if let Err(audit_err) = failure
                .log_and_record(&error, "build_write_secret_version_params")
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
            let audit_result = match upstream_failure_metadata {
                Some(metadata) => failure.record_with_metadata(metadata).await,
                None => failure.record().await,
            };
            if let Err(audit_err) = audit_result {
                tracing::error!(
                    request_id = %request_id.as_canonical_string(),
                    error = %audit_err,
                    "failure audit recording also failed"
                );
            }
            Err(ApiError::from(rpc_error))
        }
    }
}

async fn prepare_new_secret_version_for_request(
    state: &AppState,
    owner_user_id: OwnerUserId,
    command: CreateSecretCommand,
) -> Result<PreparedSecretVersion, ApiError> {
    let master_key_ring = state.master_key_ring.clone();
    let key_version = master_key_ring.active_key_version();

    tokio::task::spawn_blocking(move || {
        prepare_new_secret_version_with_keyring(
            &master_key_ring,
            NewSecretVersionInput::new(
                owner_user_id,
                command.classification,
                command.device_id,
                command.created_at,
                key_version,
                command.plaintext,
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
    command: RotateSecretCommand,
) -> Result<PreparedSecretVersion, ApiError> {
    let master_key_ring = state.master_key_ring.clone();
    let current_state = current.into_current_secret_version_state();

    tokio::task::spawn_blocking(move || {
        prepare_existing_secret_version_with_keyring(
            &master_key_ring,
            ExistingSecretVersionInput::new(
                current_state,
                command.device_id,
                command.created_at,
                command.plaintext,
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

fn build_rpc_params(
    request_id: &RequestId,
    prepared: &PreparedSecretVersion,
) -> Result<WriteSecretVersionParams, ApiError> {
    let created_at = prepared
        .created_at()
        .as_rfc3339_utc()
        .map_err(|error| ApiError::InternalError(error.to_string()))?;

    Ok(WriteSecretVersionParams {
        p_request_id: request_id.as_canonical_string(),
        p_action: prepared.write_action().as_str().to_owned(),
        p_secret_id: prepared.secret_id().as_canonical_string(),
        p_owner_user_id: prepared.owner_user_id().as_canonical_string(),
        p_classification: prepared.classification().as_str().to_owned(),
        p_created_by_device_id: prepared.created_by_device_id().as_str().to_owned(),
        p_created_at: created_at,
        p_version: prepared.version().get(),
        p_ciphertext: encode_bytea(prepared.ciphertext().as_bytes()),
        p_encrypted_data_key: encode_bytea(prepared.encrypted_data_key().as_bytes()),
        p_key_version: prepared.key_version().get(),
        p_algorithm: prepared.algorithm().to_owned(),
        p_nonce_or_iv: encode_bytea(prepared.nonce_or_iv().as_bytes()),
        p_aad_context: prepared.aad_context().clone(),
    })
}

fn encode_bytea(bytes: &[u8]) -> String {
    format!("\\x{}", hex::encode(bytes))
}

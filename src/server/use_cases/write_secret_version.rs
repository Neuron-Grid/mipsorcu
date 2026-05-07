use crate::audit::{AuditAction, AuditEventId, AuditMetadata, RequestId};
use crate::auth::{RawJwt, VerifiedJwtClaims};
use crate::server::audit_reporter::{
    FailureAuditContext, failure_audit_metadata_for_attempted_secret,
};
use crate::server::errors::ApiError;
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts};
use crate::server::read_model::{self, FetchCurrentSecretVersionError};
use crate::server::state::AppState;
use crate::server::supabase::{
    SecretVersionRetentionSnapshot, WriteSecretVersionOutcome, WriteSecretVersionParams,
};
use crate::types::{Classification, CreatedAt, DeviceId, Plaintext};
use crate::{
    ALGORITHM_XCHACHA20_POLY1305, ExistingSecretVersionInput, LedgerEntryId, LedgerEntryType,
    LedgerPayload, LedgerResult, LedgerTargetSecretVersionId, NewSecretVersionInput, OwnerUserId,
    PreparedSecretVersion, SecretId, SecretVersion, SecretVersionId, SecretWriteAction,
    SourceEventAt, authorize_existing_secret_version_write, authorize_new_secret_create,
    prepare_existing_secret_version_with_keyring, prepare_new_secret_version_with_keyring,
};

const SECRET_VERSION_RETENTION_LIMIT: usize = 4;

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
    secret_version_id: SecretVersionId,
}

impl WriteSecretVersionOutput {
    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    pub fn version(&self) -> SecretVersion {
        self.version
    }

    pub fn secret_version_id(&self) -> &SecretVersionId {
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
        None,
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
        None,
        Some(retention_snapshot),
    )
    .await
}

async fn submit_prepared_secret_version(
    state: &AppState,
    request_id: &RequestId,
    failure: &FailureAuditContext<'_>,
    prepared: PreparedSecretVersion,
    upstream_failure_metadata: Option<AuditMetadata>,
    retention_snapshot: Option<Vec<SecretVersionRetentionSnapshot>>,
) -> Result<WriteSecretVersionOutput, ApiError> {
    let action = prepared.write_action();
    let rpc_params = match build_rpc_params(state, request_id, &prepared, retention_snapshot).await
    {
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
                secret_version_id: response.secret_version_id().clone(),
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

async fn build_rpc_params(
    state: &AppState,
    request_id: &RequestId,
    prepared: &PreparedSecretVersion,
    retention_snapshot: Option<Vec<SecretVersionRetentionSnapshot>>,
) -> Result<WriteSecretVersionParams, ApiError> {
    let created_at = prepared
        .created_at()
        .as_rfc3339_utc()
        .map_err(|error| ApiError::InternalError(error.to_string()))?;
    let mut ledger_drafts = Vec::new();
    ledger_drafts.push(
        build_write_ledger_draft(request_id, prepared)
            .map_err(|error| ApiError::InternalError(error.to_string()))?,
    );
    ledger_drafts.extend(
        build_purge_ledger_drafts(request_id, prepared, retention_snapshot.unwrap_or_default())
            .map_err(|error| ApiError::InternalError(error.to_string()))?,
    );
    let ledger_entries = state
        .ledger_appender
        .sign_entries(&ledger_drafts)
        .await
        .map_err(|error| {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = prepared.write_action().as_str(),
                result = "failure",
                "failed to sign write ledger entries"
            );
            ApiError::LedgerAppendFailed
        })?;
    let ledger_entries = ledger_entries
        .iter()
        .map(crate::server::supabase::LedgerEntryRpcParams::from_signed_entry)
        .collect();

    Ok(WriteSecretVersionParams {
        p_request_id: request_id.as_canonical_string(),
        p_action: prepared.write_action().as_str().to_owned(),
        p_secret_id: prepared.secret_id().as_canonical_string(),
        p_secret_version_id: prepared.secret_version_id().as_canonical_string(),
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
        p_ledger_entries: ledger_entries,
    })
}

fn build_write_ledger_draft(
    request_id: &RequestId,
    prepared: &PreparedSecretVersion,
) -> Result<LedgerAppendDraft, crate::LedgerError> {
    let source_event_at =
        SourceEventAt::now_utc().map_err(|_| crate::LedgerError::RandomnessUnavailable)?;
    let entry_type = match prepared.write_action() {
        SecretWriteAction::EncryptCreate => LedgerEntryType::SecretCreated,
        SecretWriteAction::EncryptRotate => LedgerEntryType::SecretVersionCreated,
    };
    let payload = LedgerPayload::new(
        entry_type,
        serde_json::json!({
            "algorithm": ALGORITHM_XCHACHA20_POLY1305,
            "classification": prepared.classification().as_str(),
            "key_version": prepared.key_version().get(),
            "version": prepared.version().get(),
        }),
    )?;
    let target_secret_version_id =
        LedgerTargetSecretVersionId::from_secret_version_id(prepared.secret_version_id())?;

    LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::generate()?,
        entry_type,
        source_event_at,
        request_id: request_id.clone(),
        source_event_id: Some(AuditEventId::generate().map_err(|_| {
            crate::LedgerError::InvalidUuid {
                field: "source_event_id",
            }
        })?),
        target_secret_id: Some(prepared.secret_id().clone()),
        target_secret_version_id: Some(target_secret_version_id),
        actor_user_id: Some(prepared.owner_user_id().clone()),
        actor_device_id: Some(prepared.created_by_device_id().clone()),
        result: LedgerResult::Success,
        error_code: None,
        payload,
    })
}

#[derive(Clone)]
struct RetentionVersionSnapshot {
    secret_version_id: SecretVersionId,
    version: SecretVersion,
    key_version: crate::KeyVersion,
}

fn build_purge_ledger_drafts(
    request_id: &RequestId,
    prepared: &PreparedSecretVersion,
    retention_snapshot: Vec<SecretVersionRetentionSnapshot>,
) -> Result<Vec<LedgerAppendDraft>, crate::LedgerError> {
    if !matches!(prepared.write_action(), SecretWriteAction::EncryptRotate) {
        return Ok(Vec::new());
    }

    let mut versions = retention_snapshot
        .into_iter()
        .map(|snapshot| RetentionVersionSnapshot {
            secret_version_id: snapshot.secret_version_id().clone(),
            version: snapshot.version(),
            key_version: snapshot.key_version(),
        })
        .collect::<Vec<_>>();
    versions.push(RetentionVersionSnapshot {
        secret_version_id: prepared.secret_version_id().clone(),
        version: prepared.version(),
        key_version: prepared.key_version(),
    });
    versions.sort_by_key(|snapshot| std::cmp::Reverse(snapshot.version.get()));

    let mut purged_versions = versions
        .into_iter()
        .skip(SECRET_VERSION_RETENTION_LIMIT)
        .collect::<Vec<_>>();
    purged_versions.sort_by_key(|snapshot| snapshot.version.get());

    purged_versions
        .iter()
        .map(|purged| build_purge_ledger_draft(request_id, prepared, purged))
        .collect()
}

fn build_purge_ledger_draft(
    request_id: &RequestId,
    prepared: &PreparedSecretVersion,
    purged: &RetentionVersionSnapshot,
) -> Result<LedgerAppendDraft, crate::LedgerError> {
    let entry_type = LedgerEntryType::SecretVersionPurged;
    let payload = LedgerPayload::new(
        entry_type,
        serde_json::json!({
            "key_version": purged.key_version.get(),
            "retention_limit": SECRET_VERSION_RETENTION_LIMIT,
            "version": purged.version.get(),
        }),
    )?;
    let target_secret_version_id =
        LedgerTargetSecretVersionId::from_secret_version_id(&purged.secret_version_id)?;

    LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::generate()?,
        entry_type,
        source_event_at: SourceEventAt::now_utc()
            .map_err(|_| crate::LedgerError::RandomnessUnavailable)?,
        request_id: request_id.clone(),
        source_event_id: Some(AuditEventId::generate().map_err(|_| {
            crate::LedgerError::InvalidUuid {
                field: "source_event_id",
            }
        })?),
        target_secret_id: Some(prepared.secret_id().clone()),
        target_secret_version_id: Some(target_secret_version_id),
        actor_user_id: Some(prepared.owner_user_id().clone()),
        actor_device_id: Some(prepared.created_by_device_id().clone()),
        result: LedgerResult::Success,
        error_code: None,
        payload,
    })
}

fn encode_bytea(bytes: &[u8]) -> String {
    format!("\\x{}", hex::encode(bytes))
}

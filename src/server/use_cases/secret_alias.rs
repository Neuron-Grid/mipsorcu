use std::fmt;

use crate::alias::{
    DecryptedAlias, NormalizedAlias, PreparedAliasCreate, PreparedAliasUpdate,
    compute_lookup_fingerprint, decrypt_alias_row, prepare_alias_create, prepare_alias_update,
};
use crate::audit::{
    AuditAction, AuditEvent, AuditRecordError, AuditRecordOutcome, AuditResult, RequestId,
    SecretAliasListMetadata,
};
use crate::auth::{RawJwt, VerifiedJwtClaims};
use crate::server::audit_reporter::FailureAuditContext;
use crate::server::errors::ApiError;
use crate::server::read_model::{FetchCurrentSecretVersionError, fetch_current_secret_version};
use crate::server::state::AppState;
use crate::server::supabase::{
    CreateSecretAliasParams, DeleteSecretAliasParams, ListSecretAliasesParams, SecretAliasRpcError,
    UpdateSecretAliasParams, classify_secret_alias_rpc_error,
};
use crate::types::supabase::{SecretAliasListRow, SecretAliasResolveRow};
use crate::{
    AliasFingerprint, Ciphertext, CreatedAt, KeyVersion, Nonce, OwnerUserId, SecretAliasId,
    SecretId, SourceEventAt,
};

pub(in crate::server) struct CreateSecretAliasCommand {
    secret_id: SecretId,
    alias: NormalizedAlias,
}

impl CreateSecretAliasCommand {
    pub(in crate::server) fn new(secret_id: SecretId, alias: NormalizedAlias) -> Self {
        Self { secret_id, alias }
    }
}

impl fmt::Debug for CreateSecretAliasCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateSecretAliasCommand")
            .field("secret_id", &self.secret_id)
            .field("alias", &self.alias)
            .finish()
    }
}

pub(in crate::server) struct CreateSecretAliasOutput {
    secret_alias_id: SecretAliasId,
    secret_id: SecretId,
}

impl CreateSecretAliasOutput {
    pub fn secret_alias_id(&self) -> &SecretAliasId {
        &self.secret_alias_id
    }

    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }
}

pub(in crate::server) struct UpdateSecretAliasOutput {
    secret_alias_id: SecretAliasId,
}

impl UpdateSecretAliasOutput {
    pub fn secret_alias_id(&self) -> &SecretAliasId {
        &self.secret_alias_id
    }
}

pub(in crate::server) struct SecretAliasListItem {
    pub secret_alias_id: SecretAliasId,
    pub secret_id: SecretId,
    pub alias: NormalizedAlias,
    pub created_at: String,
    pub updated_at: String,
}

pub(in crate::server) struct ListSecretAliasesOutput {
    pub aliases: Vec<SecretAliasListItem>,
}

pub(in crate::server) struct ResolveSecretAliasOutput {
    pub secret_alias_id: SecretAliasId,
    pub secret_id: SecretId,
}

pub(in crate::server) async fn create_secret_alias(
    state: &AppState,
    request_id: &RequestId,
    raw_jwt: &RawJwt,
    claims: &VerifiedJwtClaims,
    command: CreateSecretAliasCommand,
) -> Result<CreateSecretAliasOutput, ApiError> {
    let actor_user_id = claims.subject_user_id().clone();
    let secret_id = command.secret_id;
    let failure = FailureAuditContext::new(
        state,
        request_id,
        Some(&actor_user_id),
        Some(&secret_id),
        AuditAction::SecretAliasCreate,
    );

    let current = match fetch_current_secret_version(state, &secret_id, raw_jwt).await {
        Ok(current) => current,
        Err(FetchCurrentSecretVersionError::Upstream(rpc_error)) => {
            failure.log_upstream_failure(&rpc_error, "fetch_current_secret_version");
            record_failure_audit(&failure).await;
            return Err(ApiError::from(rpc_error));
        }
        Err(FetchCurrentSecretVersionError::Api(api_error)) => {
            record_logged_failure_audit(&failure, &api_error, "fetch_current_secret_version").await;
            return Err(api_error);
        }
    };

    if current.owner_user_id() != &actor_user_id {
        let error = ApiError::Forbidden("forbidden".to_owned());
        record_logged_failure_audit(&failure, &error, "authorize_secret_alias_create").await;
        return Err(error);
    }

    let prepared = match prepare_alias_create(
        &state.alias_encryption_key,
        state.alias_encryption_key_version,
        &state.alias_fingerprint_key,
        state.alias_fingerprint_key_version,
        secret_id.clone(),
        actor_user_id.clone(),
        command.alias,
        CreatedAt::now_utc(),
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            record_logged_failure_audit(&failure, &error, "prepare_alias_create").await;
            return Err(ApiError::InternalError(error.to_string()));
        }
    };
    let params = match build_create_params(request_id, &prepared) {
        Ok(params) => params,
        Err(error) => {
            record_logged_failure_audit(&failure, &error, "build_create_alias_params").await;
            return Err(error);
        }
    };

    let secret_alias_id = match state
        .supabase_client
        .call_create_secret_alias(&params)
        .await
    {
        Ok(secret_alias_id) => secret_alias_id,
        Err(error) => {
            failure.log_upstream_failure(&error, "call_create_secret_alias");
            record_failure_audit(&failure).await;
            return Err(api_error_from_alias_rpc(error));
        }
    };

    tracing::info!(
        request_id = %request_id.as_canonical_string(),
        secret_id = %secret_id.as_canonical_string(),
        secret_alias_id = %secret_alias_id.as_canonical_string(),
        action = AuditAction::SecretAliasCreate.as_str(),
        result = "success",
    );

    Ok(CreateSecretAliasOutput {
        secret_alias_id,
        secret_id,
    })
}

pub(in crate::server) async fn update_alias(
    state: &AppState,
    request_id: &RequestId,
    claims: &VerifiedJwtClaims,
    secret_alias_id: SecretAliasId,
    new_alias: NormalizedAlias,
) -> Result<UpdateSecretAliasOutput, ApiError> {
    let actor_user_id = claims.subject_user_id().clone();
    let failure_without_target = FailureAuditContext::new(
        state,
        request_id,
        Some(&actor_user_id),
        None,
        AuditAction::SecretAliasUpdate,
    );
    let secret_id = match state
        .supabase_client
        .call_get_secret_alias_for_update(&actor_user_id, &secret_alias_id)
        .await
    {
        Ok(secret_id) => secret_id,
        Err(error) => {
            failure_without_target.log_upstream_failure(&error, "call_get_secret_alias_for_update");
            record_failure_audit(&failure_without_target).await;
            return Err(api_error_from_alias_rpc(error));
        }
    };
    let failure = FailureAuditContext::new(
        state,
        request_id,
        Some(&actor_user_id),
        Some(&secret_id),
        AuditAction::SecretAliasUpdate,
    );
    let prepared = match prepare_alias_update(
        &state.alias_encryption_key,
        state.alias_encryption_key_version,
        &state.alias_fingerprint_key,
        state.alias_fingerprint_key_version,
        secret_alias_id.clone(),
        secret_id.clone(),
        actor_user_id.clone(),
        new_alias,
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            record_logged_failure_audit(&failure, &error, "prepare_alias_update").await;
            return Err(ApiError::InternalError(error.to_string()));
        }
    };
    let params = match build_update_params(request_id, &prepared) {
        Ok(params) => params,
        Err(error) => {
            record_logged_failure_audit(&failure, &error, "build_update_alias_params").await;
            return Err(error);
        }
    };

    if let Err(error) = state
        .supabase_client
        .call_update_secret_alias(&params)
        .await
    {
        failure.log_upstream_failure(&error, "call_update_secret_alias");
        record_failure_audit(&failure).await;
        return Err(api_error_from_alias_rpc(error));
    }

    Ok(UpdateSecretAliasOutput {
        secret_alias_id: prepared.secret_alias_id,
    })
}

pub(in crate::server) async fn delete_alias(
    state: &AppState,
    request_id: &RequestId,
    claims: &VerifiedJwtClaims,
    secret_alias_id: SecretAliasId,
) -> Result<(), ApiError> {
    let actor_user_id = claims.subject_user_id().clone();
    let failure = FailureAuditContext::new(
        state,
        request_id,
        Some(&actor_user_id),
        None,
        AuditAction::SecretAliasDelete,
    );
    let source_event_at = source_event_at()?;
    let params = DeleteSecretAliasParams {
        p_request_id: request_id.as_canonical_string(),
        p_secret_alias_id: secret_alias_id.as_canonical_string(),
        p_owner_user_id: actor_user_id.as_canonical_string(),
        p_source_event_at: source_event_at.as_str().to_owned(),
    };

    if let Err(error) = state
        .supabase_client
        .call_delete_secret_alias(&params)
        .await
    {
        failure.log_upstream_failure(&error, "call_delete_secret_alias");
        record_failure_audit(&failure).await;
        return Err(api_error_from_alias_rpc(error));
    }

    Ok(())
}

pub(in crate::server) async fn list_aliases(
    state: &AppState,
    request_id: &RequestId,
    claims: &VerifiedJwtClaims,
    limit: u32,
    offset: u32,
) -> Result<ListSecretAliasesOutput, ApiError> {
    let actor_user_id = claims.subject_user_id().clone();
    let failure = FailureAuditContext::new(
        state,
        request_id,
        Some(&actor_user_id),
        None,
        AuditAction::SecretAliasList,
    );
    let params = ListSecretAliasesParams {
        p_request_id: request_id.as_canonical_string(),
        p_owner_user_id: actor_user_id.as_canonical_string(),
        p_limit: limit,
        p_offset: offset,
    };
    let rows = match state
        .supabase_client
        .call_list_secret_aliases(&params)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            failure.log_upstream_failure(&error, "call_list_secret_aliases");
            record_failure_audit(&failure).await;
            return Err(api_error_from_alias_rpc(error));
        }
    };

    let mut aliases = Vec::with_capacity(rows.len());
    for row in rows {
        aliases.push(parse_list_alias_row(state, actor_user_id.clone(), row)?);
    }

    record_alias_list_success_audit(state, request_id, &actor_user_id, aliases.len()).await?;

    Ok(ListSecretAliasesOutput { aliases })
}

pub(in crate::server) async fn resolve_alias(
    state: &AppState,
    _request_id: &RequestId,
    claims: &VerifiedJwtClaims,
    alias: NormalizedAlias,
) -> Result<ResolveSecretAliasOutput, ApiError> {
    let actor_user_id = claims.subject_user_id().clone();
    let fingerprint =
        compute_lookup_fingerprint(&state.alias_fingerprint_key, &actor_user_id, &alias)
            .map_err(|error| ApiError::InternalError(error.to_string()))?;
    let row = state
        .supabase_client
        .call_resolve_secret_alias(&actor_user_id, &fingerprint)
        .await
        .map_err(api_error_from_alias_rpc)?
        .ok_or_else(|| ApiError::NotFound("secret not found".to_owned()))?;
    let decrypted = parse_resolve_alias_row(state, actor_user_id, row)?;

    if decrypted.alias != alias {
        return Err(ApiError::DbIntegrityViolation(
            "resolved secret alias plaintext mismatch".to_owned(),
        ));
    }

    Ok(ResolveSecretAliasOutput {
        secret_alias_id: decrypted.secret_alias_id,
        secret_id: decrypted.secret_id,
    })
}

fn build_create_params(
    request_id: &RequestId,
    prepared: &PreparedAliasCreate,
) -> Result<CreateSecretAliasParams, ApiError> {
    let created_at = prepared
        .created_at
        .as_rfc3339_utc()
        .map_err(|error| ApiError::InternalError(error.to_string()))?;
    let source_event_at = source_event_at()?;

    Ok(CreateSecretAliasParams {
        p_request_id: request_id.as_canonical_string(),
        p_secret_alias_id: prepared.secret_alias_id.as_canonical_string(),
        p_secret_id: prepared.secret_id.as_canonical_string(),
        p_owner_user_id: prepared.owner_user_id.as_canonical_string(),
        p_alias_ciphertext: encode_bytea(prepared.ciphertext.as_bytes()),
        p_alias_nonce: encode_bytea(prepared.nonce.as_bytes()),
        p_alias_key_version: prepared.alias_key_version.get(),
        p_alias_fingerprint: encode_bytea(prepared.alias_fingerprint.as_bytes()),
        p_alias_fingerprint_key_version: prepared.fingerprint_key_version.get(),
        p_alias_fingerprint_schema_version: prepared.fingerprint_schema_version.get(),
        p_aad_context: prepared.aad_context.clone(),
        p_created_at: created_at,
        p_source_event_at: source_event_at.as_str().to_owned(),
    })
}

fn build_update_params(
    request_id: &RequestId,
    prepared: &PreparedAliasUpdate,
) -> Result<UpdateSecretAliasParams, ApiError> {
    let source_event_at = source_event_at()?;

    Ok(UpdateSecretAliasParams {
        p_request_id: request_id.as_canonical_string(),
        p_secret_alias_id: prepared.secret_alias_id.as_canonical_string(),
        p_owner_user_id: prepared.owner_user_id.as_canonical_string(),
        p_alias_ciphertext: encode_bytea(prepared.ciphertext.as_bytes()),
        p_alias_nonce: encode_bytea(prepared.nonce.as_bytes()),
        p_alias_key_version: prepared.alias_key_version.get(),
        p_new_alias_fingerprint: encode_bytea(prepared.new_alias_fingerprint.as_bytes()),
        p_alias_fingerprint_key_version: prepared.fingerprint_key_version.get(),
        p_alias_fingerprint_schema_version: prepared.fingerprint_schema_version.get(),
        p_aad_context: prepared.aad_context.clone(),
        p_source_event_at: source_event_at.as_str().to_owned(),
    })
}

fn parse_list_alias_row(
    state: &AppState,
    owner_user_id: OwnerUserId,
    row: SecretAliasListRow,
) -> Result<SecretAliasListItem, ApiError> {
    parse_alias_fingerprint(&row.alias_fingerprint)?;
    let decrypted = parse_alias_material(
        state,
        owner_user_id,
        row.id,
        row.secret_id,
        row.alias_ciphertext,
        row.alias_nonce,
        row.alias_key_version,
        row.aad_context,
    )?;

    Ok(SecretAliasListItem {
        secret_alias_id: decrypted.secret_alias_id,
        secret_id: decrypted.secret_id,
        alias: decrypted.alias,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn parse_resolve_alias_row(
    state: &AppState,
    owner_user_id: OwnerUserId,
    row: SecretAliasResolveRow,
) -> Result<DecryptedAlias, ApiError> {
    parse_alias_material(
        state,
        owner_user_id,
        row.id,
        row.secret_id,
        row.alias_ciphertext,
        row.alias_nonce,
        row.alias_key_version,
        row.aad_context,
    )
}

#[allow(clippy::too_many_arguments)]
fn parse_alias_material(
    state: &AppState,
    owner_user_id: OwnerUserId,
    secret_alias_id: String,
    secret_id: String,
    alias_ciphertext: String,
    alias_nonce: String,
    alias_key_version: i32,
    aad_context: serde_json::Value,
) -> Result<DecryptedAlias, ApiError> {
    let ciphertext = decode_bytea(&alias_ciphertext).map_err(|_| {
        ApiError::DbIntegrityViolation("secret alias ciphertext is invalid".to_owned())
    })?;
    let nonce = decode_bytea(&alias_nonce)
        .map_err(|_| ApiError::DbIntegrityViolation("secret alias nonce is invalid".to_owned()))?;
    let secret_alias_id = SecretAliasId::parse(&secret_alias_id)
        .map_err(|_| ApiError::DbIntegrityViolation("secret alias id is invalid".to_owned()))?;
    let secret_id = SecretId::parse(&secret_id).map_err(|_| {
        ApiError::DbIntegrityViolation("secret alias secret_id is invalid".to_owned())
    })?;
    let alias_key_version =
        parse_key_version(alias_key_version, "secret alias key_version is invalid")?;
    let ciphertext = Ciphertext::new(ciphertext).map_err(|_| {
        ApiError::DbIntegrityViolation("secret alias ciphertext is invalid".to_owned())
    })?;
    let nonce = Nonce::parse(&nonce)
        .map_err(|_| ApiError::DbIntegrityViolation("secret alias nonce is invalid".to_owned()))?;

    decrypt_alias_row(
        &state.alias_encryption_key,
        secret_alias_id,
        secret_id,
        owner_user_id,
        alias_key_version,
        &ciphertext,
        &nonce,
        &aad_context,
    )
    .map_err(|_| {
        ApiError::DbIntegrityViolation("secret alias encrypted material is invalid".to_owned())
    })
}

fn parse_alias_fingerprint(value: &str) -> Result<AliasFingerprint, ApiError> {
    let bytes = decode_bytea(value).map_err(|_| {
        ApiError::DbIntegrityViolation("secret alias fingerprint is invalid".to_owned())
    })?;
    AliasFingerprint::parse(&bytes).map_err(|_| {
        ApiError::DbIntegrityViolation("secret alias fingerprint is invalid".to_owned())
    })
}

fn parse_key_version(value: i32, message: &'static str) -> Result<KeyVersion, ApiError> {
    u32::try_from(value)
        .ok()
        .and_then(|value| KeyVersion::new(value).ok())
        .ok_or_else(|| ApiError::DbIntegrityViolation(message.to_owned()))
}

fn encode_bytea(bytes: &[u8]) -> String {
    format!("\\x{}", hex::encode(bytes))
}

fn decode_bytea(value: &str) -> Result<Vec<u8>, ()> {
    let hex_value = value.strip_prefix("\\x").ok_or(())?;
    hex::decode(hex_value).map_err(|_| ())
}

fn source_event_at() -> Result<SourceEventAt, ApiError> {
    SourceEventAt::now_utc().map_err(|error| ApiError::InternalError(error.to_string()))
}

fn api_error_from_alias_rpc(error: crate::server::supabase::SupabaseRpcError) -> ApiError {
    match classify_secret_alias_rpc_error(&error) {
        SecretAliasRpcError::AliasConflict => {
            ApiError::Conflict("secret alias already exists".to_owned())
        }
        SecretAliasRpcError::InvalidInput => {
            ApiError::BadRequest("invalid secret alias".to_owned())
        }
        SecretAliasRpcError::OwnerMismatch => ApiError::Forbidden("forbidden".to_owned()),
        SecretAliasRpcError::AliasNotFound | SecretAliasRpcError::SecretNotFound => {
            ApiError::NotFound("not found".to_owned())
        }
        SecretAliasRpcError::Failed => ApiError::from(error),
    }
}

async fn record_logged_failure_audit(
    failure: &FailureAuditContext<'_>,
    error: &impl fmt::Display,
    stage: &'static str,
) {
    if let Err(audit_err) = failure.log_and_record(error, stage).await {
        tracing::error!(
            error = %audit_err,
            "failure audit recording also failed"
        );
    }
}

async fn record_failure_audit(failure: &FailureAuditContext<'_>) {
    if let Err(audit_err) = failure.record().await {
        tracing::error!(
            error = %audit_err,
            "failure audit recording also failed"
        );
    }
}

async fn record_alias_list_success_audit(
    state: &AppState,
    request_id: &RequestId,
    actor_user_id: &OwnerUserId,
    result_count: usize,
) -> Result<AuditRecordOutcome, ApiError> {
    let result_count =
        u64::try_from(result_count).map_err(|error| ApiError::InternalError(error.to_string()))?;
    let source_event_at = source_event_at()?;
    let metadata = SecretAliasListMetadata::success(result_count, source_event_at)
        .build()
        .map_err(|error| ApiError::InternalError(error.to_string()))?;
    let event = AuditEvent::build_with_current_source_event_at(
        request_id.clone(),
        Some(actor_user_id.clone()),
        None,
        AuditAction::SecretAliasList,
        None,
        AuditResult::Success,
        None,
        metadata,
    )
    .map_err(|error| ApiError::InternalError(error.to_string()))?;

    match state.audit_recorder.record(&event).await {
        Ok(outcome) => {
            let _ = state.siem_forwarding.forward_audit_event(&event).await;
            Ok(outcome)
        }
        Err(AuditRecordError::PrimaryAndFallbackFailed { .. })
        | Err(AuditRecordError::EventConstructionFailed(_))
        | Err(AuditRecordError::IdempotencyConflict) => {
            state.readiness_state.mark_failure_audit_both_failed();
            Err(ApiError::AuditRecordFailed)
        }
        Err(
            AuditRecordError::ResendReadFailed(_)
            | AuditRecordError::ResendMarkSentFailed(_)
            | AuditRecordError::LedgerAppendFailed,
        ) => Err(ApiError::AuditRecordFailed),
    }
}

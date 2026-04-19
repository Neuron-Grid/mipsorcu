use axum::Json;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use std::path::Path;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use mipsorcu::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditMetadata, AuditResult, RequestId,
};
use mipsorcu::auth::{RawJwt, VerifiedJwtClaims};
use mipsorcu::crypto::ALGORITHM_XCHACHA20_POLY1305;
use mipsorcu::decrypt_current_secret_version;
use mipsorcu::read::{DecryptCurrentSecretVersionInput, DecryptCurrentSecretVersionInputParts};
use mipsorcu::types::{
    Ciphertext, Classification, CreatedAt, DeviceId, EncryptedDataKey, KeyVersion, Nonce,
    OwnerUserId, Plaintext, SecretId, SecretVersion,
};
use mipsorcu::write::{NewSecretVersionInput, PreparedSecretVersion, prepare_new_secret_version};

use super::dto::{
    ApiErrorResponse, CreateSecretRequest, CreateSecretResponse, DecryptSecretResponse,
    HealthResponse,
};
use super::errors::ApiError;
use super::middleware::AuthenticatedUser;
use super::state::AppState;
use super::supabase::{SecretVersionReadRow, WriteSecretVersionParams};

pub async fn create_secret(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(body): Json<CreateSecretRequest>,
) -> Result<(StatusCode, Json<CreateSecretResponse>), ApiError> {
    let request_id = generate_request_id()?;
    let owner_user_id = auth.claims.subject_user_id().clone();
    let parsed_body = parse_create_secret_request(body)?;
    let prepared = prepare_secret_version(&state, owner_user_id.clone(), parsed_body)
        .await
        .map_err(|error| {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                "encryption failed"
            );
            record_failure_audit_nonblocking(
                &state,
                &request_id,
                Some(&owner_user_id),
                None,
                AuditAction::EncryptCreate,
            );
            error
        })?;

    let rpc_params = build_rpc_params(&request_id, &prepared)?;

    let rpc_result = state
        .supabase_client
        .call_write_secret_version(&rpc_params)
        .await;

    match rpc_result {
        Ok(response) => {
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %response.secret_id,
                version = response.version,
                action = "encrypt_create",
                result = "success",
            );

            Ok((
                StatusCode::CREATED,
                Json(CreateSecretResponse {
                    secret_id: response.secret_id,
                    version: response.version as u32,
                    secret_version_id: response.secret_version_id,
                }),
            ))
        }
        Err(rpc_error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %rpc_error,
                action = "encrypt_create",
                result = "failure",
                "supabase RPC failed"
            );

            record_failure_audit_nonblocking(
                &state,
                &request_id,
                Some(&owner_user_id),
                Some(prepared.secret_id()),
                AuditAction::EncryptCreate,
            );

            Err(ApiError::from(rpc_error))
        }
    }
}

pub async fn decrypt_secret(
    State(state): State<AppState>,
    AxumPath(secret_id): AxumPath<String>,
    auth: AuthenticatedUser,
) -> Result<Json<DecryptSecretResponse>, ApiError> {
    let request_id = generate_request_id()?;
    let requested_secret_id = parse_secret_id(&secret_id)?;
    let owner_user_id = auth.claims.subject_user_id().clone();
    let row = fetch_single_current_secret_version(&state, &requested_secret_id, &auth.raw_jwt)
        .await
        .inspect_err(|error| {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %requested_secret_id.as_canonical_string(),
                error = %error,
                action = "decrypt",
                result = "failure",
                "supabase read failed"
            );
            record_failure_audit_nonblocking(
                &state,
                &request_id,
                Some(&owner_user_id),
                Some(&requested_secret_id),
                AuditAction::Decrypt,
            );
        })?;

    let key_version = row.key_version;
    let version = row.version;
    let secret_id = row.secret_id.clone();
    let input = build_decrypt_input(row, auth.claims).inspect_err(|error| {
        tracing::error!(
            request_id = %request_id.as_canonical_string(),
            secret_id = %requested_secret_id.as_canonical_string(),
            error = %error,
            action = "decrypt",
            result = "failure",
            "decrypt input validation failed"
        );
        record_failure_audit_nonblocking(
            &state,
            &request_id,
            Some(&owner_user_id),
            Some(&requested_secret_id),
            AuditAction::Decrypt,
        );
    })?;

    let plaintext = decrypt_prepared_input(&state, input)
        .await
        .inspect_err(|error| {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                secret_id = %requested_secret_id.as_canonical_string(),
                error = %error,
                action = "decrypt",
                result = "failure",
                "decrypt failed"
            );
            record_failure_audit_nonblocking(
                &state,
                &request_id,
                Some(&owner_user_id),
                Some(&requested_secret_id),
                AuditAction::Decrypt,
            );
        })?;

    record_success_audit(&state, &request_id, &owner_user_id, &secret_id, key_version).await?;

    tracing::info!(
        request_id = %request_id.as_canonical_string(),
        secret_id = %secret_id.as_canonical_string(),
        version = version.get(),
        action = "decrypt",
        result = "success",
    );

    Ok(Json(DecryptSecretResponse {
        secret_id: secret_id.as_canonical_string(),
        version: version.get(),
        plaintext: hex::encode(plaintext.as_bytes()),
    }))
}

pub async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    let supabase_ok = state.supabase_client.check_connectivity().await;
    let disk_space = available_disk_space_mb(&state.audit_fallback_path);

    Json(HealthResponse {
        status: "up",
        supabase: if supabase_ok { "ok" } else { "ng" },
        master_key: "loaded",
        disk_space_mb: disk_space,
    })
}

pub async fn not_found() -> (StatusCode, Json<ApiErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ApiErrorResponse {
            error: "not found".to_owned(),
            code: "not_found".to_owned(),
        }),
    )
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

struct ParsedCreateSecretRequest {
    classification: Classification,
    device_id: DeviceId,
    plaintext: Plaintext,
    created_at: CreatedAt,
}

fn generate_request_id() -> Result<RequestId, ApiError> {
    RequestId::generate().map_err(|error| ApiError::InternalError(error.to_string()))
}

fn parse_create_secret_request(
    body: CreateSecretRequest,
) -> Result<ParsedCreateSecretRequest, ApiError> {
    Ok(ParsedCreateSecretRequest {
        classification: parse_classification(&body.classification)?,
        device_id: parse_device_id(&body.device_id)?,
        plaintext: parse_hex_plaintext(&body.plaintext)?,
        created_at: current_created_at()?,
    })
}

fn parse_classification(value: &str) -> Result<Classification, ApiError> {
    Classification::new(value).map_err(|error| ApiError::BadRequest(error.to_string()))
}

fn parse_device_id(value: &str) -> Result<DeviceId, ApiError> {
    DeviceId::new(value).map_err(|error| ApiError::BadRequest(error.to_string()))
}

fn parse_secret_id(value: &str) -> Result<SecretId, ApiError> {
    SecretId::parse(value).map_err(|error| ApiError::BadRequest(error.to_string()))
}

fn parse_hex_plaintext(value: &str) -> Result<Plaintext, ApiError> {
    hex::decode(value)
        .map(Plaintext::new)
        .map_err(|error| ApiError::BadRequest(format!("invalid plaintext encoding: {error}")))
}

fn current_created_at() -> Result<CreatedAt, ApiError> {
    let rfc3339 = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| ApiError::InternalError(error.to_string()))?;

    CreatedAt::parse(&rfc3339).map_err(|error| ApiError::InternalError(error.to_string()))
}

struct PreparedDecryptRow {
    secret_id: SecretId,
    version: SecretVersion,
    owner_user_id: OwnerUserId,
    classification: Classification,
    created_at: CreatedAt,
    key_version: KeyVersion,
    encrypted_data_key: EncryptedDataKey,
    nonce_or_iv: Nonce,
    ciphertext: Ciphertext,
    aad_context: serde_json::Value,
}

async fn fetch_single_current_secret_version(
    state: &AppState,
    secret_id: &SecretId,
    raw_jwt: &RawJwt,
) -> Result<PreparedDecryptRow, ApiError> {
    let rows = state
        .supabase_client
        .fetch_current_secret_version_for_user(&secret_id.as_canonical_string(), raw_jwt)
        .await
        .map_err(ApiError::from)?;

    match rows.len() {
        0 => Err(ApiError::NotFound("secret not found".to_owned())),
        1 => rows
            .into_iter()
            .next()
            .ok_or_else(|| ApiError::InternalInvariantViolation("missing read row".to_owned()))
            .and_then(parse_decrypt_row),
        count => Err(ApiError::InternalInvariantViolation(format!(
            "expected one current secret version row, got {count}"
        ))),
    }
}

fn parse_decrypt_row(row: SecretVersionReadRow) -> Result<PreparedDecryptRow, ApiError> {
    if row.algorithm != ALGORITHM_XCHACHA20_POLY1305 {
        return Err(ApiError::DecryptFailed);
    }
    if row.created_by_user_id != row.secrets.owner_user_id {
        return Err(ApiError::DecryptFailed);
    }

    Ok(PreparedDecryptRow {
        secret_id: SecretId::parse(&row.secret_id).map_err(|_| ApiError::DecryptFailed)?,
        version: parse_secret_version(row.version)?,
        owner_user_id: OwnerUserId::parse(&row.secrets.owner_user_id)
            .map_err(|_| ApiError::DecryptFailed)?,
        classification: Classification::new(&row.secrets.classification)
            .map_err(|_| ApiError::DecryptFailed)?,
        created_at: CreatedAt::parse(&row.created_at).map_err(|_| ApiError::DecryptFailed)?,
        key_version: parse_key_version(row.key_version)?,
        encrypted_data_key: EncryptedDataKey::parse(&decode_bytea(&row.encrypted_data_key)?)
            .map_err(|_| ApiError::DecryptFailed)?,
        nonce_or_iv: Nonce::parse(&decode_bytea(&row.nonce_or_iv)?)
            .map_err(|_| ApiError::DecryptFailed)?,
        ciphertext: Ciphertext::new(decode_bytea(&row.ciphertext)?)
            .map_err(|_| ApiError::DecryptFailed)?,
        aad_context: row.aad_context,
    })
}

fn parse_secret_version(value: i32) -> Result<SecretVersion, ApiError> {
    u32::try_from(value)
        .ok()
        .and_then(|v| SecretVersion::new(v).ok())
        .ok_or(ApiError::DecryptFailed)
}

fn parse_key_version(value: i32) -> Result<KeyVersion, ApiError> {
    u32::try_from(value)
        .ok()
        .and_then(|v| KeyVersion::new(v).ok())
        .ok_or(ApiError::DecryptFailed)
}

fn decode_bytea(value: &str) -> Result<Vec<u8>, ApiError> {
    let hex_value = value.strip_prefix("\\x").ok_or(ApiError::DecryptFailed)?;
    hex::decode(hex_value).map_err(|_| ApiError::DecryptFailed)
}

fn build_decrypt_input(
    row: PreparedDecryptRow,
    claims: VerifiedJwtClaims,
) -> Result<DecryptCurrentSecretVersionInput, ApiError> {
    Ok(DecryptCurrentSecretVersionInput::new(
        DecryptCurrentSecretVersionInputParts {
            claims,
            secret_id: row.secret_id,
            version: row.version,
            current_version: row.version,
            owner_user_id: row.owner_user_id,
            classification: row.classification,
            created_at: row.created_at,
            key_version: row.key_version,
            encrypted_data_key: row.encrypted_data_key,
            nonce_or_iv: row.nonce_or_iv,
            ciphertext: row.ciphertext,
            aad_context: row.aad_context,
        },
    ))
}

async fn decrypt_prepared_input(
    state: &AppState,
    input: DecryptCurrentSecretVersionInput,
) -> Result<Plaintext, ApiError> {
    let master_key = state.master_key.clone();

    tokio::task::spawn_blocking(move || decrypt_current_secret_version(&master_key, input))
        .await
        .map_err(|error| ApiError::InternalError(error.to_string()))?
        .map_err(ApiError::from)
}

async fn prepare_secret_version(
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

fn encode_bytea(bytes: &[u8]) -> String {
    format!("\\x{}", hex::encode(bytes))
}

async fn record_success_audit(
    state: &AppState,
    request_id: &RequestId,
    actor_user_id: &OwnerUserId,
    target_secret_id: &SecretId,
    key_version: KeyVersion,
) -> Result<(), ApiError> {
    let audit_event_id =
        AuditEventId::generate().map_err(|error| ApiError::InternalError(error.to_string()))?;
    let event = AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: Some(actor_user_id.clone()),
        actor_device_id: None,
        action: AuditAction::Decrypt,
        target_secret_id: Some(target_secret_id.clone()),
        result: AuditResult::Success,
        key_version: Some(key_version),
        metadata_json: AuditMetadata::empty(),
    })
    .map_err(|error| ApiError::InternalError(error.to_string()))?;

    let recorder = state.audit_recorder.clone();
    tokio::task::spawn_blocking(move || recorder.record(&event))
        .await
        .map_err(|error| ApiError::InternalError(error.to_string()))?
        .map_err(|error| {
            tracing::error!(error = %error, "decrypt success audit recording failed");
            ApiError::AuditAppendFailed
        })
}

fn record_failure_audit_nonblocking(
    state: &AppState,
    request_id: &RequestId,
    actor_user_id: Option<&OwnerUserId>,
    target_secret_id: Option<&SecretId>,
    action: AuditAction,
) {
    let audit_event_id = match AuditEventId::generate() {
        Ok(id) => id,
        Err(error) => {
            tracing::error!(error = %error, "failed to generate audit event id");
            return;
        }
    };

    let event = match AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: actor_user_id.cloned(),
        actor_device_id: None,
        action,
        target_secret_id: target_secret_id.cloned(),
        result: AuditResult::Failure,
        key_version: None,
        metadata_json: AuditMetadata::empty(),
    }) {
        Ok(event) => event,
        Err(error) => {
            tracing::error!(error = %error, "failed to construct audit event");
            return;
        }
    };

    let recorder = state.audit_recorder.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(error) = recorder.record(&event) {
            tracing::error!(
                error = %error,
                "audit recording failed (including fallback)"
            );
        }
    });
}

fn available_disk_space_mb(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        let path_str = path.parent().unwrap_or(path).to_str()?;
        let c_path = CString::new(path_str).ok()?;
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if ret == 0 {
            Some((stat.f_bavail as u64 * stat.f_frsize as u64) / (1024 * 1024))
        } else {
            None
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::server::supabase::SecretReadJoin;

    const SECRET_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const CREATED_AT: &str = "2026-04-08T12:00:00Z";

    fn valid_row() -> SecretVersionReadRow {
        SecretVersionReadRow {
            id: "650e8400-e29b-41d4-a716-446655440000".to_owned(),
            secret_id: SECRET_ID.to_owned(),
            version: 1,
            ciphertext: "\\x01".to_owned(),
            encrypted_data_key: format!("\\x01{}", "00".repeat(72)),
            key_version: 1,
            algorithm: ALGORITHM_XCHACHA20_POLY1305.to_owned(),
            nonce_or_iv: format!("\\x{}", "00".repeat(24)),
            aad_context: json!({
                "aad_version": 1,
                "secret_id": SECRET_ID,
                "version": 1,
                "owner_user_id": OWNER_USER_ID,
                "classification": "confidential",
                "created_at": CREATED_AT,
            }),
            created_by_user_id: OWNER_USER_ID.to_owned(),
            created_at: CREATED_AT.to_owned(),
            secrets: SecretReadJoin {
                current_version_id: "650e8400-e29b-41d4-a716-446655440000".to_owned(),
                owner_user_id: OWNER_USER_ID.to_owned(),
                classification: "confidential".to_owned(),
            },
        }
    }

    #[test]
    fn parse_decrypt_row_accepts_valid_supabase_row() {
        let parsed = parse_decrypt_row(valid_row()).expect("valid row should parse");

        assert_eq!(parsed.secret_id.as_canonical_string(), SECRET_ID);
        assert_eq!(parsed.version.get(), 1);
        assert_eq!(parsed.key_version.get(), 1);
        assert_eq!(parsed.nonce_or_iv.as_bytes().len(), 24);
        assert_eq!(parsed.ciphertext.as_bytes(), &[1]);
    }

    #[test]
    fn parse_decrypt_row_rejects_invalid_lengths_and_metadata() {
        let mut bad_nonce = valid_row();
        bad_nonce.nonce_or_iv = "\\x00".to_owned();
        assert!(matches!(
            parse_decrypt_row(bad_nonce),
            Err(ApiError::DecryptFailed)
        ));

        let mut empty_ciphertext = valid_row();
        empty_ciphertext.ciphertext = "\\x".to_owned();
        assert!(matches!(
            parse_decrypt_row(empty_ciphertext),
            Err(ApiError::DecryptFailed)
        ));

        let mut owner_mismatch = valid_row();
        owner_mismatch.created_by_user_id = "f47ac10b-58cc-4372-a567-0e02b2c3d480".to_owned();
        assert!(matches!(
            parse_decrypt_row(owner_mismatch),
            Err(ApiError::DecryptFailed)
        ));
    }

    #[test]
    fn decode_bytea_requires_postgres_hex_prefix() {
        assert_eq!(
            decode_bytea("\\x0a0b").expect("bytea should decode"),
            vec![10, 11]
        );
        assert!(matches!(decode_bytea("0a0b"), Err(ApiError::DecryptFailed)));
        assert!(matches!(
            decode_bytea("\\xzz"),
            Err(ApiError::DecryptFailed)
        ));
    }
}

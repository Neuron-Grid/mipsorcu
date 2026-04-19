use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use std::path::Path;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use mipsorcu::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditMetadata, AuditResult, RequestId,
};
use mipsorcu::types::{Classification, CreatedAt, DeviceId, OwnerUserId, Plaintext, SecretId};
use mipsorcu::write::{NewSecretVersionInput, PreparedSecretVersion, prepare_new_secret_version};

use super::dto::{ApiErrorResponse, CreateSecretRequest, CreateSecretResponse, HealthResponse};
use super::errors::ApiError;
use super::middleware::AuthenticatedUser;
use super::state::AppState;
use super::supabase::WriteSecretVersionParams;

pub async fn create_secret(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(body): Json<CreateSecretRequest>,
) -> Result<(StatusCode, Json<CreateSecretResponse>), ApiError> {
    let request_id = generate_request_id()?;
    let owner_user_id = auth.0.subject_user_id().clone();
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

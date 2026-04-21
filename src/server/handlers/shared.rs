use crate::PreparedSecretVersion;
use crate::audit::RequestId;
use crate::server::errors::ApiError;
use crate::server::supabase::WriteSecretVersionParams;

pub(super) fn build_rpc_params(
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

pub(super) fn generate_request_id() -> Result<RequestId, ApiError> {
    RequestId::generate().map_err(|error| ApiError::InternalError(error.to_string()))
}

pub(super) fn parse_write_response_version(value: i32) -> Result<u32, ApiError> {
    u32::try_from(value)
        .ok()
        .and_then(|parsed| crate::SecretVersion::new(parsed).ok())
        .map(crate::SecretVersion::get)
        .ok_or_else(|| {
            ApiError::InternalInvariantViolation("write RPC returned invalid version".to_owned())
        })
}

fn encode_bytea(bytes: &[u8]) -> String {
    format!("\\x{}", hex::encode(bytes))
}

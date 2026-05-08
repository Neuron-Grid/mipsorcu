use crate::PreparedSecretVersion;
use crate::audit::RequestId;
use crate::server::errors::ApiError;
use crate::server::state::AppState;
use crate::types::supabase::{
    LedgerEntryRpcParams, SecretVersionRetentionSnapshot, WriteSecretVersionParams,
};

use super::ledger::{build_purge_ledger_drafts, build_write_ledger_draft};

pub(super) async fn build_rpc_params(
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
        .map(LedgerEntryRpcParams::from_signed_entry)
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

fn encode_bytea(bytes: &[u8]) -> String {
    format!("\\x{}", hex::encode(bytes))
}

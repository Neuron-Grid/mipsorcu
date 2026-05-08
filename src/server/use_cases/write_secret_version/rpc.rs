use crate::audit::{AuditMetadata, RequestId};
use crate::server::audit_reporter::FailureAuditContext;
use crate::server::errors::ApiError;
use crate::server::state::AppState;
use crate::types::supabase::{SecretVersionRetentionSnapshot, WriteSecretVersionOutcome};
use crate::{PreparedSecretVersion, SecretWriteAction};

use super::WriteSecretVersionOutput;
use super::request::build_rpc_params;

pub(super) async fn submit_prepared_secret_version(
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
            Ok(WriteSecretVersionOutput::new(
                response.secret_id().clone(),
                response.version(),
                response.secret_version_id().clone(),
            ))
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

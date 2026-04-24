use crate::audit::{AuditMetadata, AuditResult, RequestId};
use crate::auth::VerifiedJwtClaims;
use crate::decrypt_current_secret_version_with_keyring;
use crate::server::audit_reporter::{self, RestoreTestAudit};
use crate::server::errors::ApiError;
use crate::server::read_model::{self, PreparedDecryptRow};
use crate::server::state::AppState;
use crate::server::supabase::RestoreTestSampleRow;
use crate::{KeyVersion, SecretId, SecretVersion};

pub async fn run_restore_test_once(state: &AppState, sample_limit: u32) {
    let request_id = match RequestId::generate() {
        Ok(request_id) => request_id,
        Err(error) => {
            tracing::error!(
                error = %error,
                action = "restore_test",
                result = "failure",
                error_code = "request_id_generation_failed",
                "restore test setup failed"
            );
            return;
        }
    };

    let sample_rows = match state
        .supabase_client
        .call_sample_restore_test(sample_limit)
        .await
    {
        Ok(rows) if rows.is_empty() => {
            audit_reporter::record_restore_test_audit(
                state,
                &request_id,
                RestoreTestAudit {
                    result: AuditResult::Success,
                    target_secret_id: None,
                    key_version: None,
                    metadata: restore_test_metadata(0, Some("no_current_secret_versions"), None),
                    error_code: None,
                },
            )
            .await;
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                action = "restore_test",
                result = "success",
                sample_count = 0,
            );
            return;
        }
        Ok(rows) => rows,
        Err(_error) => {
            audit_reporter::record_restore_test_audit(
                state,
                &request_id,
                RestoreTestAudit {
                    result: AuditResult::Failure,
                    target_secret_id: None,
                    key_version: None,
                    metadata: restore_test_metadata(0, Some("sample_fetch_failed"), None),
                    error_code: Some("sample_fetch_failed"),
                },
            )
            .await;
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                action = "restore_test",
                result = "failure",
                error_code = "sample_fetch_failed",
                sample_count = 0,
                "restore test sample fetch failed"
            );
            return;
        }
    };

    let sample_count = sample_rows.len() as u64;

    for sample_row in sample_rows {
        let failure_context = restore_test_failure_context_from_raw(&sample_row);
        let prepared = match read_model::parse_restore_test_sample(sample_row) {
            Ok(prepared) => prepared,
            Err(_) => {
                let log_target_secret_id = failure_context
                    .target_secret_id
                    .as_ref()
                    .map(SecretId::as_canonical_string);
                let log_key_version = failure_context.key_version.map(KeyVersion::get);
                audit_reporter::record_restore_test_audit(
                    state,
                    &request_id,
                    RestoreTestAudit {
                        result: AuditResult::Failure,
                        target_secret_id: failure_context.target_secret_id,
                        key_version: failure_context.key_version,
                        metadata: restore_test_metadata(
                            sample_count,
                            Some("row_validation_failed"),
                            failure_context.failed_version,
                        ),
                        error_code: Some("row_validation_failed"),
                    },
                )
                .await;
                tracing::error!(
                    request_id = %request_id.as_canonical_string(),
                    target_secret_id = log_target_secret_id.as_deref(),
                    key_version = log_key_version,
                    failed_version = failure_context.failed_version,
                    action = "restore_test",
                    result = "failure",
                    error_code = "row_validation_failed",
                    sample_count = sample_count,
                    "restore test row validation failed"
                );
                return;
            }
        };

        let failure_context = RestoreTestFailureContext::from_prepared(&prepared);
        let input = build_restore_test_decrypt_input_from_prepared(prepared);
        let master_key_ring = state.master_key_ring.clone();
        let decrypt_result = tokio::task::spawn_blocking(move || {
            decrypt_current_secret_version_with_keyring(&master_key_ring, input)
        })
        .await
        .map_err(|error| ApiError::InternalError(error.to_string()))
        .and_then(|result| result.map_err(ApiError::from));

        if decrypt_result.is_err() {
            audit_reporter::record_restore_test_audit(
                state,
                &request_id,
                RestoreTestAudit {
                    result: AuditResult::Failure,
                    target_secret_id: failure_context.target_secret_id.clone(),
                    key_version: failure_context.key_version,
                    metadata: restore_test_metadata(
                        sample_count,
                        Some("decrypt_failed"),
                        failure_context.failed_version,
                    ),
                    error_code: Some("decrypt_failed"),
                },
            )
            .await;
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                target_secret_id = failure_context
                    .target_secret_id
                    .as_ref()
                    .map(SecretId::as_canonical_string)
                    .as_deref(),
                key_version = failure_context.key_version.map(KeyVersion::get),
                failed_version = failure_context.failed_version,
                action = "restore_test",
                result = "failure",
                error_code = "decrypt_failed",
                sample_count = sample_count,
                "restore test decrypt failed"
            );
            return;
        }
    }

    audit_reporter::record_restore_test_audit(
        state,
        &request_id,
        RestoreTestAudit {
            result: AuditResult::Success,
            target_secret_id: None,
            key_version: None,
            metadata: restore_test_metadata(sample_count, None, None),
            error_code: None,
        },
    )
    .await;
    tracing::info!(
        request_id = %request_id.as_canonical_string(),
        action = "restore_test",
        result = "success",
        sample_count = sample_count,
    );
}

pub fn build_restore_test_decrypt_input(
    row: RestoreTestSampleRow,
) -> Result<crate::DecryptCurrentSecretVersionInput, ApiError> {
    let parsed = read_model::parse_restore_test_sample(row)?;
    Ok(build_restore_test_decrypt_input_from_prepared(parsed))
}

pub fn restore_test_metadata(
    sample_count: u64,
    error_code: Option<&'static str>,
    failed_version: Option<u32>,
) -> AuditMetadata {
    let value = match error_code {
        Some("no_current_secret_versions") => serde_json::json!({
            "phase": "verify",
            "sample_count": sample_count,
            "reason": "no_current_secret_versions",
        }),
        Some(code) => serde_json::json!({
            "phase": "verify",
            "sample_count": sample_count,
            "error_code": code,
            "failed_version": failed_version,
        }),
        None => serde_json::json!({
            "phase": "verify",
            "sample_count": sample_count,
        }),
    };

    AuditMetadata::new(value).unwrap_or_else(|_| AuditMetadata::empty())
}

struct RestoreTestFailureContext {
    target_secret_id: Option<SecretId>,
    key_version: Option<KeyVersion>,
    failed_version: Option<u32>,
}

impl RestoreTestFailureContext {
    fn from_prepared(prepared: &PreparedDecryptRow) -> Self {
        Self {
            target_secret_id: Some(prepared.secret_id().clone()),
            key_version: Some(prepared.key_version()),
            failed_version: Some(prepared.version().get()),
        }
    }
}

fn restore_test_failure_context_from_raw(row: &RestoreTestSampleRow) -> RestoreTestFailureContext {
    RestoreTestFailureContext {
        target_secret_id: SecretId::parse(&row.secret_id).ok(),
        key_version: u32::try_from(row.key_version)
            .ok()
            .and_then(|parsed| KeyVersion::new(parsed).ok()),
        failed_version: u32::try_from(row.version)
            .ok()
            .and_then(|parsed| SecretVersion::new(parsed).ok())
            .map(SecretVersion::get),
    }
}

fn build_restore_test_decrypt_input_from_prepared(
    prepared: PreparedDecryptRow,
) -> crate::DecryptCurrentSecretVersionInput {
    let claims = VerifiedJwtClaims::for_restore_test_only(prepared.owner_user_id().clone());

    prepared.into_decrypt_input(claims)
}

#[doc(hidden)]
pub mod testing {
    pub use super::{build_restore_test_decrypt_input, restore_test_metadata};
}

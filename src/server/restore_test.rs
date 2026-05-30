use std::time::Instant;

use crate::audit::{AuditMetadata, AuditResult, AuditTrigger, RequestId, RestoreTestMetadata};
use crate::auth::VerifiedJwtClaims;
use crate::decrypt_current_secret_version_with_keyring;
use crate::server::audit_reporter::{self, RestoreTestAudit};
use crate::server::errors::ApiError;
use crate::server::read_model::{self, PreparedDecryptRow};
use crate::server::state::AppState;
use crate::types::supabase::RestoreTestSampleRow;
use crate::{KeyVersion, SecretId, SecretVersion};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreTestOutcome {
    Success,
    Failure { error_code: &'static str },
}

pub async fn run_restore_test_once(
    state: &AppState,
    sample_limit: u32,
    trigger: AuditTrigger,
) -> RestoreTestOutcome {
    let started_at = Instant::now();
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
            return RestoreTestOutcome::Failure {
                error_code: "request_id_generation_failed",
            };
        }
    };

    // ── 1. 復号対象サンプルを取得（空 / 取得失敗はここで確定する） ──
    let sample_rows = match state
        .supabase_client
        .call_sample_restore_test(sample_limit)
        .await
    {
        Ok(rows) if rows.is_empty() => {
            if let Some(outcome) = record_restore_test_audit_or_failure(
                state,
                &request_id,
                RestoreTestAudit {
                    result: AuditResult::Success,
                    target_secret_id: None,
                    key_version: None,
                    metadata: restore_test_metadata_with_duration(
                        0,
                        None,
                        None,
                        Some("no_current_secret_versions"),
                        trigger,
                        elapsed_ms(started_at),
                    ),
                    error_code: None,
                },
            )
            .await
            {
                return outcome;
            }
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                action = "restore_test",
                result = "success",
                sample_count = 0,
            );
            return RestoreTestOutcome::Success;
        }
        Ok(rows) => rows,
        Err(_error) => {
            if let Some(outcome) = record_restore_test_audit_or_failure(
                state,
                &request_id,
                RestoreTestAudit {
                    result: AuditResult::Failure,
                    target_secret_id: None,
                    key_version: None,
                    metadata: restore_test_metadata_with_duration(
                        0,
                        Some("sample_fetch_failed"),
                        None,
                        None,
                        trigger,
                        elapsed_ms(started_at),
                    ),
                    error_code: Some("sample_fetch_failed"),
                },
            )
            .await
            {
                return outcome;
            }
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                action = "restore_test",
                result = "failure",
                error_code = "sample_fetch_failed",
                sample_count = 0,
                "restore test sample fetch failed"
            );
            return RestoreTestOutcome::Failure {
                error_code: "sample_fetch_failed",
            };
        }
    };

    let sample_count = sample_rows.len() as u64;

    // ── 2. 各サンプルを検証・復号（最初の失敗で確定する） ──
    for sample_row in sample_rows {
        if let Err(outcome) = process_restore_test_sample(
            state,
            &request_id,
            sample_row,
            sample_count,
            trigger,
            started_at,
        )
        .await
        {
            return outcome;
        }
    }

    // ── 3. 全件成功を記録する ──
    if let Some(outcome) = record_restore_test_audit_or_failure(
        state,
        &request_id,
        RestoreTestAudit {
            result: AuditResult::Success,
            target_secret_id: None,
            key_version: None,
            metadata: restore_test_metadata_with_duration(
                sample_count,
                None,
                None,
                None,
                trigger,
                elapsed_ms(started_at),
            ),
            error_code: None,
        },
    )
    .await
    {
        return outcome;
    }
    tracing::info!(
        request_id = %request_id.as_canonical_string(),
        action = "restore_test",
        result = "success",
        sample_count = sample_count,
    );
    RestoreTestOutcome::Success
}

/// restore test サンプル1件を検証・復号する。
///
/// 正常に復号できた場合は `Ok(())`、行検証・復号・監査記録のいずれかが失敗した
/// 場合は呼び出し側が返すべき `RestoreTestOutcome` を `Err` で返す。
async fn process_restore_test_sample(
    state: &AppState,
    request_id: &RequestId,
    sample_row: RestoreTestSampleRow,
    sample_count: u64,
    trigger: AuditTrigger,
    started_at: Instant,
) -> Result<(), RestoreTestOutcome> {
    let failure_context = restore_test_failure_context_from_raw(&sample_row);
    let prepared = match read_model::parse_restore_test_sample(sample_row) {
        Ok(prepared) => prepared,
        Err(_) => {
            let log_target_secret_id = failure_context
                .target_secret_id
                .as_ref()
                .map(SecretId::as_canonical_string);
            let log_key_version = failure_context.key_version.map(KeyVersion::get);
            if let Some(outcome) = record_restore_test_audit_or_failure(
                state,
                request_id,
                RestoreTestAudit {
                    result: AuditResult::Failure,
                    target_secret_id: failure_context.target_secret_id,
                    key_version: failure_context.key_version,
                    metadata: restore_test_metadata_with_duration(
                        sample_count,
                        Some("row_validation_failed"),
                        failure_context.failed_version,
                        None,
                        trigger,
                        elapsed_ms(started_at),
                    ),
                    error_code: Some("row_validation_failed"),
                },
            )
            .await
            {
                return Err(outcome);
            }
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
            return Err(RestoreTestOutcome::Failure {
                error_code: "row_validation_failed",
            });
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
        if let Some(outcome) = record_restore_test_audit_or_failure(
            state,
            request_id,
            RestoreTestAudit {
                result: AuditResult::Failure,
                target_secret_id: failure_context.target_secret_id.clone(),
                key_version: failure_context.key_version,
                metadata: restore_test_metadata_with_duration(
                    sample_count,
                    Some("decrypt_failed"),
                    failure_context.failed_version,
                    None,
                    trigger,
                    elapsed_ms(started_at),
                ),
                error_code: Some("decrypt_failed"),
            },
        )
        .await
        {
            return Err(outcome);
        }
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
        return Err(RestoreTestOutcome::Failure {
            error_code: "decrypt_failed",
        });
    }

    Ok(())
}

/// restore test の監査イベントを記録し、記録自体が失敗した場合のみ呼び出し側が
/// 返すべき `Failure { restore_test_audit_record_failed }` を返す。
///
/// 記録に成功した場合は `None` を返し、呼び出し側が結果別ログと outcome 返却を行う。
async fn record_restore_test_audit_or_failure(
    state: &AppState,
    request_id: &RequestId,
    audit: RestoreTestAudit,
) -> Option<RestoreTestOutcome> {
    if let Err(audit_err) =
        audit_reporter::record_restore_test_audit(state, request_id, audit).await
    {
        tracing::error!(
            request_id = %request_id.as_canonical_string(),
            error = %audit_err,
            "restore test audit recording failed"
        );
        return Some(RestoreTestOutcome::Failure {
            error_code: "restore_test_audit_record_failed",
        });
    }

    None
}

fn restore_test_metadata_with_duration(
    sample_count: u64,
    error_code: Option<&'static str>,
    failed_version: Option<u32>,
    reason: Option<&'static str>,
    trigger: AuditTrigger,
    duration_ms: u64,
) -> AuditMetadata {
    restore_test_metadata_value(
        sample_count,
        error_code,
        failed_version,
        reason,
        trigger,
        Some(duration_ms),
    )
}

fn restore_test_metadata_value(
    sample_count: u64,
    error_code: Option<&'static str>,
    failed_version: Option<u32>,
    reason: Option<&'static str>,
    trigger: AuditTrigger,
    duration_ms: Option<u64>,
) -> AuditMetadata {
    let result = RestoreTestMetadata::new(sample_count, trigger)
        .with_error_code_opt(error_code)
        .with_failed_version_opt_u32(failed_version)
        .with_reason_opt(reason)
        .with_duration_ms_opt(duration_ms)
        .build();

    result.unwrap_or_else(|error| {
        tracing::error!(
            error = %error,
            action = "restore_test",
            result = "failure",
            error_code = "audit_metadata_build_failed",
            "failed to construct restore test audit metadata"
        );
        AuditMetadata::empty()
    })
}

fn elapsed_ms(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
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

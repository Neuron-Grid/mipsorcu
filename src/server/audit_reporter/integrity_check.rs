use crate::audit::{
    AuditAction, AuditEvent, AuditMetadata, AuditRecordError, AuditRecordOutcome, AuditResult,
    RequestId,
};
use crate::server::state::AppState;

use super::ledger::{build_integrity_check_ledger_draft, record_audit_with_ledger};

pub struct IntegrityCheckAudit {
    pub result: AuditResult,
    pub metadata: AuditMetadata,
    pub error_code: Option<&'static str>,
}

pub async fn record_integrity_check_audit(
    state: &AppState,
    request_id: &RequestId,
    audit: IntegrityCheckAudit,
) -> Result<AuditRecordOutcome, AuditRecordError> {
    let IntegrityCheckAudit {
        result,
        metadata,
        error_code,
    } = audit;
    let event = build_integrity_check_event(request_id, result, metadata)?;

    // 監査記録条件（§14.1）: rpc_failed のときのみ ledger を伴わない audit-only 経路を選ぶ。
    // 分岐選択はこの親に残し、各経路の本体だけをヘルパーへ委譲する。
    if error_code != Some("rpc_failed") {
        return record_with_ledger_branch(state, request_id, &event).await;
    }

    record_audit_only_with_fallback(state, request_id, &event, error_code).await
}

/// integrity check の監査イベントを構築する（純粋。構築失敗時はエラーログのみ）。
fn build_integrity_check_event(
    request_id: &RequestId,
    result: AuditResult,
    metadata: AuditMetadata,
) -> Result<AuditEvent, AuditRecordError> {
    match AuditEvent::build_with_current_source_event_at(
        request_id.clone(),
        None,
        None,
        AuditAction::IntegrityCheck,
        None,
        result,
        None,
        metadata,
    ) {
        Ok(event) => Ok(event),
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "integrity_check",
                result = "failure",
                error_code = "audit_event_build_failed",
                "integrity check audit setup failed"
            );
            Err(AuditRecordError::EventConstructionFailed(error))
        }
    }
}

/// ledger を伴う監査記録経路（rpc_failed 以外）。
async fn record_with_ledger_branch(
    state: &AppState,
    request_id: &RequestId,
    event: &AuditEvent,
) -> Result<AuditRecordOutcome, AuditRecordError> {
    let ledger_draft = build_integrity_check_ledger_draft(event).map_err(|error| {
        tracing::error!(
            request_id = %request_id.as_canonical_string(),
            error = %error,
            action = "integrity_check",
            result = event.result().as_str(),
            error_code = "ledger_entry_build_failed",
            "integrity check ledger entry setup failed"
        );
        AuditRecordError::LedgerAppendFailed
    })?;

    let outcome =
        record_audit_with_ledger(state, request_id, event, ledger_draft, "integrity_check").await?;
    tracing::debug!(
        request_id = %request_id.as_canonical_string(),
        action = "integrity_check",
        audit_record_outcome = "primary_succeeded",
        "integrity check audit and ledger recorded"
    );
    Ok(outcome)
}

/// ledger を伴わない監査-only 記録経路（rpc_failed）。
/// primary/fallback の結果に応じて SIEM へ転送する。
async fn record_audit_only_with_fallback(
    state: &AppState,
    request_id: &RequestId,
    event: &AuditEvent,
    error_code: Option<&'static str>,
) -> Result<AuditRecordOutcome, AuditRecordError> {
    let recorder = state.audit_recorder.clone();

    match recorder.record(event).await {
        Ok(outcome) => handle_audit_only_record_success(state, request_id, event, outcome).await,
        Err(error) => handle_audit_only_record_error(request_id, error, error_code),
    }
}

/// 監査-only 記録が成功した場合の後続処理を行う。
///
/// primary / fallback のどちらで成功しても SIEM 転送を試みる。
/// SIEM 転送失敗は監査記録自体の成否には影響させない。
async fn handle_audit_only_record_success(
    state: &AppState,
    request_id: &RequestId,
    event: &AuditEvent,
    outcome: AuditRecordOutcome,
) -> Result<AuditRecordOutcome, AuditRecordError> {
    let _ = state.siem_forwarding.forward_audit_event(event).await;

    log_audit_only_record_success(request_id, outcome);

    Ok(outcome)
}

/// 監査-only 記録が失敗した場合のログ出力とエラー返却を行う。
fn handle_audit_only_record_error(
    request_id: &RequestId,
    error: AuditRecordError,
    error_code: Option<&'static str>,
) -> Result<AuditRecordOutcome, AuditRecordError> {
    log_audit_only_record_error(request_id, &error, error_code);

    Err(error)
}

/// 監査-only 記録成功時のログを出力する。
fn log_audit_only_record_success(request_id: &RequestId, outcome: AuditRecordOutcome) {
    match outcome {
        AuditRecordOutcome::PrimarySucceeded => {
            tracing::debug!(
                request_id = %request_id.as_canonical_string(),
                action = "integrity_check",
                audit_record_outcome = "primary_succeeded",
                "integrity check audit recorded"
            );
        }
        AuditRecordOutcome::FallbackSucceeded => {
            tracing::warn!(
                request_id = %request_id.as_canonical_string(),
                action = "integrity_check",
                audit_record_outcome = "fallback_succeeded",
                "integrity check audit recorded to local fallback"
            );
        }
    }
}

/// 監査-only 記録失敗時のログを出力する。
fn log_audit_only_record_error(
    request_id: &RequestId,
    error: &AuditRecordError,
    error_code: Option<&'static str>,
) {
    match error {
        AuditRecordError::PrimaryAndFallbackFailed { .. } => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "integrity_check",
                result = "failure",
                error_code = error_code.unwrap_or("audit_record_failed"),
                audit_record_outcome = "both_failed",
                "integrity check audit recording failed"
            );
        }
        AuditRecordError::IdempotencyConflict => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "integrity_check",
                result = "failure",
                error_code = "audit_idempotency_conflict",
                audit_record_outcome = "idempotency_conflict",
                "integrity check audit recording failed"
            );
        }
        AuditRecordError::ResendReadFailed(_)
        | AuditRecordError::ResendMarkSentFailed(_)
        | AuditRecordError::EventConstructionFailed(_)
        | AuditRecordError::LedgerAppendFailed => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "integrity_check",
                result = "failure",
                error_code = error_code.unwrap_or("audit_record_failed"),
                audit_record_outcome = "unexpected_resend_error",
                "integrity check audit recording failed"
            );
        }
    }
}

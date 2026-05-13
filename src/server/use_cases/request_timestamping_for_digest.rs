//! 月次 digest hash に対する外部 timestamping 要求 use case（Phase 2 §8、ADR 0040）。
//!
//! SBC 内で完結する処理:
//! 1. `service.request_timestamp(&digest.digest_hash)` を呼び `TimestampingToken` を取得
//!    - 失敗: `digest_timestamping` 失敗監査を記録し `Err(BackendFailed)` を返す
//! 2. token から `TimestampingTokenHash` を計算
//! 3. `digest_timestamped` ledger entry を追記
//!    - ledger 追記失敗: ログのみ、成功監査を記録、`Err(LedgerAppendFailed)` を返す
//!    - ledger 追記成功: 成功監査を記録
//! 4. `Ok(TimestampingToken)` を返す（token raw bytes の永続化は呼び出し側責務）
//!
//! 信頼境界ノート: `TimestampingService::request_timestamp` の引数型は
//! `&DigestHash` のみ。`LedgerEntry` 全件・平文・鍵・JWT が型レベルで送信不可。
//! 失敗は `encrypt` / `decrypt` / `rotate` / `archive_export` の主要経路に伝播しない。

use std::sync::Arc;

use crate::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditRecorder, AuditResult,
    DigestTimestampingMetadata, RequestId,
};
use crate::incident::{IncidentRecorder, NotificationSink, digest_timestamping_incident_input};
use crate::ledger::{
    LedgerEntryId, LedgerEntryType, LedgerPayload, LedgerResult, MonthlyDigestPeriod,
    SignedMonthlyDigest,
};
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts, LedgerAppender};
use crate::server::supabase::SupabaseAuditAppender;
use crate::timestamping::{
    TimestampingService, TimestampingServiceError, TimestampingToken, TimestampingTokenHash,
};
use crate::types::SourceEventAt;

/// digest timestamping 失敗の原因分類。
///
/// `LedgerAppendFailed` は timestamping 成功後の付随的失敗であり、
/// token 取得自体は成功していることに注意（呼び出し側で token を保持できる）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestTimestampingError {
    /// timestamping backend からの応答取得が失敗した（主要エラー。token 未取得）。
    BackendFailed { code: String },
    /// token は取得済みだが ledger への追記が失敗した（付随的失敗）。
    LedgerAppendFailed { code: &'static str },
}

impl RequestTimestampingError {
    pub fn as_error_code(&self) -> &str {
        match self {
            Self::BackendFailed { code } => code.as_str(),
            Self::LedgerAppendFailed { code } => code,
        }
    }
}

impl std::fmt::Display for RequestTimestampingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendFailed { code } => {
                write!(formatter, "timestamping backend failed: {code}")
            }
            Self::LedgerAppendFailed { code } => {
                write!(formatter, "timestamping ledger append failed: {code}")
            }
        }
    }
}

impl std::error::Error for RequestTimestampingError {}

/// 月次 digest に対する外部 timestamping を要求する。
///
/// 成功時は `digest_timestamped` ledger entry と `digest_timestamping` 成功監査を記録し、
/// 取得した `TimestampingToken` を返却する（呼び出し側で永続化）。
/// 失敗時は `digest_timestamping` 失敗監査のみを記録し、他の操作には伝播しない。
pub async fn request_timestamping_for_digest<S: TimestampingService>(
    service: &S,
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    ledger_appender: &Arc<LedgerAppender>,
    digest: &SignedMonthlyDigest,
    request_id: RequestId,
    requested_at: SourceEventAt,
) -> Result<TimestampingToken, RequestTimestampingError> {
    let period = &digest.period;
    let digest_hash_hex = digest.digest_hash.to_hex();

    // ── 1. timestamping 要求 ──
    let token = match service.request_timestamp(&digest.digest_hash).await {
        Ok(token) => token,
        Err(error) => {
            let error_code = backend_error_code(&error);
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                error = %error,
                error_code = %error_code,
                "digest timestamping request failed"
            );
            record_digest_timestamping_failure_audit(
                audit_recorder,
                &request_id,
                period,
                &digest_hash_hex,
                &error_code,
                &requested_at,
            )
            .await;
            return Err(RequestTimestampingError::BackendFailed { code: error_code });
        }
    };

    // ── 2. token hash を計算 ──
    let token_hash = TimestampingTokenHash::from_token(&token);
    let token_hash_hex = token_hash.to_hex();

    // ── 3. ledger entry を追記 ──
    let ledger_result = append_digest_timestamped_ledger_entry(
        ledger_appender,
        digest,
        &token_hash_hex,
        &request_id,
        &requested_at,
    )
    .await;

    // ── 4. 成功監査を記録（ledger 追記結果に関わらず） ──
    record_digest_timestamping_success_audit(
        audit_recorder,
        &request_id,
        period,
        &digest_hash_hex,
        &token_hash_hex,
        &requested_at,
    )
    .await;

    match ledger_result {
        Ok(()) => {
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                digest_hash = %digest_hash_hex,
                timestamp_token_hash = %token_hash_hex,
                "digest timestamping succeeded"
            );
            Ok(token)
        }
        Err(code) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                digest_hash = %digest_hash_hex,
                timestamp_token_hash = %token_hash_hex,
                error_code = code,
                "digest timestamping ledger append failed (token was acquired)"
            );
            Err(RequestTimestampingError::LedgerAppendFailed { code })
        }
    }
}

pub async fn request_timestamping_for_digest_with_incident<T, S>(
    service: &T,
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    ledger_appender: &Arc<LedgerAppender>,
    incident_recorder: &IncidentRecorder<S>,
    digest: &SignedMonthlyDigest,
    request_id: RequestId,
    requested_at: SourceEventAt,
) -> Result<TimestampingToken, RequestTimestampingError>
where
    T: TimestampingService,
    S: NotificationSink,
{
    let result = request_timestamping_for_digest(
        service,
        audit_recorder,
        ledger_appender,
        digest,
        request_id,
        requested_at,
    )
    .await;

    if let Err(error) = &result {
        let error_code = error.as_error_code();
        if let Some(input) = digest_timestamping_incident_input(
            "digest_timestamping_verify",
            error_code,
            &digest.period,
        ) && let Err(record_error) = incident_recorder.record(input).await
        {
            tracing::error!(
                period = digest.period.as_str(),
                error_code,
                error = %record_error,
                "digest timestamping incident recording failed"
            );
        }
    }

    result
}

/// `TimestampingServiceError` を `audit_events.metadata_json.error_code` 用の
/// 文字列に変換する。
///
/// `BackendFailed { code }` の `code` が `digest_timestamping_` プレフィクスで
/// 始まる場合は backend 固有の細粒度コードとして透過する。それ以外は固定
/// 文字列に丸める（実行ログ・監査に未知の文字列が漏れないため）。
fn backend_error_code(error: &TimestampingServiceError) -> String {
    match error {
        TimestampingServiceError::BackendFailed { code } => {
            if code.starts_with("digest_timestamping_") {
                code.clone()
            } else {
                "digest_timestamping_backend_failed".to_owned()
            }
        }
        TimestampingServiceError::InvalidResponse { .. } => {
            "digest_timestamping_invalid_response".to_owned()
        }
    }
}

async fn append_digest_timestamped_ledger_entry(
    ledger_appender: &LedgerAppender,
    digest: &SignedMonthlyDigest,
    token_hash_hex: &str,
    request_id: &RequestId,
    requested_at: &SourceEventAt,
) -> Result<(), &'static str> {
    let entry_type = LedgerEntryType::DigestTimestamped;
    let payload = LedgerPayload::new(
        entry_type,
        serde_json::json!({
            "digest_hash": digest.digest_hash.to_hex(),
            "target_year_month": digest.period.as_str(),
            "timestamp_token_hash": token_hash_hex,
        }),
    )
    .map_err(|error| {
        tracing::error!(
            request_id = %request_id.as_canonical_string(),
            error = %error,
            "digest timestamping ledger payload build failed"
        );
        "digest_timestamped_payload_build_failed"
    })?;

    let ledger_entry_id =
        LedgerEntryId::generate().map_err(|_| "digest_timestamped_id_generate_failed")?;

    let draft = LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id,
        entry_type,
        source_event_at: requested_at.clone(),
        request_id: request_id.clone(),
        source_event_id: None,
        target_secret_id: None,
        target_secret_version_id: None,
        actor_user_id: None,
        actor_device_id: None,
        result: LedgerResult::Success,
        error_code: None,
        payload,
    })
    .map_err(|error| {
        tracing::error!(
            request_id = %request_id.as_canonical_string(),
            error = %error,
            "digest timestamping ledger draft build failed"
        );
        "digest_timestamped_draft_build_failed"
    })?;

    ledger_appender
        .append(&draft)
        .await
        .map_err(|error| {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error_code = error.as_error_code(),
                "digest timestamping ledger append failed"
            );
            "digest_timestamped_append_failed"
        })
        .map(|_| ())
}

async fn record_digest_timestamping_success_audit(
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    request_id: &RequestId,
    period: &MonthlyDigestPeriod,
    digest_hash_hex: &str,
    token_hash_hex: &str,
    requested_at: &SourceEventAt,
) {
    record_digest_timestamping_audit(
        audit_recorder,
        request_id,
        period,
        AuditResult::Success,
        DigestTimestampingMetadata::new(period, requested_at.clone())
            .with_digest_hash(digest_hash_hex)
            .with_timestamp_token_hash(token_hash_hex),
    )
    .await;
}

/// digest timestamping 失敗を `audit_events` に同期記録するヘルパー（non-propagating）。
pub async fn record_digest_timestamping_failure_audit(
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    request_id: &RequestId,
    period: &MonthlyDigestPeriod,
    digest_hash_hex: &str,
    error_code: &str,
    requested_at: &SourceEventAt,
) {
    record_digest_timestamping_audit(
        audit_recorder,
        request_id,
        period,
        AuditResult::Failure,
        DigestTimestampingMetadata::new(period, requested_at.clone())
            .with_digest_hash(digest_hash_hex)
            .with_error_code(error_code),
    )
    .await;
}

async fn record_digest_timestamping_audit(
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    request_id: &RequestId,
    period: &MonthlyDigestPeriod,
    result: AuditResult,
    builder: DigestTimestampingMetadata,
) {
    let audit_event_id = match AuditEventId::generate() {
        Ok(id) => id,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to generate audit event id for digest_timestamping audit"
            );
            return;
        }
    };

    let metadata = match builder.build() {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to build audit metadata for digest_timestamping audit"
            );
            return;
        }
    };

    let event = match AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::DigestTimestamping,
        target_secret_id: None,
        result,
        key_version: None,
        metadata_json: metadata,
    }) {
        Ok(e) => e,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to build audit event for digest_timestamping audit"
            );
            return;
        }
    };

    match audit_recorder.record(&event).await {
        Ok(outcome) => {
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                result = result.as_str(),
                audit_record_outcome = ?outcome,
                "digest timestamping audit recorded"
            );
        }
        Err(record_error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                error = %record_error,
                "digest timestamping audit primary and fallback recording failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_as_error_code_backend_failed_returns_dynamic_code() {
        let error = RequestTimestampingError::BackendFailed {
            code: "boom".to_owned(),
        };
        assert_eq!(error.as_error_code(), "boom");
    }

    #[test]
    fn error_as_error_code_ledger_append_failed_returns_static_code() {
        let error = RequestTimestampingError::LedgerAppendFailed {
            code: "digest_timestamped_append_failed",
        };
        assert_eq!(error.as_error_code(), "digest_timestamped_append_failed");
    }

    #[test]
    fn error_display_includes_backend_failed_code() {
        let error = RequestTimestampingError::BackendFailed {
            code: "network".to_owned(),
        };
        assert_eq!(format!("{error}"), "timestamping backend failed: network");
    }

    #[test]
    fn error_display_includes_ledger_append_failed_code() {
        let error = RequestTimestampingError::LedgerAppendFailed {
            code: "digest_timestamped_append_failed",
        };
        assert_eq!(
            format!("{error}"),
            "timestamping ledger append failed: digest_timestamped_append_failed"
        );
    }

    #[test]
    fn backend_error_code_maps_backend_failed_to_default() {
        let error = TimestampingServiceError::BackendFailed {
            code: "network".to_owned(),
        };
        assert_eq!(
            backend_error_code(&error),
            "digest_timestamping_backend_failed"
        );
    }

    #[test]
    fn backend_error_code_passes_through_digest_timestamping_prefix() {
        let error = TimestampingServiceError::BackendFailed {
            code: "digest_timestamping_rate_limited".to_owned(),
        };
        assert_eq!(
            backend_error_code(&error),
            "digest_timestamping_rate_limited"
        );
    }

    #[test]
    fn backend_error_code_maps_invalid_response() {
        let error = TimestampingServiceError::InvalidResponse {
            reason: "empty token",
        };
        assert_eq!(
            backend_error_code(&error),
            "digest_timestamping_invalid_response"
        );
    }
}

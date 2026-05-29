//! 月次 digest 外部アーカイブ export use case。
//!
//! SBC 内で完結する処理:
//! 1. `ArchiveExportPackage::from_digest` — 型安全パッケージ構築
//! 2. `ArchiveObjectKey::for_monthly_digest` — 決定的キー生成
//! 3. `backend.put_object` — 外部アーカイブへ PUT
//! 4. 失敗: `archive_export` 失敗監査を記録し `Err(BackendFailed)` を返す
//! 5. 成功: `archive_exported` ledger entry を追記
//!    - ledger 追記失敗: ログのみ、成功監査を記録、`Err(LedgerAppendFailed)` を返す
//!    - ledger 追記成功: 成功監査を記録、`Ok(key)` を返す
//!
//! 信頼境界ノート: `ArchiveExportPackage` は `SignedMonthlyDigest` からのみ構築可能。
//! 平文・Master Key・Data Key・JWT が型レベルでアーカイブバックエンドに渡せない。

use std::sync::Arc;

use crate::archive::backend::{ArchiveBackend, ArchiveBackendError, ArchiveObjectKey};
use crate::archive::export::ArchiveExportPackage;
use crate::audit::{
    ArchiveExportMetadata, AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditRecorder,
    AuditResult, RequestId,
};
use crate::incident::{IncidentRecorder, NotificationSink, archive_incident_input};
use crate::ledger::{
    LedgerEntryId, LedgerEntryType, LedgerPayload, LedgerResult, MonthlyDigestPeriod,
    SignedMonthlyDigest,
};
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts, LedgerAppender};
use crate::server::supabase::SupabaseAuditAppender;
use crate::types::SourceEventAt;

/// 外部アーカイブ export 失敗の原因分類。
///
/// `LedgerAppendFailed` は archive 保存後の付随的失敗であり、
/// archive 保全自体が成功していることに注意。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportDigestToArchiveError {
    /// archive PUT が失敗した（主要エラー。archive 未保存）。
    BackendFailed { code: String },
    /// archive は保存済みだが ledger への追記が失敗した（付随的失敗）。
    LedgerAppendFailed { code: &'static str },
}

impl ExportDigestToArchiveError {
    pub fn as_error_code(&self) -> &str {
        match self {
            Self::BackendFailed { code } => code.as_str(),
            Self::LedgerAppendFailed { code } => code,
        }
    }
}

impl std::fmt::Display for ExportDigestToArchiveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendFailed { code } => write!(formatter, "archive backend failed: {code}"),
            Self::LedgerAppendFailed { code } => {
                write!(formatter, "archive ledger append failed: {code}")
            }
        }
    }
}

impl std::error::Error for ExportDigestToArchiveError {}

/// 月次 digest を外部アーカイブへ export する。
///
/// 成功時は `archive_exported` ledger entry と `archive_export` 成功監査を記録する。
/// 失敗時は `archive_export` 失敗監査のみを記録し、他の操作には伝播しない。
pub async fn export_digest_to_archive<B: ArchiveBackend>(
    backend: &B,
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    ledger_appender: &Arc<LedgerAppender>,
    digest: &SignedMonthlyDigest,
    request_id: RequestId,
    exported_at: SourceEventAt,
) -> Result<ArchiveObjectKey, ExportDigestToArchiveError> {
    let period = &digest.period;

    // ── 1–2. パッケージとキーを構築 ──
    let package = ArchiveExportPackage::from_digest(digest).map_err(|error| {
        ExportDigestToArchiveError::BackendFailed {
            code: error.to_string(),
        }
    })?;
    let key = ArchiveObjectKey::for_monthly_digest(period).map_err(|error| {
        ExportDigestToArchiveError::BackendFailed {
            code: error.to_string(),
        }
    })?;
    let digest_hash_hex = digest.digest_hash.to_hex();

    // ── 3. PUT ──
    if let Err(error) = backend.put_object(&key, &package).await {
        let error_code = backend_error_code(&error);
        tracing::error!(
            request_id = %request_id.as_canonical_string(),
            period = period.as_str(),
            error = %error,
            error_code = %error_code,
            "archive export PUT failed"
        );
        record_archive_export_failure_audit(
            audit_recorder,
            &request_id,
            period,
            &error_code,
            &exported_at,
        )
        .await;
        return Err(ExportDigestToArchiveError::BackendFailed { code: error_code });
    }

    // ── 3.5. verify_object で外部アーカイブ不一致を検知する ──
    match backend.verify_object(&key, &package).await {
        Ok(crate::archive::ArchiveVerifyOutcome::Valid) => {}
        Ok(crate::archive::ArchiveVerifyOutcome::NotFound) => {
            let error_code = "archive_export_not_found".to_owned();
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                archive_key = key.as_str(),
                error_code = %error_code,
                "archive export verification did not find the stored object"
            );
            record_archive_export_failure_audit(
                audit_recorder,
                &request_id,
                period,
                &error_code,
                &exported_at,
            )
            .await;
            return Err(ExportDigestToArchiveError::BackendFailed { code: error_code });
        }
        Ok(crate::archive::ArchiveVerifyOutcome::ContentMismatch) => {
            let error_code = "archive_export_content_mismatch".to_owned();
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                archive_key = key.as_str(),
                error_code = %error_code,
                "archive export verification detected content mismatch without auto-repair"
            );
            record_archive_export_failure_audit(
                audit_recorder,
                &request_id,
                period,
                &error_code,
                &exported_at,
            )
            .await;
            return Err(ExportDigestToArchiveError::BackendFailed { code: error_code });
        }
        Err(error) => {
            let error_code = backend_error_code(&error);
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                archive_key = key.as_str(),
                error = %error,
                error_code = %error_code,
                "archive export verification failed"
            );
            record_archive_export_failure_audit(
                audit_recorder,
                &request_id,
                period,
                &error_code,
                &exported_at,
            )
            .await;
            return Err(ExportDigestToArchiveError::BackendFailed { code: error_code });
        }
    }

    // ── 4. ledger entry を追記 ──
    let ledger_result = append_archive_exported_ledger_entry(
        ledger_appender,
        digest,
        &key,
        &request_id,
        &exported_at,
    )
    .await;

    // ── 5. 成功監査を記録（ledger 追記結果に関わらず） ──
    record_archive_export_success_audit(
        audit_recorder,
        &request_id,
        period,
        &key,
        &digest_hash_hex,
        &exported_at,
    )
    .await;

    match ledger_result {
        Ok(()) => {
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                archive_key = key.as_str(),
                digest_hash = %digest_hash_hex,
                "archive export succeeded"
            );
            Ok(key)
        }
        Err(code) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                archive_key = key.as_str(),
                error_code = code,
                "archive export ledger append failed (archive was saved)"
            );
            Err(ExportDigestToArchiveError::LedgerAppendFailed { code })
        }
    }
}

pub async fn export_digest_to_archive_with_incident<B, S>(
    backend: &B,
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    ledger_appender: &Arc<LedgerAppender>,
    incident_recorder: &IncidentRecorder<S>,
    digest: &SignedMonthlyDigest,
    request_id: RequestId,
    exported_at: SourceEventAt,
) -> Result<ArchiveObjectKey, ExportDigestToArchiveError>
where
    B: ArchiveBackend,
    S: NotificationSink,
{
    let result = export_digest_to_archive(
        backend,
        audit_recorder,
        ledger_appender,
        digest,
        request_id,
        exported_at,
    )
    .await;

    if let Err(error) = &result {
        let error_code = error.as_error_code();
        if let Some(input) =
            archive_incident_input("archive_export_verify", error_code, &digest.period)
            && let Err(record_error) = incident_recorder.record(input).await
        {
            tracing::error!(
                period = digest.period.as_str(),
                error_code,
                error = %record_error,
                "archive incident recording failed"
            );
        }
    }

    result
}

/// `ArchiveBackendError` を `audit_events.metadata_json.error_code` 用の
/// 文字列に変換する。
///
/// `BackendFailed { code }` の `code` が `archive_export_*` プレフィクスで
/// 始まる場合は backend 固有の細粒度コードとして透過する（S3 backend が
/// 返す `archive_export_unauthenticated` / `archive_export_overwrite_rejected`
/// 等を audit にそのまま記録するため）。それ以外は固定文字列に丸める。
fn backend_error_code(error: &ArchiveBackendError) -> String {
    match error {
        ArchiveBackendError::InvalidKey { .. } => "archive_export_invalid_key".to_owned(),
        ArchiveBackendError::SerializationFailed(_) => {
            "archive_export_serialization_failed".to_owned()
        }
        ArchiveBackendError::BackendFailed { code } => {
            if code.starts_with("archive_export_") {
                code.clone()
            } else {
                "archive_export_backend_failed".to_owned()
            }
        }
        ArchiveBackendError::IoError(_) => "archive_export_io_error".to_owned(),
    }
}

async fn append_archive_exported_ledger_entry(
    ledger_appender: &LedgerAppender,
    digest: &SignedMonthlyDigest,
    key: &ArchiveObjectKey,
    request_id: &RequestId,
    exported_at: &SourceEventAt,
) -> Result<(), &'static str> {
    let entry_type = LedgerEntryType::ArchiveExported;
    let payload = LedgerPayload::new(
        entry_type,
        serde_json::json!({
            "archive_key": key.as_str(),
            "digest_hash": digest.digest_hash.to_hex(),
            "target_year_month": digest.period.as_str(),
        }),
    )
    .map_err(|error| {
        tracing::error!(
            request_id = %request_id.as_canonical_string(),
            error = %error,
            "archive export ledger payload build failed"
        );
        "archive_exported_payload_build_failed"
    })?;

    let ledger_entry_id =
        LedgerEntryId::generate().map_err(|_| "archive_exported_id_generate_failed")?;

    let draft = LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id,
        entry_type,
        source_event_at: exported_at.clone(),
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
            "archive export ledger draft build failed"
        );
        "archive_exported_draft_build_failed"
    })?;

    ledger_appender
        .append(&draft)
        .await
        .map_err(|error| {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error_code = error.as_error_code(),
                "archive export ledger append failed"
            );
            "archive_exported_append_failed"
        })
        .map(|_| ())
}

async fn record_archive_export_success_audit(
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    request_id: &RequestId,
    period: &MonthlyDigestPeriod,
    key: &ArchiveObjectKey,
    digest_hash_hex: &str,
    exported_at: &SourceEventAt,
) {
    record_archive_export_audit(
        audit_recorder,
        request_id,
        period,
        AuditResult::Success,
        ArchiveExportMetadata::new(period, exported_at.clone())
            .with_archive_key(key)
            .with_digest_hash(digest_hash_hex),
    )
    .await;
}

/// archive export 失敗を `audit_events` に同期記録するヘルパー（non-propagating）。
pub async fn record_archive_export_failure_audit(
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    request_id: &RequestId,
    period: &MonthlyDigestPeriod,
    error_code: &str,
    exported_at: &SourceEventAt,
) {
    record_archive_export_audit(
        audit_recorder,
        request_id,
        period,
        AuditResult::Failure,
        ArchiveExportMetadata::new(period, exported_at.clone()).with_error_code(error_code),
    )
    .await;
}

async fn record_archive_export_audit(
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    request_id: &RequestId,
    period: &MonthlyDigestPeriod,
    result: AuditResult,
    builder: ArchiveExportMetadata,
) {
    let audit_event_id = match AuditEventId::generate() {
        Ok(id) => id,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to generate audit event id for archive_export audit"
            );
            return;
        }
    };

    let metadata = match builder.build() {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to build audit metadata for archive_export audit"
            );
            return;
        }
    };

    let event = match AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::ArchiveExport,
        target_secret_id: None,
        result,
        key_version: None,
        metadata_json: metadata,
    }) {
        Ok(e) => e,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to build audit event for archive_export audit"
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
                "archive export audit recorded"
            );
        }
        Err(record_error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                error = %record_error,
                "archive export audit primary and fallback recording failed"
            );
        }
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/server/use_cases/export_digest_to_archive/tests.rs"]
mod tests;

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
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use serde_json::{Value, json};

    use crate::audit::LocalAuditFallbackStore;
    use crate::server::supabase::SupabaseClient;

    use super::*;
    use crate::archive::backend::{
        ArchiveBackend, ArchiveBackendError, ArchiveObjectKey, ArchiveVerifyOutcome,
    };
    use crate::archive::dummy::InMemoryArchiveBackend;
    use crate::archive::export::ArchiveExportPackage;
    use crate::ledger::{
        DigestHash, LEDGER_ED25519_SECRET_KEY_LENGTH, LedgerHash, LedgerSequenceNo,
        LedgerSignature, LedgerSignatureKeyVersion, LedgerSigningKey, MonthlyDigestPeriod,
        SignedMonthlyDigest, build_monthly_digest_canonical_form,
    };

    // ─────────────────────────────── Fixtures ───────────────────────────────

    fn test_signed_monthly_digest() -> SignedMonthlyDigest {
        let period = MonthlyDigestPeriod::parse("2026-05").expect("valid period");
        let start_hash = LedgerHash::from_bytes(&[0xaa; 32]).expect("valid hash");
        let end_hash = LedgerHash::from_bytes(&[0xbb; 32]).expect("valid hash");
        let generated_at = SourceEventAt::parse("2026-06-01T00:00:00Z").expect("valid timestamp");
        let key_version = LedgerSignatureKeyVersion::new(1).expect("valid key version");
        let start_seq = LedgerSequenceNo::new(1).expect("valid seq");
        let end_seq = LedgerSequenceNo::new(42).expect("valid seq");

        let canonical_bytes = build_monthly_digest_canonical_form(
            &period,
            start_seq,
            end_seq,
            start_hash,
            end_hash,
            42,
            &generated_at,
            key_version,
        )
        .expect("canonical form build must succeed");

        let digest_hash = DigestHash::from_canonical_bytes(&canonical_bytes);
        let sbc_signature = LedgerSignature::from_bytes(&[0u8; 64]).expect("valid sig");

        SignedMonthlyDigest {
            period,
            start_sequence_no: start_seq,
            end_sequence_no: end_seq,
            start_entry_hash: start_hash,
            end_entry_hash: end_hash,
            entry_count: 42,
            digest_generated_at: generated_at,
            signature_key_version: key_version,
            canonical_bytes,
            digest_hash,
            sbc_signature,
        }
    }

    fn test_request_id() -> RequestId {
        RequestId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("valid request id")
    }

    fn test_exported_at() -> SourceEventAt {
        SourceEventAt::parse("2026-06-02T00:00:00Z").expect("valid timestamp")
    }

    fn test_supabase_client(base_url: String) -> Arc<SupabaseClient> {
        Arc::new(SupabaseClient::new(
            reqwest::Client::new(),
            base_url,
            "service-role-secret",
            "publishable-key-secret",
        ))
    }

    fn test_audit_recorder(
        client: Arc<SupabaseClient>,
    ) -> Arc<AuditRecorder<SupabaseAuditAppender>> {
        let path = std::env::temp_dir().join("mipsorcu-archive-export-audit-fallback.jsonl");
        let archive_dir =
            std::env::temp_dir().join("mipsorcu-archive-export-audit-fallback-archive");
        let _ = std::fs::remove_file(&path);
        Arc::new(AuditRecorder::new(
            SupabaseAuditAppender::new(client),
            LocalAuditFallbackStore::with_rollover_config(path, archive_dir, 1024 * 1024),
        ))
    }

    fn test_ledger_appender(client: Arc<SupabaseClient>) -> Arc<LedgerAppender> {
        let signing_key = LedgerSigningKey::from_secret_key_bytes(
            LedgerSignatureKeyVersion::new(1).expect("valid key version"),
            &[9u8; LEDGER_ED25519_SECRET_KEY_LENGTH],
        )
        .expect("signing key build must succeed");
        Arc::new(LedgerAppender::new(client, signing_key))
    }

    // ────────────────────────────── Unit tests ──────────────────────────────

    #[test]
    fn error_as_error_code_backend_failed_returns_dynamic_code() {
        let error = ExportDigestToArchiveError::BackendFailed {
            code: "boom".to_owned(),
        };
        assert_eq!(error.as_error_code(), "boom");
    }

    #[test]
    fn error_as_error_code_ledger_append_failed_returns_static_code() {
        let error = ExportDigestToArchiveError::LedgerAppendFailed {
            code: "archive_exported_append_failed",
        };
        assert_eq!(error.as_error_code(), "archive_exported_append_failed");
    }

    #[test]
    fn error_display_includes_backend_failed_code() {
        let error = ExportDigestToArchiveError::BackendFailed {
            code: "io_error".to_owned(),
        };
        assert_eq!(format!("{error}"), "archive backend failed: io_error");
    }

    #[test]
    fn error_display_includes_ledger_append_failed_code() {
        let error = ExportDigestToArchiveError::LedgerAppendFailed {
            code: "archive_exported_append_failed",
        };
        assert_eq!(
            format!("{error}"),
            "archive ledger append failed: archive_exported_append_failed"
        );
    }

    #[test]
    fn backend_error_code_maps_invalid_key() {
        let error = ArchiveBackendError::InvalidKey {
            reason: "must not be empty",
        };
        assert_eq!(backend_error_code(&error), "archive_export_invalid_key");
    }

    #[test]
    fn backend_error_code_maps_serialization_failed() {
        let error = ArchiveBackendError::SerializationFailed("bad json".to_owned());
        assert_eq!(
            backend_error_code(&error),
            "archive_export_serialization_failed"
        );
    }

    #[test]
    fn backend_error_code_maps_backend_failed() {
        let error = ArchiveBackendError::BackendFailed {
            code: "network".to_owned(),
        };
        assert_eq!(backend_error_code(&error), "archive_export_backend_failed");
    }

    #[test]
    fn backend_error_code_passes_through_archive_export_prefix() {
        let error = ArchiveBackendError::BackendFailed {
            code: "archive_export_overwrite_rejected".to_owned(),
        };
        assert_eq!(
            backend_error_code(&error),
            "archive_export_overwrite_rejected"
        );
    }

    #[test]
    fn backend_error_code_passes_through_unauthenticated() {
        let error = ArchiveBackendError::BackendFailed {
            code: "archive_export_unauthenticated".to_owned(),
        };
        assert_eq!(backend_error_code(&error), "archive_export_unauthenticated");
    }

    #[test]
    fn backend_error_code_maps_io_error() {
        let error = ArchiveBackendError::IoError(std::io::Error::other("disk full"));
        assert_eq!(backend_error_code(&error), "archive_export_io_error");
    }

    // ─────────────────────── Integration test helpers ───────────────────────

    #[derive(Debug, Clone)]
    struct CapturedRequest {
        path: String,
        body: Value,
    }

    #[derive(Clone, Copy)]
    struct MockConfig {
        chain_head_status: u16,
        expected_requests: usize,
    }

    struct MockServer {
        url: String,
        receiver: mpsc::Receiver<CapturedRequest>,
        thread: JoinHandle<std::io::Result<()>>,
    }

    fn spawn_mock_supabase(config: MockConfig) -> std::io::Result<MockServer> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let (sender, receiver) = mpsc::channel();
        let thread = thread::spawn(move || -> std::io::Result<()> {
            for _ in 0..config.expected_requests {
                let (mut stream, _) = listener.accept()?;
                let request = read_http_request(&mut stream)?;

                let is_chain = request.path.starts_with("/rest/v1/ledger_chain_state");
                let is_append_ledger = request
                    .path
                    .ends_with("/rest/v1/rpc/rpc_append_ledger_entry");
                let response_body_for_append = if is_append_ledger {
                    Some(append_ledger_success_body(&request.body))
                } else {
                    None
                };

                sender.send(request).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "captured request receiver was dropped",
                    )
                })?;

                if is_chain {
                    if config.chain_head_status == 200 {
                        write_http_response(&mut stream, 200, "OK", &chain_head_body())?;
                    } else {
                        write_http_response(
                            &mut stream,
                            config.chain_head_status,
                            "Internal Server Error",
                            r#"{"error":"chain head fetch failed"}"#,
                        )?;
                    }
                } else if let Some(body) = response_body_for_append {
                    write_http_response(&mut stream, 200, "OK", &body)?;
                } else {
                    write_http_response(&mut stream, 200, "OK", r#"{"status":"ok"}"#)?;
                }
            }
            Ok(())
        });

        Ok(MockServer {
            url: format!("http://{addr}"),
            receiver,
            thread,
        })
    }

    fn read_http_request(stream: &mut TcpStream) -> std::io::Result<CapturedRequest> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];

        let header_end = loop {
            let bytes_read = stream.read(&mut chunk)?;
            if bytes_read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before headers were complete",
                ));
            }
            buffer.extend_from_slice(&chunk[..bytes_read]);
            if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break index;
            }
        };

        let headers = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
        let content_length = parse_content_length(&headers)?.unwrap_or(0);
        let body_start = header_end + 4;
        let body_end = body_start + content_length;

        while buffer.len() < body_end {
            let bytes_read = stream.read(&mut chunk)?;
            if bytes_read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before body was complete",
                ));
            }
            buffer.extend_from_slice(&chunk[..bytes_read]);
        }

        let path = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_owned();
        let body = if content_length == 0 {
            Value::Null
        } else {
            serde_json::from_slice(&buffer[body_start..body_end])
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?
        };

        Ok(CapturedRequest { path, body })
    }

    fn parse_content_length(headers: &str) -> std::io::Result<Option<usize>> {
        headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    Some(value.trim().parse::<usize>())
                } else {
                    None
                }
            })
            .transpose()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    }

    fn write_http_response(
        stream: &mut TcpStream,
        status: u16,
        reason: &str,
        body: &str,
    ) -> std::io::Result<()> {
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes())
    }

    fn chain_head_body() -> String {
        json!([{
            "last_sequence_no": 0,
            "last_entry_hash": "\\x0000000000000000000000000000000000000000000000000000000000000000",
        }])
        .to_string()
    }

    fn append_ledger_success_body(request_body: &Value) -> String {
        json!([{
            "ledger_entry_id": request_body["p_ledger_entry_id"].clone(),
            "sequence_no": request_body["p_sequence_no"].clone(),
            "entry_hash": request_body["p_entry_hash"].clone(),
            "chain_last_sequence_no": request_body["p_sequence_no"].clone(),
            "chain_last_entry_hash": request_body["p_entry_hash"].clone(),
            "replayed": false,
        }])
        .to_string()
    }

    fn drain_requests(server: MockServer) -> std::io::Result<Vec<CapturedRequest>> {
        let mut requests = Vec::new();
        while let Ok(request) = server.receiver.recv_timeout(Duration::from_secs(2)) {
            requests.push(request);
        }
        let join_result = server
            .thread
            .join()
            .map_err(|_| std::io::Error::other("mock supabase server thread panicked"))?;
        join_result?;
        Ok(requests)
    }

    // ────────────────────── Test-only backend: failing put ───────────────────

    struct FailingPutBackend;

    impl ArchiveBackend for FailingPutBackend {
        async fn put_object(
            &self,
            _key: &ArchiveObjectKey,
            _package: &ArchiveExportPackage,
        ) -> Result<(), ArchiveBackendError> {
            Err(ArchiveBackendError::BackendFailed {
                code: "simulated_put_failure".to_owned(),
            })
        }

        async fn verify_object(
            &self,
            _key: &ArchiveObjectKey,
            _package: &ArchiveExportPackage,
        ) -> Result<ArchiveVerifyOutcome, ArchiveBackendError> {
            Ok(ArchiveVerifyOutcome::NotFound)
        }

        async fn list_objects(&self) -> Result<Vec<ArchiveObjectKey>, ArchiveBackendError> {
            Ok(Vec::new())
        }
    }

    struct MismatchAfterPutBackend;

    impl ArchiveBackend for MismatchAfterPutBackend {
        async fn put_object(
            &self,
            _key: &ArchiveObjectKey,
            _package: &ArchiveExportPackage,
        ) -> Result<(), ArchiveBackendError> {
            Ok(())
        }

        async fn verify_object(
            &self,
            _key: &ArchiveObjectKey,
            _package: &ArchiveExportPackage,
        ) -> Result<ArchiveVerifyOutcome, ArchiveBackendError> {
            Ok(ArchiveVerifyOutcome::ContentMismatch)
        }

        async fn list_objects(&self) -> Result<Vec<ArchiveObjectKey>, ArchiveBackendError> {
            Ok(Vec::new())
        }
    }

    // ───────────────────────── Integration tests ─────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn happy_path_records_ledger_and_success_audit() -> Result<(), Box<dyn std::error::Error>>
    {
        let server = spawn_mock_supabase(MockConfig {
            chain_head_status: 200,
            expected_requests: 3,
        })?;
        let supabase_client = test_supabase_client(server.url.clone());
        let audit_recorder = test_audit_recorder(supabase_client.clone());
        let ledger_appender = test_ledger_appender(supabase_client.clone());
        let backend = InMemoryArchiveBackend::new();
        let digest = test_signed_monthly_digest();

        let result = export_digest_to_archive(
            &backend,
            &audit_recorder,
            &ledger_appender,
            &digest,
            test_request_id(),
            test_exported_at(),
        )
        .await;

        let key = result.expect("happy path must succeed");
        assert_eq!(key.as_str(), "digests/2026-05/digest.json");
        assert_eq!(backend.len(), 1);

        let requests = drain_requests(server)?;
        let paths: Vec<&str> = requests.iter().map(|r| r.path.as_str()).collect();
        assert!(
            paths
                .iter()
                .any(|p| p.starts_with("/rest/v1/ledger_chain_state")),
            "expected ledger_chain_state request, got {paths:?}",
        );
        assert!(
            paths
                .iter()
                .any(|p| p.ends_with("/rest/v1/rpc/rpc_append_ledger_entry")),
            "expected rpc_append_ledger_entry request, got {paths:?}",
        );
        let audit_request = requests
            .iter()
            .find(|r| r.path.ends_with("/rest/v1/rpc/rpc_append_audit_event"))
            .expect("expected rpc_append_audit_event request");
        assert_eq!(audit_request.body["p_action"], "archive_export");
        assert_eq!(audit_request.body["p_result"], "success");
        assert_eq!(
            audit_request.body["p_metadata_json"]["target_year_month"],
            "2026-05"
        );
        assert_eq!(
            audit_request.body["p_metadata_json"]["archive_key"],
            "digests/2026-05/digest.json"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn backend_put_failure_records_failure_audit_and_skips_ledger()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = spawn_mock_supabase(MockConfig {
            chain_head_status: 200,
            expected_requests: 1,
        })?;
        let supabase_client = test_supabase_client(server.url.clone());
        let audit_recorder = test_audit_recorder(supabase_client.clone());
        let ledger_appender = test_ledger_appender(supabase_client.clone());
        let digest = test_signed_monthly_digest();

        let result = export_digest_to_archive(
            &FailingPutBackend,
            &audit_recorder,
            &ledger_appender,
            &digest,
            test_request_id(),
            test_exported_at(),
        )
        .await;

        match result {
            Err(ExportDigestToArchiveError::BackendFailed { code }) => {
                assert_eq!(code, "archive_export_backend_failed");
            }
            other => panic!("expected BackendFailed, got {other:?}"),
        }

        let requests = drain_requests(server)?;
        assert_eq!(requests.len(), 1, "only the failure audit RPC must be sent");
        let audit_request = &requests[0];
        assert!(
            audit_request
                .path
                .ends_with("/rest/v1/rpc/rpc_append_audit_event"),
            "unexpected path: {}",
            audit_request.path,
        );
        assert_eq!(audit_request.body["p_action"], "archive_export");
        assert_eq!(audit_request.body["p_result"], "failure");
        assert_eq!(
            audit_request.body["p_metadata_json"]["error_code"],
            "archive_export_backend_failed"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn archive_mismatch_records_failure_audit_and_does_not_auto_repair()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = spawn_mock_supabase(MockConfig {
            chain_head_status: 200,
            expected_requests: 1,
        })?;
        let supabase_client = test_supabase_client(server.url.clone());
        let audit_recorder = test_audit_recorder(supabase_client.clone());
        let ledger_appender = test_ledger_appender(supabase_client.clone());
        let digest = test_signed_monthly_digest();

        let result = export_digest_to_archive(
            &MismatchAfterPutBackend,
            &audit_recorder,
            &ledger_appender,
            &digest,
            test_request_id(),
            test_exported_at(),
        )
        .await;

        match result {
            Err(ExportDigestToArchiveError::BackendFailed { code }) => {
                assert_eq!(code, "archive_export_content_mismatch");
            }
            other => panic!("expected ContentMismatch BackendFailed, got {other:?}"),
        }

        let requests = drain_requests(server)?;
        assert_eq!(
            requests.len(),
            1,
            "archive mismatch must only record failure audit and must not append repair ledger entries"
        );
        let audit_request = &requests[0];
        assert_eq!(audit_request.body["p_action"], "archive_export");
        assert_eq!(audit_request.body["p_result"], "failure");
        assert_eq!(
            audit_request.body["p_metadata_json"]["error_code"],
            "archive_export_content_mismatch"
        );
        assert!(
            !requests.iter().any(|request| request
                .path
                .ends_with("/rest/v1/rpc/rpc_append_ledger_entry")),
            "mismatch detection must not auto-repair by writing ledger entries"
        );
        Ok(())
    }
}

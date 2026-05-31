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
use crate::archive::opaque::ArchiveOpaqueObject;
use crate::ledger::{
    DigestHash, LEDGER_ED25519_SECRET_KEY_LENGTH, LedgerHash, LedgerSequenceNo, LedgerSignature,
    LedgerSignatureKeyVersion, LedgerSigningKey, MonthlyDigestPeriod, SignedMonthlyDigest,
    build_monthly_digest_canonical_form,
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

fn test_audit_recorder(client: Arc<SupabaseClient>) -> Arc<AuditRecorder<SupabaseAuditAppender>> {
    let path = std::env::temp_dir().join("mipsorcu-archive-export-audit-fallback.jsonl");
    let archive_dir = std::env::temp_dir().join("mipsorcu-archive-export-audit-fallback-archive");
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

    async fn put_opaque_object(
        &self,
        _key: &ArchiveObjectKey,
        _object: &ArchiveOpaqueObject,
    ) -> Result<(), ArchiveBackendError> {
        Ok(())
    }

    async fn get_opaque_object(
        &self,
        _key: &ArchiveObjectKey,
    ) -> Result<Option<Vec<u8>>, ArchiveBackendError> {
        Ok(None)
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

    async fn put_opaque_object(
        &self,
        _key: &ArchiveObjectKey,
        _object: &ArchiveOpaqueObject,
    ) -> Result<(), ArchiveBackendError> {
        Ok(())
    }

    async fn get_opaque_object(
        &self,
        _key: &ArchiveObjectKey,
    ) -> Result<Option<Vec<u8>>, ArchiveBackendError> {
        Ok(None)
    }
}

// ───────────────────────── Integration tests ─────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn happy_path_records_ledger_and_success_audit() -> Result<(), Box<dyn std::error::Error>> {
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

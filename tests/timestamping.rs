//! T10 外部 timestamping 統合の統合テスト。
//!
//! - dummy backend での happy path（ledger 追記 + 成功監査）
//! - backend 失敗時の挙動（失敗監査のみ、ledger 追記なし）
//! - ledger 追記失敗時の挙動（token 取得済み、成功監査記録、LedgerAppendFailed エラー）
//! - 送信ペイロードの型レベル排除確認（trait 引数が `&DigestHash` のみ）

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{Value, json};

use mipsorcu::{
    AuditRecorder, DigestHash, FailingTimestampingService, InMemoryTimestampingService, LedgerHash,
    LedgerSequenceNo, LedgerSignature, LedgerSignatureKeyVersion, LocalAuditFallbackStore,
    MonthlyDigestPeriod, RequestId, RequestTimestampingError, SignedMonthlyDigest, SourceEventAt,
    TimestampingService, TimestampingServiceError, TimestampingToken, TimestampingTokenHash,
    build_monthly_digest_canonical_form, request_timestamping_for_digest,
};

// LedgerAppender / SupabaseClient はクレート内 (pub) なので直接アクセス可能。
use mipsorcu::server::ledger_appender::LedgerAppender;
use mipsorcu::server::supabase::{SupabaseAuditAppender, SupabaseClient};

const LEDGER_ED25519_SECRET_KEY_LENGTH: usize = 32;

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

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

fn test_requested_at() -> SourceEventAt {
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
    let path = std::env::temp_dir().join("mipsorcu-timestamping-audit-fallback.jsonl");
    let archive_dir = std::env::temp_dir().join("mipsorcu-timestamping-audit-fallback-archive");
    let _ = std::fs::remove_file(&path);
    Arc::new(AuditRecorder::new(
        SupabaseAuditAppender::new(client),
        LocalAuditFallbackStore::with_rollover_config(path, archive_dir, 1024 * 1024),
    ))
}

fn test_ledger_appender(client: Arc<SupabaseClient>) -> Arc<LedgerAppender> {
    use mipsorcu::LedgerSigningKey;
    let signing_key = LedgerSigningKey::from_secret_key_bytes(
        LedgerSignatureKeyVersion::new(1).expect("valid key version"),
        &[9u8; LEDGER_ED25519_SECRET_KEY_LENGTH],
    )
    .expect("signing key build must succeed");
    Arc::new(LedgerAppender::new(client, signing_key))
}

// ─────────────────────────────────────────────────────────────────────────────
// 単体: dummy backend 単独動作
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn dummy_backend_completes_request_independently() {
    let service = InMemoryTimestampingService::new();
    let digest = test_signed_monthly_digest();
    let token = service
        .request_timestamp(&digest.digest_hash)
        .await
        .expect("dummy backend must succeed");
    assert!(!token.is_empty());
    let hash = TimestampingTokenHash::from_token(&token);
    assert_eq!(hash.to_hex().len(), 64);
}

#[tokio::test]
async fn failing_backend_returns_backend_failed_error() {
    let service = FailingTimestampingService::new("simulated_failure");
    let digest = test_signed_monthly_digest();
    let error = service
        .request_timestamp(&digest.digest_hash)
        .await
        .expect_err("must fail");
    match error {
        TimestampingServiceError::BackendFailed { code } => {
            assert_eq!(code, "simulated_failure");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 型安全性: payload に digest hash 以外を含めることが構造的に不可能であることを示す。
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn payload_to_backend_contains_only_digest_hash_bytes() {
    // dummy backend が受け取った hash と、digest 自身の hash バイト列のみが
    // 渡されることを実証する。SignedMonthlyDigest の他フィールドや
    // LedgerEntry 全件は trait 引数型 `&DigestHash` の制約により渡せない。
    struct CapturingBackend {
        captured: std::sync::Mutex<Vec<[u8; 32]>>,
    }

    impl TimestampingService for CapturingBackend {
        async fn request_timestamp(
            &self,
            digest_hash: &DigestHash,
        ) -> Result<TimestampingToken, TimestampingServiceError> {
            self.captured.lock().unwrap().push(*digest_hash.as_bytes());
            TimestampingToken::new(vec![0xfa, 0xce, 0xfe, 0xed])
        }
    }

    let backend = CapturingBackend {
        captured: std::sync::Mutex::new(Vec::new()),
    };
    let digest = test_signed_monthly_digest();
    let token = backend
        .request_timestamp(&digest.digest_hash)
        .await
        .unwrap();
    assert_eq!(token.as_bytes(), &[0xfa, 0xce, 0xfe, 0xed]);

    let captured = backend.captured.lock().unwrap();
    assert_eq!(captured.len(), 1);
    // backend に渡されたバイトは digest_hash と完全一致（他フィールドは触れない）
    assert_eq!(&captured[0], digest.digest_hash.as_bytes());
}

// ─────────────────────────────────────────────────────────────────────────────
// 統合: use case を mock supabase でラップ
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CapturedRequest {
    path: String,
    body: Value,
}

#[derive(Clone, Copy)]
struct MockConfig {
    chain_head_status: u16,
    append_ledger_status: u16,
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
            } else if is_append_ledger {
                if config.append_ledger_status == 200 {
                    let body = response_body_for_append.unwrap_or_default();
                    write_http_response(&mut stream, 200, "OK", &body)?;
                } else {
                    write_http_response(
                        &mut stream,
                        config.append_ledger_status,
                        "Internal Server Error",
                        r#"{"error":"append failed"}"#,
                    )?;
                }
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

// ─────────────────────────────────────────────────────────────────────────────
// Happy path
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn happy_path_records_ledger_and_success_audit() -> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_mock_supabase(MockConfig {
        chain_head_status: 200,
        append_ledger_status: 200,
        expected_requests: 3, // chain_head + append_ledger + audit
    })?;
    let supabase_client = test_supabase_client(server.url.clone());
    let audit_recorder = test_audit_recorder(supabase_client.clone());
    let ledger_appender = test_ledger_appender(supabase_client.clone());
    let service = InMemoryTimestampingService::new();
    let digest = test_signed_monthly_digest();

    let result = request_timestamping_for_digest(
        &service,
        &audit_recorder,
        &ledger_appender,
        &digest,
        test_request_id(),
        test_requested_at(),
    )
    .await;

    let token = result.expect("happy path must succeed");
    assert!(!token.is_empty());
    assert_eq!(service.issued_count(), 1);

    let requests = drain_requests(server)?;
    let paths: Vec<&str> = requests.iter().map(|r| r.path.as_str()).collect();
    assert!(
        paths
            .iter()
            .any(|p| p.starts_with("/rest/v1/ledger_chain_state")),
        "expected ledger_chain_state request, got {paths:?}",
    );

    let append_ledger = requests
        .iter()
        .find(|r| r.path.ends_with("/rest/v1/rpc/rpc_append_ledger_entry"))
        .expect("expected rpc_append_ledger_entry request");
    assert_eq!(append_ledger.body["p_entry_type"], "digest_timestamped");
    let payload = &append_ledger.body["p_payload"];
    let token_hash_hex = TimestampingTokenHash::from_token(&token).to_hex();
    assert_eq!(payload["digest_hash"], digest.digest_hash.to_hex());
    assert_eq!(payload["target_year_month"], "2026-05");
    assert_eq!(payload["timestamp_token_hash"], token_hash_hex);

    let audit_request = requests
        .iter()
        .find(|r| r.path.ends_with("/rest/v1/rpc/rpc_append_audit_event"))
        .expect("expected rpc_append_audit_event request");
    assert_eq!(audit_request.body["p_action"], "digest_timestamping");
    assert_eq!(audit_request.body["p_result"], "success");
    assert_eq!(
        audit_request.body["p_metadata_json"]["target_year_month"],
        "2026-05"
    );
    assert_eq!(
        audit_request.body["p_metadata_json"]["timestamp_token_hash"],
        token_hash_hex
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Backend 失敗
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn backend_failure_records_failure_audit_and_skips_ledger()
-> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_mock_supabase(MockConfig {
        chain_head_status: 200,
        append_ledger_status: 200,
        expected_requests: 1, // failure audit のみ
    })?;
    let supabase_client = test_supabase_client(server.url.clone());
    let audit_recorder = test_audit_recorder(supabase_client.clone());
    let ledger_appender = test_ledger_appender(supabase_client.clone());
    let service = FailingTimestampingService::new("simulated_backend_failure");
    let digest = test_signed_monthly_digest();

    let result = request_timestamping_for_digest(
        &service,
        &audit_recorder,
        &ledger_appender,
        &digest,
        test_request_id(),
        test_requested_at(),
    )
    .await;

    match result {
        Err(RequestTimestampingError::BackendFailed { code }) => {
            assert_eq!(code, "digest_timestamping_backend_failed");
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
    assert_eq!(audit_request.body["p_action"], "digest_timestamping");
    assert_eq!(audit_request.body["p_result"], "failure");
    assert_eq!(
        audit_request.body["p_metadata_json"]["error_code"],
        "digest_timestamping_backend_failed"
    );
    // 失敗時 metadata に token hash は含まれない
    assert!(
        audit_request.body["p_metadata_json"]
            .get("timestamp_token_hash")
            .is_none()
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Ledger 追記失敗（token 取得後）
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ledger_append_failure_after_token_acquired_records_success_audit_and_returns_error()
-> Result<(), Box<dyn std::error::Error>> {
    // chain_head は成功するが、append_ledger_entry が 500 を返す。
    // expected_requests = chain_head + retries(2) + audit
    let server = spawn_mock_supabase(MockConfig {
        chain_head_status: 200,
        append_ledger_status: 500,
        expected_requests: 3,
    })?;
    let supabase_client = test_supabase_client(server.url.clone());
    let audit_recorder = test_audit_recorder(supabase_client.clone());
    let ledger_appender = test_ledger_appender(supabase_client.clone());
    let service = InMemoryTimestampingService::new();
    let digest = test_signed_monthly_digest();

    let result = request_timestamping_for_digest(
        &service,
        &audit_recorder,
        &ledger_appender,
        &digest,
        test_request_id(),
        test_requested_at(),
    )
    .await;

    match result {
        Err(RequestTimestampingError::LedgerAppendFailed { code }) => {
            assert_eq!(code, "digest_timestamped_append_failed");
        }
        other => panic!("expected LedgerAppendFailed, got {other:?}"),
    }

    // token は取得済み（dummy backend に記録されている）
    assert_eq!(service.issued_count(), 1);

    let requests = drain_requests(server)?;
    let audit_request = requests
        .iter()
        .find(|r| r.path.ends_with("/rest/v1/rpc/rpc_append_audit_event"))
        .expect("success audit must be recorded even when ledger append fails");
    assert_eq!(audit_request.body["p_action"], "digest_timestamping");
    assert_eq!(audit_request.body["p_result"], "success");
    Ok(())
}

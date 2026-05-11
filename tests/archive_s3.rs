//! `S3ImmutableArchiveBackend` の統合テスト。
//!
//! 局所 TCP リスナーで mock S3 を立てて、署名済み PUT / HEAD / GET の
//! ヘッダ・body・リトライ挙動を assert する。
//!
//! 検証対象:
//! - Object Lock ヘッダが付与される
//! - If-None-Match: * が付与される
//! - body が `ArchiveExportPackage::to_json_bytes()` と完全一致する
//! - body / ヘッダ / URL に秘密語が含まれない
//! - 503 リトライ後に成功する
//! - 412 PreconditionFailed が `archive_export_overwrite_rejected` に分類される
//! - 401/403 が `archive_export_unauthenticated` に分類される

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mipsorcu::{
    ArchiveBackend, ArchiveBackendError, ArchiveExportPackage, ArchiveObjectKey,
    ArchiveVerifyOutcome, DigestHash, LedgerHash, LedgerSequenceNo, LedgerSignature,
    LedgerSignatureKeyVersion, MonthlyDigestPeriod, S3ArchiveBackendConfig,
    S3ImmutableArchiveBackend, S3ObjectLockMode, SignedMonthlyDigest, SourceEventAt,
    build_monthly_digest_canonical_form,
};
use time::OffsetDateTime;

// Fixtures

fn make_test_digest() -> SignedMonthlyDigest {
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
    .expect("canonical form must build");

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

fn make_package() -> ArchiveExportPackage {
    ArchiveExportPackage::from_digest(&make_test_digest()).expect("package must build")
}

fn make_key() -> ArchiveObjectKey {
    ArchiveObjectKey::for_monthly_digest(&MonthlyDigestPeriod::parse("2026-05").unwrap())
        .expect("key must build")
}

fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_717_200_000).expect("valid timestamp")
}

fn make_config(endpoint_url: String) -> S3ArchiveBackendConfig {
    S3ArchiveBackendConfig::new(
        endpoint_url,
        "us-east-1".to_owned(),
        "mipsorcu-archive".to_owned(),
        "AKIAIOSFODNN7EXAMPLE".to_owned(),
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
        None,
        S3ObjectLockMode::Compliance,
        30,
    )
    .expect("config must build")
    .with_retry_base_millis(1)
    .with_max_retries(3)
}

fn make_backend(config: S3ArchiveBackendConfig) -> S3ImmutableArchiveBackend {
    S3ImmutableArchiveBackend::new_with_clock(config, reqwest::Client::new(), fixed_now)
}

// Mock S3 server

#[derive(Debug, Clone)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Clone, Copy)]
struct CannedResponse {
    status: u16,
    reason: &'static str,
}

const OK: CannedResponse = CannedResponse {
    status: 200,
    reason: "OK",
};
const SERVER_ERROR: CannedResponse = CannedResponse {
    status: 503,
    reason: "Service Unavailable",
};
const PRECONDITION_FAILED: CannedResponse = CannedResponse {
    status: 412,
    reason: "Precondition Failed",
};
const FORBIDDEN: CannedResponse = CannedResponse {
    status: 403,
    reason: "Forbidden",
};

struct MockServer {
    base_url: String,
    receiver: mpsc::Receiver<CapturedRequest>,
    thread: JoinHandle<std::io::Result<()>>,
}

fn spawn_mock_s3(responses: Vec<CannedResponse>) -> std::io::Result<MockServer> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let expected = responses.len();
    let thread = thread::spawn(move || -> std::io::Result<()> {
        let mut responses_iter = responses.into_iter();
        for _ in 0..expected {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let response = responses_iter
                .next()
                .expect("response count must match request count");
            sender.send(request).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request receiver was dropped",
                )
            })?;
            write_http_response(&mut stream, response.status, response.reason)?;
        }
        Ok(())
    });
    Ok(MockServer {
        base_url: format!("http://{addr}"),
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

    let header_text = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or("").to_owned();
    let path = request_parts.next().unwrap_or("").to_owned();

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: usize = 0;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_owned();
            let value = value.trim().to_owned();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }

    let body_start = header_end + 4;
    let body_end = body_start + content_length;
    while buffer.len() < body_end {
        let bytes_read = stream.read(&mut chunk)?;
        if bytes_read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);
    }
    let body = buffer[body_start..body_end.min(buffer.len())].to_vec();

    Ok(CapturedRequest {
        method,
        path,
        headers,
        body,
    })
}

fn write_http_response(stream: &mut TcpStream, status: u16, reason: &str) -> std::io::Result<()> {
    let response =
        format!("HTTP/1.1 {status} {reason}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
    stream.write_all(response.as_bytes())
}

fn drain_requests(server: MockServer) -> std::io::Result<Vec<CapturedRequest>> {
    let mut requests = Vec::new();
    while let Ok(request) = server.receiver.recv_timeout(Duration::from_secs(2)) {
        requests.push(request);
    }
    let join_result = server
        .thread
        .join()
        .map_err(|_| std::io::Error::other("mock S3 server thread panicked"))?;
    join_result?;
    Ok(requests)
}

/// 秘密語が登場してはならない検証。ログ・送信禁止項目に対応する
/// 文字列リスト。実コードの credentials / Master Key 由来の値が **どこにも**
/// 含まれていないことをペイロード・ヘッダ・URL 全体で確認する。
fn assert_no_secrets(buffer: &str) {
    const FORBIDDEN: &[&str] = &[
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "MIPSORCU_MASTER_KEY",
        "service_role",
        "service-role",
        "publishable",
        "BEGIN PRIVATE KEY",
        "ssh-rsa",
        "JWT",
    ];
    for word in FORBIDDEN {
        assert!(
            !buffer.contains(word),
            "forbidden token `{word}` found in:\n{buffer}",
        );
    }
}

// Tests

#[tokio::test(flavor = "multi_thread")]
async fn put_object_sends_signed_request_with_object_lock_headers()
-> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_mock_s3(vec![OK])?;
    let config = make_config(server.base_url.clone());
    let backend = make_backend(config);

    let key = make_key();
    let package = make_package();

    backend.put_object(&key, &package).await?;

    let requests = drain_requests(server)?;
    assert_eq!(requests.len(), 1);
    let request = &requests[0];

    assert_eq!(request.method, "PUT");
    assert_eq!(
        request.path,
        "/mipsorcu-archive/digests/2026-05/digest.json"
    );

    // 1. Authorization header is AWS sigv4
    let authorization = request
        .header("authorization")
        .expect("Authorization header must be present");
    assert!(
        authorization.starts_with("AWS4-HMAC-SHA256 "),
        "got: {authorization}"
    );
    assert!(
        authorization.contains("Credential=AKIAIOSFODNN7EXAMPLE/"),
        "got: {authorization}"
    );
    assert!(
        authorization.contains("/us-east-1/s3/aws4_request,"),
        "got: {authorization}"
    );

    // 2. Object Lock headers
    assert_eq!(request.header("x-amz-object-lock-mode"), Some("COMPLIANCE"));
    let retain_until = request
        .header("x-amz-object-lock-retain-until-date")
        .expect("retain-until-date must be present");
    assert!(retain_until.ends_with('Z'), "got: {retain_until}");

    // 3. If-None-Match for overwrite rejection
    assert_eq!(request.header("if-none-match"), Some("*"));

    // 4. content-type
    assert_eq!(request.header("content-type"), Some("application/json"));

    // 5. Body matches ArchiveExportPackage exactly
    let expected_body = package.to_json_bytes()?;
    assert_eq!(request.body, expected_body);

    // 6. x-amz-content-sha256 matches body hash
    let body_hex_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&request.body))
    };
    assert_eq!(
        request.header("x-amz-content-sha256"),
        Some(body_hex_hash.as_str())
    );

    // 7. No secret material anywhere in the wire payload
    let body_text = String::from_utf8_lossy(&request.body).into_owned();
    assert_no_secrets(&body_text);
    let header_text: String = request
        .headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\n"))
        .collect();
    assert_no_secrets(&header_text);
    assert_no_secrets(&request.path);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn put_object_retries_503_then_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_mock_s3(vec![SERVER_ERROR, SERVER_ERROR, OK])?;
    let config = make_config(server.base_url.clone());
    let backend = make_backend(config);

    backend.put_object(&make_key(), &make_package()).await?;

    let requests = drain_requests(server)?;
    assert_eq!(
        requests.len(),
        3,
        "must retry until success (initial + 2 retries)"
    );
    for request in &requests {
        assert_eq!(request.method, "PUT");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn put_object_rejects_412_immediately() -> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_mock_s3(vec![PRECONDITION_FAILED])?;
    let config = make_config(server.base_url.clone());
    let backend = make_backend(config);

    let result = backend.put_object(&make_key(), &make_package()).await;
    match result {
        Err(ArchiveBackendError::BackendFailed { code }) => {
            assert_eq!(code, "archive_export_overwrite_rejected");
        }
        other => panic!("expected BackendFailed, got {other:?}"),
    }

    let requests = drain_requests(server)?;
    assert_eq!(requests.len(), 1, "412 must not be retried");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn put_object_classifies_403_as_unauthenticated() -> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_mock_s3(vec![FORBIDDEN])?;
    let config = make_config(server.base_url.clone());
    let backend = make_backend(config);

    let result = backend.put_object(&make_key(), &make_package()).await;
    match result {
        Err(ArchiveBackendError::BackendFailed { code }) => {
            assert_eq!(code, "archive_export_unauthenticated");
        }
        other => panic!("expected BackendFailed, got {other:?}"),
    }

    let requests = drain_requests(server)?;
    assert_eq!(requests.len(), 1, "403 must not be retried");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn put_object_gives_up_after_max_retries() -> Result<(), Box<dyn std::error::Error>> {
    // max_retries == 3 → initial + 3 retries = 4 attempts
    let server = spawn_mock_s3(vec![SERVER_ERROR, SERVER_ERROR, SERVER_ERROR, SERVER_ERROR])?;
    let config = make_config(server.base_url.clone());
    let backend = make_backend(config);

    let result = backend.put_object(&make_key(), &make_package()).await;
    match result {
        Err(ArchiveBackendError::BackendFailed { code }) => {
            assert_eq!(code, "archive_export_server_error");
        }
        other => panic!("expected BackendFailed, got {other:?}"),
    }

    let requests = drain_requests(server)?;
    assert_eq!(requests.len(), 4);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn put_object_omits_if_none_match_when_overwrite_allowed()
-> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_mock_s3(vec![OK])?;
    let config = make_config(server.base_url.clone()).with_forbid_overwrite(false);
    let backend = make_backend(config);

    backend.put_object(&make_key(), &make_package()).await?;

    let requests = drain_requests(server)?;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].header("if-none-match"),
        None,
        "If-None-Match must be omitted when forbid_overwrite=false"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_object_returns_valid_when_payload_matches() -> Result<(), Box<dyn std::error::Error>>
{
    // We need GET to return the exact body bytes the backend wrote.
    // Build a small server that returns the package body on GET.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let package = make_package();
    let body = package.to_json_bytes()?;
    let thread = thread::spawn(move || -> std::io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        let _ = read_http_request(&mut stream)?;
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes())?;
        stream.write_all(&body)
    });

    let config = make_config(format!("http://{addr}"));
    let backend = make_backend(config);
    let outcome = backend.verify_object(&make_key(), &make_package()).await?;
    assert_eq!(outcome, ArchiveVerifyOutcome::Valid);
    thread
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_object_returns_not_found_on_404() -> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_mock_s3(vec![CannedResponse {
        status: 404,
        reason: "Not Found",
    }])?;
    let config = make_config(server.base_url.clone());
    let backend = make_backend(config);
    let outcome = backend.verify_object(&make_key(), &make_package()).await?;
    assert_eq!(outcome, ArchiveVerifyOutcome::NotFound);

    let _ = drain_requests(server)?;
    Ok(())
}

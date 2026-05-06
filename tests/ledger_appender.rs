use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use mipsorcu::server::ledger_appender::{
    LedgerAppendDraft, LedgerAppendDraftParts, LedgerAppendError, LedgerAppender,
    LedgerAppenderConfig,
};
use mipsorcu::server::supabase::SupabaseClient;
use mipsorcu::{
    DeviceId, LedgerEntryId, LedgerEntryType, LedgerHash, LedgerPayload, LedgerResult,
    LedgerSignatureKeyVersion, LedgerSigningKey, LedgerTargetSecretVersionId, OwnerUserId,
    RequestId, SecretId, SourceEventAt,
};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type TestServer = (
    String,
    mpsc::Receiver<CapturedRequest>,
    thread::JoinHandle<std::io::Result<()>>,
);

const REQUEST_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const TARGET_SECRET_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const TARGET_SECRET_VERSION_ID: &str = "11111111-2222-4333-8444-555555555555";
const DEVICE_ID: &str = "sbc-device-1";
const SOURCE_EVENT_AT: &str = "2026-04-08T12:00:00Z";

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

enum ResponseSpec {
    Static { status: u16, body: String },
    AppendSuccessFromRequest,
}

#[tokio::test(flavor = "current_thread")]
async fn ledger_appender_fetches_chain_head_then_appends_signed_entry() -> TestResult {
    let head_hash =
        LedgerHash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")?;
    let (base_url, receiver, server_thread) = spawn_scripted_server(vec![
        ResponseSpec::Static {
            status: 200,
            body: chain_head_body(4, head_hash),
        },
        ResponseSpec::AppendSuccessFromRequest,
    ])?;
    let appender = sample_appender(base_url, LedgerAppenderConfig::default())?;
    let draft = sample_draft("confidential")?;

    let outcome = appender.append(&draft).await?;
    let chain_head_request = recv_request(&receiver)?;
    let append_request = recv_request(&receiver)?;
    join_server(server_thread)?;
    let append_body: Value = serde_json::from_str(&append_request.body)?;

    assert_eq!(chain_head_request.method, "GET");
    assert_eq!(
        chain_head_request.path,
        "/rest/v1/ledger_chain_state?select=last_sequence_no,last_entry_hash&chain_id=eq.global&limit=1"
    );
    assert_eq!(
        chain_head_request.headers.get("authorization"),
        Some(&"Bearer service-role-secret".to_owned())
    );
    assert_eq!(
        chain_head_request.headers.get("apikey"),
        Some(&"service-role-secret".to_owned())
    );

    assert_eq!(append_request.method, "POST");
    assert_eq!(append_request.path, "/rest/v1/rpc/rpc_append_ledger_entry");
    assert_eq!(append_body["p_sequence_no"], 5);
    assert_eq!(
        append_body["p_previous_entry_hash"],
        head_hash.to_bytea_hex()
    );
    assert_eq!(
        append_body["p_ledger_entry_id"],
        draft.ledger_entry_id().as_canonical_string()
    );
    assert_eq!(append_body["p_signature_key_version"], 1);
    assert_eq!(outcome.sequence_no().get(), 5);
    assert_eq!(outcome.chain_head().last_sequence_no(), 5);

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ledger_appender_classifies_previous_hash_mismatch_as_conflict() -> TestResult {
    let error =
        append_with_single_failure(r#"{"message":"ledger_previous_hash_mismatch"}"#).await?;

    assert!(matches!(
        error,
        LedgerAppendError::Conflict {
            failure: mipsorcu::server::supabase::LedgerAppendRpcFailure::PreviousHashMismatch,
            attempts: 1
        }
    ));

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ledger_appender_classifies_sequence_mismatch_as_conflict() -> TestResult {
    let error = append_with_single_failure(r#"{"message":"ledger_sequence_mismatch"}"#).await?;

    assert!(matches!(
        error,
        LedgerAppendError::Conflict {
            failure: mipsorcu::server::supabase::LedgerAppendRpcFailure::SequenceMismatch,
            attempts: 1
        }
    ));

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ledger_appender_treats_markerless_non_2xx_as_external_dependency_failure() -> TestResult {
    let (base_url, receiver, server_thread) = spawn_scripted_server(vec![
        ResponseSpec::Static {
            status: 200,
            body: chain_head_body(0, LedgerHash::genesis()),
        },
        ResponseSpec::Static {
            status: 503,
            body: r#"{"message":"plaintext jwt service-role-secret should not leak"}"#.to_owned(),
        },
    ])?;
    let appender = sample_appender(base_url, LedgerAppenderConfig::new(0))?;
    let draft = sample_draft("confidential")?;

    let error = appender
        .append(&draft)
        .await
        .expect_err("append failure must not be reported as success");
    recv_request(&receiver)?;
    recv_request(&receiver)?;
    join_server(server_thread)?;

    assert!(matches!(
        error,
        LedgerAppendError::ExternalDependencyFailed {
            code: "ledger_append_failed",
            upstream_status: Some(503),
            attempts: 1
        }
    ));
    assert_eq!(error.as_error_code(), "ledger_append_failed");
    assert_eq!(error.upstream_status(), Some(503));
    assert_error_output_is_redacted(error);

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ledger_appender_retries_conflict_once_and_resigns_new_payload() -> TestResult {
    let retry_head_hash =
        LedgerHash::from_hex("2222222222222222222222222222222222222222222222222222222222222222")?;
    let (base_url, receiver, server_thread) = spawn_scripted_server(vec![
        ResponseSpec::Static {
            status: 200,
            body: chain_head_body(0, LedgerHash::genesis()),
        },
        ResponseSpec::Static {
            status: 409,
            body: r#"{"message":"ledger_previous_hash_mismatch"}"#.to_owned(),
        },
        ResponseSpec::Static {
            status: 200,
            body: chain_head_body(1, retry_head_hash),
        },
        ResponseSpec::AppendSuccessFromRequest,
    ])?;
    let appender = sample_appender(base_url, LedgerAppenderConfig::default())?;
    let draft = sample_draft("confidential")?;

    let outcome = appender.append(&draft).await?;
    let first_head_request = recv_request(&receiver)?;
    let first_append_request = recv_request(&receiver)?;
    let second_head_request = recv_request(&receiver)?;
    let second_append_request = recv_request(&receiver)?;
    join_server(server_thread)?;
    let first_body: Value = serde_json::from_str(&first_append_request.body)?;
    let second_body: Value = serde_json::from_str(&second_append_request.body)?;

    assert_eq!(first_head_request.method, "GET");
    assert_eq!(second_head_request.method, "GET");
    assert_eq!(first_body["p_sequence_no"], 1);
    assert_eq!(
        first_body["p_previous_entry_hash"],
        LedgerHash::genesis().to_bytea_hex()
    );
    assert_eq!(second_body["p_sequence_no"], 2);
    assert_eq!(
        second_body["p_previous_entry_hash"],
        retry_head_hash.to_bytea_hex()
    );
    assert_ne!(first_body["p_entry_hash"], second_body["p_entry_hash"]);
    assert_ne!(first_body["p_signature"], second_body["p_signature"]);
    assert_eq!(outcome.sequence_no().get(), 2);

    Ok(())
}

#[test]
fn ledger_appender_debug_redacts_payload_and_keys() -> TestResult {
    let appender = sample_appender(
        "http://127.0.0.1:54321".to_owned(),
        LedgerAppenderConfig::default(),
    )?;
    let draft = sample_draft("payload-secret-value")?;

    let appender_debug = format!("{appender:?}");
    let draft_debug = format!("{draft:?}");

    assert!(appender_debug.contains("LedgerAppender"));
    assert!(appender_debug.contains("<redacted>"));
    assert!(!appender_debug.contains("service-role-secret"));
    assert!(!appender_debug.contains("publishable-key-secret"));
    assert!(draft_debug.contains("LedgerAppendDraft"));
    assert!(draft_debug.contains("<redacted>"));
    assert!(!draft_debug.contains("payload-secret-value"));

    Ok(())
}

async fn append_with_single_failure(
    body: &str,
) -> Result<LedgerAppendError, Box<dyn std::error::Error>> {
    let (base_url, receiver, server_thread) = spawn_scripted_server(vec![
        ResponseSpec::Static {
            status: 200,
            body: chain_head_body(0, LedgerHash::genesis()),
        },
        ResponseSpec::Static {
            status: 409,
            body: body.to_owned(),
        },
    ])?;
    let appender = sample_appender(base_url, LedgerAppenderConfig::new(0))?;
    let draft = sample_draft("confidential")?;

    let error = appender
        .append(&draft)
        .await
        .expect_err("append failure must not be reported as success");
    recv_request(&receiver)?;
    recv_request(&receiver)?;
    join_server(server_thread)?;

    Ok(error)
}

fn sample_appender(
    base_url: String,
    config: LedgerAppenderConfig,
) -> Result<LedgerAppender, Box<dyn std::error::Error>> {
    let client = Arc::new(SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key-secret",
    ));
    let signing_key =
        LedgerSigningKey::from_secret_key_bytes(LedgerSignatureKeyVersion::new(1)?, &[9u8; 32])?;

    Ok(LedgerAppender::with_config(client, signing_key, config))
}

fn sample_draft(classification: &str) -> Result<LedgerAppendDraft, Box<dyn std::error::Error>> {
    let payload = LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "algorithm": "xchacha20-poly1305",
            "classification": classification,
            "key_version": 1,
            "version": 1
        }),
    )?;

    Ok(LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::parse("22222222-2222-4222-8222-222222222222")?,
        entry_type: LedgerEntryType::SecretCreated,
        source_event_at: SourceEventAt::parse(SOURCE_EVENT_AT)?,
        request_id: RequestId::parse(REQUEST_ID)?,
        source_event_id: None,
        target_secret_id: Some(SecretId::parse(TARGET_SECRET_ID)?),
        target_secret_version_id: Some(LedgerTargetSecretVersionId::parse(
            TARGET_SECRET_VERSION_ID,
        )?),
        actor_user_id: Some(OwnerUserId::parse(OWNER_USER_ID)?),
        actor_device_id: Some(DeviceId::new(DEVICE_ID)?),
        result: LedgerResult::Success,
        error_code: None,
        payload,
    })?)
}

fn chain_head_body(last_sequence_no: u64, last_entry_hash: LedgerHash) -> String {
    json!([{
        "last_sequence_no": last_sequence_no,
        "last_entry_hash": last_entry_hash.to_bytea_hex()
    }])
    .to_string()
}

fn spawn_scripted_server(
    responses: Vec<ResponseSpec>,
) -> Result<TestServer, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let response_body = response_body_for(&response, &request)?;
            let status = response_status(&response);
            sender.send(request).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request receiver was dropped",
                )
            })?;
            write_http_response(&mut stream, status, &response_body)?;
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn response_status(response: &ResponseSpec) -> u16 {
    match response {
        ResponseSpec::Static { status, .. } => *status,
        ResponseSpec::AppendSuccessFromRequest => 200,
    }
}

fn response_body_for(
    response: &ResponseSpec,
    request: &CapturedRequest,
) -> std::io::Result<String> {
    match response {
        ResponseSpec::Static { body, .. } => Ok(body.clone()),
        ResponseSpec::AppendSuccessFromRequest => append_success_body(request),
    }
}

fn append_success_body(request: &CapturedRequest) -> std::io::Result<String> {
    let body: Value = serde_json::from_str(&request.body).map_err(io_other)?;
    let response = json!([{
        "ledger_entry_id": body["p_ledger_entry_id"].clone(),
        "sequence_no": body["p_sequence_no"].clone(),
        "entry_hash": body["p_entry_hash"].clone(),
        "chain_last_sequence_no": body["p_sequence_no"].clone(),
        "chain_last_entry_hash": body["p_entry_hash"].clone(),
        "replayed": false
    }]);

    Ok(response.to_string())
}

fn recv_request(receiver: &mpsc::Receiver<CapturedRequest>) -> std::io::Result<CapturedRequest> {
    receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .map_err(io_other)
}

fn join_server(thread: thread::JoinHandle<std::io::Result<()>>) -> std::io::Result<()> {
    thread
        .join()
        .map_err(|_| io_other("server thread panicked"))?
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

        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
    };

    let headers = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let request_line = headers.lines().next().unwrap_or_default();
    let method = request_line
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let headers = headers
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect::<HashMap<_, _>>();
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    let mut body = buffer.get(body_start..).unwrap_or_default().to_vec();

    while body.len() < content_length {
        let bytes_read = stream.read(&mut chunk)?;
        if bytes_read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..bytes_read]);
    }
    body.truncate(content_length);

    Ok(CapturedRequest {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        409 => "Conflict",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

fn assert_error_output_is_redacted(error: LedgerAppendError) {
    let debug = format!("{error:?}");
    let display = error.to_string();

    for rendered in [debug, display] {
        assert!(!rendered.contains("plaintext"));
        assert!(!rendered.contains("jwt"));
        assert!(!rendered.contains("service-role-secret"));
    }
}

fn io_other(error: impl ToString) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

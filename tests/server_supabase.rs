use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use mipsorcu::server::supabase::{
    IntegrityCheckViolationSummary, SupabaseAuditAppender, SupabaseClient, SupabaseRpcError,
};
use mipsorcu::{
    AuditAction, AuditAppendError, AuditEvent, AuditEventAppender, AuditEventId, AuditEventParts,
    AuditMetadata, AuditResult, DeviceId, KeyVersion, OwnerUserId, RawJwt, RequestId, SecretId,
};
use serde_json::json;

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
}

type ProbeServer = (
    String,
    mpsc::Receiver<CapturedRequest>,
    thread::JoinHandle<std::io::Result<()>>,
);

const AUDIT_EVENT_ID: &str = "11111111-1111-4111-8111-111111111111";
const REQUEST_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const TARGET_SECRET_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const DEVICE_ID: &str = "sbc-device-1";
const SOURCE_EVENT_AT: &str = "2026-04-08T12:00:00Z";

#[test]
fn supabase_error_display_does_not_expose_response_body() {
    let error = SupabaseRpcError::NonSuccessStatus {
        status: 400,
        body: "secret internal upstream details".to_owned(),
    };

    let rendered = error.to_string();

    assert!(rendered.contains("status 400"));
    assert!(rendered.contains("response body length"));
    assert!(!rendered.contains("secret internal upstream details"));
}

#[test]
fn supabase_error_debug_does_not_expose_response_body() {
    let error = SupabaseRpcError::NonSuccessStatus {
        status: 403,
        body: "secret internal upstream details".to_owned(),
    };

    let rendered = format!("{error:?}");

    assert!(rendered.contains("NonSuccessStatus"));
    assert!(rendered.contains("403"));
    assert!(rendered.contains("body_len"));
    assert!(!rendered.contains("secret internal upstream details"));
}

#[tokio::test(flavor = "current_thread")]
async fn audit_appender_maps_conflict_response_to_idempotency_conflict() {
    let (base_url, receiver, server_thread) =
        spawn_capture_server(409, r#"{"details":"audit_event_id_conflict"}"#)
            .expect("capture server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );
    let appender = SupabaseAuditAppender::new(Arc::new(client));

    let event = sample_audit_event();
    let result = appender.append_audit_event(&event).await;
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");

    assert!(matches!(result, Err(AuditAppendError::IdempotencyConflict)));
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/rest/v1/rpc/rpc_append_audit_event");
    assert_eq!(
        request.headers.get("authorization"),
        Some(&"Bearer service-role-secret".to_owned())
    );
    assert_eq!(
        request.headers.get("apikey"),
        Some(&"service-role-secret".to_owned())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn audit_appender_keeps_non_conflict_responses_as_external_dependency_failure() {
    let (base_url, receiver, server_thread) =
        spawn_capture_server(409, r#"{"message":"different_conflict"}"#)
            .expect("capture server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );
    let appender = SupabaseAuditAppender::new(Arc::new(client));

    let event = sample_audit_event();
    let result = appender.append_audit_event(&event).await;
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");

    assert!(matches!(
        result,
        Err(AuditAppendError::ExternalDependencyFailed {
            code: "supabase_rpc_failed"
        })
    ));
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/rest/v1/rpc/rpc_append_audit_event");
}

#[tokio::test(flavor = "current_thread")]
async fn current_secret_version_read_uses_expected_columns_and_publishable_auth() {
    let (base_url, receiver, server_thread) =
        spawn_capture_server(200, "[]").expect("capture server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );
    let secret_id =
        SecretId::parse("550e8400-e29b-41d4-a716-446655440000").expect("secret id must be valid");
    let raw_jwt = RawJwt::new("sample-user-jwt").expect("raw jwt must be valid");

    let rows = client
        .fetch_current_secret_version_for_user(&secret_id, &raw_jwt)
        .await
        .expect("current secret version read should succeed");
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");

    assert!(rows.is_empty());
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.path,
        "/rest/v1/secret_versions?select=id,secret_id,version,ciphertext,encrypted_data_key,key_version,algorithm,classification,nonce_or_iv,aad_context,created_by_user_id,created_at,secrets!inner(current_version_id,owner_user_id,classification)&secret_id=eq.550e8400-e29b-41d4-a716-446655440000"
    );
    assert_eq!(
        request.headers.get("authorization"),
        Some(&"Bearer sample-user-jwt".to_owned())
    );
    assert_eq!(
        request.headers.get("apikey"),
        Some(&"publishable-key".to_owned())
    );
    assert!(
        !request
            .headers
            .values()
            .any(|value| value.contains("service-role-secret"))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn integrity_check_uses_service_role_rpc_and_parses_summary() {
    let response_body = serde_json::to_string(&json!([{
        "checked_secret_count": 2,
        "checked_secret_version_count": 4,
        "checked_audit_event_count": 6,
        "violation_count": 0,
        "violation_summary": IntegrityCheckViolationSummary::zero(),
    }]))
    .expect("integrity response should serialize");
    let (base_url, receiver, server_thread) =
        spawn_capture_server(200, &response_body).expect("capture server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let summary = client
        .call_integrity_check()
        .await
        .expect("integrity check RPC should succeed");
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");

    assert_eq!(summary.checked_secret_count, 2);
    assert_eq!(summary.checked_secret_version_count, 4);
    assert_eq!(summary.checked_audit_event_count, 6);
    assert_eq!(summary.violation_count, 0);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/rest/v1/rpc/rpc_integrity_check");
    assert_eq!(
        request.headers.get("authorization"),
        Some(&"Bearer service-role-secret".to_owned())
    );
    assert_eq!(
        request.headers.get("apikey"),
        Some(&"service-role-secret".to_owned())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn readiness_probe_retries_with_publishable_key_after_unauthorized_head() {
    let (base_url, receiver, server_thread) =
        spawn_probe_server(vec![401, 200]).expect("probe server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let reachable = client.probe_readiness().await;
    let first_request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("first request should be captured");
    let second_request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("second request should be captured");
    let join_result = server_thread
        .join()
        .expect("probe server thread should not panic");
    join_result.expect("probe server should exit cleanly");

    assert!(reachable);
    assert_eq!(first_request.method, "HEAD");
    assert_eq!(first_request.path, "/rest/v1/");
    assert!(!first_request.headers.contains_key("authorization"));
    assert!(!first_request.headers.contains_key("apikey"));

    assert_eq!(second_request.method, "HEAD");
    assert_eq!(second_request.path, "/rest/v1/");
    assert!(!second_request.headers.contains_key("authorization"));
    assert_eq!(
        second_request.headers.get("apikey"),
        Some(&"publishable-key".to_owned())
    );
    assert!(
        !second_request
            .headers
            .values()
            .any(|value| value.contains("service-role-secret"))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn readiness_probe_succeeds_without_auth_when_head_is_public() {
    let (base_url, receiver, server_thread) =
        spawn_probe_server(vec![200]).expect("probe server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let reachable = client.probe_readiness().await;
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("probe server thread should not panic");
    join_result.expect("probe server should exit cleanly");

    assert!(reachable);
    assert_eq!(request.method, "HEAD");
    assert_eq!(request.path, "/rest/v1/");
    assert!(!request.headers.contains_key("authorization"));
    assert!(!request.headers.contains_key("apikey"));
}

#[tokio::test(flavor = "current_thread")]
async fn readiness_probe_does_not_retry_on_non_auth_failure() {
    let (base_url, receiver, server_thread) =
        spawn_probe_server(vec![404]).expect("probe server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let reachable = client.probe_readiness().await;
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("probe server thread should not panic");
    join_result.expect("probe server should exit cleanly");

    assert!(!reachable);
    assert_eq!(request.method, "HEAD");
    assert_eq!(request.path, "/rest/v1/");
    assert!(
        receiver
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err()
    );
}

fn spawn_capture_server(
    status: u16,
    body: &str,
) -> Result<ProbeServer, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let body = body.to_owned();
    let thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let request = read_http_request(&mut stream)?;
        sender.send(request).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "captured request receiver was dropped",
            )
        })?;
        write_http_response(&mut stream, status, &body)?;

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn sample_audit_event() -> AuditEvent {
    AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::parse(AUDIT_EVENT_ID).expect("audit event id must be valid"),
        request_id: RequestId::parse(REQUEST_ID).expect("request id must be valid"),
        actor_user_id: Some(
            OwnerUserId::parse(OWNER_USER_ID).expect("owner user id must be valid"),
        ),
        actor_device_id: Some(DeviceId::new(DEVICE_ID).expect("device id must be valid")),
        action: AuditAction::Decrypt,
        target_secret_id: Some(
            SecretId::parse(TARGET_SECRET_ID).expect("target secret id must be valid"),
        ),
        result: AuditResult::Failure,
        key_version: Some(KeyVersion::new(1).expect("key version must be valid")),
        metadata_json: AuditMetadata::new(json!({
            "error_code": "decrypt_failed",
            "source_event_at": SOURCE_EVENT_AT
        }))
        .expect("metadata must be valid"),
    })
    .expect("audit event must be valid")
}

fn spawn_probe_server(statuses: Vec<u16>) -> Result<ProbeServer, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for status in statuses {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            sender.send(request).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request receiver was dropped",
                )
            })?;
            write_http_response(&mut stream, status, "{}")?;
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
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

    Ok(CapturedRequest {
        method,
        path,
        headers,
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

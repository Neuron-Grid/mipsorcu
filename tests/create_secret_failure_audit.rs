use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use mipsorcu::server::dto::CreateSecretRequest;
use mipsorcu::server::handlers::create_secret;
use mipsorcu::server::middleware::AuthenticatedUser;
use mipsorcu::server::state::{AppState, ReadinessState};
use mipsorcu::server::supabase::{SupabaseAuditAppender, SupabaseClient};
use mipsorcu::{
    AuditRecorder, Jwk, Jwks, JwtVerifier, JwtVerifierConfig, KeyVersion, LocalAuditFallbackStore,
    MASTER_KEY_LENGTH, MasterKey, OwnerUserId, RawJwt, VerifiedJwtClaims,
};
use serde_json::Value;

const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

type TestResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct CapturedRequest {
    path: String,
    body: Value,
}

#[tokio::test(flavor = "multi_thread")]
async fn create_secret_write_rpc_failure_audit_uses_attempted_secret_metadata() -> TestResult<()> {
    let (supabase_url, receiver, server_thread) = spawn_supabase_rpc_server()?;
    let state = test_app_state(&supabase_url)?;
    let auth = test_authenticated_user()?;

    let result = create_secret(
        State(state),
        auth,
        Json(CreateSecretRequest {
            classification: "confidential".to_owned(),
            device_id: "sbc-device-1".to_owned(),
            plaintext_hex: "64756d6d7920736563726574".to_owned(),
        }),
    )
    .await;

    assert!(result.is_err());

    let write_request = receiver.recv_timeout(Duration::from_secs(2))?;
    let append_request = receiver.recv_timeout(Duration::from_secs(2))?;
    let join_result = server_thread
        .join()
        .map_err(|_| std::io::Error::other("test Supabase RPC server thread panicked"))?;
    join_result?;

    assert!(
        write_request
            .path
            .ends_with("/rest/v1/rpc/rpc_write_secret_version")
    );
    assert!(
        append_request
            .path
            .ends_with("/rest/v1/rpc/rpc_append_audit_event")
    );

    let attempted_secret_id = write_request.body["p_secret_id"].as_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "write RPC request should include p_secret_id",
        )
    })?;
    let append_body = append_request.body.as_object().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "append audit RPC request should be a JSON object",
        )
    })?;

    assert_eq!(append_body["p_action"], "encrypt_create");
    assert_eq!(append_body["p_result"], "failure");
    assert!(append_body.contains_key("p_target_secret_id"));
    assert!(append_body["p_target_secret_id"].is_null());
    assert_eq!(
        append_body["p_metadata_json"]["attempted_secret_id"],
        attempted_secret_id
    );

    Ok(())
}

fn test_app_state(supabase_url: &str) -> TestResult<AppState> {
    let http_client = reqwest::Client::new();
    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        supabase_url.to_owned(),
        "service-role-key",
        "publishable-key",
    ));
    let audit_appender =
        SupabaseAuditAppender::new(supabase_client.clone(), tokio::runtime::Handle::current());
    let audit_fallback_store =
        LocalAuditFallbackStore::new(temp_jsonl_path("create-secret-failure-audit"));
    let audit_recorder = Arc::new(AuditRecorder::new(
        audit_appender,
        audit_fallback_store.clone(),
    ));

    Ok(AppState {
        master_key: Arc::new(MasterKey::from_bytes([42u8; MASTER_KEY_LENGTH])),
        key_version: KeyVersion::new(1)?,
        jwt_verifier: Arc::new(test_jwt_verifier()?),
        supabase_client,
        audit_recorder,
        audit_fallback_store,
        readiness_state: ReadinessState::new(),
        health_readiness_poll_interval: Duration::from_secs(30),
    })
}

fn test_jwt_verifier() -> TestResult<JwtVerifier> {
    let jwks = Jwks::new(vec![Jwk::new(
        "RSA",
        "test-key",
        Some("RS256".to_owned()),
        Some("sig".to_owned()),
        "abc",
        "AQAB",
    )])?;

    Ok(JwtVerifier::new(
        JwtVerifierConfig::new("https://issuer.example.test", "authenticated")?,
        jwks,
    ))
}

fn test_authenticated_user() -> TestResult<AuthenticatedUser> {
    let owner_user_id = OwnerUserId::parse(OWNER_USER_ID)?;

    Ok(AuthenticatedUser {
        claims: VerifiedJwtClaims::from_verified_subject(owner_user_id),
        raw_jwt: RawJwt::new("test-token")?,
    })
}

fn temp_jsonl_path(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    std::env::temp_dir().join(format!("mipsorcu-{test_name}-{unique}.jsonl"))
}

fn spawn_supabase_rpc_server() -> TestResult<(
    String,
    mpsc::Receiver<CapturedRequest>,
    thread::JoinHandle<std::io::Result<()>>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let is_write_rpc = request
                .path
                .ends_with("/rest/v1/rpc/rpc_write_secret_version");
            sender.send(request).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request receiver was dropped",
                )
            })?;

            if is_write_rpc {
                write_http_response(
                    &mut stream,
                    500,
                    "Internal Server Error",
                    r#"{"error":"write failed"}"#,
                )?;
            } else {
                write_http_response(&mut stream, 200, "OK", r#"{"status":"ok"}"#)?;
            }
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
    let content_length = content_length(&headers)?;
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
    let body = serde_json::from_slice(&buffer[body_start..body_end])?;

    Ok(CapturedRequest { path, body })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> std::io::Result<usize> {
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
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request is missing content-length",
            )
        })
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

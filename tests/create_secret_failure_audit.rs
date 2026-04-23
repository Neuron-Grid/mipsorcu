use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mipsorcu::server::dto::CreateSecretRequest;
use mipsorcu::server::handlers::create_secret;
use mipsorcu::server::middleware::{AuthenticatedUser, RequestContext, RequestJson};
use mipsorcu::server::state::{AppState, ReadinessState};
use mipsorcu::server::supabase::{SupabaseAuditAppender, SupabaseClient};
use mipsorcu::{
    AuditRecorder, Jwk, Jwks, JwtVerifier, JwtVerifierConfig, KeyVersion, LocalAuditFallbackStore,
    MASTER_KEY_LENGTH, MasterKey, RawJwt, RequestId, SourceEventAt, VerifiedJwtClaims,
};
use serde::Serialize;
use serde_json::Value;

const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const KEY_ID: &str = "test-key-1";
const ISSUER: &str = "https://project-ref.supabase.co/auth/v1";
const AUDIENCE: &str = "authenticated";
const RSA_MODULUS: &str = "0cOAzuft7zMhmD42QSngblYMsfhQD5IqUDK2S8sZw_TM0tNaPvMj-JqyM1bx4PaWDDjX018m8ys7wmOFSyfrl0TpWFzFMwUxLzsTgM1izd_a_Kk1IBRUREuYuAHr1TDZOoXqGncTC6xb-Jd4n58zjxsB3wO3OFBn_qP_Wsv4oPhiqLcya1UdyXEO905iIkigCdDa7VT7T6ogTrR-RGqZHON05UYXCmqSfAUBTy6dHowjQio0eHLUYAhDTv5q7oIcvb_SHbL-W-Q6GqsdFlQXJMXydSsTqBwlxs_7fSbOPqGfTxUeEzN5kyH1kn78oRK-toDT-ASKyu3Uh9sMV7fdqw";
const RSA_EXPONENT: &str = "AQAB";
const RSA_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRw4DO5+3vMyGY
PjZBKeBuVgyx+FAPkipQMrZLyxnD9MzS01o+8yP4mrIzVvHg9pYMONfTXybzKzvC
Y4VLJ+uXROlYXMUzBTEvOxOAzWLN39r8qTUgFFRES5i4AevVMNk6heoadxMLrFv4
l3ifnzOPGwHfA7c4UGf+o/9ay/ig+GKotzJrVR3JcQ73TmIiSKAJ0NrtVPtPqiBO
tH5Eapkc43TlRhcKapJ8BQFPLp0ejCNCKjR4ctRgCENO/mrughy9v9Idsv5b5Doa
qx0WVBckxfJ1KxOoHCXGz/t9Js4+oZ9PFR4TM3mTIfWSfvyhEr62gNP4BIrK7dSH
2wxXt92rAgMBAAECggEAAewnItm/dZRomg5ixDH7Rc52Oy55yDmbyc/y4sPx+d1J
25EUdt/yT4XEAaAFcQ+YWgcJ6aFgsV2ztrkooqd8XcWfRQJop2pEaOsMecg6ZIVb
WF9SD660liY5OE8UxSw3gpnfKy5/MrBno6tDuNI4oq2gndWP9IisHsFDBqcUD1dQ
5wUILJiQwI4wW0Bm5MHkzMjuSx0W5ZwkRjfc8EI17mbmBYQD56l6NJsiPatvYn2T
dFeW/jtPhnX8xXslxIDlKgdT/HODUE/azNJKw8vzDWjTAbSejuEJriZXcQxvtZfN
YY6P9Au5IQsjamJdas75PzF6XhT6QODatnxVV7ySPQKBgQDpSxX8wVwF/qHFk0YM
59ACc71kOkkkaT2Hc1fCoZPYbgYR4seO2cOkkRpiFoi5HrA5lNEoQBJJIJvtoL/4
cLSFIWRqGNtvH/NDoGEeF7GSn2i0LCb2jX5vuiY3bSlEj2JHiFTwizsmwhydokQM
jFKzDBJ+snk6gddUx1DgKaMMVwKBgQDmLiKiSwI615c3fCAEXP5UakK9VwjpkYAp
KIIz/RIokcW7+NP1xbFtj/06M7O4IasLOvugMPDzN/WJQ/gzA1m+bajwl22f7lRn
l4GMnFztVmGptTg+EzU0GORkRd3boEtwpd2FZ/WhfaTLP8BGIcvNu7frdGbpkcWK
iVNqtjNkzQKBgD9FO+tWzYxaqKka7g6l+AYSObUrEZcsa6GGqLCCfcRe4oqLRK/7
Y1IIgG1Fy0LZjdWwBKGz7sGidGeYBzhr6KmKit8zap/SvHkE0BIHPwOS9CSZLOAF
M9s9UwwJMP4FHRRlZxPtztcOIhCmZ2o3zF3+0i1GXhZ+DFZT0B1bbXr1AoGBANC5
XSaVpfv9q13g7JeITAf4I3TWC3rhOboYxZinD2RCa2+8f1gKYI3dV98DKyD5RsT0
Q2BLgPLL95b1T4fSrfqELgGdDwdLcrZNKGh9EbcV8ZGWht2jRUdsmw5iXH/fpwkL
Hwjt8Er0SA8WTCBMXSa95lVYREngqaSqSj4l4gyxAoGBAMf4zUq0pOLJA2rk9k7f
P7LJUPgASNpxGsG/FBDE+rTQl1tqVgHsI20KULCrQ5a2ob4sGlGfF8p2M5s5dcoM
fgr74PXMRn15mEnR/ieIFJEIIKAqG+eJE8E4wtXf8L3swtrg1s2mYe3km/Ly0gNH
o6OiVJrW2fR4F3HzG53Td7eh
-----END PRIVATE KEY-----"#;

type TestResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct CapturedRequest {
    path: String,
    body: Value,
}

#[derive(Clone, Serialize)]
struct TestClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
}

#[tokio::test(flavor = "multi_thread")]
async fn create_secret_write_rpc_failure_audit_uses_attempted_secret_metadata() -> TestResult<()> {
    let (supabase_url, receiver, server_thread) = spawn_supabase_rpc_server()?;
    let state = test_app_state(&supabase_url)?;
    let auth = test_authenticated_user()?;

    let result = create_secret(
        State(state),
        RequestContext::new(RequestId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?),
        auth,
        RequestJson(CreateSecretRequest {
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
    let source_event_at = append_body["p_metadata_json"]["source_event_at"]
        .as_str()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "append audit RPC request should include metadata_json.source_event_at",
            )
        })?;
    assert!(SourceEventAt::parse(source_event_at).is_ok());

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn create_secret_write_rpc_failure_writes_local_fallback_before_return() -> TestResult<()> {
    let (supabase_url, receiver, server_thread) = spawn_supabase_rpc_server_with_append_response(
        500,
        "Internal Server Error",
        r#"{"error":"audit append failed"}"#,
    )?;
    let fallback_path = temp_jsonl_path("create-secret-failure-audit-fallback");
    let state = test_app_state_with_fallback(&supabase_url, fallback_path.clone())?;
    let auth = test_authenticated_user()?;

    let result = create_secret(
        State(state),
        RequestContext::new(RequestId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")?),
        auth,
        RequestJson(CreateSecretRequest {
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
    let fallback_contents = fs::read_to_string(&fallback_path)?;
    let fallback_records = fallback_contents
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(fallback_records.len(), 1);
    let fallback_record = &fallback_records[0];
    assert_eq!(fallback_record["action"], "encrypt_create");
    assert_eq!(fallback_record["result"], "failure");
    assert!(fallback_record["target_secret_id"].is_null());
    assert_eq!(
        fallback_record["metadata_json"]["attempted_secret_id"],
        attempted_secret_id
    );
    let source_event_at = fallback_record["metadata_json"]["source_event_at"]
        .as_str()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fallback audit record should include metadata_json.source_event_at",
            )
        })?;
    assert!(SourceEventAt::parse(source_event_at).is_ok());
    assert_eq!(fallback_record["delivery_status"], "pending");

    Ok(())
}

fn test_app_state(supabase_url: &str) -> TestResult<AppState> {
    test_app_state_with_fallback(supabase_url, temp_jsonl_path("create-secret-failure-audit"))
}

fn test_app_state_with_fallback(
    supabase_url: &str,
    fallback_path: PathBuf,
) -> TestResult<AppState> {
    let http_client = reqwest::Client::new();
    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        supabase_url.to_owned(),
        "service-role-key",
        "publishable-key",
    ));
    let audit_appender = SupabaseAuditAppender::new(supabase_client.clone());
    let audit_fallback_store = LocalAuditFallbackStore::new(fallback_path);
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
    let key = EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_PEM.as_bytes())?;
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KEY_ID.to_owned());
    let token = encode(
        &header,
        &TestClaims {
            sub: OWNER_USER_ID.to_owned(),
            iss: ISSUER.to_owned(),
            aud: AUDIENCE.to_owned(),
            exp: 4_102_444_800,
        },
        &key,
    )?;
    let raw_jwt = RawJwt::new(&token)?;
    let claims = verified_claims_from_raw_jwt(&raw_jwt)?;

    Ok(AuthenticatedUser { claims, raw_jwt })
}

fn verified_claims_from_raw_jwt(raw_jwt: &RawJwt) -> TestResult<VerifiedJwtClaims> {
    let verifier = JwtVerifier::new(
        JwtVerifierConfig::new(ISSUER, AUDIENCE)?,
        Jwks::new(vec![Jwk::new(
            "RSA",
            KEY_ID,
            Some("RS256".to_owned()),
            Some("sig".to_owned()),
            RSA_MODULUS,
            RSA_EXPONENT,
        )])?,
    );

    Ok(verifier.verify(raw_jwt)?)
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
    spawn_supabase_rpc_server_with_append_response(200, "OK", r#"{"status":"ok"}"#)
}

fn spawn_supabase_rpc_server_with_append_response(
    append_status: u16,
    append_reason: &'static str,
    append_body: &'static str,
) -> TestResult<(
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
                write_http_response(&mut stream, append_status, append_reason, append_body)?;
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

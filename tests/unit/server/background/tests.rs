use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tokio::sync::watch;

use crate::audit::{AuditRecordError, AuditRecorder, LocalAuditFallbackStore};
use crate::auth::{Jwk, Jwks, JwksCache, JwtVerifier, JwtVerifierConfig};
use crate::crypto::MasterKeyRing;
use crate::incident::{DummyNotificationSink, IncidentRecorder};
use crate::ledger::{
    LEDGER_ED25519_SECRET_KEY_LENGTH, LedgerSignatureKeyVersion, LedgerSigningKey,
};
use crate::server::ledger_appender::LedgerAppender;
use crate::server::siem_forwarding::SiemForwardingService;
use crate::server::state::{AppState, ReadinessState};
use crate::server::supabase::{
    IntegrityCheckViolationSummary, SupabaseAuditAppender, SupabaseClient,
};
use crate::siem::{
    InMemorySiemSink, LocalSiemFallbackBuffer, SiemForwarder, SiemForwarderStatus,
    SiemResendSummary,
};
use crate::types::{
    AliasEncryptionKey, AliasFingerprintKey, KeyVersion, MASTER_KEY_LENGTH, MasterKey,
};

const JWT_ISSUER: &str = "issuer";
const JWT_AUDIENCE: &str = "audience";

#[derive(Debug, Clone)]
struct CapturedRequest {
    path: String,
    body: Option<Value>,
}

type TestServerHandle = (
    String,
    mpsc::Receiver<CapturedRequest>,
    thread::JoinHandle<std::io::Result<()>>,
);

async fn recv_captured_request(
    label: &str,
    receiver: &mpsc::Receiver<CapturedRequest>,
) -> Result<CapturedRequest, Box<dyn std::error::Error>> {
    for _ in 0..10_000 {
        match receiver.try_recv() {
            Ok(request) => return Ok(request),
            Err(mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request channel disconnected",
                )
                .into());
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("timed out waiting for captured request: {label}"),
    )
    .into())
}

async fn assert_no_captured_request(
    receiver: &mpsc::Receiver<CapturedRequest>,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..100 {
        match receiver.try_recv() {
            Ok(_) => return Err(std::io::Error::other(message).into()),
            Err(mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request channel disconnected",
                )
                .into());
            }
        }
    }

    Ok(())
}

fn temp_path(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    std::env::temp_dir().join(format!("mipsorcu-background-{test_name}-{unique}"))
}

fn sample_master_key() -> MasterKey {
    MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH])
}

fn test_app_state(
    supabase_url: &str,
    audit_fallback_path: PathBuf,
) -> Result<AppState, Box<dyn std::error::Error>> {
    let http_client = reqwest::Client::new();
    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        supabase_url.to_owned(),
        "service-role-key",
        "publishable-key",
    ));
    let audit_appender = SupabaseAuditAppender::new(supabase_client.clone());
    let audit_fallback_store = LocalAuditFallbackStore::new(audit_fallback_path);
    let audit_recorder = Arc::new(AuditRecorder::new(
        audit_appender,
        audit_fallback_store.clone(),
    ));
    let ledger_signing_key = LedgerSigningKey::from_secret_key_bytes(
        LedgerSignatureKeyVersion::new(1)?,
        &[9u8; LEDGER_ED25519_SECRET_KEY_LENGTH],
    )?;
    let ledger_appender = Arc::new(LedgerAppender::new(
        supabase_client.clone(),
        ledger_signing_key,
    ));
    let notification_sink =
        crate::incident::AnyNotificationSink::Dummy(DummyNotificationSink::new());
    let incident_recorder = Arc::new(IncidentRecorder::new(
        supabase_client.clone(),
        ledger_appender.clone(),
        "dummy",
    ));
    let incident_dispatcher = Arc::new(crate::incident::IncidentDispatcher::new(
        Arc::new(notification_sink),
        audit_recorder.clone(),
    ));
    let incident_detector = crate::incident::IncidentDetector::new();
    let readiness_state = ReadinessState::new();
    let siem_forwarding = Arc::new(SiemForwardingService::new(
        SiemForwarder::new(
            crate::siem::AnySiemSink::InMemory(InMemorySiemSink::new()),
            LocalSiemFallbackBuffer::new(temp_path("siem-buffer")),
        ),
        audit_recorder.clone(),
        readiness_state.clone(),
    ));
    let jwt_verifier = JwtVerifier::new(
        JwtVerifierConfig::new(JWT_ISSUER, JWT_AUDIENCE)?,
        Jwks::new(vec![Jwk::new(
            "RSA",
            "test-key",
            Some("RS256".to_owned()),
            Some("sig".to_owned()),
            "abc",
            "AQAB",
        )])?,
    );

    Ok(AppState {
        master_key_ring: Arc::new(MasterKeyRing::single(
            KeyVersion::new(1)?,
            sample_master_key(),
        )?),
        alias_encryption_key: Arc::new(AliasEncryptionKey::from_bytes([11u8; MASTER_KEY_LENGTH])),
        alias_encryption_key_version: KeyVersion::new(1)?,
        alias_fingerprint_key: Arc::new(AliasFingerprintKey::from_bytes([12u8; MASTER_KEY_LENGTH])),
        alias_fingerprint_key_version: KeyVersion::new(1)?,
        jwt_verifier: Arc::new(jwt_verifier),
        supabase_client,
        audit_recorder,
        ledger_appender,
        incident_recorder,
        incident_dispatcher: Some(incident_dispatcher),
        incident_detector,
        siem_forwarding,
        scheduler_status: crate::scheduler::SchedulerStatusState::default(),
        audit_fallback_store,
        readiness_state,
        health_readiness_poll_interval: Duration::from_secs(30),
        siem_long_failure_threshold: Duration::from_secs(900),
        http_handler_timeout: Duration::from_secs(75),
        http_rate_limit_requests: 300,
        http_rate_limit_window: Duration::from_secs(60),
    })
}

fn integrity_summary_json(violation_count: u64) -> Value {
    let mut summary = IntegrityCheckViolationSummary::zero();
    summary.algorithm_invalid = violation_count;

    json!({
        "checked_secret_count": 2,
        "checked_secret_version_count": 4,
        "checked_audit_event_count": 6,
        "violation_count": violation_count,
        "violation_summary": summary,
    })
}

fn spawn_supabase_restore_integrity_audit_server()
-> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for _ in 0..6 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let path = request.path.clone();
            let response_body = if path == "/rest/v1/rpc/rpc_append_audit_event_with_ledger" {
                Some(ledger_append_success_body(&request)?)
            } else {
                None
            };
            sender.send(request).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request receiver was dropped",
                )
            })?;

            if path == "/rest/v1/rpc/rpc_sample_restore_test" {
                write_http_response(&mut stream, 200, "OK", "[]")?;
            } else if path == "/rest/v1/rpc/rpc_integrity_check" {
                let body = serde_json::to_string(&json!([integrity_summary_json(0)]))
                    .map_err(std::io::Error::other)?;
                write_http_response(&mut stream, 200, "OK", &body)?;
            } else if path.starts_with("/rest/v1/ledger_chain_state") {
                write_http_response(&mut stream, 200, "OK", &ledger_chain_head_body())?;
            } else {
                let body = response_body.as_deref().unwrap_or(r#""ok""#);
                write_http_response(&mut stream, 200, "OK", body)?;
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn ledger_chain_head_body() -> String {
    json!([{
        "last_sequence_no": 0,
        "last_entry_hash": "\\x0000000000000000000000000000000000000000000000000000000000000000",
    }])
    .to_string()
}

fn ledger_append_success_body(request: &CapturedRequest) -> std::io::Result<String> {
    let body = request.body.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ledger append request body is missing",
        )
    })?;
    Ok(json!([{
        "ledger_entry_id": body["p_ledger_entry_id"].clone(),
        "sequence_no": body["p_sequence_no"].clone(),
        "entry_hash": body["p_entry_hash"].clone(),
        "chain_last_sequence_no": body["p_sequence_no"].clone(),
        "chain_last_entry_hash": body["p_entry_hash"].clone(),
        "replayed": false,
    }])
    .to_string())
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
    let content_length = content_length(&headers)?.unwrap_or(0);
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

    let request_line = headers.lines().next().unwrap_or_default();
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let body = if content_length == 0 {
        None
    } else {
        Some(serde_json::from_slice(&buffer[body_start..body_end])?)
    };

    Ok(CapturedRequest { path, body })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> std::io::Result<Option<usize>> {
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

#[tokio::test]
async fn jwks_refresh_loop_stops_on_shutdown_signal() {
    let jwks = Jwks::new(vec![Jwk::new(
        "RSA",
        "test-key",
        Some("RS256".to_owned()),
        Some("sig".to_owned()),
        "abc",
        "AQAB",
    )])
    .expect("test JWKS should be valid");
    let cache = JwksCache::new(jwks);
    let client = reqwest::Client::new();
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let task = tokio::spawn(super::run_jwks_refresh_loop(
        cache,
        client,
        "http://127.0.0.1:1/jwks".to_owned(),
        Duration::from_secs(60),
        shutdown_receiver,
    ));

    shutdown_sender
        .send(true)
        .expect("shutdown signal should send");

    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("JWKS refresh loop should stop promptly")
        .expect("JWKS refresh loop task should not panic");
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn background_restore_and_integrity_startup_offsets_are_phased()
-> Result<(), Box<dyn std::error::Error>> {
    let (supabase_url, receiver, server_thread) = spawn_supabase_restore_integrity_audit_server()?;
    let state = test_app_state(&supabase_url, temp_path("background-offsets"))?;
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let restore_handle = tokio::spawn(super::run_restore_test_loop(
        state.clone(),
        Duration::from_secs(86_400),
        Duration::from_secs(300),
        3,
        shutdown_sender.subscribe(),
    ));
    let integrity_handle = tokio::spawn(super::run_integrity_check_loop(
        state,
        Duration::from_secs(86_400),
        Duration::from_secs(3900),
        shutdown_receiver,
    ));

    tokio::task::yield_now().await;
    assert_no_captured_request(
        &receiver,
        "background jobs should not run before their startup delays",
    )
    .await?;

    tokio::time::advance(Duration::from_secs(299)).await;
    tokio::task::yield_now().await;
    assert_no_captured_request(&receiver, "restore test should wait until +300s").await?;

    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    let restore_request = recv_captured_request("restore RPC", &receiver).await?;
    let restore_chain_request = recv_captured_request("restore ledger chain", &receiver).await?;
    let restore_audit_request = recv_captured_request("restore audit ledger", &receiver).await?;
    assert_eq!(restore_request.path, "/rest/v1/rpc/rpc_sample_restore_test");
    assert!(
        restore_chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );
    assert_eq!(
        restore_audit_request.path,
        "/rest/v1/rpc/rpc_append_audit_event_with_ledger"
    );
    assert_eq!(
        restore_audit_request
            .body
            .as_ref()
            .and_then(|body| body["p_entry_type"].as_str()),
        Some("restore_test_completed")
    );
    assert_eq!(
        restore_audit_request
            .body
            .as_ref()
            .and_then(|body| body["p_metadata_json"]["trigger"].as_str()),
        Some("startup")
    );
    assert_no_captured_request(
        &receiver,
        "integrity check must not run at the restore test startup time",
    )
    .await?;

    tokio::time::advance(Duration::from_secs(3599)).await;
    tokio::task::yield_now().await;
    assert_no_captured_request(&receiver, "integrity check should wait until +3900s").await?;

    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    let integrity_request = recv_captured_request("integrity RPC", &receiver).await?;
    let integrity_chain_request =
        recv_captured_request("integrity ledger chain", &receiver).await?;
    let integrity_audit_request =
        recv_captured_request("integrity audit ledger", &receiver).await?;
    assert_eq!(integrity_request.path, "/rest/v1/rpc/rpc_integrity_check");
    assert!(
        integrity_chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );
    assert_eq!(
        integrity_audit_request.path,
        "/rest/v1/rpc/rpc_append_audit_event_with_ledger"
    );
    assert_eq!(
        integrity_audit_request
            .body
            .as_ref()
            .and_then(|body| body["p_entry_type"].as_str()),
        Some("integrity_check_completed")
    );
    assert_eq!(
        integrity_audit_request
            .body
            .as_ref()
            .and_then(|body| body["p_metadata_json"]["trigger"].as_str()),
        Some("startup")
    );

    shutdown_sender
        .send(true)
        .expect("shutdown signal should send");
    restore_handle.await?;
    integrity_handle.await?;
    server_thread
        .join()
        .expect("background server thread should not panic")?;

    Ok(())
}

#[test]
fn resend_audit_error_kind_reports_idempotency_conflict() {
    assert_eq!(
        super::resend_audit_error_kind(&AuditRecordError::IdempotencyConflict),
        "idempotency_conflict"
    );
}

#[test]
fn siem_resend_attempted_reports_only_non_empty_batches() {
    assert!(!super::siem_resend_attempted(&SiemResendSummary {
        attempted: 0,
        sent: 0,
        failed: 0,
    }));
    assert!(super::siem_resend_attempted(&SiemResendSummary {
        attempted: 1,
        sent: 0,
        failed: 1,
    }));
}

#[test]
fn fresh_siem_status_does_not_record_long_failure_incident() {
    assert!(!super::should_record_siem_long_failure(
        &SiemForwarderStatus::new(),
        time::OffsetDateTime::now_utc(),
        Duration::from_secs(1),
    ));
}

#[test]
fn siem_long_failure_incident_input_uses_fixed_operational_vocabulary() {
    let input = crate::server::incident::siem_long_failure_incident_input("siem_resend_loop");

    assert_eq!(
        input.incident_type,
        crate::incident::IncidentType::SiemLongFailure
    );
    assert_eq!(input.detection_source, "siem_resend_loop");
    assert_eq!(input.dedupe_key, "siem-long-failure");
    assert_eq!(input.error_code, "siem_long_outage");
    assert_eq!(input.incident_source_event_id, None);
    assert_eq!(input.target_sequence_no, None);
    assert_eq!(input.target_year_month, None);
    assert_eq!(input.dedupe_window_seconds, 3600);
}

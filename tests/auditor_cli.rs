use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use mipsorcu::{
    LEDGER_ED25519_SECRET_KEY_LENGTH, LedgerEntryDraft, LedgerEntryDraftParts, LedgerEntryId,
    LedgerEntryType, LedgerHash, LedgerPayload, LedgerResult, LedgerSequenceNo,
    LedgerSignatureKeyVersion, MASTER_KEY_LENGTH, RequestId, SourceEventAt,
};
use serde_json::{Value, json};

const SERVICE_ROLE_KEY: &str = "service-role-key";
const PUBLISHABLE_KEY: &str = "publishable-key";
const MASTER_KEY_BYTES: [u8; MASTER_KEY_LENGTH] = [11u8; MASTER_KEY_LENGTH];
const LEDGER_SIGNING_KEY_BYTES: [u8; LEDGER_ED25519_SECRET_KEY_LENGTH] =
    [9u8; LEDGER_ED25519_SECRET_KEY_LENGTH];

#[derive(Debug)]
#[expect(
    dead_code,
    reason = "fields retained for HTTP request capture consistency with key_rotation_cli tests"
)]
struct CapturedRequest {
    method: String,
    path: String,
    body: Option<Value>,
}

type TestServerHandle = (
    String,
    mpsc::Receiver<CapturedRequest>,
    thread::JoinHandle<std::io::Result<()>>,
);

struct AuditorCliRun {
    output: Output,
    temp_dir: PathBuf,
    #[expect(
        dead_code,
        reason = "retained for cleanup audit check parity with key_rotation_cli tests"
    )]
    fallback_path: PathBuf,
}

fn temp_dir(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("mipsorcu-auditor-cli-{test_name}-{unique}"))
}

fn spawn_auditor_server(
    status: u16,
    body: &'static str,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        let mut attempts = 0;
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false)?;
                    let request = read_http_request(&mut stream)?;
                    sender.send(request).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "captured request receiver was dropped",
                        )
                    })?;
                    write_http_response(&mut stream, status, "OK", body)?;
                    return Ok(());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    attempts += 1;
                    if attempts > 200 {
                        // Give up after ~2 seconds (200 * 10ms)
                        return Ok(());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => return Err(e),
            }
        }
    });
    Ok((format!("http://{addr}"), receiver, thread))
}

fn run_auditor_verify(
    supabase_url: &str,
    test_name: &str,
    from_seq: u64,
    to_seq: u64,
) -> Result<AuditorCliRun, Box<dyn std::error::Error>> {
    let temp_dir = temp_dir(test_name);
    let key_dir = temp_dir.join("keys");
    let fallback_path = temp_dir.join("audit-fallback-current.jsonl");
    let fallback_archive_dir = temp_dir.join("audit-fallback-archive");
    fs::create_dir_all(&key_dir)?;
    fs::write(key_dir.join("1.key"), hex::encode(MASTER_KEY_BYTES))?;

    let output = Command::new(env!("CARGO_BIN_EXE_mipsorcu"))
        .current_dir(&temp_dir)
        .env_clear()
        .env("MIPSORCU_MASTER_KEY_DIR", &key_dir)
        .env("MIPSORCU_ACTIVE_KEY_VERSION", "1")
        .env(
            "MIPSORCU_ALIAS_ENCRYPTION_KEY",
            hex::encode([3u8; MASTER_KEY_LENGTH]),
        )
        .env("MIPSORCU_ALIAS_ENCRYPTION_KEY_VERSION", "1")
        .env(
            "MIPSORCU_ALIAS_FINGERPRINT_KEY",
            hex::encode([4u8; MASTER_KEY_LENGTH]),
        )
        .env("MIPSORCU_ALIAS_FINGERPRINT_KEY_VERSION", "1")
        .env("MIPSORCU_SUPABASE_URL", supabase_url)
        .env("MIPSORCU_SUPABASE_SERVICE_ROLE_KEY", SERVICE_ROLE_KEY)
        .env("MIPSORCU_SUPABASE_PUBLISHABLE_KEY", PUBLISHABLE_KEY)
        .env(
            "MIPSORCU_LEDGER_SIGNING_KEY",
            hex::encode(LEDGER_SIGNING_KEY_BYTES),
        )
        .env("MIPSORCU_LEDGER_SIGNATURE_KEY_VERSION", "1")
        .env("MIPSORCU_JWT_ISSUER", "issuer")
        .env("MIPSORCU_JWT_AUDIENCE", "authenticated")
        .env("MIPSORCU_JWKS_URL", "http://127.0.0.1:1/jwks")
        .env("MIPSORCU_AUDIT_FALLBACK_PATH", &fallback_path)
        .env("MIPSORCU_AUDIT_FALLBACK_ARCHIVE_DIR", &fallback_archive_dir)
        .args([
            "auditor",
            "verify",
            "--from-sequence",
            &from_seq.to_string(),
            "--to-sequence",
            &to_seq.to_string(),
            "--format",
            "json",
        ])
        .output()?;

    Ok(AuditorCliRun {
        output,
        temp_dir,
        fallback_path,
    })
}

fn run_mipsorcu_args_without_server(
    args: &[&str],
    test_name: &str,
) -> Result<AuditorCliRun, Box<dyn std::error::Error>> {
    let temp_dir = temp_dir(test_name);
    let key_dir = temp_dir.join("keys");
    let fallback_path = temp_dir.join("audit-fallback-current.jsonl");
    let fallback_archive_dir = temp_dir.join("audit-fallback-archive");
    fs::create_dir_all(&key_dir)?;
    fs::write(key_dir.join("1.key"), hex::encode(MASTER_KEY_BYTES))?;

    let output = Command::new(env!("CARGO_BIN_EXE_mipsorcu"))
        .current_dir(&temp_dir)
        .env_clear()
        .env("MIPSORCU_MASTER_KEY_DIR", &key_dir)
        .env("MIPSORCU_ACTIVE_KEY_VERSION", "1")
        .env(
            "MIPSORCU_ALIAS_ENCRYPTION_KEY",
            hex::encode([3u8; MASTER_KEY_LENGTH]),
        )
        .env("MIPSORCU_ALIAS_ENCRYPTION_KEY_VERSION", "1")
        .env(
            "MIPSORCU_ALIAS_FINGERPRINT_KEY",
            hex::encode([4u8; MASTER_KEY_LENGTH]),
        )
        .env("MIPSORCU_ALIAS_FINGERPRINT_KEY_VERSION", "1")
        .env("MIPSORCU_SUPABASE_URL", "http://127.0.0.1:9")
        .env("MIPSORCU_SUPABASE_SERVICE_ROLE_KEY", SERVICE_ROLE_KEY)
        .env("MIPSORCU_SUPABASE_PUBLISHABLE_KEY", PUBLISHABLE_KEY)
        .env(
            "MIPSORCU_LEDGER_SIGNING_KEY",
            hex::encode(LEDGER_SIGNING_KEY_BYTES),
        )
        .env("MIPSORCU_LEDGER_SIGNATURE_KEY_VERSION", "1")
        .env("MIPSORCU_JWT_ISSUER", "issuer")
        .env("MIPSORCU_JWT_AUDIENCE", "authenticated")
        .env("MIPSORCU_JWKS_URL", "http://127.0.0.1:1/jwks")
        .env("MIPSORCU_AUDIT_FALLBACK_PATH", &fallback_path)
        .env("MIPSORCU_AUDIT_FALLBACK_ARCHIVE_DIR", &fallback_archive_dir)
        .args(args)
        .output()?;

    Ok(AuditorCliRun {
        output,
        temp_dir,
        fallback_path,
    })
}

fn valid_single_entry_body() -> &'static str {
    Box::leak(
        json!([{
            "ledger_entry_id": "00000000-0000-4000-8000-000000000000",
            "sequence_no": 1,
            "entry_hash": "\\x0000000000000000000000000000000000000000000000000000000000000000",
            "previous_entry_hash": "\\x0000000000000000000000000000000000000000000000000000000000000000",
            "signature": "\\x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "signature_key_version": 1,
            "entry_type": "integrity_check_completed",
            "source_event_at": "2026-04-08T12:00:00Z",
            "request_id": "00000000-0000-4000-8000-000000000000",
            "source_event_id": null,
            "target_secret_id": null,
            "target_secret_version_id": null,
            "actor_user_id": null,
            "actor_device_id": null,
            "result": "success",
            "error_code": null,
            "payload": {},
            "canonicalization_version": 1,
            "hash_algorithm": "sha-256",
            "signature_algorithm": "ed25519",
            "pk_key_version": 1,
            "pk_public_key": "\\x0000000000000000000000000000000000000000000000000000000000000000",
            "pk_algorithm": "ed25519",
            "pk_status": "active",
            "pk_created_at": null,
            "pk_retired_at": null
        }])
        .to_string()
        .into_boxed_str(),
    )
}

fn make_missing_key_test_body() -> &'static str {
    let entry_type = LedgerEntryType::IntegrityCheckCompleted;
    let payload = LedgerPayload::empty(entry_type).expect("valid empty payload");
    let source_event_at =
        SourceEventAt::parse("2026-04-08T12:00:00Z").expect("valid source_event_at");
    let request_id =
        RequestId::parse("00000000-0000-4000-8000-000000000000").expect("valid request_id");
    let previous_hash = LedgerHash::genesis();

    let draft = LedgerEntryDraft::new(LedgerEntryDraftParts {
        ledger_entry_id: LedgerEntryId::parse("00000000-0000-4000-8000-000000000000")
            .expect("valid ledger_entry_id"),
        sequence_no: LedgerSequenceNo::new(1).expect("valid sequence_no"),
        entry_type,
        source_event_at,
        request_id,
        source_event_id: None,
        target_secret_id: None,
        target_secret_version_id: None,
        actor_user_id: None,
        actor_device_id: None,
        result: LedgerResult::Success,
        error_code: None,
        payload,
        previous_entry_hash: previous_hash,
        signature_key_version: LedgerSignatureKeyVersion::new(99).expect("valid key_version"),
    })
    .expect("valid draft");

    let canonical = draft.canonical_payload().expect("valid canonical");
    let entry_hash = LedgerHash::from_canonical_payload(&canonical);

    let body = json!([{
        "ledger_entry_id": "00000000-0000-4000-8000-000000000000",
        "sequence_no": 1i64,
        "entry_hash": format!("\\x{}", entry_hash.to_hex()),
        "previous_entry_hash": format!("\\x{}", previous_hash.to_hex()),
        "signature": "\\x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "signature_key_version": 99,
        "entry_type": "integrity_check_completed",
        "source_event_at": "2026-04-08T12:00:00Z",
        "request_id": "00000000-0000-4000-8000-000000000000",
        "source_event_id": null,
        "target_secret_id": null,
        "target_secret_version_id": null,
        "actor_user_id": null,
        "actor_device_id": null,
        "result": "success",
        "error_code": null,
        "payload": {},
        "canonicalization_version": 1,
        "hash_algorithm": "sha-256",
        "signature_algorithm": "ed25519",
        "pk_key_version": null,
        "pk_public_key": null,
        "pk_algorithm": null,
        "pk_status": null,
        "pk_created_at": null,
        "pk_retired_at": null
    }]);

    Box::leak(body.to_string().into_boxed_str())
}

//  Tests
#[test]
fn auditor_top_level_help_exit_code_0_without_rpc() -> Result<(), Box<dyn std::error::Error>> {
    let run = run_mipsorcu_args_without_server(&["auditor", "--help"], "top-level-help")?;

    assert!(run.output.status.success(), "expected --help to exit 0");
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(stdout.contains("mipsorcu auditor verify"));
    assert!(!stderr.contains("auditor Supabase RPC error"));

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn auditor_verify_help_exit_code_0_without_rpc() -> Result<(), Box<dyn std::error::Error>> {
    let run = run_mipsorcu_args_without_server(&["auditor", "verify", "--help"], "verify-help")?;

    assert!(
        run.output.status.success(),
        "expected verify --help to exit 0"
    );
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(stdout.contains("mipsorcu auditor verify"));
    assert!(!stderr.contains("auditor Supabase RPC error"));

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn auditor_verify_empty_valid_chain_exit_code_0() -> Result<(), Box<dyn std::error::Error>> {
    let body: &'static str = Box::leak(json!([]).to_string().into_boxed_str());
    let (supabase_url, _receiver, server_thread) = spawn_auditor_server(200, body)?;
    let run = run_auditor_verify(&supabase_url, "empty-valid", 1, 10)?;
    server_thread
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        run.output.status.success(),
        "expected exit 0 for valid empty chain"
    );

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_eq!(parsed["valid"], true);
    assert_eq!(parsed["checked_count"], 0);
    assert_eq!(parsed["first_sequence_no"], 1);
    assert_eq!(parsed["last_sequence_no"], 10);
    assert_eq!(parsed["first_error"], Value::Null);

    assert_no_secret_material(&parsed, "auditor verify output")?;
    assert!(!stdout.contains(SERVICE_ROLE_KEY));
    assert!(!stdout.contains(PUBLISHABLE_KEY));

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn auditor_verify_rpc_failure_non_zero_exit() -> Result<(), Box<dyn std::error::Error>> {
    let (supabase_url, _receiver, server_thread) =
        spawn_auditor_server(500, r#"{"message":"internal server error"}"#)?;
    let run = run_auditor_verify(&supabase_url, "rpc-failure", 1, 10)?;
    server_thread
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected non-zero exit for RPC failure"
    );
    assert_eq!(run.output.status.code(), Some(2));

    let stderr = String::from_utf8_lossy(&run.output.stderr);
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let combined = format!("{stdout}{stderr}");

    assert!(!combined.contains(SERVICE_ROLE_KEY));
    assert!(!combined.contains(PUBLISHABLE_KEY));
    assert!(!combined.contains("internal server error"));

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn auditor_verify_invalid_range_non_zero_exit() -> Result<(), Box<dyn std::error::Error>> {
    let body: &'static str = Box::leak(json!([]).to_string().into_boxed_str());
    let (supabase_url, _receiver, server_thread) = spawn_auditor_server(200, body)?;
    let run = run_auditor_verify(&supabase_url, "invalid-range", 10, 5)?;
    server_thread
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected non-zero exit for invalid range"
    );
    assert_eq!(run.output.status.code(), Some(2));

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn auditor_verify_json_output_is_parseable() -> Result<(), Box<dyn std::error::Error>> {
    let body: &'static str = Box::leak(json!([]).to_string().into_boxed_str());
    let (supabase_url, _receiver, server_thread) = spawn_auditor_server(200, body)?;
    let run = run_auditor_verify(&supabase_url, "parseable", 1, 5)?;
    server_thread
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;

    assert!(parsed["valid"].is_boolean());
    assert!(parsed["checked_count"].is_u64());
    assert!(parsed["first_sequence_no"].is_u64());
    assert!(parsed["last_sequence_no"].is_u64());

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn auditor_verify_no_secret_bearing_fields_in_output() -> Result<(), Box<dyn std::error::Error>> {
    let body: &'static str = valid_single_entry_body();
    let (supabase_url, _receiver, server_thread) = spawn_auditor_server(200, body)?;
    let run = run_auditor_verify(&supabase_url, "no-secrets", 1, 1)?;
    server_thread
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    let combined = format!("{stdout}{stderr}");

    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_no_secret_material(&parsed, "auditor verify output")?;

    let ledger_signing_key_hex = hex::encode(LEDGER_SIGNING_KEY_BYTES);
    assert!(!combined.contains("plaintext"));
    assert!(!combined.contains("ciphertext"));
    assert!(!combined.contains("encrypted_data_key"));
    assert!(!combined.contains("nonce_or_iv"));
    assert!(!combined.contains("aad_context"));
    assert!(!combined.contains(SERVICE_ROLE_KEY));
    assert!(!combined.contains(PUBLISHABLE_KEY));
    assert!(!combined.contains(&ledger_signing_key_hex));

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn auditor_verify_missing_key_non_zero_exit() -> Result<(), Box<dyn std::error::Error>> {
    let body: &'static str = make_missing_key_test_body();
    let (supabase_url, _receiver, server_thread) = spawn_auditor_server(200, body)?;
    let run = run_auditor_verify(&supabase_url, "missing-key", 1, 1)?;
    server_thread
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected non-zero exit for missing key"
    );
    assert_eq!(run.output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_eq!(parsed["valid"], false);
    let error_code = parsed["first_error"]["code"].as_str().unwrap_or("");
    assert!(!error_code.is_empty(), "first_error.code must be present");
    // Integration test requirement 7: missing key must produce UnknownSignatureKey
    assert_eq!(
        error_code, "unknown_signature_key",
        "expected error code 'unknown_signature_key' for missing key, got '{error_code}'"
    );
    assert!(parsed["first_error"]["sequence_no"].is_u64());

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

//  Helpers

fn assert_no_secret_material(
    value: &Value,
    label: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    let serialized = serde_json::to_string(value)?;
    let master_key_hex = hex::encode(MASTER_KEY_BYTES);
    let ledger_signing_key_hex = hex::encode(LEDGER_SIGNING_KEY_BYTES);

    for forbidden in [
        "master_key",
        "data_key",
        "encrypted_data_key",
        "ciphertext",
        "jwt",
        "service_role_key",
        SERVICE_ROLE_KEY,
        PUBLISHABLE_KEY,
        "secret_key",
        "plaintext",
        "nonce_or_iv",
        "aad_context",
        master_key_hex.as_str(),
        ledger_signing_key_hex.as_str(),
    ] {
        assert!(
            !serialized.contains(forbidden),
            "{label} should not contain {forbidden}"
        );
    }

    Ok(())
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
    let body = if content_length == 0 {
        None
    } else {
        Some(serde_json::from_slice(&buffer[body_start..body_end])?)
    };
    Ok(CapturedRequest { method, path, body })
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

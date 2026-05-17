use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use mipsorcu::{
    LEDGER_CANONICALIZATION_VERSION_V1, LEDGER_ED25519_SECRET_KEY_LENGTH,
    LEDGER_HASH_ALGORITHM_SHA256, LEDGER_HASH_LENGTH, LEDGER_SIGNATURE_ALGORITHM_ED25519,
    LEDGER_SIGNATURE_LENGTH, LedgerSignatureKeyVersion, LedgerSigningKey, MASTER_KEY_LENGTH,
    SourceEventAt,
};
use serde_json::{Value, json};

const SERVICE_ROLE_KEY: &str = "service-role-key";
const PUBLISHABLE_KEY: &str = "publishable-key";
const OLD_MASTER_KEY_BYTES: [u8; MASTER_KEY_LENGTH] = [11u8; MASTER_KEY_LENGTH];
const NEW_MASTER_KEY_BYTES: [u8; MASTER_KEY_LENGTH] = [12u8; MASTER_KEY_LENGTH];
const LEDGER_SIGNING_KEY_BYTES: [u8; LEDGER_ED25519_SECRET_KEY_LENGTH] =
    [9u8; LEDGER_ED25519_SECRET_KEY_LENGTH];

#[derive(Debug)]
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

struct KeyRotationCliRun {
    output: Output,
    temp_dir: PathBuf,
    fallback_path: PathBuf,
}

fn temp_dir(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    std::env::temp_dir().join(format!("mipsorcu-key-rotation-cli-{test_name}-{unique}"))
}

fn spawn_key_rotation_start_server(
    append_status: u16,
    append_body: &'static str,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let path = request.path.clone();
            let append_success_body = if path == "/rest/v1/rpc/rpc_append_audit_event_with_ledger"
                && append_status == 200
            {
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

            if path == "/rest/v1/rpc/rpc_get_ledger_signing_public_key_status" {
                write_http_response(
                    &mut stream,
                    200,
                    "OK",
                    &ledger_signing_public_key_status_body(),
                )?;
            } else if path.starts_with("/rest/v1/ledger_chain_state") {
                write_http_response(&mut stream, 200, "OK", &ledger_chain_head_body())?;
            } else if append_status == 200 {
                let body = append_success_body.as_deref().unwrap_or(r#""ok""#);
                write_http_response(&mut stream, 200, "OK", body)?;
            } else {
                write_http_response(
                    &mut stream,
                    append_status,
                    "Internal Server Error",
                    append_body,
                )?;
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn run_key_rotation_start(
    supabase_url: &str,
    test_name: &str,
) -> Result<KeyRotationCliRun, Box<dyn std::error::Error>> {
    let temp_dir = temp_dir(test_name);
    let key_dir = temp_dir.join("keys");
    let fallback_path = temp_dir.join("audit-fallback-current.jsonl");
    let fallback_archive_dir = temp_dir.join("audit-fallback-archive");
    fs::create_dir_all(&key_dir)?;
    fs::write(key_dir.join("1.key"), hex::encode(OLD_MASTER_KEY_BYTES))?;
    fs::write(key_dir.join("2.key"), hex::encode(NEW_MASTER_KEY_BYTES))?;

    let output = Command::new(env!("CARGO_BIN_EXE_mipsorcu"))
        .current_dir(&temp_dir)
        .env_clear()
        .env("MIPSORCU_MASTER_KEY_DIR", &key_dir)
        .env("MIPSORCU_ACTIVE_KEY_VERSION", "2")
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
            "key-rotation",
            "start",
            "--old-key-version",
            "1",
            "--new-key-version",
            "2",
        ])
        .output()?;

    Ok(KeyRotationCliRun {
        output,
        temp_dir,
        fallback_path,
    })
}

#[test]
fn key_rotation_start_appends_audit_event_with_signed_ledger_entry()
-> Result<(), Box<dyn std::error::Error>> {
    let (supabase_url, receiver, server_thread) = spawn_key_rotation_start_server(200, r#""ok""#)?;

    let run = run_key_rotation_start(&supabase_url, "success")?;
    let status_request = receiver.recv_timeout(std::time::Duration::from_secs(2))?;
    let chain_request = receiver.recv_timeout(std::time::Duration::from_secs(2))?;
    let audit_request = receiver.recv_timeout(std::time::Duration::from_secs(2))?;
    server_thread
        .join()
        .map_err(|_| std::io::Error::other("key rotation server thread panicked"))??;

    assert!(run.output.status.success());
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    assert!(stdout.contains("key_rotation_start"));
    assert!(stdout.contains("old_key_version=1"));
    assert!(stdout.contains("new_key_version=2"));
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(
        stderr.is_empty(),
        "success stderr should be empty: {stderr}"
    );

    assert_eq!(status_request.method, "POST");
    assert_eq!(
        status_request.path,
        "/rest/v1/rpc/rpc_get_ledger_signing_public_key_status"
    );
    assert_eq!(chain_request.method, "GET");
    assert!(
        chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );
    assert_eq!(audit_request.method, "POST");
    assert_eq!(
        audit_request.path,
        "/rest/v1/rpc/rpc_append_audit_event_with_ledger"
    );

    let body = audit_request
        .body
        .ok_or_else(|| std::io::Error::other("audit request body should be JSON"))?;
    assert_eq!(body["p_action"], "key_rotation_start");
    assert_eq!(body["p_entry_type"], "key_rotation_started");
    assert_eq!(body["p_result"], "success");
    assert_eq!(body["p_key_version"], 2);
    assert_eq!(body["p_metadata_json"]["old_key_version"], 1);
    assert_eq!(body["p_metadata_json"]["new_key_version"], 2);
    assert_eq!(body["p_payload"]["old_key_version"], 1);
    assert_eq!(body["p_payload"]["new_key_version"], 2);
    let source_event_at = body["p_metadata_json"]["source_event_at"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("source_event_at should be present"))?;
    assert!(SourceEventAt::parse(source_event_at).is_ok());
    assert_eq!(
        required_str(&body["p_source_event_at"], "p_source_event_at")?,
        source_event_at
    );
    assert_eq!(
        required_str(&body["p_source_event_id"], "p_source_event_id")?,
        required_str(&body["p_audit_event_id"], "p_audit_event_id")?
    );
    assert_uuid(&body["p_request_id"], "p_request_id")?;
    assert_uuid(&body["p_audit_event_id"], "p_audit_event_id")?;
    assert_uuid(&body["p_source_event_id"], "p_source_event_id")?;
    assert_uuid(&body["p_ledger_entry_id"], "p_ledger_entry_id")?;
    assert_eq!(body["p_target_secret_id"], Value::Null);
    assert_eq!(body["p_target_secret_version_id"], Value::Null);
    assert_eq!(body["p_actor_user_id"], Value::Null);
    assert_eq!(body["p_actor_device_id"], Value::Null);
    assert_eq!(body["p_error_code"], Value::Null);
    assert_eq!(body["p_sequence_no"], 1);
    assert_eq!(
        body["p_canonicalization_version"],
        Value::from(LEDGER_CANONICALIZATION_VERSION_V1)
    );
    assert_eq!(body["p_hash_algorithm"], LEDGER_HASH_ALGORITHM_SHA256);
    assert_eq!(
        body["p_signature_algorithm"],
        LEDGER_SIGNATURE_ALGORITHM_ED25519
    );
    assert_eq!(body["p_signature_key_version"], 1);
    assert_bytea_hex(
        &body["p_previous_entry_hash"],
        "p_previous_entry_hash",
        LEDGER_HASH_LENGTH,
    )?;
    assert_bytea_hex(&body["p_entry_hash"], "p_entry_hash", LEDGER_HASH_LENGTH)?;
    assert_bytea_hex(&body["p_signature"], "p_signature", LEDGER_SIGNATURE_LENGTH)?;

    assert_no_secret_material(&body, "append request body")?;
    assert_no_secret_material(&body["p_metadata_json"], "append metadata")?;
    assert_no_secret_material(&body["p_payload"], "append ledger payload")?;

    fs::remove_dir_all(run.temp_dir)?;

    Ok(())
}

#[test]
fn key_rotation_start_fails_when_append_audit_event_with_ledger_fails()
-> Result<(), Box<dyn std::error::Error>> {
    let (supabase_url, receiver, server_thread) =
        spawn_key_rotation_start_server(500, r#"{"message":"secret internal upstream details"}"#)?;

    let run = run_key_rotation_start(&supabase_url, "append-failure")?;
    let status_request = receiver.recv_timeout(std::time::Duration::from_secs(2))?;
    let chain_request = receiver.recv_timeout(std::time::Duration::from_secs(2))?;
    let audit_request = receiver.recv_timeout(std::time::Duration::from_secs(2))?;
    server_thread
        .join()
        .map_err(|_| std::io::Error::other("key rotation server thread panicked"))??;

    assert!(!run.output.status.success());
    assert_eq!(run.output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    assert!(!stdout.contains("key_rotation_start request_id="));
    assert_eq!(status_request.method, "POST");
    assert_eq!(
        status_request.path,
        "/rest/v1/rpc/rpc_get_ledger_signing_public_key_status"
    );
    assert_eq!(chain_request.method, "GET");
    assert!(
        chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );
    assert_eq!(audit_request.method, "POST");
    assert_eq!(
        audit_request.path,
        "/rest/v1/rpc/rpc_append_audit_event_with_ledger"
    );
    let body = audit_request
        .body
        .ok_or_else(|| std::io::Error::other("audit request body should be JSON"))?;
    assert_eq!(body["p_action"], "key_rotation_start");
    assert_eq!(body["p_entry_type"], "key_rotation_started");
    assert_eq!(body["p_result"], "success");
    assert_eq!(body["p_key_version"], 2);
    assert_eq!(body["p_metadata_json"]["old_key_version"], 1);
    assert_eq!(body["p_metadata_json"]["new_key_version"], 2);
    assert_eq!(body["p_payload"]["old_key_version"], 1);
    assert_eq!(body["p_payload"]["new_key_version"], 2);
    assert_no_secret_material(&body, "failed append request body")?;
    assert_no_secret_material(&body["p_metadata_json"], "failed append metadata")?;
    assert_no_secret_material(&body["p_payload"], "failed append ledger payload")?;

    let stderr = String::from_utf8_lossy(&run.output.stderr);
    let combined_output = format!("{stdout}{stderr}");
    assert!(combined_output.contains("supabase returned status 500"));
    assert!(combined_output.contains("response body length"));
    assert!(!combined_output.contains("secret internal upstream details"));
    assert!(!combined_output.contains(SERVICE_ROLE_KEY));
    assert!(!combined_output.contains(PUBLISHABLE_KEY));
    assert!(!run.fallback_path.exists());

    fs::remove_dir_all(run.temp_dir)?;

    Ok(())
}

fn assert_no_secret_material(
    value: &Value,
    label: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    let serialized = serde_json::to_string(value)?;
    let old_master_key_hex = hex::encode(OLD_MASTER_KEY_BYTES);
    let new_master_key_hex = hex::encode(NEW_MASTER_KEY_BYTES);
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
        old_master_key_hex.as_str(),
        new_master_key_hex.as_str(),
        ledger_signing_key_hex.as_str(),
    ] {
        assert!(
            !serialized.contains(forbidden),
            "{label} should not contain {forbidden}"
        );
    }

    Ok(())
}

fn ledger_chain_head_body() -> String {
    json!([{
        "last_sequence_no": 0,
        "last_entry_hash": "\\x0000000000000000000000000000000000000000000000000000000000000000",
    }])
    .to_string()
}

fn ledger_signing_public_key_status_body() -> String {
    let key = LedgerSigningKey::from_secret_key_bytes(
        LedgerSignatureKeyVersion::new(1).expect("valid key version"),
        &LEDGER_SIGNING_KEY_BYTES,
    )
    .expect("valid signing key")
    .verification_key();

    json!([{
        "key_version": 1,
        "public_key": format!("\\x{}", hex::encode(key.as_bytes())),
        "public_key_fingerprint": key.fingerprint_hex(),
        "algorithm": "ed25519",
        "status": "active",
        "created_at": "2026-05-13T00:00:00Z",
        "activated_at": "2026-05-13T00:00:00Z",
        "retired_at": null
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

fn required_str<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    value
        .as_str()
        .ok_or_else(|| std::io::Error::other(format!("{field} should be a string")).into())
}

fn assert_uuid(value: &Value, field: &'static str) -> Result<(), Box<dyn std::error::Error>> {
    let text = required_str(value, field)?;
    uuid::Uuid::parse_str(text)?;

    Ok(())
}

fn assert_bytea_hex(
    value: &Value,
    field: &'static str,
    expected_byte_len: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let text = required_str(value, field)?;
    let hex_value = text
        .strip_prefix("\\x")
        .ok_or_else(|| std::io::Error::other(format!("{field} should use bytea hex format")))?;

    assert_eq!(hex_value.len(), expected_byte_len * 2, "{field} length");
    assert!(
        hex_value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{field} should contain only hex digits"
    );

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

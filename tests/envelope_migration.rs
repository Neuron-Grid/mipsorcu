use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mipsorcu::{
    ALGORITHM_XCHACHA20_POLY1305, AuditAction, AuditResult, Ciphertext,
    KeyRotationEnvelopeFailedMetadata, KeyRotationEnvelopeMigratedMetadata,
    LEDGER_ED25519_SECRET_KEY_LENGTH, LedgerEntryType, LedgerPayload, LedgerSignatureKeyVersion,
    LedgerSigningKey, MASTER_KEY_LENGTH, MasterKey, Nonce, SecretVersion, SecretVersionId,
    SourceEventAt, WrappedDek, open_v02,
};
use serde::Deserialize;
use serde_json::{Value, json};

const SERVICE_ROLE_KEY: &str = "service-role-key";
const PUBLISHABLE_KEY: &str = "publishable-key";
const V01_FIXTURE_JSON: &str = include_str!("fixtures/v01_envelope/expected.json");
const MASTER_KEY_V1_BYTES: [u8; MASTER_KEY_LENGTH] = [11u8; MASTER_KEY_LENGTH];
const MASTER_KEY_V2_BYTES: [u8; MASTER_KEY_LENGTH] = [12u8; MASTER_KEY_LENGTH];
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

#[derive(Debug, Deserialize)]
struct LegacyEnvelopeFixture {
    secret_id: String,
    owner_user_id: String,
    classification: String,
    created_at: String,
    version: u32,
    key_version: u32,
    plaintext_utf8: String,
    ciphertext_hex: String,
    nonce_hex: String,
    encrypted_data_key_hex: String,
    aad_context: Value,
}

#[test]
fn envelope_migration_audit_and_ledger_vocabulary_is_accepted()
-> Result<(), Box<dyn std::error::Error>> {
    let source_event_at = SourceEventAt::parse("2026-04-08T12:00:00Z")?;
    let migrated = KeyRotationEnvelopeMigratedMetadata::new(100, 99, 1)
        .with_source_event_at(source_event_at.clone())
        .build()?;
    migrated.validate_allowlist_for_action(
        AuditAction::KeyRotationEnvelopeMigrated,
        AuditResult::Success,
    )?;

    let secret_version_id = SecretVersionId::parse("550e8400-e29b-41d4-a716-446655440000")?;
    let failed = KeyRotationEnvelopeFailedMetadata::new(
        secret_version_id,
        SecretVersion::new(7)?,
        "aad_context_mismatch",
    )
    .with_source_event_at(source_event_at)
    .build()?;
    failed.validate_allowlist_for_action(
        AuditAction::KeyRotationEnvelopeFailed,
        AuditResult::Failure,
    )?;

    let payload = LedgerPayload::new(
        LedgerEntryType::EnvelopeMigrationBatchCompleted,
        json!({
            "batch_size": 100,
            "success_count": 99,
            "failure_count": 1,
        }),
    )?;
    assert_eq!(payload.as_value()["success_count"], 99);

    Ok(())
}

#[test]
fn envelope_migration_cli_converts_legacy_fixture_to_decryptable_v02_apply_row()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = legacy_fixture()?;
    let (supabase_url, receiver, server_thread) = spawn_envelope_migration_apply_server(&fixture)?;

    let run = run_key_rotation_migrate(&supabase_url, "envelope-apply")?;
    let public_key_request = receiver.recv_timeout(Duration::from_secs(2))?;
    let list_request = receiver.recv_timeout(Duration::from_secs(2))?;
    let chain_request = receiver.recv_timeout(Duration::from_secs(2))?;
    let apply_request = receiver.recv_timeout(Duration::from_secs(2))?;
    let status_request = receiver.recv_timeout(Duration::from_secs(2))?;
    server_thread
        .join()
        .map_err(|_| std::io::Error::other("envelope apply server thread panicked"))??;

    assert!(run.output.status.success());
    assert_eq!(
        public_key_request.path,
        "/rest/v1/rpc/rpc_get_ledger_signing_public_key_status"
    );
    assert_eq!(
        list_request.path,
        "/rest/v1/rpc/rpc_list_envelope_migration_batch"
    );
    assert_eq!(chain_request.method, "GET");
    assert!(
        chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );
    assert_eq!(
        apply_request.path,
        "/rest/v1/rpc/rpc_apply_envelope_migration_batch"
    );
    assert_eq!(
        status_request.path,
        "/rest/v1/rpc/rpc_envelope_migration_status"
    );

    let list_body = list_request
        .body
        .as_ref()
        .ok_or_else(|| std::io::Error::other("list request body should be JSON"))?;
    assert_eq!(list_body["p_limit"], 1);
    assert_eq!(list_body["p_secret_id"], Value::Null);

    let apply_body = apply_request
        .body
        .as_ref()
        .ok_or_else(|| std::io::Error::other("apply request body should be JSON"))?;
    let rows = apply_body["p_rows"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("p_rows should be an array"))?;
    let failure_rows = apply_body["p_failure_rows"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("p_failure_rows should be an array"))?;
    assert_eq!(rows.len(), 1);
    assert!(failure_rows.is_empty());
    assert_eq!(rows[0]["dek_wrap_algorithm"], "envvar-xchacha-v2");
    assert_eq!(rows[0]["secret_id"], fixture.secret_id);
    assert_eq!(rows[0]["version"], fixture.version);
    assert_eq!(rows[0]["kek_version"], 2);
    assert!(rows[0].get("encrypted_data_key").is_none());
    assert!(rows[0].get("wrapped_dek").is_some());
    assert!(
        apply_body["p_ledger_entry"]["p_payload"]
            .get("wrapped_dek")
            .is_none()
    );
    assert!(
        apply_body["p_ledger_entry"]["p_payload"]
            .get("encrypted_data_key")
            .is_none()
    );

    let decrypted = decrypt_apply_row(&rows[0], &fixture)?;
    assert_eq!(decrypted.as_bytes(), fixture.plaintext_utf8.as_bytes());

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(stdout.contains("\"success_count\": 1"));
    assert!(
        stderr.is_empty(),
        "migration success stderr should be empty: {stderr}"
    );
    assert_no_cli_secret_material(&format!("{stdout}{stderr}"), &fixture)?;
    assert!(!run.fallback_path.exists());

    fs::remove_dir_all(run.temp_dir)?;

    Ok(())
}

#[test]
fn envelope_migration_dry_run_skips_apply_rpc_in_task08_suite()
-> Result<(), Box<dyn std::error::Error>> {
    let (supabase_url, receiver, server_thread) = spawn_envelope_migration_dry_run_server()?;

    let run = run_key_rotation_migrate_dry_run(&supabase_url, "envelope-dry-run-task08")?;
    let public_key_request = receiver.recv_timeout(Duration::from_secs(2))?;
    let status_request = receiver.recv_timeout(Duration::from_secs(2))?;
    let list_request = receiver.recv_timeout(Duration::from_secs(2))?;
    server_thread
        .join()
        .map_err(|_| std::io::Error::other("dry-run server thread panicked"))??;

    assert!(run.output.status.success());
    assert_eq!(
        public_key_request.path,
        "/rest/v1/rpc/rpc_get_ledger_signing_public_key_status"
    );
    assert_eq!(
        status_request.path,
        "/rest/v1/rpc/rpc_envelope_migration_status"
    );
    assert_eq!(
        list_request.path,
        "/rest/v1/rpc/rpc_list_envelope_migration_batch"
    );
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_eq!(parsed["envelope_migration"]["dry_run"], true);
    assert_eq!(parsed["envelope_migration"]["remaining_legacy_rows"], 1);
    assert!(!stdout.contains("rpc_apply_envelope_migration_batch"));
    assert!(!run.fallback_path.exists());

    fs::remove_dir_all(run.temp_dir)?;

    Ok(())
}

fn legacy_fixture() -> Result<LegacyEnvelopeFixture, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(V01_FIXTURE_JSON)?)
}

fn spawn_envelope_migration_apply_server(
    fixture: &LegacyEnvelopeFixture,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let batch_body = legacy_batch_body(fixture)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for _ in 0..5 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let path = request.path.clone();
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
            } else if path == "/rest/v1/rpc/rpc_list_envelope_migration_batch" {
                write_http_response(&mut stream, 200, "OK", &batch_body)?;
            } else if path.starts_with("/rest/v1/ledger_chain_state") {
                write_http_response(&mut stream, 200, "OK", &ledger_chain_head_body())?;
            } else if path == "/rest/v1/rpc/rpc_apply_envelope_migration_batch" {
                write_http_response(
                    &mut stream,
                    200,
                    "OK",
                    r#"[{"success_count":1,"failure_count":0,"remaining_legacy_rows":0,"retry_secret_version_ids":[]}]"#,
                )?;
            } else if path == "/rest/v1/rpc/rpc_envelope_migration_status" {
                write_http_response(
                    &mut stream,
                    200,
                    "OK",
                    r#"[{"total_legacy_rows":0,"last_run_at":"2026-04-08T12:10:00Z","last_batch_size":1,"last_success_count":1,"last_failure_count":0}]"#,
                )?;
            } else {
                write_http_response(&mut stream, 500, "Unexpected Request", r#""unexpected""#)?;
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn spawn_envelope_migration_dry_run_server() -> Result<TestServerHandle, Box<dyn std::error::Error>>
{
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let path = request.path.clone();
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
            } else if path == "/rest/v1/rpc/rpc_envelope_migration_status" {
                write_http_response(
                    &mut stream,
                    200,
                    "OK",
                    r#"[{"total_legacy_rows":1,"last_run_at":null,"last_batch_size":null,"last_success_count":null,"last_failure_count":null}]"#,
                )?;
            } else if path == "/rest/v1/rpc/rpc_list_envelope_migration_batch" {
                write_http_response(&mut stream, 200, "OK", r#"[]"#)?;
            } else {
                write_http_response(&mut stream, 500, "Unexpected Request", r#""unexpected""#)?;
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn legacy_batch_body(
    fixture: &LegacyEnvelopeFixture,
) -> Result<String, Box<dyn std::error::Error>> {
    let version = i32::try_from(fixture.version)?;
    let key_version = i32::try_from(fixture.key_version)?;
    Ok(json!([{
        "id": "650e8400-e29b-41d4-a716-446655440001",
        "secret_id": fixture.secret_id,
        "version": version,
        "ciphertext": format!("\\x{}", fixture.ciphertext_hex),
        "encrypted_data_key": format!("\\x{}", fixture.encrypted_data_key_hex),
        "key_version": key_version,
        "algorithm": ALGORITHM_XCHACHA20_POLY1305,
        "classification": fixture.classification,
        "nonce_or_iv": format!("\\x{}", fixture.nonce_hex),
        "aad_context": fixture.aad_context,
        "created_at": fixture.created_at,
        "owner_user_id": fixture.owner_user_id,
    }])
    .to_string())
}

fn run_key_rotation_migrate(
    supabase_url: &str,
    test_name: &str,
) -> Result<KeyRotationCliRun, Box<dyn std::error::Error>> {
    run_key_rotation_migrate_with_args(
        supabase_url,
        test_name,
        &[
            "key-rotation",
            "--migrate-envelope",
            "--batch-size",
            "1",
            "--max-batches",
            "1",
            "--format",
            "json",
        ],
    )
}

fn run_key_rotation_migrate_dry_run(
    supabase_url: &str,
    test_name: &str,
) -> Result<KeyRotationCliRun, Box<dyn std::error::Error>> {
    run_key_rotation_migrate_with_args(
        supabase_url,
        test_name,
        &[
            "key-rotation",
            "--migrate-envelope",
            "--batch-size",
            "1",
            "--max-batches",
            "1",
            "--dry-run",
            "--format",
            "json",
        ],
    )
}

fn run_key_rotation_migrate_with_args(
    supabase_url: &str,
    test_name: &str,
    args: &[&str],
) -> Result<KeyRotationCliRun, Box<dyn std::error::Error>> {
    let temp_dir = temp_dir(test_name);
    let key_dir = temp_dir.join("keys");
    let fallback_path = temp_dir.join("audit-fallback-current.jsonl");
    let fallback_archive_dir = temp_dir.join("audit-fallback-archive");
    fs::create_dir_all(&key_dir)?;
    fs::write(key_dir.join("1.key"), hex::encode(MASTER_KEY_V1_BYTES))?;
    fs::write(key_dir.join("2.key"), hex::encode(MASTER_KEY_V2_BYTES))?;

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
        .args(args)
        .output()?;

    Ok(KeyRotationCliRun {
        output,
        temp_dir,
        fallback_path,
    })
}

fn temp_dir(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    std::env::temp_dir().join(format!("mipsorcu-envelope-migration-{test_name}-{unique}"))
}

fn decrypt_apply_row(
    row: &Value,
    fixture: &LegacyEnvelopeFixture,
) -> Result<mipsorcu::Plaintext, Box<dyn std::error::Error>> {
    let kek_version = row["kek_version"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| std::io::Error::other("kek_version should be a u32"))?;
    let ciphertext = Ciphertext::new(decode_bytea(required_str(
        &row["ciphertext"],
        "ciphertext",
    )?)?)?;
    let nonce = Nonce::parse(&decode_bytea(required_str(
        &row["nonce_or_iv"],
        "nonce_or_iv",
    )?)?)?;
    let wrapped_dek = WrappedDek::parse(
        mipsorcu::KekVersion::new(kek_version)?,
        &decode_bytea(required_str(&row["wrapped_dek"], "wrapped_dek")?)?,
    )?;
    let aad = mipsorcu::AadV1::from_stored_context(&fixture.aad_context)?;
    let kek = mipsorcu::EnvVarKek::single(
        mipsorcu::KekVersion::new(2)?,
        MasterKey::from_bytes(MASTER_KEY_V2_BYTES),
    )?;

    Ok(open_v02(&kek, &wrapped_dek, &ciphertext, &nonce, &aad)?)
}

fn decode_bytea(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let hex_value = value
        .strip_prefix("\\x")
        .ok_or_else(|| std::io::Error::other("bytea value should use \\x prefix"))?;

    Ok(hex::decode(hex_value)?)
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

fn required_str<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    value
        .as_str()
        .ok_or_else(|| std::io::Error::other(format!("{field} should be a string")).into())
}

fn assert_no_cli_secret_material(
    output: &str,
    fixture: &LegacyEnvelopeFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    for forbidden in [
        fixture.plaintext_utf8.as_str(),
        fixture.encrypted_data_key_hex.as_str(),
        &hex::encode(MASTER_KEY_V1_BYTES),
        &hex::encode(MASTER_KEY_V2_BYTES),
        &hex::encode(LEDGER_SIGNING_KEY_BYTES),
        SERVICE_ROLE_KEY,
        PUBLISHABLE_KEY,
        "master_key",
        "data_key",
        "encrypted_data_key",
        "wrapped_dek",
        "plaintext",
    ] {
        assert!(
            !output.contains(forbidden),
            "CLI output should not contain {forbidden}"
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

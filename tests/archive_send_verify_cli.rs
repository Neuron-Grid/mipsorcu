//! `mipsorcu archive send|verify` CLI 統合テスト（local_dummy backend）。
//!
//! Supabase RPC は scripted mock server で応答を順に返す。backend は
//! `local_dummy`（共有 temp dir）を使い、send が書いた object を verify が一致
//! 確認できることを E2E で検証する。ADR-0032 / ADR-0033 準拠の挙動を確認する:
//! object key は `digests/{YYYY-MM}/digest.json`、出力・ログに秘密情報を出さない。

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use mipsorcu::{
    DigestHash, LEDGER_ED25519_SECRET_KEY_LENGTH, LedgerEntryDraft, LedgerEntryDraftParts,
    LedgerEntryId, LedgerEntryType, LedgerHash, LedgerPayload, LedgerResult, LedgerSequenceNo,
    LedgerSignatureKeyVersion, LedgerSigningKey, MASTER_KEY_LENGTH, MonthlyDigestPeriod, RequestId,
    SourceEventAt, build_monthly_digest_canonical_form,
};
use serde_json::{Value, json};

const SERVICE_ROLE_KEY: &str = "service-role-key";
const PUBLISHABLE_KEY: &str = "publishable-key";
const MASTER_KEY_BYTES: [u8; MASTER_KEY_LENGTH] = [11u8; MASTER_KEY_LENGTH];
const LEDGER_SIGNING_KEY_BYTES: [u8; LEDGER_ED25519_SECRET_KEY_LENGTH] =
    [9u8; LEDGER_ED25519_SECRET_KEY_LENGTH];

const CHAIN_SOURCE_EVENT_AT: &str = "2026-04-15T12:00:00Z";
const DIGEST_GENERATED_AT: &str = "2026-04-30T23:59:59Z";
const TEST_YEAR_MONTH: &str = "2026-04";
const EXPECTED_OBJECT_KEY: &str = "digests/2026-04/digest.json";

#[derive(Debug)]
#[expect(
    dead_code,
    reason = "fields retained for HTTP request capture consistency with other CLI tests"
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

struct ArchiveCliRun {
    output: Output,
    temp_dir: PathBuf,
}

struct ValidTestMaterials {
    entry_hash_hex: String,
    entry_previous_hash_hex: String,
    entry_signature_hex: String,
    digest_hash_hex: String,
    digest_signature_hex: String,
    public_key_hex: String,
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

fn temp_dir(test_name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "mipsorcu-archive-cli-{test_name}-{}",
        unique_suffix()
    ))
}

/// Scripted mock server: serves each response in order, one connection per response.
fn spawn_scripted_server(
    responses: Vec<(u16, String)>,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for (status, body) in responses {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            sender.send(request).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request receiver was dropped",
                )
            })?;
            write_http_response(&mut stream, status, "OK", &body)?;
        }
        Ok(())
    });
    Ok((format!("http://{addr}"), receiver, thread))
}

/// Runs `mipsorcu archive <args>` with a shared `local_dir` for the local_dummy
/// backend. `backend` of `None` omits `MIPSORCU_ARCHIVE_BACKEND` (to test the
/// required-backend guard).
fn run_archive(
    supabase_url: &str,
    test_name: &str,
    local_dir: &Path,
    backend: Option<&str>,
    args: &[&str],
) -> Result<ArchiveCliRun, Box<dyn std::error::Error>> {
    let temp_dir = temp_dir(test_name);
    let key_dir = temp_dir.join("keys");
    let fallback_path = temp_dir.join("audit-fallback-current.jsonl");
    let fallback_archive_dir = temp_dir.join("audit-fallback-archive");
    fs::create_dir_all(&key_dir)?;
    fs::write(key_dir.join("1.key"), hex::encode(MASTER_KEY_BYTES))?;

    let mut command = Command::new(env!("CARGO_BIN_EXE_mipsorcu"));
    command
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
        .env("MIPSORCU_ARCHIVE_LOCAL_DIR", local_dir);

    if let Some(backend) = backend {
        command.env("MIPSORCU_ARCHIVE_BACKEND", backend);
    }

    let output = command.arg("archive").args(args).output()?;

    Ok(ArchiveCliRun { output, temp_dir })
}

/// Builds cryptographically valid materials for a single-entry chain + digest.
fn make_valid_test_materials() -> Result<ValidTestMaterials, Box<dyn std::error::Error>> {
    let key_version = LedgerSignatureKeyVersion::new(1)?;
    let signing_key =
        LedgerSigningKey::from_secret_key_bytes(key_version, &LEDGER_SIGNING_KEY_BYTES)?;

    let entry_type = LedgerEntryType::IntegrityCheckCompleted;
    let source_event_at = SourceEventAt::parse(CHAIN_SOURCE_EVENT_AT)?;
    let request_id = RequestId::parse("00000000-0000-4000-8000-000000000000")?;
    let previous_hash = LedgerHash::genesis();

    let draft = LedgerEntryDraft::new(LedgerEntryDraftParts {
        ledger_entry_id: LedgerEntryId::parse("00000000-0000-4000-8000-000000000000")?,
        sequence_no: LedgerSequenceNo::new(1)?,
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
        payload: LedgerPayload::empty(entry_type)?,
        previous_entry_hash: previous_hash,
        signature_key_version: key_version,
    })?;

    let signed_entry = draft.sign(&signing_key)?;
    let entry_hash = signed_entry.entry_hash();
    let entry_signature = signed_entry.signature();

    let period = MonthlyDigestPeriod::parse(TEST_YEAR_MONTH)?;
    let generated_at = SourceEventAt::parse(DIGEST_GENERATED_AT)?;
    let start_seq = LedgerSequenceNo::new(1)?;
    let end_seq = LedgerSequenceNo::new(1)?;

    let canonical_bytes = build_monthly_digest_canonical_form(
        &period,
        start_seq,
        end_seq,
        entry_hash,
        entry_hash,
        1,
        &generated_at,
        key_version,
    )?;

    let digest_hash = DigestHash::from_canonical_bytes(&canonical_bytes).to_hex();
    let digest_signature = signing_key.sign_raw_bytes(key_version, canonical_bytes.as_bytes())?;
    let public_key_bytes = signing_key.verification_key().as_bytes();

    Ok(ValidTestMaterials {
        entry_hash_hex: entry_hash.to_hex(),
        entry_previous_hash_hex: previous_hash.to_hex(),
        entry_signature_hex: hex::encode(entry_signature.as_bytes()),
        digest_hash_hex: digest_hash,
        digest_signature_hex: hex::encode(digest_signature.as_bytes()),
        public_key_hex: hex::encode(public_key_bytes),
    })
}

/// `rpc_fetch_monthly_digest_for_verification` 成功応答（1 行）。
fn digest_materials_body(m: &ValidTestMaterials) -> String {
    json!([{
        "start_sequence_no": 1i64,
        "end_sequence_no": 1i64,
        "stored_entry_count": 1i64,
        "stored_digest_hash": m.digest_hash_hex,
        "target_year_month": TEST_YEAR_MONTH,
        "digest_generated_at": DIGEST_GENERATED_AT,
        "signature": format!("\\x{}", m.entry_signature_hex),
        "sbc_signature": m.digest_signature_hex,
        "signature_key_version": 1i32,
        "public_key": format!("\\x{}", m.public_key_hex),
        "start_entry_hash": format!("\\x{}", m.entry_hash_hex),
        "end_entry_hash": format!("\\x{}", m.entry_hash_hex),
    }])
    .to_string()
}

/// `rpc_export_ledger_verification_materials`（1 件の有効 chain entry）。
fn chain_export_body(m: &ValidTestMaterials) -> String {
    json!([{
        "ledger_entry_id": "00000000-0000-4000-8000-000000000000",
        "sequence_no": 1i64,
        "entry_hash": format!("\\x{}", m.entry_hash_hex),
        "previous_entry_hash": format!("\\x{}", m.entry_previous_hash_hex),
        "signature": format!("\\x{}", m.entry_signature_hex),
        "signature_key_version": 1i32,
        "entry_type": "integrity_check_completed",
        "source_event_at": CHAIN_SOURCE_EVENT_AT,
        "request_id": "00000000-0000-4000-8000-000000000000",
        "source_event_id": Value::Null,
        "target_secret_id": Value::Null,
        "target_secret_version_id": Value::Null,
        "actor_user_id": Value::Null,
        "actor_device_id": Value::Null,
        "result": "success",
        "error_code": Value::Null,
        "payload": {},
        "canonicalization_version": 1i32,
        "hash_algorithm": "sha3-256",
        "signature_algorithm": "ed25519",
        "pk_key_version": 1i32,
        "pk_public_key": format!("\\x{}", m.public_key_hex),
        "pk_algorithm": "ed25519",
        "pk_status": "active",
        "pk_created_at": Value::Null,
        "pk_retired_at": Value::Null,
    }])
    .to_string()
}

/// `rpc_fetch_ledger_range_for_month`（digest range と一致）。
fn range_body(m: &ValidTestMaterials) -> String {
    json!([{
        "start_sequence_no": 1i64,
        "end_sequence_no": 1i64,
        "start_entry_hash": format!("\\x{}", m.entry_hash_hex),
        "end_entry_hash": format!("\\x{}", m.entry_hash_hex),
        "entry_count": 1i64,
    }])
    .to_string()
}

/// `ledger_chain_state` GET 応答（chain head）。
fn chain_state_body(m: &ValidTestMaterials) -> String {
    json!([{
        "last_sequence_no": 1i64,
        "last_entry_hash": format!("\\x{}", m.entry_hash_hex),
    }])
    .to_string()
}

/// `rpc_append_ledger_entry` 成功応答。
fn append_body(m: &ValidTestMaterials) -> String {
    json!([{
        "ledger_entry_id": "a0000000-0000-4000-8000-000000000099",
        "sequence_no": 2i64,
        "entry_hash": format!("\\x{}", m.entry_hash_hex),
        "chain_last_sequence_no": 2i64,
        "chain_last_entry_hash": format!("\\x{}", m.entry_hash_hex),
        "replayed": false,
    }])
    .to_string()
}

/// send が成功するときの完全な RPC 応答列（local_dummy backend）。
fn send_success_responses(m: &ValidTestMaterials) -> Vec<(u16, String)> {
    vec![
        // verify_monthly_digest: fetch -> chain export -> range
        (200, digest_materials_body(m)),
        (200, chain_export_body(m)),
        (200, range_body(m)),
        // monthly_digest_verify 成功 audit
        (200, r#""ok""#.to_owned()),
        // 再構成のための再 fetch
        (200, digest_materials_body(m)),
        // ledger append: chain head GET -> append POST
        (200, chain_state_body(m)),
        (200, append_body(m)),
        // archive_export 成功 audit
        (200, r#""ok""#.to_owned()),
    ]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn send_then_verify_match() -> Result<(), Box<dyn std::error::Error>> {
    let m = make_valid_test_materials()?;
    let local_dir = temp_dir("shared-local");
    fs::create_dir_all(&local_dir)?;

    // 1. send（8 RPC）
    let (send_url, send_rx, send_server) = spawn_scripted_server(send_success_responses(&m))?;
    let send = run_archive(
        &send_url,
        "send",
        &local_dir,
        Some("local_dummy"),
        &["send", "--month", TEST_YEAR_MONTH, "--format", "json"],
    )?;
    send_server
        .join()
        .map_err(|_| std::io::Error::other("send server thread panicked"))??;

    assert!(
        send.output.status.success(),
        "expected exit 0 for archive send, stderr={}",
        String::from_utf8_lossy(&send.output.stderr)
    );
    let send_stdout = String::from_utf8_lossy(&send.output.stdout);
    let send_parsed: Value = serde_json::from_str(&send_stdout)?;
    assert_eq!(send_parsed["period"], TEST_YEAR_MONTH);
    assert_eq!(send_parsed["object_key"], EXPECTED_OBJECT_KEY);
    assert_eq!(send_parsed["backend_kind"], "local_dummy");
    assert_eq!(send_parsed["digest_hash"], m.digest_hash_hex);

    // object が local dir に書かれていること
    assert!(
        local_dir.join(EXPECTED_OBJECT_KEY).exists(),
        "archive object should be written to the shared local dir"
    );

    let send_requests: Vec<CapturedRequest> = send_rx.try_iter().collect();
    let verify_audit = send_requests
        .iter()
        .find(|request| {
            request
                .path
                .ends_with("/rest/v1/rpc/rpc_append_audit_event")
                && request
                    .body
                    .as_ref()
                    .is_some_and(|body| body["p_action"] == "monthly_digest_verify")
        })
        .expect("archive send should audit successful monthly digest verification");
    let verify_audit_body = verify_audit
        .body
        .as_ref()
        .expect("verify audit request should carry a JSON body");
    assert_eq!(verify_audit_body["p_result"], "success");
    assert_eq!(
        verify_audit_body["p_metadata_json"]["target_year_month"],
        TEST_YEAR_MONTH
    );
    assert_eq!(
        verify_audit_body["p_metadata_json"]["verify_result"],
        "valid"
    );

    let archive_audit = send_requests
        .iter()
        .find(|request| {
            request
                .path
                .ends_with("/rest/v1/rpc/rpc_append_audit_event")
                && request
                    .body
                    .as_ref()
                    .is_some_and(|body| body["p_action"] == "archive_export")
        })
        .expect("archive send should audit archive_export success");
    let archive_audit_body = archive_audit
        .body
        .as_ref()
        .expect("archive audit request should carry a JSON body");
    assert_eq!(archive_audit_body["p_result"], "success");

    // 2. verify（1 RPC）— 同じ local dir を見て一致
    let (verify_url, _verify_rx, verify_server) =
        spawn_scripted_server(vec![(200, digest_materials_body(&m))])?;
    let verify = run_archive(
        &verify_url,
        "verify",
        &local_dir,
        Some("local_dummy"),
        &["verify", "--month", TEST_YEAR_MONTH, "--format", "json"],
    )?;
    verify_server
        .join()
        .map_err(|_| std::io::Error::other("verify server thread panicked"))??;

    assert!(
        verify.output.status.success(),
        "expected exit 0 for archive verify (match), stderr={}",
        String::from_utf8_lossy(&verify.output.stderr)
    );
    let verify_stdout = String::from_utf8_lossy(&verify.output.stdout);
    let verify_parsed: Value = serde_json::from_str(&verify_stdout)?;
    assert_eq!(verify_parsed["period"], TEST_YEAR_MONTH);
    assert_eq!(verify_parsed["object_key"], EXPECTED_OBJECT_KEY);
    assert_eq!(verify_parsed["verify_result"], "match");
    assert_eq!(verify_parsed["backend_kind"], "local_dummy");

    // 秘密情報が send/verify いずれの出力にも漏れていないこと
    let combined = format!(
        "{send_stdout}{}{verify_stdout}{}",
        String::from_utf8_lossy(&send.output.stderr),
        String::from_utf8_lossy(&verify.output.stderr),
    );
    let ledger_signing_key_hex = hex::encode(LEDGER_SIGNING_KEY_BYTES);
    assert!(!combined.contains(&ledger_signing_key_hex));
    assert!(!combined.contains(SERVICE_ROLE_KEY));
    assert!(!combined.contains(PUBLISHABLE_KEY));
    assert!(!combined.contains("ciphertext"));
    assert!(!combined.contains("wrapped_dek"));
    assert!(!combined.contains("encrypted_data_key"));
    assert!(!combined.contains("nonce_or_iv"));

    fs::remove_dir_all(&local_dir)?;
    fs::remove_dir_all(send.temp_dir)?;
    fs::remove_dir_all(verify.temp_dir)?;
    Ok(())
}

#[test]
fn send_digest_not_found_exit_2() -> Result<(), Box<dyn std::error::Error>> {
    // verify_monthly_digest の fetch が空 → DigestNotFound → verify 失敗 audit を記録
    let local_dir = temp_dir("notfound-local");
    fs::create_dir_all(&local_dir)?;
    let (url, _rx, server) =
        spawn_scripted_server(vec![(200, "[]".to_owned()), (200, r#""ok""#.to_owned())])?;

    let run = run_archive(
        &url,
        "send-not-found",
        &local_dir,
        Some("local_dummy"),
        &["send", "--month", TEST_YEAR_MONTH, "--format", "json"],
    )?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected exit non-zero when digest is missing"
    );
    assert_eq!(run.output.status.code(), Some(2));
    assert!(
        !local_dir.join(EXPECTED_OBJECT_KEY).exists(),
        "no archive object should be written when send aborts"
    );

    fs::remove_dir_all(&local_dir)?;
    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn verify_not_found_exit_2() -> Result<(), Box<dyn std::error::Error>> {
    // object が存在しない local dir に対する verify → not_found（incident は suppress）
    let m = make_valid_test_materials()?;
    let local_dir = temp_dir("verify-missing-local");
    fs::create_dir_all(&local_dir)?;

    let (url, _rx, server) = spawn_scripted_server(vec![
        (200, digest_materials_body(&m)),
        // incident_recently_seen → suppressed（追加 RPC を発生させない）
        (200, "true".to_owned()),
    ])?;

    let run = run_archive(
        &url,
        "verify-missing",
        &local_dir,
        Some("local_dummy"),
        &["verify", "--month", TEST_YEAR_MONTH, "--format", "json"],
    )?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected exit non-zero when archived object is missing"
    );
    assert_eq!(run.output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_eq!(parsed["verify_result"], "not_found");

    fs::remove_dir_all(&local_dir)?;
    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn send_requires_backend_selection_exit_2() -> Result<(), Box<dyn std::error::Error>> {
    // MIPSORCU_ARCHIVE_BACKEND 未設定 → verify と成功監査、再 fetch 後に build_backend で失敗
    let m = make_valid_test_materials()?;
    let local_dir = temp_dir("no-backend-local");
    fs::create_dir_all(&local_dir)?;

    let (url, _rx, server) = spawn_scripted_server(vec![
        (200, digest_materials_body(&m)),
        (200, chain_export_body(&m)),
        (200, range_body(&m)),
        (200, r#""ok""#.to_owned()),
        (200, digest_materials_body(&m)),
    ])?;

    let run = run_archive(
        &url,
        "no-backend",
        &local_dir,
        None,
        &["send", "--month", TEST_YEAR_MONTH, "--format", "json"],
    )?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected exit non-zero when MIPSORCU_ARCHIVE_BACKEND is unset"
    );
    assert_eq!(run.output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(
        stderr.contains("MIPSORCU_ARCHIVE_BACKEND"),
        "error should name the required backend env var, stderr={stderr}"
    );

    fs::remove_dir_all(&local_dir)?;
    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

// ─── HTTP mock server helpers ─────────────────────────────────────────────────

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

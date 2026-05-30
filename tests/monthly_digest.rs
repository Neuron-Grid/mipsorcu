//! 月次 digest CLI（`generate` / `list`）の integration test。
//!
//! verify サブコマンドは `tests/digest_verify_cli.rs` が担保するため、本ファイルは
//! `list`（Task 09 で追加）と `generate` の重複失敗パスを対象とする。
//!
//! 信頼境界ノート: 出力に署名鍵・service role key・平文が漏れないことを検証する。

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use mipsorcu::{
    LEDGER_ED25519_SECRET_KEY_LENGTH, LedgerSignatureKeyVersion, LedgerSigningKey,
    MASTER_KEY_LENGTH,
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

struct DigestCliRun {
    output: Output,
    temp_dir: PathBuf,
}

fn temp_dir(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("mipsorcu-monthly-digest-cli-{test_name}-{unique}"))
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

/// Runs `mipsorcu digest <args...>` against the given mock Supabase URL.
fn run_digest(
    supabase_url: &str,
    test_name: &str,
    digest_args: &[&str],
) -> Result<DigestCliRun, Box<dyn std::error::Error>> {
    let temp_dir = temp_dir(test_name);
    let key_dir = temp_dir.join("keys");
    let fallback_path = temp_dir.join("audit-fallback-current.jsonl");
    let fallback_archive_dir = temp_dir.join("audit-fallback-archive");
    fs::create_dir_all(&key_dir)?;
    fs::write(key_dir.join("1.key"), hex::encode(MASTER_KEY_BYTES))?;

    let mut args = vec!["digest"];
    args.extend_from_slice(digest_args);

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
        .args(&args)
        .output()?;

    Ok(DigestCliRun { output, temp_dir })
}

/// Hex of the configured ledger signing key's public (verification) key.
fn configured_public_key_hex() -> Result<String, Box<dyn std::error::Error>> {
    let key_version = LedgerSignatureKeyVersion::new(1)?;
    let signing_key =
        LedgerSigningKey::from_secret_key_bytes(key_version, &LEDGER_SIGNING_KEY_BYTES)?;
    Ok(hex::encode(signing_key.verification_key().as_bytes()))
}

/// JSON body for `rpc_get_ledger_signing_public_key_status` (active, matching key).
fn active_key_status_body(public_key_hex: &str) -> String {
    json!([{
        "key_version": 1i32,
        "public_key": format!("\\x{public_key_hex}"),
        "public_key_fingerprint": "test-fingerprint",
        "algorithm": "ed25519",
        "status": "active",
        "created_at": "2026-01-01T00:00:00Z",
        "activated_at": "2026-01-01T00:00:00Z",
        "retired_at": Value::Null,
    }])
    .to_string()
}

/// JSON body for `rpc_list_monthly_digests` with two recorded digests.
fn list_body_two_rows() -> String {
    json!([
        {
            "target_year_month": "2026-03",
            "start_sequence_no": 1i64,
            "end_sequence_no": 40i64,
            "entry_count": 40i64,
            "signature_key_version": 1i32,
            "digest_generated_at": "2026-03-31T23:59:59Z",
        },
        {
            "target_year_month": "2026-04",
            "start_sequence_no": 41i64,
            "end_sequence_no": 90i64,
            "entry_count": 50i64,
            "signature_key_version": 1i32,
            "digest_generated_at": "2026-04-30T23:59:59Z",
        }
    ])
    .to_string()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn list_returns_recorded_digests() -> Result<(), Box<dyn std::error::Error>> {
    let (url, _receiver, server) = spawn_scripted_server(vec![(200, list_body_two_rows())])?;

    let run = run_digest(&url, "list-two", &["list", "--format", "json"])?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        run.output.status.success(),
        "expected exit 0 for digest list, stderr={}",
        String::from_utf8_lossy(&run.output.stderr)
    );

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    let digests = parsed["digests"]
        .as_array()
        .ok_or("digests should be an array")?;
    assert_eq!(digests.len(), 2);

    assert_eq!(digests[0]["period"], "2026-03");
    assert_eq!(digests[0]["start_sequence_no"], 1);
    assert_eq!(digests[0]["end_sequence_no"], 40);
    assert_eq!(digests[0]["entry_count"], 40);
    assert_eq!(digests[0]["signature_key_version"], 1);
    assert_eq!(digests[0]["digest_generated_at"], "2026-03-31T23:59:59Z");

    assert_eq!(digests[1]["period"], "2026-04");
    assert_eq!(digests[1]["entry_count"], 50);

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn list_empty_returns_empty_array() -> Result<(), Box<dyn std::error::Error>> {
    let (url, _receiver, server) = spawn_scripted_server(vec![(200, "[]".to_owned())])?;

    let run = run_digest(&url, "list-empty", &["list", "--format", "json"])?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        run.output.status.success(),
        "expected exit 0 for empty list"
    );

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_eq!(parsed["digests"], json!([]));

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn list_does_not_leak_secret_material() -> Result<(), Box<dyn std::error::Error>> {
    let (url, _receiver, server) = spawn_scripted_server(vec![(200, list_body_two_rows())])?;

    let run = run_digest(&url, "list-no-secrets", &["list", "--format", "json"])?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    let combined = format!("{stdout}{stderr}");

    let ledger_signing_key_hex = hex::encode(LEDGER_SIGNING_KEY_BYTES);
    assert!(!combined.contains(&ledger_signing_key_hex));
    assert!(!combined.contains(SERVICE_ROLE_KEY));
    assert!(!combined.contains(PUBLISHABLE_KEY));
    assert!(!combined.contains("plaintext"));
    assert!(!combined.contains("master_key"));
    // list は hash / signature を返さない
    assert!(!combined.contains("digest_hash"));
    assert!(!combined.contains("sbc_signature"));

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn list_rpc_error_exit_2() -> Result<(), Box<dyn std::error::Error>> {
    let (url, _receiver, server) = spawn_scripted_server(vec![(
        500,
        r#"{"message":"internal server error"}"#.to_owned(),
    )])?;

    let run = run_digest(&url, "list-error", &["list", "--format", "json"])?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected non-zero exit on list RPC failure"
    );
    assert_eq!(run.output.status.code(), Some(2));

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&run.output.stdout),
        String::from_utf8_lossy(&run.output.stderr)
    );
    // 上流のレスポンス本文を漏らさない
    assert!(!combined.contains("internal server error"));

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn generate_duplicate_month_exit_2() -> Result<(), Box<dyn std::error::Error>> {
    let public_key_hex = configured_public_key_hex()?;

    // 1. 署名鍵 status（active・一致）→ 2. 重複チェック exists=true → 3. 失敗 audit
    let (url, _receiver, server) = spawn_scripted_server(vec![
        (200, active_key_status_body(&public_key_hex)),
        (200, r#"[{"exists":true}]"#.to_owned()),
        (200, r#""ok""#.to_owned()),
    ])?;

    let run = run_digest(
        &url,
        "generate-duplicate",
        &["generate", "--year-month", "2026-04", "--format", "json"],
    )?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected non-zero exit when digest already exists for the month"
    );
    assert_eq!(run.output.status.code(), Some(2));

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&run.output.stdout),
        String::from_utf8_lossy(&run.output.stderr)
    );
    let ledger_signing_key_hex = hex::encode(LEDGER_SIGNING_KEY_BYTES);
    assert!(!combined.contains(&ledger_signing_key_hex));
    assert!(!combined.contains(SERVICE_ROLE_KEY));

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn generate_success_records_success_audit_without_poison() -> Result<(), Box<dyn std::error::Error>>
{
    let public_key_hex = configured_public_key_hex()?;
    let hash_hex = "ab".repeat(32);
    let range_body = json!([{
        "start_sequence_no": 1i64,
        "end_sequence_no": 40i64,
        "start_entry_hash": format!("\\x{hash_hex}"),
        "end_entry_hash": format!("\\x{hash_hex}"),
        "entry_count": 40i64,
    }])
    .to_string();
    let chain_state_body = json!([{
        "last_sequence_no": 40i64,
        "last_entry_hash": format!("\\x{hash_hex}"),
    }])
    .to_string();
    let append_body = json!([{
        "ledger_entry_id": "a0000000-0000-4000-8000-000000000099",
        "sequence_no": 41i64,
        "entry_hash": format!("\\x{hash_hex}"),
        "chain_last_sequence_no": 41i64,
        "chain_last_entry_hash": format!("\\x{hash_hex}"),
        "replayed": false,
    }])
    .to_string();

    // 1. 署名鍵 status（active・一致）→ 2. 重複チェック exists=false →
    // 3. 範囲取得 → 4. chain head 取得 → 5. ledger 追記 → 6. 成功 audit
    let (url, receiver, server) = spawn_scripted_server(vec![
        (200, active_key_status_body(&public_key_hex)),
        (200, r#"[{"exists":false}]"#.to_owned()),
        (200, range_body),
        (200, chain_state_body),
        (200, append_body),
        (200, r#""ok""#.to_owned()),
    ])?;

    let run = run_digest(
        &url,
        "generate-success",
        &["generate", "--year-month", "2026-05", "--format", "json"],
    )?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        run.output.status.success(),
        "expected exit 0 for successful generate, stderr={}",
        String::from_utf8_lossy(&run.output.stderr)
    );

    // 生成成功は monthly_digest_generate/success として rpc_append_audit_event に送られる。
    let requests: Vec<CapturedRequest> = receiver.try_iter().collect();
    let audit_request = requests
        .iter()
        .find(|request| request.path.contains("rpc_append_audit_event"))
        .expect("rpc_append_audit_event should be called on generate success");
    let body = audit_request
        .body
        .as_ref()
        .expect("audit request should carry a JSON body");
    assert_eq!(body["p_action"], "monthly_digest_generate");
    assert_eq!(body["p_result"], "success");
    assert_eq!(body["p_metadata_json"]["target_year_month"], "2026-05");

    // 成功時は audit fallback の poison entry が書かれないこと。
    let fallback_path = run.temp_dir.join("audit-fallback-current.jsonl");
    let fallback_empty = match fs::read_to_string(&fallback_path) {
        Ok(contents) => contents.trim().is_empty(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => return Err(error.into()),
    };
    assert!(
        fallback_empty,
        "no audit fallback poison entry should be written on generate success"
    );

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

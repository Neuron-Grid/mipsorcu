use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
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

struct ValidTestMaterials {
    entry_hash_hex: String,
    entry_previous_hash_hex: String,
    entry_signature_hex: String,
    digest_hash_hex: String,
    digest_signature_hex: String,
    public_key_hex: String,
}

fn temp_dir(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("mipsorcu-digest-verify-cli-{test_name}-{unique}"))
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

fn run_digest_verify(
    supabase_url: &str,
    test_name: &str,
    year_month: &str,
) -> Result<DigestCliRun, Box<dyn std::error::Error>> {
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
            "digest",
            "verify",
            "--year-month",
            year_month,
            "--format",
            "json",
        ])
        .output()?;

    Ok(DigestCliRun { output, temp_dir })
}

/// Builds cryptographically valid test materials for a single-entry chain + digest.
///
/// Uses placeholder IDs matching `try_restore_signed_ledger_entry` so that
/// `verify_ledger_chain` accepts the chain export mock response.
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

/// JSON body for `rpc_fetch_monthly_digest_for_verification` (success, 1 row).
fn digest_materials_body(m: &ValidTestMaterials) -> String {
    json!([{
        "start_sequence_no": 1i64,
        "end_sequence_no": 1i64,
        "stored_entry_count": 1i64,
        "stored_digest_hash": m.digest_hash_hex,
        "target_year_month": TEST_YEAR_MONTH,
        "digest_generated_at": DIGEST_GENERATED_AT,
        "signature": format!("\\x{}", m.digest_signature_hex),
        "signature_key_version": 1i32,
        "public_key": format!("\\x{}", m.public_key_hex),
        "start_entry_hash": format!("\\x{}", m.entry_hash_hex),
        "end_entry_hash": format!("\\x{}", m.entry_hash_hex),
    }])
    .to_string()
}

/// JSON body for `rpc_export_ledger_verification_materials` (1 valid chain entry).
fn chain_export_body(m: &ValidTestMaterials) -> String {
    chain_export_body_with_entry_hash(m, &m.entry_hash_hex)
}

fn chain_export_body_with_entry_hash(m: &ValidTestMaterials, entry_hash_hex: &str) -> String {
    json!([{
        "ledger_entry_id": "00000000-0000-4000-8000-000000000000",
        "sequence_no": 1i64,
        "entry_hash": format!("\\x{entry_hash_hex}"),
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
        "hash_algorithm": "sha-256",
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

/// JSON body for `rpc_fetch_ledger_range_for_month` (matches stored digest range).
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

/// chain export where entry_hash is zeros — triggers chain hash mismatch.
fn chain_export_body_tampered_entry_hash(m: &ValidTestMaterials) -> String {
    let zero_hash = "0".repeat(64);
    chain_export_body_with_entry_hash(m, &zero_hash)
}

/// digest materials where end_entry_hash is zeros — triggers end hash mismatch.
fn digest_materials_body_wrong_end_hash(m: &ValidTestMaterials) -> String {
    let zero_hash = "0".repeat(64);
    json!([{
        "start_sequence_no": 1i64,
        "end_sequence_no": 1i64,
        "stored_entry_count": 1i64,
        "stored_digest_hash": m.digest_hash_hex,
        "target_year_month": TEST_YEAR_MONTH,
        "digest_generated_at": DIGEST_GENERATED_AT,
        "signature": format!("\\x{}", m.digest_signature_hex),
        "signature_key_version": 1i32,
        "public_key": format!("\\x{}", m.public_key_hex),
        "start_entry_hash": format!("\\x{}", m.entry_hash_hex),
        "end_entry_hash": format!("\\x{zero_hash}"),
    }])
    .to_string()
}

/// digest materials where public_key is null — triggers unknown signature key.
fn digest_materials_body_null_key(m: &ValidTestMaterials) -> String {
    json!([{
        "start_sequence_no": 1i64,
        "end_sequence_no": 1i64,
        "stored_entry_count": 1i64,
        "stored_digest_hash": m.digest_hash_hex,
        "target_year_month": TEST_YEAR_MONTH,
        "digest_generated_at": DIGEST_GENERATED_AT,
        "signature": format!("\\x{}", m.digest_signature_hex),
        "signature_key_version": 1i32,
        "public_key": Value::Null,
        "start_entry_hash": format!("\\x{}", m.entry_hash_hex),
        "end_entry_hash": format!("\\x{}", m.entry_hash_hex),
    }])
    .to_string()
}

/// digest materials where stored_digest_hash is wrong — triggers hash mismatch.
fn digest_materials_body_wrong_digest_hash(m: &ValidTestMaterials) -> String {
    let wrong_hash = "cd".repeat(32);
    json!([{
        "start_sequence_no": 1i64,
        "end_sequence_no": 1i64,
        "stored_entry_count": 1i64,
        "stored_digest_hash": wrong_hash,
        "target_year_month": TEST_YEAR_MONTH,
        "digest_generated_at": DIGEST_GENERATED_AT,
        "signature": format!("\\x{}", m.digest_signature_hex),
        "signature_key_version": 1i32,
        "public_key": format!("\\x{}", m.public_key_hex),
        "start_entry_hash": format!("\\x{}", m.entry_hash_hex),
        "end_entry_hash": format!("\\x{}", m.entry_hash_hex),
    }])
    .to_string()
}

/// digest materials where signature has first byte flipped — triggers signature invalid.
fn digest_materials_body_wrong_signature(m: &ValidTestMaterials) -> String {
    let mut sig_bytes = hex::decode(&m.digest_signature_hex).expect("valid hex");
    sig_bytes[0] ^= 0xff;
    let wrong_sig = hex::encode(sig_bytes);
    json!([{
        "start_sequence_no": 1i64,
        "end_sequence_no": 1i64,
        "stored_entry_count": 1i64,
        "stored_digest_hash": m.digest_hash_hex,
        "target_year_month": TEST_YEAR_MONTH,
        "digest_generated_at": DIGEST_GENERATED_AT,
        "signature": format!("\\x{wrong_sig}"),
        "signature_key_version": 1i32,
        "public_key": format!("\\x{}", m.public_key_hex),
        "start_entry_hash": format!("\\x{}", m.entry_hash_hex),
        "end_entry_hash": format!("\\x{}", m.entry_hash_hex),
    }])
    .to_string()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn digest_not_found_exit_2() -> Result<(), Box<dyn std::error::Error>> {
    // fetch_monthly_digest_for_verification returns empty → DigestNotFound
    // then audit event is recorded (failure path)
    let (url, _receiver, server) =
        spawn_scripted_server(vec![(200, "[]".to_owned()), (200, r#""ok""#.to_owned())])?;

    let run = run_digest_verify(&url, "not-found", TEST_YEAR_MONTH)?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected exit non-zero when digest not found"
    );
    assert_eq!(run.output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_eq!(parsed["valid"], false);
    assert_eq!(parsed["period"], TEST_YEAR_MONTH);
    assert_eq!(parsed["error"]["code"], "monthly_digest_not_found");

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn digest_fetch_rpc_error_exit_2() -> Result<(), Box<dyn std::error::Error>> {
    // fetch_monthly_digest_for_verification returns 500 → FetchFailed
    // then audit event is recorded (failure path)
    let (url, _receiver, server) = spawn_scripted_server(vec![
        (500, r#"{"message":"internal server error"}"#.to_owned()),
        (200, r#""ok""#.to_owned()),
    ])?;

    let run = run_digest_verify(&url, "fetch-error", TEST_YEAR_MONTH)?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected exit non-zero on RPC fetch failure"
    );
    assert_eq!(run.output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(!combined.contains("internal server error"));

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn valid_digest_exit_0() -> Result<(), Box<dyn std::error::Error>> {
    let m = make_valid_test_materials()?;

    let (url, _receiver, server) = spawn_scripted_server(vec![
        (200, digest_materials_body(&m)),
        (200, chain_export_body(&m)),
        (200, range_body(&m)),
    ])?;

    let run = run_digest_verify(&url, "valid", TEST_YEAR_MONTH)?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        run.output.status.success(),
        "expected exit 0 for valid digest"
    );

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_eq!(parsed["valid"], true);
    assert_eq!(parsed["period"], TEST_YEAR_MONTH);
    assert_eq!(parsed["start_sequence_no"], 1);
    assert_eq!(parsed["end_sequence_no"], 1);
    assert_eq!(parsed["entry_count"], 1);
    assert_eq!(parsed["error"], Value::Null);

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn range_modified_after_digest_exit_2() -> Result<(), Box<dyn std::error::Error>> {
    let m = make_valid_test_materials()?;

    let modified_range = json!([{
        "start_sequence_no": 1i64,
        "end_sequence_no": 2i64,
        "start_entry_hash": format!("\\x{}", m.entry_hash_hex),
        "end_entry_hash": format!("\\x{}", m.entry_hash_hex),
        "entry_count": 2i64,
    }])
    .to_string();

    let (url, _receiver, server) = spawn_scripted_server(vec![
        (200, digest_materials_body(&m)),
        (200, chain_export_body(&m)),
        (200, modified_range),
        (200, r#""ok""#.to_owned()),
        (200, "true".to_owned()),
    ])?;

    let run = run_digest_verify(&url, "range-modified", TEST_YEAR_MONTH)?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected exit non-zero when range was modified"
    );
    assert_eq!(run.output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_eq!(parsed["valid"], false);
    assert_eq!(parsed["error"]["code"], "monthly_digest_range_modified");

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn no_secret_material_in_output() -> Result<(), Box<dyn std::error::Error>> {
    let m = make_valid_test_materials()?;

    let (url, _receiver, server) = spawn_scripted_server(vec![
        (200, digest_materials_body(&m)),
        (200, chain_export_body(&m)),
        (200, range_body(&m)),
    ])?;

    let run = run_digest_verify(&url, "no-secrets", TEST_YEAR_MONTH)?;
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

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn chain_broken_exit_2() -> Result<(), Box<dyn std::error::Error>> {
    let m = make_valid_test_materials()?;

    let (url, _receiver, server) = spawn_scripted_server(vec![
        (200, digest_materials_body(&m)),
        (200, chain_export_body_tampered_entry_hash(&m)),
        (200, r#""ok""#.to_owned()),
        (200, "true".to_owned()),
    ])?;

    let run = run_digest_verify(&url, "chain-broken", TEST_YEAR_MONTH)?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected exit non-zero when chain entry hash is tampered"
    );
    assert_eq!(run.output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_eq!(parsed["valid"], false);
    assert_eq!(
        parsed["error"]["code"],
        "monthly_digest_chain_continuity_error"
    );

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn end_hash_mismatch_exit_2() -> Result<(), Box<dyn std::error::Error>> {
    let m = make_valid_test_materials()?;

    let (url, _receiver, server) = spawn_scripted_server(vec![
        (200, digest_materials_body_wrong_end_hash(&m)),
        (200, chain_export_body(&m)),
        (200, r#""ok""#.to_owned()),
        (200, "true".to_owned()),
    ])?;

    let run = run_digest_verify(&url, "end-hash-mismatch", TEST_YEAR_MONTH)?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected exit non-zero when end_entry_hash in digest materials is wrong"
    );
    assert_eq!(run.output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_eq!(parsed["valid"], false);
    assert_eq!(parsed["error"]["code"], "monthly_digest_end_hash_mismatch");

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn unknown_signature_key_exit_2() -> Result<(), Box<dyn std::error::Error>> {
    let m = make_valid_test_materials()?;

    let (url, _receiver, server) = spawn_scripted_server(vec![
        (200, digest_materials_body_null_key(&m)),
        (200, chain_export_body(&m)),
        (200, r#""ok""#.to_owned()),
        (200, "true".to_owned()),
    ])?;

    let run = run_digest_verify(&url, "unknown-key", TEST_YEAR_MONTH)?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected exit non-zero when public key is null (key not registered)"
    );
    assert_eq!(run.output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_eq!(parsed["valid"], false);
    assert_eq!(
        parsed["error"]["code"],
        "monthly_digest_unknown_signature_key"
    );

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn digest_hash_mismatch_exit_2() -> Result<(), Box<dyn std::error::Error>> {
    let m = make_valid_test_materials()?;

    let (url, _receiver, server) = spawn_scripted_server(vec![
        (200, digest_materials_body_wrong_digest_hash(&m)),
        (200, chain_export_body(&m)),
        (200, r#""ok""#.to_owned()),
        (200, "true".to_owned()),
    ])?;

    let run = run_digest_verify(&url, "hash-mismatch", TEST_YEAR_MONTH)?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected exit non-zero when stored_digest_hash does not match recomputed hash"
    );
    assert_eq!(run.output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_eq!(parsed["valid"], false);
    assert_eq!(parsed["error"]["code"], "monthly_digest_hash_mismatch");

    fs::remove_dir_all(run.temp_dir)?;
    Ok(())
}

#[test]
fn digest_signature_invalid_exit_2() -> Result<(), Box<dyn std::error::Error>> {
    let m = make_valid_test_materials()?;

    let (url, _receiver, server) = spawn_scripted_server(vec![
        (200, digest_materials_body_wrong_signature(&m)),
        (200, chain_export_body(&m)),
        (200, r#""ok""#.to_owned()),
        (200, "true".to_owned()),
    ])?;

    let run = run_digest_verify(&url, "sig-invalid", TEST_YEAR_MONTH)?;
    server
        .join()
        .map_err(|_| std::io::Error::other("server thread panicked"))??;

    assert!(
        !run.output.status.success(),
        "expected exit non-zero when digest Ed25519 signature is corrupted"
    );
    assert_eq!(run.output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&run.output.stdout);
    let parsed: Value = serde_json::from_str(&stdout)?;
    assert_eq!(parsed["valid"], false);
    assert_eq!(parsed["error"]["code"], "monthly_digest_signature_invalid");

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

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mipsorcu::server::runtime::testing as runtime_testing;
use mipsorcu::server::runtime::{
    AuditFallbackSizeAlert, JwtVerifierInitError, audit_fallback_file_size,
    audit_fallback_size_alert, initialize_jwt_verifier_from_jwks_url, refresh_jwks_cache_once,
    run_audit_fallback_rollover_once, sweep_audit_fallback_archive_once,
};
use mipsorcu::server::supabase::{SecretReadJoin, SecretVersionReadRow};
use mipsorcu::{
    Classification, CreatedAt, DeviceId, Jwks, JwksCache, KeyVersion, LocalAuditFallbackStore,
    MASTER_KEY_LENGTH, MasterKey, NewSecretVersionInput, OwnerUserId, Plaintext, RolloverOutcome,
    SecretDecryptError, prepare_new_secret_version,
};
use serde_json::json;
use tokio::sync::watch;

fn temp_path(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    std::env::temp_dir().join(format!("mipsorcu-runtime-{test_name}-{unique}"))
}

fn write_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::File::create(path).expect("test file should be created");
    file.write_all(bytes).expect("test file should be written");
}

fn valid_audit_fallback_line(audit_event_id: &str, delivery_status: &str) -> String {
    format!(
        r#"{{"audit_event_id":"{audit_event_id}","request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","actor_user_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479","actor_device_id":"sbc-device-1","action":"decrypt","target_secret_id":"550e8400-e29b-41d4-a716-446655440000","result":"failure","key_version":1,"metadata_json":{{"error_code":"decrypt_failed"}},"occurred_at":"2026-04-08T12:00:00Z","delivery_status":"{delivery_status}"}}"#
    )
}

fn archive_file_count(path: &Path) -> usize {
    if !path.exists() {
        return 0;
    }

    fs::read_dir(path)
        .expect("archive directory should be readable")
        .count()
}

const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const CLASSIFICATION: &str = "confidential";
const CREATED_AT: &str = "2026-04-08T12:00:00Z";
const DEVICE_ID: &str = "sbc-device-1";

fn sample_master_key() -> MasterKey {
    MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH])
}

fn prepared_restore_test_row(
    plaintext: Vec<u8>,
) -> Result<(MasterKey, SecretVersionReadRow), Box<dyn std::error::Error>> {
    let master_key = sample_master_key();
    let prepared = prepare_new_secret_version(
        &master_key,
        NewSecretVersionInput::new(
            OwnerUserId::parse(OWNER_USER_ID)?,
            Classification::new(CLASSIFICATION)?,
            DeviceId::new(DEVICE_ID)?,
            CreatedAt::parse(CREATED_AT)?,
            KeyVersion::new(1)?,
            Plaintext::new(plaintext),
        ),
    )?;
    let version_id = "650e8400-e29b-41d4-a716-446655440000".to_owned();

    Ok((
        master_key,
        SecretVersionReadRow {
            id: version_id.clone(),
            secret_id: prepared.secret_id().as_canonical_string(),
            version: i32::try_from(prepared.version().get())?,
            ciphertext: format!("\\x{}", hex::encode(prepared.ciphertext().as_bytes())),
            encrypted_data_key: format!(
                "\\x{}",
                hex::encode(prepared.encrypted_data_key().as_bytes())
            ),
            key_version: i32::try_from(prepared.key_version().get())?,
            algorithm: mipsorcu::ALGORITHM_XCHACHA20_POLY1305.to_owned(),
            nonce_or_iv: format!("\\x{}", hex::encode(prepared.nonce_or_iv().as_bytes())),
            aad_context: prepared.aad_context().clone(),
            created_by_user_id: OWNER_USER_ID.to_owned(),
            created_at: prepared.created_at().as_rfc3339_utc()?,
            secrets: SecretReadJoin {
                current_version_id: version_id,
                owner_user_id: prepared.owner_user_id().as_canonical_string(),
                classification: prepared.classification().as_str().to_owned(),
            },
        },
    ))
}

#[test]
fn audit_fallback_file_size_returns_none_when_file_is_missing() {
    let path = temp_path("missing");

    let size = audit_fallback_file_size(&path).expect("missing file should not fail");

    assert_eq!(size, None);
}

#[test]
fn audit_fallback_size_alert_ignores_missing_file() {
    let path = temp_path("missing-alert");

    let alert = audit_fallback_size_alert(&path, 10).expect("missing file should not fail");

    assert_eq!(alert, None);
}

#[test]
fn audit_fallback_size_alert_ignores_files_below_threshold() {
    let path = temp_path("below-threshold");
    write_file(&path, b"12345");

    let alert = audit_fallback_size_alert(&path, 6).expect("size check should succeed");

    assert_eq!(alert, None);
    let _ = fs::remove_file(path);
}

#[test]
fn audit_fallback_size_alert_triggers_at_threshold() {
    let path = temp_path("at-threshold");
    write_file(&path, b"12345");

    let alert = audit_fallback_size_alert(&path, 5).expect("size check should succeed");

    assert_eq!(
        alert,
        Some(AuditFallbackSizeAlert {
            size_bytes: 5,
            threshold_bytes: 5,
        })
    );
    let _ = fs::remove_file(path);
}

#[test]
fn audit_fallback_file_size_ignores_directories() {
    let path = temp_path("directory");
    fs::create_dir(&path).expect("test directory should be created");

    let size = audit_fallback_file_size(&path).expect("directory metadata should be readable");

    assert_eq!(size, None);
    let _ = fs::remove_dir(path);
}

#[tokio::test]
async fn audit_fallback_rollover_once_seals_eligible_current_file() {
    let path = temp_path("rollover-current.jsonl");
    let archive_dir = temp_path("rollover-archive");
    let line = valid_audit_fallback_line("11111111-1111-4111-8111-111111111111", "sent");
    write_file(&path, format!("{line}\n").as_bytes());
    let store = LocalAuditFallbackStore::with_rollover_config(&path, &archive_dir, 1);

    let outcome = run_audit_fallback_rollover_once(store)
        .await
        .expect("rollover helper should succeed");

    let RolloverOutcome::Sealed(archive) = outcome else {
        panic!("eligible current file should be sealed");
    };
    assert!(archive.archive_path.exists());
    assert_eq!(archive.line_count, 1);
    assert_eq!(archive_file_count(&archive_dir), 1);
    assert_eq!(
        fs::read_to_string(&path).expect("current file should be readable"),
        ""
    );
}

#[tokio::test]
async fn archive_sweep_once_deletes_archives_only_when_called() {
    let path = temp_path("sweep-current.jsonl");
    let archive_dir = temp_path("sweep-archive");
    let line = valid_audit_fallback_line("22222222-2222-4222-8222-222222222222", "sent");
    write_file(&path, format!("{line}\n").as_bytes());
    let store = LocalAuditFallbackStore::with_rollover_config(&path, &archive_dir, 1);

    let rollover = run_audit_fallback_rollover_once(store.clone())
        .await
        .expect("rollover helper should succeed");
    assert!(matches!(rollover, RolloverOutcome::Sealed(_)));
    assert_eq!(archive_file_count(&archive_dir), 1);

    let sweep = sweep_audit_fallback_archive_once(store, Duration::ZERO)
        .await
        .expect("archive sweep helper should succeed");

    assert_eq!(sweep.deleted_archives.len(), 1);
    assert_eq!(sweep.deleted_archives[0].line_count, Some(1));
    assert!(sweep.deleted_archives[0].sha256_hex.is_some());
    assert_eq!(archive_file_count(&archive_dir), 0);
}

#[tokio::test]
async fn initialize_jwt_verifier_from_jwks_url_accepts_valid_jwks() {
    let body = r#"{"keys":[{"kty":"RSA","kid":"test-key","alg":"RS256","use":"sig","n":"abc","e":"AQAB"}]}"#;
    let url = spawn_single_response_server(200, body);
    let client = reqwest::Client::new();

    let verifier = initialize_jwt_verifier_from_jwks_url(&client, &url, "issuer", "audience").await;

    assert!(verifier.is_ok());
}

#[tokio::test]
async fn initialize_jwt_verifier_from_jwks_url_fails_closed_on_fetch_error() {
    let body = r#"{"error":"upstream secret details"}"#;
    let url = spawn_single_response_server(500, body);
    let client = reqwest::Client::new();

    let result = initialize_jwt_verifier_from_jwks_url(&client, &url, "issuer", "audience").await;

    assert!(matches!(result, Err(JwtVerifierInitError::Fetch(_))));
}

#[tokio::test]
async fn refresh_jwks_cache_once_keeps_existing_cache_when_fetch_fails() {
    let initial_jwks = Jwks::new(vec![mipsorcu::Jwk::new(
        "RSA",
        "initial-key",
        Some("RS256".to_owned()),
        Some("sig".to_owned()),
        "abc",
        "AQAB",
    )])
    .expect("initial jwks should be valid");
    let cache = JwksCache::new(initial_jwks);
    let body = r#"{"keys":[]}"#;
    let url = spawn_single_response_server(200, body);
    let client = reqwest::Client::new();

    let result = refresh_jwks_cache_once(&cache, &client, &url).await;

    assert!(result.is_err());
    let snapshot = cache.snapshot().expect("cache should remain readable");
    assert_eq!(snapshot.keys()[0].key_id(), "initial-key");
}

#[tokio::test]
async fn refresh_jwks_cache_once_replaces_existing_cache_on_success() {
    let initial_jwks = Jwks::new(vec![mipsorcu::Jwk::new(
        "RSA",
        "initial-key",
        Some("RS256".to_owned()),
        Some("sig".to_owned()),
        "abc",
        "AQAB",
    )])
    .expect("initial jwks should be valid");
    let cache = JwksCache::new(initial_jwks);
    let body = r#"{"keys":[{"kty":"RSA","kid":"refreshed-key","alg":"RS256","use":"sig","n":"abc","e":"AQAB"}]}"#;
    let url = spawn_single_response_server(200, body);
    let client = reqwest::Client::new();

    refresh_jwks_cache_once(&cache, &client, &url)
        .await
        .expect("refresh should succeed");

    let snapshot = cache.snapshot().expect("cache should remain readable");
    assert_eq!(snapshot.keys()[0].key_id(), "refreshed-key");
}

#[test]
fn restore_test_metadata_records_no_sample_reason_without_forbidden_keys() {
    let metadata = runtime_testing::restore_test_metadata(0, Some("no_current_secret_versions"));

    assert_eq!(
        metadata.as_value(),
        &json!({
            "sample_count": 0,
            "reason": "no_current_secret_versions",
        })
    );
}

#[test]
fn restore_test_metadata_records_failure_code_without_forbidden_keys() {
    let metadata = runtime_testing::restore_test_metadata(1, Some("decrypt_failed"));

    assert_eq!(
        metadata.as_value(),
        &json!({
            "sample_count": 1,
            "error_code": "decrypt_failed",
        })
    );
}

#[test]
fn restore_test_input_round_trips_existing_encrypted_sample()
-> Result<(), Box<dyn std::error::Error>> {
    let plaintext = b"restore test sample".to_vec();
    let (master_key, row) = prepared_restore_test_row(plaintext.clone())?;
    let input = runtime_testing::build_restore_test_decrypt_input(row)?;

    let decrypted = mipsorcu::decrypt_current_secret_version(&master_key, input)?;

    assert_eq!(decrypted.as_bytes(), plaintext.as_slice());
    Ok(())
}

#[test]
fn restore_test_input_rejects_aad_tampering() -> Result<(), Box<dyn std::error::Error>> {
    let (master_key, mut row) = prepared_restore_test_row(b"restore test sample".to_vec())?;
    row.aad_context = json!({
        "aad_version": 1,
        "secret_id": row.secret_id.clone(),
        "version": row.version,
        "owner_user_id": row.secrets.owner_user_id.clone(),
        "classification": "tampered",
        "created_at": row.created_at.clone(),
    });
    let input = runtime_testing::build_restore_test_decrypt_input(row)?;

    let result = mipsorcu::decrypt_current_secret_version(&master_key, input);

    assert!(matches!(
        result,
        Err(SecretDecryptError::Integrity(
            mipsorcu::DecryptIntegrityError::AadContextMismatch
        ))
    ));
    Ok(())
}

#[test]
fn restore_test_input_rejects_ciphertext_tampering() -> Result<(), Box<dyn std::error::Error>> {
    let (master_key, mut row) = prepared_restore_test_row(b"restore test sample".to_vec())?;
    let mut ciphertext = hex::decode(
        row.ciphertext
            .strip_prefix("\\x")
            .ok_or(mipsorcu::CryptoError::DecryptionFailed)?,
    )?;
    let first = ciphertext
        .first_mut()
        .ok_or(mipsorcu::CryptoError::DecryptionFailed)?;
    *first ^= 1;
    row.ciphertext = format!("\\x{}", hex::encode(ciphertext));
    let input = runtime_testing::build_restore_test_decrypt_input(row)?;

    let result = mipsorcu::decrypt_current_secret_version(&master_key, input);

    assert!(matches!(
        result,
        Err(SecretDecryptError::Crypto(
            mipsorcu::CryptoError::DecryptionFailed
        ))
    ));
    Ok(())
}

#[tokio::test]
async fn jwks_refresh_loop_stops_on_shutdown_signal() {
    let jwks = Jwks::new(vec![mipsorcu::Jwk::new(
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
    let task = tokio::spawn(runtime_testing::run_jwks_refresh_loop(
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

fn spawn_single_response_server(status: u16, body: &'static str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("test server should bind to a local port");
    let addr = listener
        .local_addr()
        .expect("test server local address should be available");
    std::thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("test server should accept one connection");
        let mut buffer = [0u8; 1024];
        let _ = stream.read(&mut buffer);
        let response = format!(
            "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
    });

    format!("http://{addr}/jwks")
}

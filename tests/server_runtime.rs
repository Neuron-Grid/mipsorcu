use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mipsorcu::server::runtime::{
    AuditFallbackSizeAlert, JwtVerifierInitError, audit_fallback_file_size,
    audit_fallback_size_alert, initialize_jwt_verifier_from_jwks_url, refresh_jwks_cache_once,
};
use mipsorcu::{Jwks, JwksCache};

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

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mipsorcu::incident::{DummyNotificationSink, IncidentRecorder};
use mipsorcu::server::ledger_appender::LedgerAppender;
use mipsorcu::server::runtime::{
    AuditFallbackSizeAlert, JwtVerifierInitError, audit_fallback_file_size,
    audit_fallback_size_alert, build_app, initialize_jwt_verifier_from_jwks_url,
    refresh_jwks_cache_once, run_audit_fallback_rollover_once, sweep_audit_fallback_archive_once,
};
use mipsorcu::server::siem_forwarding::SiemForwardingService;
use mipsorcu::server::state::{AppState, ReadinessState};
use mipsorcu::server::supabase::{
    IntegrityCheckSummary, IntegrityCheckViolationSummary, RestoreTestSampleRow,
    SupabaseAuditAppender, SupabaseClient,
};
use mipsorcu::{
    AliasEncryptionKey, AliasFingerprintKey, AuditRecorder, AuditTrigger, Classification,
    CreatedAt, DeviceId, InMemorySiemSink, Jwk, Jwks, JwksCache, JwtVerifier, JwtVerifierConfig,
    KeyVersion, LEDGER_ED25519_SECRET_KEY_LENGTH, LedgerSignatureKeyVersion, LedgerSigningKey,
    LocalAuditFallbackStore, LocalSiemFallbackBuffer, MASTER_KEY_LENGTH, MasterKey, MasterKeyRing,
    NewSecretVersionInput, NormalizedAlias, OwnerUserId, Plaintext, RolloverOutcome, SecretId,
    SiemForwarder, SourceEventAt, prepare_alias_create, prepare_new_secret_version,
};
use serde::Serialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tracing_subscriber::EnvFilter;

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
        r#"{{"audit_event_id":"{audit_event_id}","request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","actor_user_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479","actor_device_id":"sbc-device-1","action":"decrypt","target_secret_id":"550e8400-e29b-41d4-a716-446655440000","result":"failure","key_version":1,"metadata_json":{{"attempted_secret_id":"550e8400-e29b-41d4-a716-446655440000","source_event_at":"2026-04-08T12:00:00Z"}},"occurred_at":"2026-04-08T12:00:00Z","delivery_status":"{delivery_status}"}}"#
    )
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
const JWT_KEY_ID: &str = "test-key-1";
const JWT_ISSUER: &str = "https://project-ref.supabase.co/auth/v1";
const JWT_AUDIENCE: &str = "authenticated";
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

#[derive(Debug, Clone)]
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
type HangingServerHandle = (String, thread::JoinHandle<std::io::Result<()>>);
type DecryptRowMutation = fn(&mut Value);

#[derive(Debug, Clone, Serialize)]
struct TestClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
}

#[derive(Clone, Default)]
struct SharedLogBuffer {
    bytes: Arc<Mutex<Vec<u8>>>,
}

struct SharedLogWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl SharedLogBuffer {
    fn contents(&self) -> String {
        let bytes = self
            .bytes
            .lock()
            .expect("log buffer lock should be available");
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedLogBuffer {
    type Writer = SharedLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogWriter {
            bytes: self.bytes.clone(),
        }
    }
}

impl Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut bytes = self
            .bytes
            .lock()
            .expect("log buffer lock should be available");
        bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn sample_master_key() -> MasterKey {
    MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH])
}

fn prepared_restore_test_row(
    plaintext: Vec<u8>,
) -> Result<(MasterKey, RestoreTestSampleRow), Box<dyn std::error::Error>> {
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
        RestoreTestSampleRow {
            id: version_id.clone(),
            secret_id: prepared.secret_id().as_canonical_string(),
            version: i32::try_from(prepared.version().get())?,
            ciphertext: format!("\\x{}", hex::encode(prepared.ciphertext().as_bytes())),
            encrypted_data_key: format!(
                "\\x{}",
                hex::encode(
                    prepared
                        .encrypted_data_key()
                        .expect("legacy prepared version should include encrypted_data_key")
                        .as_bytes()
                )
            ),
            key_version: i32::try_from(prepared.key_version().get())?,
            classification: prepared.classification().as_str().to_owned(),
            nonce_or_iv: format!("\\x{}", hex::encode(prepared.nonce_or_iv().as_bytes())),
            aad_context: prepared.aad_context().clone(),
            created_at: prepared.created_at().as_rfc3339_utc()?,
        },
    ))
}

fn decrypt_row_json(plaintext: &[u8]) -> Result<(String, Value), Box<dyn std::error::Error>> {
    let master_key = sample_master_key();
    let prepared = prepare_new_secret_version(
        &master_key,
        NewSecretVersionInput::new(
            OwnerUserId::parse(OWNER_USER_ID)?,
            Classification::new(CLASSIFICATION)?,
            DeviceId::new(DEVICE_ID)?,
            CreatedAt::parse(CREATED_AT)?,
            KeyVersion::new(1)?,
            Plaintext::new(plaintext.to_vec()),
        ),
    )?;
    let version_id = "650e8400-e29b-41d4-a716-446655440000".to_owned();

    let secret_id = prepared.secret_id().as_canonical_string();

    Ok((
        secret_id.clone(),
        json!([{
            "id": version_id,
            "secret_id": secret_id,
            "version": i32::try_from(prepared.version().get())?,
            "ciphertext": format!("\\x{}", hex::encode(prepared.ciphertext().as_bytes())),
            "encrypted_data_key": format!(
                "\\x{}",
                hex::encode(
                    prepared
                        .encrypted_data_key()
                        .expect("legacy prepared version should include encrypted_data_key")
                        .as_bytes()
                )
            ),
            "key_version": i32::try_from(prepared.key_version().get())?,
            "algorithm": mipsorcu::ALGORITHM_XCHACHA20_POLY1305,
            "classification": prepared.classification().as_str(),
            "nonce_or_iv": format!("\\x{}", hex::encode(prepared.nonce_or_iv().as_bytes())),
            "aad_context": prepared.aad_context(),
            "created_by_user_id": prepared.owner_user_id().as_canonical_string(),
            "created_at": prepared.created_at().as_rfc3339_utc()?,
            "secrets": {
                "current_version_id": "650e8400-e29b-41d4-a716-446655440000",
                "owner_user_id": prepared.owner_user_id().as_canonical_string(),
                "classification": prepared.classification().as_str(),
            }
        }]),
    ))
}

fn alias_resolve_row_json(
    secret_id: &str,
    alias: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let prepared = prepare_alias_create(
        &AliasEncryptionKey::from_bytes([11u8; MASTER_KEY_LENGTH]),
        KeyVersion::new(1)?,
        &AliasFingerprintKey::from_bytes([12u8; MASTER_KEY_LENGTH]),
        KeyVersion::new(1)?,
        SecretId::parse(secret_id)?,
        OwnerUserId::parse(OWNER_USER_ID)?,
        NormalizedAlias::parse(alias)?,
        CreatedAt::parse(CREATED_AT)?,
    )?;

    Ok(json!([{
        "id": prepared.secret_alias_id.as_canonical_string(),
        "secret_id": prepared.secret_id.as_canonical_string(),
        "alias_ciphertext": format!("\\x{}", hex::encode(prepared.ciphertext.as_bytes())),
        "alias_nonce": format!("\\x{}", hex::encode(prepared.nonce.as_bytes())),
        "alias_key_version": i32::try_from(prepared.alias_key_version.get())?,
        "aad_context": prepared.aad_context,
    }]))
}

fn alias_list_row_json(secret_id: &str, alias: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let prepared = prepare_alias_create(
        &AliasEncryptionKey::from_bytes([11u8; MASTER_KEY_LENGTH]),
        KeyVersion::new(1)?,
        &AliasFingerprintKey::from_bytes([12u8; MASTER_KEY_LENGTH]),
        KeyVersion::new(1)?,
        SecretId::parse(secret_id)?,
        OwnerUserId::parse(OWNER_USER_ID)?,
        NormalizedAlias::parse(alias)?,
        CreatedAt::parse(CREATED_AT)?,
    )?;

    Ok(json!([{
        "id": prepared.secret_alias_id.as_canonical_string(),
        "secret_id": prepared.secret_id.as_canonical_string(),
        "alias_ciphertext": format!("\\x{}", hex::encode(prepared.ciphertext.as_bytes())),
        "alias_nonce": format!("\\x{}", hex::encode(prepared.nonce.as_bytes())),
        "alias_key_version": i32::try_from(prepared.alias_key_version.get())?,
        "alias_fingerprint": format!("\\x{}", hex::encode(prepared.alias_fingerprint.as_bytes())),
        "alias_fingerprint_key_version": i32::try_from(prepared.fingerprint_key_version.get())?,
        "alias_fingerprint_schema_version": i32::try_from(prepared.fingerprint_schema_version.get())?,
        "aad_context": prepared.aad_context,
        "created_at": CREATED_AT,
        "updated_at": "2026-04-08T12:01:00Z",
    }]))
}

fn set_first_decrypt_row_field(rows: &mut Value, field: &str, value: Value) {
    if let Some(row) = rows.as_array_mut().and_then(|array| array.first_mut()) {
        row[field] = value;
    }
}

fn set_first_decrypt_row_secret_field(rows: &mut Value, field: &str, value: Value) {
    if let Some(row) = rows.as_array_mut().and_then(|array| array.first_mut()) {
        row["secrets"][field] = value;
    }
}

fn make_decrypt_row_bad_nonce(rows: &mut Value) {
    set_first_decrypt_row_field(rows, "nonce_or_iv", Value::String("\\x00".to_owned()));
}

fn make_decrypt_row_empty_ciphertext(rows: &mut Value) {
    set_first_decrypt_row_field(rows, "ciphertext", Value::String("\\x".to_owned()));
}

fn make_decrypt_row_ciphertext_without_bytea_prefix(rows: &mut Value) {
    set_first_decrypt_row_field(rows, "ciphertext", Value::String("00".to_owned()));
}

fn make_decrypt_row_ciphertext_invalid_hex(rows: &mut Value) {
    set_first_decrypt_row_field(rows, "ciphertext", Value::String("\\xzz".to_owned()));
}

fn make_decrypt_row_bad_encrypted_data_key(rows: &mut Value) {
    set_first_decrypt_row_field(
        rows,
        "encrypted_data_key",
        Value::String("\\x01".to_owned()),
    );
}

fn make_decrypt_row_bad_algorithm(rows: &mut Value) {
    set_first_decrypt_row_field(
        rows,
        "algorithm",
        Value::String("chacha20-poly1305".to_owned()),
    );
}

fn make_decrypt_row_owner_mismatch(rows: &mut Value) {
    set_first_decrypt_row_field(
        rows,
        "created_by_user_id",
        Value::String("f47ac10b-58cc-4372-a567-0e02b2c3d480".to_owned()),
    );
}

fn make_decrypt_row_classification_mismatch(rows: &mut Value) {
    set_first_decrypt_row_field(
        rows,
        "classification",
        Value::String("restricted".to_owned()),
    );
}

fn make_decrypt_row_non_current(rows: &mut Value) {
    set_first_decrypt_row_secret_field(
        rows,
        "current_version_id",
        Value::String("750e8400-e29b-41d4-a716-446655440000".to_owned()),
    );
}

fn make_decrypt_rows_multiple_current(rows: &mut Value) {
    if let Some(array) = rows.as_array_mut()
        && let Some(row) = array.first().cloned()
    {
        array.push(row);
    }
}

fn make_decrypt_rows_empty(rows: &mut Value) {
    *rows = Value::Array(Vec::new());
}

fn test_jwt_verifier() -> Result<JwtVerifier, Box<dyn std::error::Error>> {
    Ok(JwtVerifier::new(
        JwtVerifierConfig::new(JWT_ISSUER, JWT_AUDIENCE)?,
        Jwks::new(vec![Jwk::new(
            "RSA",
            JWT_KEY_ID,
            Some("RS256".to_owned()),
            Some("sig".to_owned()),
            RSA_MODULUS,
            RSA_EXPONENT,
        )])?,
    ))
}

fn valid_token() -> Result<String, Box<dyn std::error::Error>> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(JWT_KEY_ID.to_owned());
    let key = EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY_PEM.as_bytes())?;

    Ok(encode(
        &header,
        &TestClaims {
            sub: OWNER_USER_ID.to_owned(),
            iss: JWT_ISSUER.to_owned(),
            aud: JWT_AUDIENCE.to_owned(),
            exp: 4_102_444_800,
        },
        &key,
    )?)
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
    let incident_recorder = Arc::new(IncidentRecorder::new(
        supabase_client.clone(),
        ledger_appender.clone(),
        DummyNotificationSink::new(),
    ));
    let readiness_state = ReadinessState::new();
    let siem_forwarding = Arc::new(SiemForwardingService::new(
        SiemForwarder::new(
            InMemorySiemSink::new(),
            LocalSiemFallbackBuffer::new(temp_path("siem-buffer")),
        ),
        audit_recorder.clone(),
        readiness_state.clone(),
    ));

    Ok(AppState {
        master_key_ring: Arc::new(MasterKeyRing::single(
            KeyVersion::new(1)?,
            sample_master_key(),
        )?),
        alias_encryption_key: Arc::new(AliasEncryptionKey::from_bytes([11u8; MASTER_KEY_LENGTH])),
        alias_encryption_key_version: KeyVersion::new(1)?,
        alias_fingerprint_key: Arc::new(AliasFingerprintKey::from_bytes([12u8; MASTER_KEY_LENGTH])),
        alias_fingerprint_key_version: KeyVersion::new(1)?,
        jwt_verifier: Arc::new(test_jwt_verifier()?),
        supabase_client,
        audit_recorder,
        ledger_appender,
        incident_recorder,
        siem_forwarding,
        audit_fallback_store,
        readiness_state,
        health_readiness_poll_interval: Duration::from_secs(30),
        siem_long_failure_threshold: Duration::from_secs(900),
        http_handler_timeout: Duration::from_secs(75),
        http_rate_limit_requests: 300,
        http_rate_limit_window: Duration::from_secs(60),
    })
}

async fn spawn_app(
    state: AppState,
) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = build_app(state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test app should serve requests");
    });

    Ok((format!("http://{addr}"), handle))
}

async fn spawn_runtime_resilience_test_app(
    state: AppState,
    sleep_duration: Duration,
) -> Result<(String, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = build_runtime_resilience_test_app(state, sleep_duration);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test sleep app should serve requests");
    });

    Ok((format!("http://{addr}"), handle))
}

fn build_runtime_resilience_test_app(state: AppState, sleep_duration: Duration) -> axum::Router {
    let runtime_resilience = mipsorcu::server::middleware::RuntimeResilience::new(
        state.http_handler_timeout,
        state.http_rate_limit_requests,
        state.http_rate_limit_window,
    );

    // This test app intentionally applies only runtime resilience and request context.
    // Production standard layers are covered through build_app-based endpoint tests.
    axum::Router::<AppState>::new()
        .route(
            "/__test/sleep",
            axum::routing::get(move || async move {
                tokio::time::sleep(sleep_duration).await;
                axum::http::StatusCode::NO_CONTENT
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            runtime_resilience,
            mipsorcu::server::middleware::enforce_runtime_resilience,
        ))
        .layer(axum::middleware::from_fn(
            mipsorcu::server::middleware::attach_request_context,
        ))
        .with_state(state)
}

fn spawn_supabase_read_and_audit_server(
    secret_versions_body: String,
    audit_status: u16,
    audit_body: &'static str,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let is_secret_read = request.path.starts_with("/rest/v1/secret_versions");
            let is_ledger_chain_head = request.path.starts_with("/rest/v1/ledger_chain_state");
            let response_body = if audit_status == 200 && !is_secret_read && !is_ledger_chain_head {
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

            if is_secret_read {
                write_http_response(&mut stream, 200, "OK", &secret_versions_body)?;
            } else if is_ledger_chain_head {
                write_http_response(&mut stream, 200, "OK", &ledger_chain_head_body())?;
            } else if audit_status == 200 {
                let body = response_body.as_deref().unwrap_or(audit_body);
                write_http_response(&mut stream, 200, "OK", body)?;
            } else {
                write_http_response(
                    &mut stream,
                    audit_status,
                    "Internal Server Error",
                    audit_body,
                )?;
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn spawn_supabase_alias_read_and_audit_server(
    alias_body: String,
    secret_versions_body: String,
    audit_status: u16,
    audit_body: &'static str,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let is_alias_read = request
                .path
                .starts_with("/rest/v1/rpc/rpc_resolve_secret_alias");
            let is_secret_read = request.path.starts_with("/rest/v1/secret_versions");
            let is_ledger_chain_head = request.path.starts_with("/rest/v1/ledger_chain_state");
            let response_body = if audit_status == 200
                && !is_alias_read
                && !is_secret_read
                && !is_ledger_chain_head
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

            if is_alias_read {
                write_http_response(&mut stream, 200, "OK", &alias_body)?;
            } else if is_secret_read {
                write_http_response(&mut stream, 200, "OK", &secret_versions_body)?;
            } else if is_ledger_chain_head {
                write_http_response(&mut stream, 200, "OK", &ledger_chain_head_body())?;
            } else if audit_status == 200 {
                let body = response_body.as_deref().unwrap_or(audit_body);
                write_http_response(&mut stream, 200, "OK", body)?;
            } else {
                write_http_response(
                    &mut stream,
                    audit_status,
                    "Internal Server Error",
                    audit_body,
                )?;
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn spawn_supabase_read_failure_audit_server(
    secret_versions_body: String,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let is_secret_read = request.path.starts_with("/rest/v1/secret_versions");
            sender.send(request).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request receiver was dropped",
                )
            })?;

            if is_secret_read {
                write_http_response(&mut stream, 200, "OK", &secret_versions_body)?;
            } else {
                write_http_response(&mut stream, 200, "OK", r#""ok""#)?;
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn spawn_supabase_alias_create_server(
    secret_versions_body: String,
    alias_response_body: String,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    spawn_supabase_alias_create_status_server(secret_versions_body, 200, alias_response_body)
}

fn spawn_supabase_alias_create_status_server(
    secret_versions_body: String,
    alias_status: u16,
    alias_response_body: String,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let is_secret_read = request.path.starts_with("/rest/v1/secret_versions");
            sender.send(request).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request receiver was dropped",
                )
            })?;

            if is_secret_read {
                write_http_response(&mut stream, 200, "OK", &secret_versions_body)?;
            } else {
                let reason = if alias_status == 200 {
                    "OK"
                } else {
                    "Conflict"
                };
                write_http_response(&mut stream, alias_status, reason, &alias_response_body)?;
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn spawn_supabase_alias_context_error_server(
    status: u16,
    body: &'static str,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let request = read_http_request(&mut stream)?;
        sender.send(request).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "captured request receiver was dropped",
            )
        })?;
        write_http_response(&mut stream, status, "Forbidden", body)?;

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn spawn_supabase_alias_update_server(
    secret_id: String,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let is_context_lookup = request
                .path
                .starts_with("/rest/v1/rpc/rpc_get_secret_alias_for_update");
            sender.send(request).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request receiver was dropped",
                )
            })?;

            if is_context_lookup {
                write_http_response(
                    &mut stream,
                    200,
                    "OK",
                    &json!([{ "secret_id": secret_id }]).to_string(),
                )?;
            } else {
                write_http_response(
                    &mut stream,
                    200,
                    "OK",
                    r#"[{"old_alias_fingerprint":"\\x1111111111111111111111111111111111111111111111111111111111111111"}]"#,
                )?;
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn spawn_supabase_alias_delete_server() -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let request = read_http_request(&mut stream)?;
        sender.send(request).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "captured request receiver was dropped",
            )
        })?;
        write_http_response(
            &mut stream,
            200,
            "OK",
            r#"[{"alias_fingerprint":"\\x2222222222222222222222222222222222222222222222222222222222222222"}]"#,
        )?;

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn spawn_supabase_alias_list_server(
    list_body: String,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let is_list = request
                .path
                .starts_with("/rest/v1/rpc/rpc_list_secret_aliases");
            sender.send(request).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request receiver was dropped",
                )
            })?;

            if is_list {
                write_http_response(&mut stream, 200, "OK", &list_body)?;
            } else {
                write_http_response(&mut stream, 200, "OK", r#"[]"#)?;
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn spawn_supabase_alias_resolve_server(
    resolve_body: String,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let request = read_http_request(&mut stream)?;
        sender.send(request).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "captured request receiver was dropped",
            )
        })?;
        write_http_response(&mut stream, 200, "OK", &resolve_body)?;

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn spawn_supabase_rotate_server(
    secret_versions_body: String,
    write_status: u16,
    write_body: &'static str,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let is_secret_read = request.path.starts_with("/rest/v1/secret_versions");
            let is_ledger_chain_head = request.path.starts_with("/rest/v1/ledger_chain_state");
            sender.send(request).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request receiver was dropped",
                )
            })?;

            if is_secret_read {
                write_http_response(&mut stream, 200, "OK", &secret_versions_body)?;
            } else if is_ledger_chain_head {
                write_http_response(&mut stream, 200, "OK", &ledger_chain_head_body())?;
            } else if write_status == 200 {
                write_http_response(&mut stream, 200, "OK", write_body)?;
            } else {
                write_http_response(
                    &mut stream,
                    write_status,
                    "Internal Server Error",
                    write_body,
                )?;
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

fn spawn_supabase_integrity_and_audit_server(
    integrity_status: u16,
    integrity_body: String,
    audit_status: u16,
    audit_body: &'static str,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let request_count = if integrity_status == 200 { 3 } else { 2 };
    let thread = thread::spawn(move || {
        for _ in 0..request_count {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let is_integrity_check = request.path == "/rest/v1/rpc/rpc_integrity_check";
            let is_ledger_chain_head = request.path.starts_with("/rest/v1/ledger_chain_state");
            let response_body =
                if audit_status == 200 && !is_integrity_check && !is_ledger_chain_head {
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

            if is_integrity_check {
                let reason = if integrity_status == 200 {
                    "OK"
                } else {
                    "Internal Server Error"
                };
                write_http_response(&mut stream, integrity_status, reason, &integrity_body)?;
            } else if is_ledger_chain_head {
                write_http_response(&mut stream, 200, "OK", &ledger_chain_head_body())?;
            } else if audit_status == 200 {
                let body = response_body.as_deref().unwrap_or(audit_body);
                write_http_response(&mut stream, 200, "OK", body)?;
            } else {
                write_http_response(
                    &mut stream,
                    audit_status,
                    "Internal Server Error",
                    audit_body,
                )?;
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn restore_test_row_json(row: &RestoreTestSampleRow) -> Value {
    json!({
        "id": &row.id,
        "secret_id": &row.secret_id,
        "version": row.version,
        "ciphertext": &row.ciphertext,
        "encrypted_data_key": &row.encrypted_data_key,
        "key_version": row.key_version,
        "nonce_or_iv": &row.nonce_or_iv,
        "aad_context": &row.aad_context,
        "classification": &row.classification,
        "created_at": &row.created_at,
    })
}

fn spawn_supabase_restore_test_audit_server(
    sample_status: u16,
    sample_body: String,
    audit_status: u16,
    audit_body: &'static str,
    request_count: usize,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for _ in 0..request_count {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            let path = request.path.clone();
            let response_body = if path == "/rest/v1/rpc/rpc_append_audit_event_with_ledger"
                && audit_status == 200
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

            if path == "/rest/v1/rpc/rpc_sample_restore_test" {
                let reason = if sample_status == 200 {
                    "OK"
                } else {
                    "Internal Server Error"
                };
                write_http_response(&mut stream, sample_status, reason, &sample_body)?;
            } else if path.starts_with("/rest/v1/ledger_chain_state") {
                write_http_response(&mut stream, 200, "OK", &ledger_chain_head_body())?;
            } else if audit_status == 200 {
                let body = response_body.as_deref().unwrap_or(r#""ok""#);
                write_http_response(&mut stream, 200, "OK", body)?;
            } else {
                write_http_response(
                    &mut stream,
                    audit_status,
                    "Internal Server Error",
                    audit_body,
                )?;
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn spawn_supabase_single_request_server(
    status: u16,
    reason: &'static str,
    body: &'static str,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let request = read_http_request(&mut stream)?;
        sender.send(request).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "captured request receiver was dropped",
            )
        })?;
        write_http_response(&mut stream, status, reason, body)?;

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn spawn_capture_server(
    idle_timeout: Duration,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        let deadline = Instant::now() + idle_timeout;

        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = read_http_request(&mut stream)?;
                    sender.send(request).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "captured request receiver was dropped",
                        )
                    })?;
                    write_http_response(&mut stream, 200, "OK", r#"{"status":"ok"}"#)?;
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn spawn_capture_server_until_idle(
    idle_timeout: Duration,
) -> Result<TestServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        let mut deadline = next_idle_deadline(idle_timeout);

        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = read_http_request(&mut stream)?;
                    sender.send(request).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "captured request receiver was dropped",
                        )
                    })?;
                    write_http_response(&mut stream, 200, "OK", r#"{"status":"ok"}"#)?;
                    deadline = next_idle_deadline(idle_timeout);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn next_idle_deadline(idle_timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(idle_timeout)
        .unwrap_or_else(Instant::now)
}

fn spawn_hanging_jwks_server(
    response_delay: Duration,
) -> Result<HangingServerHandle, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let mut buffer = [0u8; 1024];
        let _ = stream.read(&mut buffer);
        thread::sleep(response_delay);
        Ok(())
    });

    Ok((format!("http://{addr}/jwks"), thread))
}

fn build_log_subscriber(buffer: SharedLogBuffer) -> impl tracing::Subscriber + Send + Sync {
    tracing_subscriber::fmt()
        .json()
        .with_writer(buffer)
        .with_env_filter(EnvFilter::new("info"))
        .finish()
}

fn assert_auth_failure_audit_body(body: &Value, expected_error_code: &str) {
    assert_eq!(body["p_actor_user_id"], Value::Null);
    assert_eq!(body["p_actor_device_id"], Value::Null);
    assert_eq!(body["p_action"], Value::String("auth_failure".to_owned()));
    assert_eq!(body["p_target_secret_id"], Value::Null);
    assert_eq!(body["p_result"], Value::String("failure".to_owned()));
    assert_eq!(body["p_key_version"], Value::Null);
    assert_eq!(
        body["p_metadata_json"]["error_code"],
        Value::String(expected_error_code.to_owned())
    );
    let source_event_at = body["p_metadata_json"]["source_event_at"]
        .as_str()
        .expect("auth failure audit should include source_event_at");
    assert!(SourceEventAt::parse(source_event_at).is_ok());

    let serialized = body.to_string();
    assert!(!serialized.contains("Authorization"));
    assert!(!serialized.contains("authorization_header_value"));
    assert!(!serialized.contains("not-a-jwt"));
    assert!(!serialized.contains("service-role-key"));
    assert!(!serialized.contains("publishable-key"));
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
async fn initialize_jwt_verifier_from_jwks_url_uses_configured_request_timeout() {
    let (url, server_thread) = spawn_hanging_jwks_server(Duration::from_millis(250))
        .expect("JWKS test server should start");
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(20))
        .timeout(Duration::from_millis(20))
        .build()
        .expect("test HTTP client should build");
    let started_at = Instant::now();

    let result = initialize_jwt_verifier_from_jwks_url(&client, &url, "issuer", "audience").await;

    assert!(matches!(result, Err(JwtVerifierInitError::Fetch(_))));
    assert!(started_at.elapsed() < Duration::from_millis(200));
    server_thread
        .join()
        .expect("JWKS test server thread should join")
        .expect("JWKS test server should stop cleanly");
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

#[tokio::test(flavor = "current_thread")]
async fn health_endpoint_returns_minimal_liveness_and_does_not_call_supabase() {
    let (supabase_url, receiver, server_thread) =
        spawn_capture_server(Duration::from_millis(250)).expect("capture server should start");
    let state = test_app_state(&supabase_url, temp_path("health-minimal"))
        .expect("test app state should be created");
    state
        .readiness_state
        .record_supabase_probe_result_at(true, OffsetDateTime::now_utc());
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::get(format!("{app_url}/health"))
        .await
        .expect("health request should succeed");
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .expect("health response should be JSON");

    app_task.abort();
    assert!(receiver.recv_timeout(Duration::from_millis(300)).is_err());
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");

    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["status"], "up");
    assert_eq!(body["supabase"], "ok");
    assert_eq!(body["master_key"], "loaded");
    assert!(body["disk_free_mb"].is_number() || body["disk_free_mb"].is_null());
    assert_eq!(body.as_object().map(|object| object.len()), Some(4));
    assert!(body.get("siem").is_none());
    assert!(body.get("fallback_writable").is_none());
    assert!(body.get("audit_fallback_pending").is_none());
    assert!(body.get("supabase_last_checked_at").is_none());
    assert!(body.get("supabase_reachable").is_none());
    assert!(body.get("master_key_loaded").is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn health_endpoint_returns_service_unavailable_when_supabase_state_is_unhealthy() {
    let (supabase_url, receiver, server_thread) =
        spawn_capture_server(Duration::from_millis(250)).expect("capture server should start");
    let state = test_app_state(&supabase_url, temp_path("health-unhealthy"))
        .expect("test app state should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::get(format!("{app_url}/health"))
        .await
        .expect("health request should succeed");
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .expect("health response should be JSON");

    app_task.abort();
    assert!(receiver.recv_timeout(Duration::from_millis(300)).is_err());
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");

    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "down");
    assert_eq!(body["supabase"], "ng");
    assert_eq!(body["master_key"], "loaded");
    assert!(body["disk_free_mb"].is_number() || body["disk_free_mb"].is_null());
    assert_eq!(body.as_object().map(|object| object.len()), Some(4));
    assert!(body.get("siem").is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn ready_endpoint_returns_cached_supabase_state_when_fresh() {
    let state = test_app_state("http://127.0.0.1:1", temp_path("ready-fresh"))
        .expect("test app state should be created");
    let checked_at = OffsetDateTime::now_utc();
    state
        .readiness_state
        .record_supabase_probe_result_at(true, checked_at);
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::get(format!("{app_url}/ready"))
        .await
        .expect("ready request should succeed");
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .expect("ready response should be JSON");

    app_task.abort();

    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["status"], "ready");
    assert_eq!(body["supabase"], "ok");
    assert_eq!(body["master_key"], "loaded");
    assert!(body["disk_free_mb"].is_number() || body["disk_free_mb"].is_null());
    assert_eq!(body.as_object().map(|object| object.len()), Some(4));
    assert!(body.get("siem").is_none());
    assert!(body.get("supabase_reachable").is_none());
    assert!(body.get("supabase_last_checked_at").is_none());
    assert!(body.get("master_key_loaded").is_none());
    assert!(body.get("fallback_writable").is_none());
    assert!(body.get("audit_fallback_pending").is_none());
    assert!(
        body.get("audit_failure_append_both_failed_recent")
            .is_none()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn ready_endpoint_returns_service_unavailable_when_supabase_probe_is_stale() {
    let state = test_app_state("http://127.0.0.1:1", temp_path("ready-stale"))
        .expect("test app state should be created");
    state.readiness_state.record_supabase_probe_result_at(
        true,
        OffsetDateTime::now_utc() - time::Duration::seconds(61),
    );
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::get(format!("{app_url}/ready"))
        .await
        .expect("ready request should succeed");
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .expect("ready response should be JSON");

    app_task.abort();

    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["supabase"], "ng");
    assert_eq!(body["master_key"], "loaded");
    assert!(body["disk_free_mb"].is_number() || body["disk_free_mb"].is_null());
    assert_eq!(body.as_object().map(|object| object.len()), Some(4));
    assert!(body.get("siem").is_none());
    assert!(body.get("supabase_reachable").is_none());
    assert!(body.get("supabase_last_checked_at").is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn ready_endpoint_does_not_expose_failure_audit_state() {
    let state = test_app_state("http://127.0.0.1:1", temp_path("ready-both-failed"))
        .expect("test app state should be created");
    state
        .readiness_state
        .record_supabase_probe_result_at(true, OffsetDateTime::now_utc());
    let (app_url, app_task) = spawn_app(state.clone())
        .await
        .expect("test app should start");

    state
        .readiness_state
        .mark_failure_audit_both_failed_at(OffsetDateTime::now_utc());
    let response = reqwest::get(format!("{app_url}/ready"))
        .await
        .expect("ready request should succeed");
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .expect("ready response should be JSON");

    app_task.abort();

    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["status"], "ready");
    assert!(
        body.get("audit_failure_append_both_failed_recent")
            .is_none()
    );
    assert!(body.get("siem").is_none());
    assert_eq!(body.as_object().map(|object| object.len()), Some(4));
}

#[tokio::test(flavor = "current_thread")]
async fn ready_endpoint_does_not_create_fallback_file_for_probe() {
    let fallback_path = temp_path("ready-no-fallback-probe.jsonl");
    assert!(!fallback_path.exists());
    let state = test_app_state("http://127.0.0.1:1", fallback_path.clone())
        .expect("test app state should be created");
    state
        .readiness_state
        .record_supabase_probe_result_at(true, OffsetDateTime::now_utc());
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::get(format!("{app_url}/ready"))
        .await
        .expect("ready request should succeed");
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .expect("ready response should be JSON");

    app_task.abort();

    assert_eq!(status, reqwest::StatusCode::OK);
    assert_eq!(body["status"], "ready");
    assert_eq!(body["supabase"], "ok");
    assert!(body["disk_free_mb"].is_number() || body["disk_free_mb"].is_null());
    assert!(body.get("audit_fallback_pending").is_none());
    assert!(body.get("fallback_writable").is_none());
    assert!(!fallback_path.exists());
}

#[tokio::test(flavor = "current_thread")]
async fn rate_limit_returns_429_with_request_id() {
    let mut state = test_app_state("http://127.0.0.1:1", temp_path("rate-limit"))
        .expect("test app state should be created");
    state.http_rate_limit_requests = 1;
    state.http_rate_limit_window = Duration::from_secs(60);
    let (app_url, app_task) = spawn_runtime_resilience_test_app(state, Duration::ZERO)
        .await
        .expect("test app should start");
    let client = reqwest::Client::new();

    let first = client
        .get(format!("{app_url}/__test/sleep"))
        .send()
        .await
        .expect("first request should succeed");
    assert_eq!(first.status(), reqwest::StatusCode::NO_CONTENT);

    let second = client
        .get(format!("{app_url}/__test/sleep"))
        .send()
        .await
        .expect("second request should succeed");
    assert_eq!(second.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let body: Value = second
        .json()
        .await
        .expect("rate limit response should be JSON");
    assert_eq!(body["code"], Value::String("rate_limited".to_owned()));
    let request_id = body["request_id"]
        .as_str()
        .expect("rate limit response should include request_id");
    assert!(uuid::Uuid::parse_str(request_id).is_ok());

    app_task.abort();
    let _ = app_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn health_and_ready_bypass_rate_limit() {
    let mut state = test_app_state("http://127.0.0.1:1", temp_path("probe-rate-limit-bypass"))
        .expect("test app state should be created");
    state
        .readiness_state
        .record_supabase_probe_result_at(true, OffsetDateTime::now_utc());
    state.http_rate_limit_requests = 1;
    state.http_rate_limit_window = Duration::from_secs(60);
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");
    let client = reqwest::Client::new();

    for path in ["/health", "/ready", "/health", "/ready"] {
        let response = client
            .get(format!("{app_url}{path}"))
            .send()
            .await
            .expect("probe request should succeed");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    app_task.abort();
    let _ = app_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn runtime_resilience_timeout_returns_503_with_request_id() {
    let mut state = test_app_state("http://127.0.0.1:1", temp_path("handler-timeout"))
        .expect("test app state should be created");
    state.http_handler_timeout = Duration::from_millis(20);
    let (app_url, app_task) = spawn_runtime_resilience_test_app(state, Duration::from_millis(100))
        .await
        .expect("test sleep app should start");

    let response = reqwest::Client::new()
        .get(format!("{app_url}/__test/sleep"))
        .send()
        .await
        .expect("sleep request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = response
        .json()
        .await
        .expect("timeout response should be JSON");
    assert_eq!(body["code"], Value::String("request_timeout".to_owned()));
    let request_id = body["request_id"]
        .as_str()
        .expect("timeout response should include request_id");
    assert!(uuid::Uuid::parse_str(request_id).is_ok());

    app_task.abort();
    let _ = app_task.await;
}

#[test]
fn integrity_check_metadata_records_aggregate_only_summary()
-> Result<(), Box<dyn std::error::Error>> {
    let mut summary = IntegrityCheckSummary::zero();
    summary.checked_secret_count = 2;
    summary.checked_secret_version_count = 4;
    summary.checked_audit_event_count = 6;
    summary.violation_count = 1;
    summary.violation_summary.algorithm_invalid = 1;

    let metadata = mipsorcu::server::integrity_check::build_integrity_check_metadata(
        &summary,
        AuditTrigger::Startup,
        None,
    )?;
    let serialized = serde_json::to_string(metadata.as_value())?;

    assert_eq!(metadata.as_value()["check_name"], "mvp_integrity_check");
    assert_eq!(metadata.as_value()["trigger"], "startup");
    assert_eq!(metadata.as_value()["checked_secret_count"], 2);
    assert_eq!(
        metadata.as_value()["violation_summary"]["algorithm_invalid"],
        1
    );
    assert!(!serialized.contains("secret_id"));
    assert!(!serialized.contains("version_id"));
    assert!(!serialized.contains("aad_context"));
    assert!(!serialized.contains("jwt"));
    assert!(!serialized.contains("service-role-key"));
    assert!(!serialized.contains("publishable-key"));
    assert!(!serialized.contains("\\x"));
    assert!(!serialized.contains("550e8400-e29b-41d4-a716-446655440000"));
    assert!(!serialized.contains("plaintext"));

    Ok(())
}

#[test]
fn integrity_check_metadata_records_failure_error_code() -> Result<(), Box<dyn std::error::Error>> {
    let metadata = mipsorcu::server::integrity_check::build_integrity_check_metadata(
        &IntegrityCheckSummary::zero(),
        AuditTrigger::Cli,
        Some("rpc_failed"),
    )?;

    assert_eq!(metadata.as_value()["trigger"], "cli");
    assert_eq!(metadata.as_value()["error_code"], "rpc_failed");

    Ok(())
}

#[test]
fn integrity_check_cli_usage_documents_once_command() {
    let usage = mipsorcu::server::integrity_check::usage();

    assert!(usage.contains("mipsorcu integrity-check once"));
}

#[tokio::test(flavor = "current_thread")]
async fn integrity_check_success_records_success_audit() -> Result<(), Box<dyn std::error::Error>> {
    let body = serde_json::to_string(&json!([integrity_summary_json(0)]))?;
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_integrity_and_audit_server(200, body, 200, r#""ok""#)?;
    let state = test_app_state(&supabase_url, temp_path("integrity-success"))?;

    let outcome =
        mipsorcu::server::integrity_check::run_integrity_check_once(&state, AuditTrigger::Cli)
            .await?;
    let integrity_request = receiver.recv_timeout(Duration::from_secs(1))?;
    let chain_request = receiver.recv_timeout(Duration::from_secs(1))?;
    let audit_request = receiver.recv_timeout(Duration::from_secs(1))?;
    server_thread
        .join()
        .expect("integrity server thread should not panic")?;

    assert_eq!(outcome.audit_result, mipsorcu::AuditResult::Success);
    assert_eq!(outcome.summary.violation_count, 0);
    assert_eq!(integrity_request.method, "POST");
    assert_eq!(integrity_request.path, "/rest/v1/rpc/rpc_integrity_check");
    assert_eq!(integrity_request.body, Some(json!({})));
    assert_eq!(chain_request.method, "GET");
    assert!(
        chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );
    assert_eq!(
        audit_request.path,
        "/rest/v1/rpc/rpc_append_audit_event_with_ledger"
    );
    let audit_body = audit_request
        .body
        .ok_or_else(|| std::io::Error::other("audit append body should be JSON"))?;
    assert_eq!(audit_body["p_action"], "integrity_check");
    assert_eq!(audit_body["p_entry_type"], "integrity_check_completed");
    assert_eq!(audit_body["p_result"], "success");
    assert_eq!(audit_body["p_metadata_json"]["trigger"], "cli");
    assert_eq!(audit_body["p_metadata_json"]["violation_count"], 0);
    assert_eq!(audit_body["p_payload"]["violation_count"], 0);
    assert!(audit_body["p_payload"]["duration_ms"].is_number());
    let source_event_at = audit_body["p_metadata_json"]["source_event_at"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("integrity audit should include source_event_at"))?;
    assert!(SourceEventAt::parse(source_event_at).is_ok());

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn integrity_check_violation_records_failure_audit() -> Result<(), Box<dyn std::error::Error>>
{
    let body = serde_json::to_string(&json!([integrity_summary_json(1)]))?;
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_integrity_and_audit_server(200, body, 200, r#""ok""#)?;
    let state = test_app_state(&supabase_url, temp_path("integrity-violation"))?;

    let result = mipsorcu::server::integrity_check::run_integrity_check_once(
        &state,
        AuditTrigger::Background,
    )
    .await;
    let _integrity_request = receiver.recv_timeout(Duration::from_secs(1))?;
    let chain_request = receiver.recv_timeout(Duration::from_secs(1))?;
    let audit_request = receiver.recv_timeout(Duration::from_secs(1))?;
    server_thread
        .join()
        .expect("integrity server thread should not panic")?;

    assert!(matches!(
        result,
        Err(
            mipsorcu::server::integrity_check::IntegrityCheckError::ViolationDetected {
                violation_count: 1
            }
        )
    ));
    assert!(
        chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );
    let audit_body = audit_request
        .body
        .ok_or_else(|| std::io::Error::other("audit append body should be JSON"))?;
    assert_eq!(audit_body["p_action"], "integrity_check");
    assert_eq!(audit_body["p_entry_type"], "integrity_check_completed");
    assert_eq!(audit_body["p_result"], "failure");
    assert_eq!(audit_body["p_metadata_json"]["trigger"], "background");
    assert_eq!(
        audit_body["p_metadata_json"]["error_code"],
        "integrity_violation_detected"
    );
    assert_eq!(
        audit_body["p_metadata_json"]["violation_summary"]["algorithm_invalid"],
        1
    );
    assert_eq!(audit_body["p_payload"]["violation_count"], 1);
    let source_event_at = audit_body["p_metadata_json"]["source_event_at"]
        .as_str()
        .ok_or_else(|| {
            std::io::Error::other("integrity failure audit should include source_event_at")
        })?;
    assert!(SourceEventAt::parse(source_event_at).is_ok());

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn integrity_check_rpc_failure_falls_back_when_primary_audit_fails()
-> Result<(), Box<dyn std::error::Error>> {
    let fallback_path = temp_path("integrity-rpc-fallback");
    let (supabase_url, receiver, server_thread) = spawn_supabase_integrity_and_audit_server(
        500,
        r#"{"message":"internal"}"#.to_owned(),
        503,
        r#"{"message":"unavailable"}"#,
    )?;
    let state = test_app_state(&supabase_url, fallback_path.clone())?;

    let result =
        mipsorcu::server::integrity_check::run_integrity_check_once(&state, AuditTrigger::Cli)
            .await;
    let _integrity_request = receiver.recv_timeout(Duration::from_secs(1))?;
    let audit_request = receiver.recv_timeout(Duration::from_secs(1))?;
    server_thread
        .join()
        .expect("integrity server thread should not panic")?;

    assert!(matches!(
        result,
        Err(mipsorcu::server::integrity_check::IntegrityCheckError::RpcFailed)
    ));
    assert_eq!(audit_request.path, "/rest/v1/rpc/rpc_append_audit_event");
    let fallback_contents = fs::read_to_string(fallback_path)?;
    assert!(fallback_contents.contains(r#""action":"integrity_check""#));
    assert!(fallback_contents.contains(r#""error_code":"rpc_failed""#));
    assert!(fallback_contents.contains(r#""trigger":"cli""#));
    assert!(!fallback_contents.contains("\\x"));
    assert!(!fallback_contents.contains("550e8400-e29b-41d4-a716-446655440000"));
    assert!(!fallback_contents.contains("plaintext"));
    assert!(!fallback_contents.contains("service-role-key"));

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restore_test_records_no_sample_reason_without_forbidden_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_restore_test_audit_server(200, "[]".to_owned(), 200, r#""ok""#, 3)?;
    let state = test_app_state(&supabase_url, temp_path("restore-no-sample"))?;

    let restore_ok = mipsorcu::server::runtime::run_restore_test_once(&state, 3).await;
    let sample_request = receiver.recv_timeout(Duration::from_secs(1))?;
    let chain_request = receiver.recv_timeout(Duration::from_secs(1))?;
    let audit_request = receiver.recv_timeout(Duration::from_secs(1))?;
    server_thread
        .join()
        .expect("restore test server thread should not panic")?;

    assert_eq!(sample_request.path, "/rest/v1/rpc/rpc_sample_restore_test");
    assert!(restore_ok);
    assert!(
        chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );
    assert_eq!(
        audit_request.path,
        "/rest/v1/rpc/rpc_append_audit_event_with_ledger"
    );
    let audit_body = audit_request
        .body
        .ok_or_else(|| std::io::Error::other("restore audit body should be JSON"))?;
    assert_eq!(audit_body["p_action"], "restore_test");
    assert_eq!(audit_body["p_entry_type"], "restore_test_completed");
    assert_eq!(audit_body["p_result"], "success");
    assert_eq!(
        audit_body["p_metadata_json"]["reason"],
        "no_current_secret_versions"
    );
    assert_eq!(audit_body["p_metadata_json"]["sample_count"], 0);
    assert_eq!(audit_body["p_metadata_json"]["trigger"], "cli");
    let source_event_at = audit_body["p_metadata_json"]["source_event_at"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("restore audit should include source_event_at"))?;
    assert!(SourceEventAt::parse(source_event_at).is_ok());
    let metadata_and_payload = serde_json::to_string(&json!({
        "metadata_json": audit_body["p_metadata_json"].clone(),
        "payload": audit_body["p_payload"].clone(),
    }))?;
    assert!(!metadata_and_payload.contains("\\x"));
    assert!(!metadata_and_payload.contains("plaintext"));
    assert!(!metadata_and_payload.contains("service-role-key"));

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restore_test_returns_failure_when_sample_fetch_fails()
-> Result<(), Box<dyn std::error::Error>> {
    let (supabase_url, receiver, server_thread) = spawn_supabase_restore_test_audit_server(
        500,
        r#"{"message":"sample failed"}"#.to_owned(),
        200,
        r#""ok""#,
        2,
    )?;
    let state = test_app_state(&supabase_url, temp_path("restore-sample-fetch-failure"))?;

    let restore_ok = mipsorcu::server::runtime::run_restore_test_once(&state, 3).await;
    let sample_request = receiver.recv_timeout(Duration::from_secs(1))?;
    let audit_request = receiver.recv_timeout(Duration::from_secs(1))?;
    server_thread
        .join()
        .expect("restore test server thread should not panic")?;

    assert_eq!(sample_request.path, "/rest/v1/rpc/rpc_sample_restore_test");
    assert!(!restore_ok);
    assert_eq!(audit_request.path, "/rest/v1/rpc/rpc_append_audit_event");
    let audit_body = audit_request
        .body
        .ok_or_else(|| std::io::Error::other("restore failure audit body should be JSON"))?;
    assert_eq!(audit_body["p_action"], "restore_test");
    assert_eq!(audit_body["p_result"], "failure");
    assert_eq!(
        audit_body["p_metadata_json"]["error_code"],
        "sample_fetch_failed"
    );
    assert_eq!(audit_body["p_metadata_json"]["trigger"], "cli");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restore_test_round_trips_existing_encrypted_sample_via_runtime()
-> Result<(), Box<dyn std::error::Error>> {
    let (_, row) = prepared_restore_test_row(b"restore test sample".to_vec())?;
    let sample_body = serde_json::to_string(&json!([restore_test_row_json(&row)]))?;
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_restore_test_audit_server(200, sample_body, 200, r#""ok""#, 3)?;
    let state = test_app_state(&supabase_url, temp_path("restore-valid-sample"))?;

    let restore_ok = mipsorcu::server::runtime::run_restore_test_once(&state, 3).await;
    let sample_request = receiver.recv_timeout(Duration::from_secs(1))?;
    let chain_request = receiver.recv_timeout(Duration::from_secs(1))?;
    let audit_request = receiver.recv_timeout(Duration::from_secs(1))?;
    server_thread
        .join()
        .expect("restore test server thread should not panic")?;

    assert_eq!(sample_request.path, "/rest/v1/rpc/rpc_sample_restore_test");
    assert!(restore_ok);
    assert!(
        chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );
    let audit_body = audit_request
        .body
        .ok_or_else(|| std::io::Error::other("restore audit body should be JSON"))?;
    assert_eq!(audit_body["p_action"], "restore_test");
    assert_eq!(audit_body["p_entry_type"], "restore_test_completed");
    assert_eq!(audit_body["p_result"], "success");
    assert_eq!(audit_body["p_metadata_json"]["sample_count"], 1);
    assert_eq!(audit_body["p_metadata_json"]["trigger"], "cli");
    assert!(audit_body["p_metadata_json"].get("error_code").is_none());
    let source_event_at = audit_body["p_metadata_json"]["source_event_at"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("restore audit should include source_event_at"))?;
    assert!(SourceEventAt::parse(source_event_at).is_ok());
    let metadata_and_payload = serde_json::to_string(&json!({
        "metadata_json": audit_body["p_metadata_json"].clone(),
        "payload": audit_body["p_payload"].clone(),
    }))?;
    assert!(!metadata_and_payload.contains("restore test sample"));
    assert!(!metadata_and_payload.contains("plaintext"));
    assert!(!metadata_and_payload.contains("\\x"));

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restore_test_rejects_aad_tampering_via_runtime() -> Result<(), Box<dyn std::error::Error>>
{
    let (_, mut row) = prepared_restore_test_row(b"restore test sample".to_vec())?;
    row.aad_context = json!({
        "aad_version": 1,
        "secret_id": row.secret_id.clone(),
        "version": row.version,
        "owner_user_id": OWNER_USER_ID,
        "classification": "tampered",
        "created_at": row.created_at.clone(),
    });
    let sample_body = serde_json::to_string(&json!([restore_test_row_json(&row)]))?;
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_restore_test_audit_server(200, sample_body, 200, r#""ok""#, 2)?;
    let state = test_app_state(&supabase_url, temp_path("restore-aad-tamper"))?;

    let restore_ok = mipsorcu::server::runtime::run_restore_test_once(&state, 3).await;
    let sample_request = receiver.recv_timeout(Duration::from_secs(1))?;
    let audit_request = receiver.recv_timeout(Duration::from_secs(1))?;
    server_thread
        .join()
        .expect("restore test server thread should not panic")?;

    assert_eq!(sample_request.path, "/rest/v1/rpc/rpc_sample_restore_test");
    assert!(!restore_ok);
    assert_eq!(audit_request.path, "/rest/v1/rpc/rpc_append_audit_event");
    let audit_body = audit_request
        .body
        .ok_or_else(|| std::io::Error::other("restore failure audit body should be JSON"))?;
    assert_eq!(audit_body["p_action"], "restore_test");
    assert_eq!(audit_body["p_result"], "failure");
    assert_eq!(
        audit_body["p_metadata_json"]["error_code"],
        "row_validation_failed"
    );
    assert_eq!(audit_body["p_metadata_json"]["trigger"], "cli");
    let source_event_at = audit_body["p_metadata_json"]["source_event_at"]
        .as_str()
        .ok_or_else(|| {
            std::io::Error::other("restore failure audit should include source_event_at")
        })?;
    assert!(SourceEventAt::parse(source_event_at).is_ok());

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restore_test_rejects_ciphertext_tampering_via_runtime()
-> Result<(), Box<dyn std::error::Error>> {
    let (_, mut row) = prepared_restore_test_row(b"restore test sample".to_vec())?;
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
    let sample_body = serde_json::to_string(&json!([restore_test_row_json(&row)]))?;
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_restore_test_audit_server(200, sample_body, 200, r#""ok""#, 2)?;
    let state = test_app_state(&supabase_url, temp_path("restore-ciphertext-tamper"))?;

    let restore_ok = mipsorcu::server::runtime::run_restore_test_once(&state, 3).await;
    let sample_request = receiver.recv_timeout(Duration::from_secs(1))?;
    let audit_request = receiver.recv_timeout(Duration::from_secs(1))?;
    server_thread
        .join()
        .expect("restore test server thread should not panic")?;

    assert_eq!(sample_request.path, "/rest/v1/rpc/rpc_sample_restore_test");
    assert!(!restore_ok);
    assert_eq!(audit_request.path, "/rest/v1/rpc/rpc_append_audit_event");
    let audit_body = audit_request
        .body
        .ok_or_else(|| std::io::Error::other("restore failure audit body should be JSON"))?;
    assert_eq!(audit_body["p_action"], "restore_test");
    assert_eq!(audit_body["p_result"], "failure");
    assert_eq!(
        audit_body["p_metadata_json"]["error_code"],
        "decrypt_failed"
    );
    assert_eq!(audit_body["p_metadata_json"]["trigger"], "cli");
    let source_event_at = audit_body["p_metadata_json"]["source_event_at"]
        .as_str()
        .ok_or_else(|| {
            std::io::Error::other("restore failure audit should include source_event_at")
        })?;
    assert!(SourceEventAt::parse(source_event_at).is_ok());

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn decrypt_endpoint_returns_plaintext_after_audit_and_ledger_append() {
    let plaintext = b"router secret";
    let (secret_id, row_json) =
        decrypt_row_json(plaintext).expect("decrypt row JSON should be constructed");
    let body = row_json.to_string();
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_read_and_audit_server(body, 200, r#"[]"#)
            .expect("Supabase test server should start");
    let fallback_path = temp_path("decrypt-audit-ledger-success.jsonl");
    let state = test_app_state(&supabase_url, fallback_path.clone())
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets/{secret_id}/decrypt"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("decrypt request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );

    let json: Value = response
        .json()
        .await
        .expect("decrypt response should be JSON");
    assert_eq!(json["secret_id"], Value::String(secret_id.clone()));
    assert_eq!(json["version"], Value::from(1));
    assert_eq!(json["plaintext_hex"], Value::String(hex::encode(plaintext)));
    assert_eq!(json["encoding"], Value::String("hex".to_owned()));

    let read_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("secret read request should be captured");
    let chain_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("ledger chain head request should be captured");
    let audit_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("audit and ledger append request should be captured");
    assert_eq!(read_request.method, "GET");
    assert!(read_request.path.starts_with("/rest/v1/secret_versions"));
    assert_eq!(chain_request.method, "GET");
    assert!(
        chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );
    assert_eq!(audit_request.method, "POST");
    assert!(
        audit_request
            .path
            .ends_with("/rest/v1/rpc/rpc_append_audit_event_with_ledger")
    );
    assert!(audit_request.body.is_some());
    let audit_body = audit_request
        .body
        .as_ref()
        .and_then(Value::as_object)
        .expect("audit append request body should be a JSON object");
    assert_eq!(audit_body["p_action"], "decrypt");
    assert_eq!(audit_body["p_entry_type"], "secret_decrypted");
    assert_eq!(audit_body["p_result"], "success");
    assert_eq!(
        audit_body["p_payload"]["algorithm"],
        mipsorcu::ALGORITHM_XCHACHA20_POLY1305
    );
    assert_eq!(audit_body["p_payload"]["version"], 1);
    assert!(audit_body["p_payload"].get("plaintext").is_none());
    assert!(audit_body["p_payload"].get("decrypt_result").is_none());
    let source_event_at = audit_body["p_metadata_json"]["source_event_at"]
        .as_str()
        .expect("decrypt audit append request should include metadata_json.source_event_at");
    assert!(SourceEventAt::parse(source_event_at).is_ok());
    assert!(!fallback_path.exists());

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn decrypt_endpoint_resolves_alias_without_putting_alias_in_audit_or_logs() {
    let alias = "prod-alias";
    let plaintext = b"router alias secret";
    let (secret_id, row_json) =
        decrypt_row_json(plaintext).expect("decrypt row JSON should be constructed");
    let alias_body = alias_resolve_row_json(&secret_id, alias)
        .expect("alias resolve row JSON should be constructed")
        .to_string();
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_alias_read_and_audit_server(alias_body, row_json.to_string(), 200, r#"[]"#)
            .expect("Supabase test server should start");
    let fallback_path = temp_path("decrypt-alias-audit-ledger-success.jsonl");
    let state = test_app_state(&supabase_url, fallback_path.clone())
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let log_buffer = SharedLogBuffer::default();
    let subscriber = build_log_subscriber(log_buffer.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets/{alias}/decrypt"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("decrypt request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let json: Value = response
        .json()
        .await
        .expect("decrypt response should be JSON");
    assert_eq!(json["secret_id"], Value::String(secret_id.clone()));
    assert_eq!(json["plaintext_hex"], Value::String(hex::encode(plaintext)));

    let alias_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("alias read request should be captured");
    let read_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("secret read request should be captured");
    let chain_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("ledger chain head request should be captured");
    let audit_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("audit and ledger append request should be captured");
    assert!(
        alias_request
            .path
            .starts_with("/rest/v1/rpc/rpc_resolve_secret_alias")
    );
    assert!(read_request.path.starts_with("/rest/v1/secret_versions"));
    assert!(
        chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );
    assert!(
        audit_request
            .path
            .ends_with("/rest/v1/rpc/rpc_append_audit_event_with_ledger")
    );
    assert!(
        !audit_request
            .body
            .as_ref()
            .is_some_and(|body| body.to_string().contains(alias))
    );

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");

    let logs = log_buffer.contents();
    assert!(!logs.contains(alias));
    assert!(!fallback_path.exists());
}

#[tokio::test(flavor = "current_thread")]
async fn create_alias_endpoint_returns_created_and_keeps_alias_out_of_logs() {
    let alias = "Prod_API-1";
    let (secret_id, row_json) =
        decrypt_row_json(b"alias create seed").expect("decrypt row JSON should be constructed");
    let alias_response_body = json!([{
        "secret_alias_id": "750e8400-e29b-41d4-a716-446655440000",
    }])
    .to_string();
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_alias_create_server(row_json.to_string(), alias_response_body)
            .expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("create-alias"))
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let log_buffer = SharedLogBuffer::default();
    let subscriber = build_log_subscriber(log_buffer.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets/{secret_id}/aliases"))
        .bearer_auth(&token)
        .json(&json!({ "alias": alias }))
        .send()
        .await
        .expect("create alias request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    let json: Value = response
        .json()
        .await
        .expect("create alias response should be JSON");
    assert_eq!(json["secret_id"], Value::String(secret_id.clone()));
    assert_eq!(
        json["secret_alias_id"],
        Value::String("750e8400-e29b-41d4-a716-446655440000".to_owned())
    );
    assert!(json.get("alias").is_none());
    assert!(json.get("alias_normalized").is_none());

    let read_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("secret read request should be captured");
    let create_alias_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("create alias request should be captured");
    assert!(read_request.path.starts_with("/rest/v1/secret_versions"));
    assert!(
        create_alias_request
            .path
            .ends_with("/rest/v1/rpc/rpc_create_secret_alias")
    );
    let create_body = create_alias_request
        .body
        .as_ref()
        .expect("create alias request body should be JSON");
    assert_eq!(create_body["p_secret_id"], Value::String(secret_id.clone()));
    assert_eq!(
        create_body["p_owner_user_id"],
        Value::String(OWNER_USER_ID.to_owned())
    );
    assert!(
        create_body["p_alias_fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("\\x") && value.len() == 66)
    );
    assert!(
        create_body["p_source_event_at"]
            .as_str()
            .is_some_and(|value| SourceEventAt::parse(value).is_ok())
    );
    assert!(
        !create_alias_request
            .body
            .as_ref()
            .is_some_and(|body| body.to_string().contains(alias))
    );

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");

    let logs = log_buffer.contents();
    assert!(!logs.contains(alias));
}

#[tokio::test(flavor = "current_thread")]
async fn create_alias_endpoint_maps_duplicate_alias_to_conflict() {
    let alias = "Prod_API-Conflict";
    let (secret_id, row_json) = decrypt_row_json(b"alias create conflict seed")
        .expect("decrypt row JSON should be constructed");
    let (supabase_url, receiver, server_thread) = spawn_supabase_alias_create_status_server(
        row_json.to_string(),
        409,
        r#"{"message":"alias_conflict"}"#.to_owned(),
    )
    .expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("create-alias-conflict"))
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets/{secret_id}/aliases"))
        .bearer_auth(&token)
        .json(&json!({ "alias": alias }))
        .send()
        .await
        .expect("create alias request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    let json: Value = response
        .json()
        .await
        .expect("error response should be JSON");
    assert_eq!(json["code"], Value::String("alias_conflict".to_owned()));
    assert!(!json.to_string().contains(alias));

    let read_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("secret read request should be captured");
    let create_alias_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("create alias request should be captured");
    assert!(read_request.path.starts_with("/rest/v1/secret_versions"));
    assert!(
        create_alias_request
            .path
            .ends_with("/rest/v1/rpc/rpc_create_secret_alias")
    );

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn create_alias_endpoint_rejects_invalid_alias_without_upstream_call()
-> Result<(), Box<dyn std::error::Error>> {
    let alias = "invalid alias with space";
    let secret_id = "550e8400-e29b-41d4-a716-446655440000";
    let (supabase_url, receiver, server_thread) =
        spawn_capture_server_until_idle(Duration::from_millis(300))?;
    let state = test_app_state(&supabase_url, temp_path("create-alias-invalid"))?;
    let token = valid_token()?;
    let log_buffer = SharedLogBuffer::default();
    let subscriber = build_log_subscriber(log_buffer.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let (app_url, app_task) = spawn_app(state).await?;

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets/{secret_id}/aliases"))
        .bearer_auth(&token)
        .json(&json!({ "alias": alias }))
        .send()
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let json: Value = response.json().await?;
    assert_eq!(json["code"], Value::String("bad_request".to_owned()));
    assert!(!json.to_string().contains(alias));

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .map_err(|_| std::io::Error::other("capture server thread panicked"))??;
    assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());

    let logs = log_buffer.contents();
    assert!(!logs.contains(alias));

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn create_alias_endpoint_rejects_non_uuid_secret_id_path_without_upstream_call()
-> Result<(), Box<dyn std::error::Error>> {
    let secret_ref = "Prod_API-Path";
    let alias = "valid-alias";
    let (supabase_url, receiver, server_thread) =
        spawn_capture_server_until_idle(Duration::from_millis(300))?;
    let state = test_app_state(&supabase_url, temp_path("create-alias-non-uuid-path"))?;
    let token = valid_token()?;
    let log_buffer = SharedLogBuffer::default();
    let subscriber = build_log_subscriber(log_buffer.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let (app_url, app_task) = spawn_app(state).await?;

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets/{secret_ref}/aliases"))
        .bearer_auth(&token)
        .json(&json!({ "alias": alias }))
        .send()
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let json: Value = response.json().await?;
    assert_eq!(json["code"], Value::String("bad_request".to_owned()));
    assert!(!json.to_string().contains(secret_ref));
    assert!(!json.to_string().contains(alias));

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .map_err(|_| std::io::Error::other("capture server thread panicked"))??;
    assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());

    let logs = log_buffer.contents();
    assert!(!logs.contains(secret_ref));
    assert!(!logs.contains(alias));

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn create_alias_endpoint_missing_authorization_returns_401_without_alias_rpc() {
    let alias = "NoAuthAlias";
    let secret_id = "550e8400-e29b-41d4-a716-446655440000";
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_single_request_server(200, "OK", r#"{"status":"ok"}"#)
            .expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("create-alias-auth-missing"))
        .expect("test app state should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets/{secret_id}/aliases"))
        .json(&json!({ "alias": alias }))
        .send()
        .await
        .expect("create alias request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let json: Value = response
        .json()
        .await
        .expect("error response should be JSON");
    assert_eq!(json["code"], Value::String("unauthorized".to_owned()));
    assert!(json.get("request_id").is_some());
    assert!(!json.to_string().contains(alias));

    let audit_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("auth failure audit request should be captured");
    assert_eq!(audit_request.path, "/rest/v1/rpc/rpc_append_audit_event");
    assert!(!audit_request.path.contains("rpc_create_secret_alias"));
    let audit_body = audit_request
        .body
        .as_ref()
        .expect("auth failure audit body should be JSON");
    assert_auth_failure_audit_body(audit_body, "authorization_header_missing");
    assert!(!audit_body.to_string().contains(alias));

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn update_alias_endpoint_returns_ok_and_keeps_alias_out_of_rpc_body_and_logs() {
    let alias = "Prod_API-2";
    let alias_id = "750e8400-e29b-41d4-a716-446655440000";
    let (secret_id, _) =
        decrypt_row_json(b"alias update seed").expect("decrypt row JSON should be constructed");
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_alias_update_server(secret_id.clone())
            .expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("update-alias"))
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let log_buffer = SharedLogBuffer::default();
    let subscriber = build_log_subscriber(log_buffer.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .put(format!("{app_url}/v1/aliases/{alias_id}"))
        .bearer_auth(&token)
        .json(&json!({ "alias": alias }))
        .send()
        .await
        .expect("update alias request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let json: Value = response
        .json()
        .await
        .expect("update alias response should be JSON");
    assert_eq!(json["secret_alias_id"], Value::String(alias_id.to_owned()));
    assert!(json.get("alias").is_none());

    let context_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("alias update context request should be captured");
    let update_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("alias update request should be captured");
    assert!(
        context_request
            .path
            .ends_with("/rest/v1/rpc/rpc_get_secret_alias_for_update")
    );
    assert!(
        update_request
            .path
            .ends_with("/rest/v1/rpc/rpc_update_secret_alias")
    );
    let update_body = update_request
        .body
        .as_ref()
        .expect("alias update request body should be JSON");
    assert!(
        update_body["p_new_alias_fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("\\x") && value.len() == 66)
    );
    assert!(
        update_body["p_source_event_at"]
            .as_str()
            .is_some_and(|value| SourceEventAt::parse(value).is_ok())
    );
    assert!(
        !update_request
            .body
            .as_ref()
            .is_some_and(|body| body.to_string().contains(alias))
    );

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");

    let logs = log_buffer.contents();
    assert!(!logs.contains(alias));
}

#[tokio::test(flavor = "current_thread")]
async fn update_alias_endpoint_maps_owner_mismatch_to_forbidden() {
    let alias = "Prod_API-Forbidden";
    let alias_id = "750e8400-e29b-41d4-a716-446655440000";
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_alias_context_error_server(403, r#"{"message":"owner_mismatch"}"#)
            .expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("update-alias-forbidden"))
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .put(format!("{app_url}/v1/aliases/{alias_id}"))
        .bearer_auth(&token)
        .json(&json!({ "alias": alias }))
        .send()
        .await
        .expect("update alias request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let json: Value = response
        .json()
        .await
        .expect("error response should be JSON");
    assert_eq!(json["code"], Value::String("forbidden".to_owned()));

    let context_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("alias update context request should be captured");
    assert!(
        context_request
            .path
            .ends_with("/rest/v1/rpc/rpc_get_secret_alias_for_update")
    );

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn delete_alias_endpoint_returns_no_content() {
    let alias_id = "750e8400-e29b-41d4-a716-446655440000";
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_alias_delete_server().expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("delete-alias"))
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .delete(format!("{app_url}/v1/aliases/{alias_id}"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete alias request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);

    let delete_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("alias delete request should be captured");
    assert!(
        delete_request
            .path
            .ends_with("/rest/v1/rpc/rpc_delete_secret_alias")
    );
    let body = delete_request
        .body
        .expect("alias delete request body should be JSON");
    assert_eq!(
        body["p_secret_alias_id"],
        Value::String(alias_id.to_owned())
    );
    assert!(
        body["p_source_event_at"]
            .as_str()
            .is_some_and(|value| { SourceEventAt::parse(value).is_ok() })
    );

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn list_aliases_endpoint_returns_no_store_and_records_list_audit_without_alias_plaintext() {
    let alias = "Prod_API-List";
    let (secret_id, _) =
        decrypt_row_json(b"alias list seed").expect("decrypt row JSON should be constructed");
    let list_body = alias_list_row_json(&secret_id, alias)
        .expect("alias list row JSON should be constructed")
        .to_string();
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_alias_list_server(list_body).expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("list-alias"))
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let log_buffer = SharedLogBuffer::default();
    let subscriber = build_log_subscriber(log_buffer.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .get(format!("{app_url}/v1/aliases?limit=100&offset=0"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list aliases request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let json: Value = response
        .json()
        .await
        .expect("list aliases response should be JSON");
    assert_eq!(json["limit"], Value::from(100));
    assert_eq!(json["offset"], Value::from(0));
    assert_eq!(json["total_returned"], Value::from(1));
    assert_eq!(json["aliases"][0]["secret_id"], Value::String(secret_id));
    assert_eq!(json["aliases"][0]["alias"], Value::String(alias.to_owned()));

    let list_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("alias list request should be captured");
    let audit_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("alias list audit request should be captured");
    assert!(
        list_request
            .path
            .ends_with("/rest/v1/rpc/rpc_list_secret_aliases")
    );
    let list_body = list_request
        .body
        .as_ref()
        .expect("alias list request body should be JSON");
    assert_eq!(
        list_body["p_owner_user_id"],
        Value::String(OWNER_USER_ID.to_owned())
    );
    assert_eq!(list_body["p_limit"], Value::from(100));
    assert_eq!(list_body["p_offset"], Value::from(0));
    assert_eq!(audit_request.path, "/rest/v1/rpc/rpc_append_audit_event");
    let audit_body = audit_request
        .body
        .expect("alias list audit request body should be JSON");
    assert_eq!(
        audit_body["p_action"],
        Value::String("secret_alias_list".to_owned())
    );
    assert_eq!(audit_body["p_result"], Value::String("success".to_owned()));
    assert_eq!(
        audit_body["p_metadata_json"]["result_count"],
        Value::from(1)
    );
    assert!(
        audit_body["p_metadata_json"]["source_event_at"]
            .as_str()
            .is_some_and(|value| SourceEventAt::parse(value).is_ok())
    );
    assert!(!audit_body.to_string().contains(alias));

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");

    let logs = log_buffer.contents();
    assert!(!logs.contains(alias));
}

#[tokio::test(flavor = "current_thread")]
async fn list_aliases_endpoint_rejects_invalid_limit_without_upstream_call() {
    let (supabase_url, receiver, server_thread) =
        spawn_capture_server(Duration::from_millis(100)).expect("capture server should start");
    let state = test_app_state(&supabase_url, temp_path("list-alias-invalid-limit"))
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .get(format!("{app_url}/v1/aliases?limit=0"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list aliases request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let json: Value = response
        .json()
        .await
        .expect("error response should be JSON");
    assert_eq!(json["code"], Value::String("bad_request".to_owned()));
    assert!(receiver.recv_timeout(Duration::from_millis(200)).is_err());

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn resolve_alias_endpoint_returns_secret_id_without_audit() {
    let alias = "Prod_API-Resolve";
    let (secret_id, _) =
        decrypt_row_json(b"alias resolve seed").expect("decrypt row JSON should be constructed");
    let resolve_body = alias_resolve_row_json(&secret_id, alias)
        .expect("alias resolve row JSON should be constructed")
        .to_string();
    let (supabase_url, receiver, server_thread) = spawn_supabase_alias_resolve_server(resolve_body)
        .expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("resolve-alias"))
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let log_buffer = SharedLogBuffer::default();
    let subscriber = build_log_subscriber(log_buffer.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/aliases/resolve"))
        .bearer_auth(&token)
        .json(&json!({ "alias": alias }))
        .send()
        .await
        .expect("resolve alias request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let json: Value = response
        .json()
        .await
        .expect("resolve alias response should be JSON");
    assert_eq!(json["secret_id"], Value::String(secret_id));
    assert!(
        json["secret_alias_id"]
            .as_str()
            .is_some_and(|value| uuid::Uuid::parse_str(value).is_ok())
    );
    assert!(json.get("alias").is_none());

    let resolve_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("alias resolve request should be captured");
    assert!(
        resolve_request
            .path
            .ends_with("/rest/v1/rpc/rpc_resolve_secret_alias")
    );
    assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());
    assert!(
        !resolve_request
            .body
            .as_ref()
            .is_some_and(|body| body.to_string().contains(alias))
    );

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");

    let logs = log_buffer.contents();
    assert!(!logs.contains(alias));
}

#[tokio::test(flavor = "current_thread")]
async fn resolve_alias_endpoint_returns_not_found_without_audit() {
    let alias = "missing-alias";
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_alias_resolve_server("[]".to_owned())
            .expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("resolve-alias-not-found"))
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/aliases/resolve"))
        .bearer_auth(&token)
        .json(&json!({ "alias": alias }))
        .send()
        .await
        .expect("resolve alias request should complete");

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    let json: Value = response
        .json()
        .await
        .expect("error response should be JSON");
    assert_eq!(json["code"], Value::String("not_found".to_owned()));
    assert!(!json.to_string().contains(alias));

    let resolve_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("alias resolve request should be captured");
    assert!(
        resolve_request
            .path
            .ends_with("/rest/v1/rpc/rpc_resolve_secret_alias")
    );
    assert!(receiver.recv_timeout(Duration::from_millis(100)).is_err());

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn decrypt_endpoint_fails_closed_when_primary_and_fallback_audit_both_fail() {
    let plaintext = b"both fail secret";
    let (secret_id, row_json) =
        decrypt_row_json(plaintext).expect("decrypt row JSON should be constructed");
    let body = row_json.to_string();
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_read_and_audit_server(body, 500, r#"{"error":"audit failed"}"#)
            .expect("Supabase test server should start");
    let fallback_path = temp_path("decrypt-fallback-both-fail");
    fs::create_dir(&fallback_path).expect("fallback path should be a directory");
    let state = test_app_state(&supabase_url, fallback_path.clone())
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets/{secret_id}/decrypt"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("decrypt request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    let json: Value = response
        .json()
        .await
        .expect("decrypt response should be JSON");
    assert_eq!(
        json["code"],
        Value::String("ledger_append_failed".to_owned())
    );
    assert!(json.get("request_id").is_some());
    assert!(json.get("plaintext_hex").is_none());

    let read_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("secret read request should be captured");
    let chain_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("ledger chain head request should be captured");
    let audit_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("audit and ledger append request should be captured");
    assert_eq!(read_request.method, "GET");
    assert_eq!(chain_request.method, "GET");
    assert!(
        chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );
    assert_eq!(audit_request.method, "POST");
    assert!(
        audit_request
            .path
            .ends_with("/rest/v1/rpc/rpc_append_audit_event_with_ledger")
    );
    assert!(!fallback_path.is_file());

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn decrypt_endpoint_rejects_invalid_read_model_rows_without_plaintext()
-> Result<(), Box<dyn std::error::Error>> {
    let cases: [(&str, DecryptRowMutation); 11] = [
        ("bad-nonce", make_decrypt_row_bad_nonce),
        ("empty-ciphertext", make_decrypt_row_empty_ciphertext),
        (
            "ciphertext-without-bytea-prefix",
            make_decrypt_row_ciphertext_without_bytea_prefix,
        ),
        (
            "ciphertext-invalid-hex",
            make_decrypt_row_ciphertext_invalid_hex,
        ),
        (
            "bad-encrypted-data-key",
            make_decrypt_row_bad_encrypted_data_key,
        ),
        ("bad-algorithm", make_decrypt_row_bad_algorithm),
        ("owner-mismatch", make_decrypt_row_owner_mismatch),
        (
            "classification-mismatch",
            make_decrypt_row_classification_mismatch,
        ),
        ("non-current", make_decrypt_row_non_current),
        ("multiple-current", make_decrypt_rows_multiple_current),
        ("empty-row", make_decrypt_rows_empty),
    ];

    for (case_name, mutate) in cases {
        let (secret_id, mut row_json) = decrypt_row_json(b"invalid read model row")?;
        mutate(&mut row_json);
        let (supabase_url, receiver, server_thread) =
            spawn_supabase_read_failure_audit_server(row_json.to_string())?;
        let state = test_app_state(&supabase_url, temp_path(case_name))?;
        let token = valid_token()?;
        let (app_url, app_task) = spawn_app(state).await?;

        let response = reqwest::Client::new()
            .post(format!("{app_url}/v1/secrets/{secret_id}/decrypt"))
            .bearer_auth(&token)
            .send()
            .await?;

        assert!(
            !response.status().is_success(),
            "{case_name} should be rejected"
        );
        let json: Value = response.json().await?;
        assert!(
            json.get("plaintext_hex").is_none(),
            "{case_name} must not expose plaintext"
        );
        let response_body = serde_json::to_string(&json)?;
        for forbidden in [
            "plaintext_hex",
            "ciphertext",
            "encrypted_data_key",
            "service_role_key",
            "service-role-key",
        ] {
            assert!(
                !response_body.contains(forbidden),
                "{case_name} response leaked {forbidden}"
            );
        }

        let read_request = receiver.recv_timeout(Duration::from_secs(2))?;
        let audit_request = receiver.recv_timeout(Duration::from_secs(2))?;
        assert_eq!(read_request.method, "GET");
        assert!(read_request.path.starts_with("/rest/v1/secret_versions"));
        assert_eq!(audit_request.method, "POST");
        assert_eq!(audit_request.path, "/rest/v1/rpc/rpc_append_audit_event");
        let audit_body = audit_request
            .body
            .ok_or_else(|| std::io::Error::other("failure audit body should be JSON"))?;
        assert_eq!(audit_body["p_action"], "decrypt");
        assert_eq!(audit_body["p_result"], "failure");
        assert!(audit_body["p_metadata_json"]["source_event_at"].is_string());
        let audit_metadata = serde_json::to_string(&audit_body["p_metadata_json"])?;
        for forbidden in [
            "plaintext_hex",
            "ciphertext",
            "encrypted_data_key",
            "service_role_key",
            "service-role-key",
        ] {
            assert!(
                !audit_metadata.contains(forbidden),
                "{case_name} audit metadata leaked {forbidden}"
            );
        }

        app_task.abort();
        let _ = app_task.await;
        server_thread
            .join()
            .map_err(|_| std::io::Error::other("read failure server thread panicked"))??;
    }

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn create_endpoint_maps_upstream_401_to_502_with_request_id() {
    let (supabase_url, receiver, server_thread) = spawn_supabase_single_request_server(
        401,
        "Unauthorized",
        r#"{"error":"upstream denied create"}"#,
    )
    .expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("create-upstream-401"))
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets"))
        .bearer_auth(&token)
        .json(&json!({
            "classification": CLASSIFICATION,
            "device_id": DEVICE_ID,
            "plaintext_hex": "00aa11ff"
        }))
        .send()
        .await
        .expect("create request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    let json: Value = response
        .json()
        .await
        .expect("error response should be JSON");
    assert_eq!(
        json["code"],
        Value::String("ledger_append_failed".to_owned())
    );
    let request_id = json["request_id"]
        .as_str()
        .expect("error response should include request_id");
    assert!(uuid::Uuid::parse_str(request_id).is_ok());
    assert!(
        !json
            .as_object()
            .is_some_and(|object| object.contains_key("error"))
    );

    let chain_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("ledger chain head request should be captured");
    assert_eq!(chain_request.method, "GET");
    assert!(
        chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn rotate_endpoint_maps_upstream_403_to_502_with_request_id() {
    let (secret_id, row_json) =
        decrypt_row_json(b"rotate seed secret").expect("decrypt row JSON should be constructed");
    let (supabase_url, receiver, server_thread) = spawn_supabase_rotate_server(
        row_json.to_string(),
        403,
        r#"{"error":"upstream denied rotate"}"#,
    )
    .expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("rotate-upstream-403"))
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets/{secret_id}/versions"))
        .bearer_auth(&token)
        .json(&json!({
            "device_id": DEVICE_ID,
            "plaintext_hex": "00aa11ff"
        }))
        .send()
        .await
        .expect("rotate request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    let json: Value = response
        .json()
        .await
        .expect("error response should be JSON");
    assert_eq!(
        json["code"],
        Value::String("upstream_dependency_failed".to_owned())
    );
    let request_id = json["request_id"]
        .as_str()
        .expect("error response should include request_id");
    assert!(uuid::Uuid::parse_str(request_id).is_ok());
    assert!(
        !json
            .as_object()
            .is_some_and(|object| object.contains_key("error"))
    );

    let read_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("secret read request should be captured");
    let snapshot_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("retention snapshot request should be captured");
    let chain_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("ledger chain head request should be captured");
    let write_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("write RPC request should be captured");
    assert_eq!(read_request.method, "GET");
    assert_eq!(snapshot_request.method, "GET");
    assert!(
        snapshot_request
            .path
            .starts_with("/rest/v1/secret_versions")
    );
    assert_eq!(chain_request.method, "GET");
    assert!(
        chain_request
            .path
            .starts_with("/rest/v1/ledger_chain_state")
    );
    assert_eq!(write_request.method, "POST");
    assert!(
        write_request
            .path
            .ends_with("/rest/v1/rpc/rpc_write_secret_version")
    );
    let write_body = write_request
        .body
        .as_ref()
        .expect("write RPC request should include JSON body");
    assert!(
        write_body["p_encrypted_data_key"].is_null(),
        "v0.2 rotate write should not send legacy encrypted_data_key"
    );
    assert_eq!(write_body["p_dek_wrap_algorithm"], "envvar-xchacha-v2");
    assert_eq!(write_body["p_key_version"], write_body["p_kek_version"]);
    let wrapped_dek = write_body["p_wrapped_dek"]
        .as_str()
        .expect("v0.2 rotate write should include wrapped_dek");
    let wrapped_dek_hex = wrapped_dek
        .strip_prefix("\\x")
        .expect("wrapped_dek should use bytea hex encoding");
    assert_eq!(
        hex::decode(wrapped_dek_hex)
            .expect("wrapped_dek should be hex")
            .len(),
        72
    );

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn decrypt_endpoint_maps_upstream_404_to_502_with_request_id() {
    let (supabase_url, receiver, server_thread) = spawn_supabase_single_request_server(
        404,
        "Not Found",
        r#"{"error":"upstream secret missing"}"#,
    )
    .expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("decrypt-upstream-404"))
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let secret_id = "550e8400-e29b-41d4-a716-446655440000";
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets/{secret_id}/decrypt"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("decrypt request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    let json: Value = response
        .json()
        .await
        .expect("error response should be JSON");
    assert_eq!(
        json["code"],
        Value::String("upstream_dependency_failed".to_owned())
    );
    let request_id = json["request_id"]
        .as_str()
        .expect("error response should include request_id");
    assert!(uuid::Uuid::parse_str(request_id).is_ok());
    assert!(
        !json
            .as_object()
            .is_some_and(|object| object.contains_key("error"))
    );

    let read_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("secret read request should be captured");
    assert_eq!(read_request.method, "GET");
    assert!(read_request.path.starts_with("/rest/v1/secret_versions"));

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn create_endpoint_missing_authorization_returns_401_with_request_id() {
    let state = test_app_state("http://127.0.0.1:1", temp_path("create-auth-missing"))
        .expect("test app state should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets"))
        .json(&json!({
            "classification": CLASSIFICATION,
            "device_id": DEVICE_ID,
            "plaintext_hex": "00aa11ff"
        }))
        .send()
        .await
        .expect("create request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let json: Value = response
        .json()
        .await
        .expect("error response should be JSON");
    assert_eq!(json["code"], Value::String("unauthorized".to_owned()));
    let request_id = json["request_id"]
        .as_str()
        .expect("error response should include request_id");
    assert!(uuid::Uuid::parse_str(request_id).is_ok());
    assert!(
        !json
            .as_object()
            .is_some_and(|object| object.contains_key("error"))
    );

    app_task.abort();
    let _ = app_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn missing_authorization_records_auth_failure_audit() {
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_single_request_server(200, "OK", r#"{"status":"ok"}"#)
            .expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("auth-failure-missing"))
        .expect("test app state should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets"))
        .json(&json!({
            "classification": CLASSIFICATION,
            "device_id": DEVICE_ID,
            "plaintext_hex": "00aa11ff"
        }))
        .send()
        .await
        .expect("create request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let audit_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("auth failure audit request should be captured");
    assert_eq!(audit_request.method, "POST");
    assert!(
        audit_request
            .path
            .ends_with("/rest/v1/rpc/rpc_append_audit_event")
    );
    assert_auth_failure_audit_body(
        audit_request
            .body
            .as_ref()
            .expect("audit append body should be JSON"),
        "authorization_header_missing",
    );

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn rate_limited_unauthenticated_request_does_not_append_auth_failure_audit() {
    let (supabase_url, receiver, server_thread) =
        spawn_capture_server_until_idle(Duration::from_millis(500))
            .expect("capture server should start");
    let mut state = test_app_state(&supabase_url, temp_path("rate-limit-auth-failure"))
        .expect("test app state should be created");
    state.http_rate_limit_requests = 1;
    state.http_rate_limit_window = Duration::from_secs(60);
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");
    let client = reqwest::Client::new();

    let first = client
        .post(format!("{app_url}/v1/secrets"))
        .json(&json!({
            "classification": CLASSIFICATION,
            "device_id": DEVICE_ID,
            "plaintext_hex": "00aa11ff"
        }))
        .send()
        .await
        .expect("first create request should succeed");
    assert_eq!(first.status(), reqwest::StatusCode::UNAUTHORIZED);

    let audit_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("first auth failure audit request should be captured");
    assert!(
        audit_request
            .path
            .ends_with("/rest/v1/rpc/rpc_append_audit_event")
    );
    assert_auth_failure_audit_body(
        audit_request
            .body
            .as_ref()
            .expect("audit append body should be JSON"),
        "authorization_header_missing",
    );

    let second = client
        .post(format!("{app_url}/v1/secrets"))
        .json(&json!({
            "classification": CLASSIFICATION,
            "device_id": DEVICE_ID,
            "plaintext_hex": "00aa11ff"
        }))
        .send()
        .await
        .expect("second create request should succeed");
    assert_eq!(second.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let body: Value = second
        .json()
        .await
        .expect("rate limit response should be JSON");
    assert_eq!(body["code"], Value::String("rate_limited".to_owned()));

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("capture server thread should join")
        .expect("capture server should stop cleanly");
    assert!(
        receiver.recv_timeout(Duration::from_millis(100)).is_err(),
        "rate-limited request must not append another auth_failure audit event"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_authorization_scheme_records_auth_failure_audit() {
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_single_request_server(200, "OK", r#"{"status":"ok"}"#)
            .expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("auth-failure-scheme"))
        .expect("test app state should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets"))
        .header(reqwest::header::AUTHORIZATION, "Basic not-a-jwt")
        .json(&json!({
            "classification": CLASSIFICATION,
            "device_id": DEVICE_ID,
            "plaintext_hex": "00aa11ff"
        }))
        .send()
        .await
        .expect("create request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let audit_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("auth failure audit request should be captured");
    assert_auth_failure_audit_body(
        audit_request
            .body
            .as_ref()
            .expect("audit append body should be JSON"),
        "authorization_scheme_invalid",
    );

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_jwt_records_auth_failure_audit() {
    let (supabase_url, receiver, server_thread) =
        spawn_supabase_single_request_server(200, "OK", r#"{"status":"ok"}"#)
            .expect("Supabase test server should start");
    let state = test_app_state(&supabase_url, temp_path("auth-failure-jwt"))
        .expect("test app state should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets"))
        .bearer_auth("not-a-jwt")
        .json(&json!({
            "classification": CLASSIFICATION,
            "device_id": DEVICE_ID,
            "plaintext_hex": "00aa11ff"
        }))
        .send()
        .await
        .expect("create request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let audit_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("auth failure audit request should be captured");
    assert_auth_failure_audit_body(
        audit_request
            .body
            .as_ref()
            .expect("audit append body should be JSON"),
        "jwt_verification_failed",
    );

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn auth_failure_audit_falls_back_without_changing_401_response() {
    let (supabase_url, receiver, server_thread) = spawn_supabase_single_request_server(
        500,
        "Internal Server Error",
        r#"{"error":"audit failed"}"#,
    )
    .expect("Supabase test server should start");
    let fallback_path = temp_path("auth-failure-fallback.jsonl");
    let state = test_app_state(&supabase_url, fallback_path.clone())
        .expect("test app state should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets"))
        .json(&json!({
            "classification": CLASSIFICATION,
            "device_id": DEVICE_ID,
            "plaintext_hex": "00aa11ff"
        }))
        .send()
        .await
        .expect("create request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body: Value = response
        .json()
        .await
        .expect("error response should be JSON");
    assert_eq!(body["code"], Value::String("unauthorized".to_owned()));

    let audit_request = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("auth failure audit request should be captured");
    assert_auth_failure_audit_body(
        audit_request
            .body
            .as_ref()
            .expect("audit append body should be JSON"),
        "authorization_header_missing",
    );

    let fallback_contents =
        fs::read_to_string(&fallback_path).expect("fallback JSON Lines file should exist");
    assert!(fallback_contents.contains(r#""action":"auth_failure""#));
    assert!(fallback_contents.contains(r#""result":"failure""#));
    assert!(fallback_contents.contains(r#""delivery_status":"pending""#));
    assert!(fallback_contents.contains(r#""source_event_at":"#));
    assert!(!fallback_contents.contains("Authorization"));
    assert!(!fallback_contents.contains("not-a-jwt"));

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");
}

#[tokio::test(flavor = "current_thread")]
async fn create_endpoint_rejects_invalid_json_with_request_id() {
    let state = test_app_state("http://127.0.0.1:1", temp_path("create-invalid-json"))
        .expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets"))
        .bearer_auth(&token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body("{")
        .send()
        .await
        .expect("create request should succeed");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let json: Value = response
        .json()
        .await
        .expect("error response should be JSON");
    assert_eq!(json["code"], Value::String("bad_request".to_owned()));
    let request_id = json["request_id"]
        .as_str()
        .expect("error response should include request_id");
    assert!(uuid::Uuid::parse_str(request_id).is_ok());
    assert!(
        !json
            .as_object()
            .is_some_and(|object| object.contains_key("error"))
    );

    app_task.abort();
    let _ = app_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn create_and_rotate_endpoints_reject_invalid_request_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let state = test_app_state("http://127.0.0.1:1", temp_path("invalid-request-fields"))?;
    let token = valid_token()?;
    let (app_url, app_task) = spawn_app(state).await?;
    let client = reqwest::Client::new();

    for body in [
        json!({
            "classification": CLASSIFICATION,
            "device_id": DEVICE_ID,
            "plaintext_hex": "not hex"
        }),
        json!({
            "classification": CLASSIFICATION,
            "device_id": DEVICE_ID,
            "plaintext_hex": "abc"
        }),
        json!({
            "classification": CLASSIFICATION,
            "device_id": DEVICE_ID,
            "plaintext_hex": "AA"
        }),
        json!({
            "classification": CLASSIFICATION,
            "device_id": "   ",
            "plaintext_hex": "00"
        }),
    ] {
        let response = client
            .post(format!("{app_url}/v1/secrets"))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        let json: Value = response.json().await?;
        assert_eq!(json["code"], Value::String("bad_request".to_owned()));
        assert!(json.get("plaintext_hex").is_none());
    }

    for body in [
        json!({
            "device_id": "   ",
            "plaintext_hex": "00"
        }),
        json!({
            "device_id": DEVICE_ID,
            "plaintext_hex": "AA"
        }),
        json!({
            "device_id": DEVICE_ID,
            "plaintext_hex": "not hex"
        }),
        json!({
            "device_id": DEVICE_ID,
            "plaintext_hex": "abc"
        }),
    ] {
        let response = client
            .post(format!(
                "{app_url}/v1/secrets/550e8400-e29b-41d4-a716-446655440000/versions"
            ))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        let json: Value = response.json().await?;
        assert_eq!(json["code"], Value::String("bad_request".to_owned()));
        assert!(json.get("plaintext_hex").is_none());
    }

    app_task.abort();
    let _ = app_task.await;

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_layer_does_not_log_response_body_or_authorization_values() {
    let plaintext = b"never-log-this";
    let plaintext_hex = hex::encode(plaintext);
    let (secret_id, row_json) =
        decrypt_row_json(plaintext).expect("decrypt row JSON should be constructed");
    let body = row_json.to_string();
    let (supabase_url, _receiver, server_thread) =
        spawn_supabase_read_and_audit_server(body, 200, r#"{"status":"ok"}"#)
            .expect("Supabase test server should start");
    let fallback_path = temp_path("decrypt-log-redaction.jsonl");
    let state =
        test_app_state(&supabase_url, fallback_path).expect("test app state should be created");
    let token = valid_token().expect("test JWT should be created");
    let log_buffer = SharedLogBuffer::default();
    let subscriber = build_log_subscriber(log_buffer.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    let (app_url, app_task) = spawn_app(state).await.expect("test app should start");

    let response = reqwest::Client::new()
        .post(format!("{app_url}/v1/secrets/{secret_id}/decrypt"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("decrypt request should succeed");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let _ = response
        .text()
        .await
        .expect("response body should be readable");

    app_task.abort();
    let _ = app_task.await;
    server_thread
        .join()
        .expect("Supabase test server thread should join")
        .expect("Supabase test server should stop cleanly");

    let logs = log_buffer.contents();
    assert!(!logs.contains("plaintext_hex"));
    assert!(!logs.contains(&plaintext_hex));
    assert!(!logs.contains(&token));
    assert!(!logs.contains("Authorization"));
    assert!(!logs.contains("authorization"));
}

fn spawn_single_response_server(status: u16, body: &'static str) -> String {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("test server should bind to a local port");
    let addr = listener
        .local_addr()
        .expect("test server local address should be available");
    thread::spawn(move || {
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

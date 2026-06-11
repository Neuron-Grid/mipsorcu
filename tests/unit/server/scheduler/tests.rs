use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use time::{Date, Time};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::jobs::{
    fetch_signed_digest, map_envelope_migration_error, persist_timestamping_token_to_archive,
    run_job_body, run_monthly_timestamping_obtain_job,
};
use super::*;
use crate::archive::{AnyArchiveBackend, LocalFileArchiveBackend};
use crate::audit::{AuditRecorder, LocalAuditFallbackStore};
use crate::auth::{Jwk, Jwks, JwtVerifier, JwtVerifierConfig};
use crate::crypto::MasterKeyRing;
use crate::incident::{
    AnyNotificationSink, DummyNotificationSink, IncidentDetector, IncidentDispatcher,
    IncidentRecorder,
};
use crate::ledger::{
    DigestHash, LEDGER_ED25519_SECRET_KEY_LENGTH, LedgerHash, LedgerSequenceNo, LedgerSignature,
    LedgerSignatureKeyVersion, LedgerSigningKey, MonthlyDigestPeriod, SignedMonthlyDigest,
    build_monthly_digest_canonical_form,
};
use crate::server::ledger_appender::LedgerAppender;
use crate::server::siem_forwarding::SiemForwardingService;
use crate::server::state::{AppState, ReadinessState};
use crate::server::supabase::{SupabaseAuditAppender, SupabaseClient};
use crate::siem::{AnySiemSink, InMemorySiemSink, LocalSiemFallbackBuffer, SiemForwarder};
use crate::timestamping::{
    AnyTimestampingProvider, InMemoryTimestampingService, TimestampingToken,
};
use crate::types::{
    AliasEncryptionKey, AliasFingerprintKey, KeyVersion, MASTER_KEY_LENGTH, MasterKey,
    SourceEventAt,
};

const JWT_ISSUER: &str = "issuer";
const JWT_AUDIENCE: &str = "audience";

fn dt(year: i32, month: Month, day: u8, hour: u8) -> OffsetDateTime {
    let date = Date::from_calendar_date(year, month, day).expect("valid test date");
    let time = Time::from_hms(hour, 0, 0).expect("valid test time");
    date.with_time(time).assume_utc()
}

fn unique_temp_path(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after UNIX_EPOCH for tests")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "mipsorcu-scheduler-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn token_path(base_dir: &Path, period: &MonthlyDigestPeriod) -> PathBuf {
    base_dir
        .join("timestamping")
        .join(period.as_str())
        .join("token.tsr")
}

fn test_scheduler_config(
    local_archive_dir: PathBuf,
    archive_backend: Option<Arc<AnyArchiveBackend>>,
    timestamping_provider: Option<Arc<AnyTimestampingProvider>>,
) -> SchedulerConfig {
    SchedulerConfig {
        startup_delay: Duration::from_secs(0),
        poll_interval: Duration::from_secs(60),
        monthly_day: 1,
        monthly_hour_utc: 4,
        quarterly_hour_utc: 5,
        daily_hour_utc: 4,
        envelope_migration_batch_size: 100,
        envelope_migration_max_batches: 1,
        restore_test_sample_limit: 10,
        local_archive_dir,
        archive_backend,
        timestamping_provider,
    }
}

fn test_period() -> MonthlyDigestPeriod {
    MonthlyDigestPeriod::parse("2026-05").expect("valid test period")
}

fn test_token() -> TimestampingToken {
    TimestampingToken::new(b"DUMMY-TST-V1:scheduler-regression".to_vec())
        .expect("valid non-empty timestamping token")
}

fn sample_master_key() -> MasterKey {
    MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH])
}

fn test_signed_monthly_digest() -> SignedMonthlyDigest {
    let period = test_period();
    let start_hash = LedgerHash::from_bytes(&[0xaa; 32]).expect("valid hash");
    let end_hash = LedgerHash::from_bytes(&[0xbb; 32]).expect("valid hash");
    let generated_at = SourceEventAt::parse("2026-06-01T00:00:00Z").expect("valid timestamp");
    let key_version = LedgerSignatureKeyVersion::new(1).expect("valid key version");
    let start_seq = LedgerSequenceNo::new(1).expect("valid seq");
    let end_seq = LedgerSequenceNo::new(42).expect("valid seq");

    let canonical_bytes = build_monthly_digest_canonical_form(
        &period,
        start_seq,
        end_seq,
        start_hash,
        end_hash,
        42,
        &generated_at,
        key_version,
    )
    .expect("canonical form build must succeed");

    let digest_hash = DigestHash::from_canonical_bytes(&canonical_bytes);
    let sbc_signature = LedgerSignature::from_bytes(&[0u8; 64]).expect("valid signature");

    SignedMonthlyDigest {
        period,
        start_sequence_no: start_seq,
        end_sequence_no: end_seq,
        start_entry_hash: start_hash,
        end_entry_hash: end_hash,
        entry_count: 42,
        digest_generated_at: generated_at,
        signature_key_version: key_version,
        canonical_bytes,
        digest_hash,
        sbc_signature,
    }
}

struct DigestFetchFixture {
    period: MonthlyDigestPeriod,
    start_hash: LedgerHash,
    end_hash: LedgerHash,
    generated_at: SourceEventAt,
    key_version: LedgerSignatureKeyVersion,
    start_sequence_no: LedgerSequenceNo,
    end_sequence_no: LedgerSequenceNo,
    entry_count: u64,
    digest_hash_hex: String,
    sbc_signature_hex: String,
    public_key_hex: String,
}

fn digest_fetch_fixture() -> DigestFetchFixture {
    let period = test_period();
    let start_hash = LedgerHash::from_bytes(&[0xaa; 32]).expect("valid hash");
    let end_hash = LedgerHash::from_bytes(&[0xbb; 32]).expect("valid hash");
    let generated_at = SourceEventAt::parse("2026-06-01T00:00:00Z").expect("valid timestamp");
    let key_version = LedgerSignatureKeyVersion::new(1).expect("valid key version");
    let start_sequence_no = LedgerSequenceNo::new(1).expect("valid seq");
    let end_sequence_no = LedgerSequenceNo::new(42).expect("valid seq");
    let entry_count = 42;
    let signing_key = LedgerSigningKey::from_secret_key_bytes(
        key_version,
        &[9u8; LEDGER_ED25519_SECRET_KEY_LENGTH],
    )
    .expect("valid signing key");

    let canonical_bytes = build_monthly_digest_canonical_form(
        &period,
        start_sequence_no,
        end_sequence_no,
        start_hash,
        end_hash,
        entry_count,
        &generated_at,
        key_version,
    )
    .expect("canonical form build must succeed");
    let digest_hash_hex = DigestHash::from_canonical_bytes(&canonical_bytes).to_hex();
    let sbc_signature = signing_key
        .sign_raw_bytes(key_version, canonical_bytes.as_bytes())
        .expect("digest signing must succeed");
    let public_key_hex = format!(
        "\\x{}",
        hex::encode(signing_key.verification_key().as_bytes())
    );

    DigestFetchFixture {
        period,
        start_hash,
        end_hash,
        generated_at,
        key_version,
        start_sequence_no,
        end_sequence_no,
        entry_count,
        digest_hash_hex,
        sbc_signature_hex: sbc_signature.to_lower_hex(),
        public_key_hex,
    }
}

fn digest_fetch_body(fixture: &DigestFetchFixture) -> Value {
    json!([{
        "start_sequence_no": fixture.start_sequence_no.get(),
        "end_sequence_no": fixture.end_sequence_no.get(),
        "stored_entry_count": fixture.entry_count,
        "stored_digest_hash": fixture.digest_hash_hex,
        "target_year_month": fixture.period.as_str(),
        "digest_generated_at": fixture.generated_at.as_str(),
        "signature": format!("\\x{}", "11".repeat(64)),
        "sbc_signature": fixture.sbc_signature_hex,
        "signature_key_version": fixture.key_version.get(),
        "public_key": fixture.public_key_hex,
        "start_entry_hash": fixture.start_hash.to_bytea_hex(),
        "end_entry_hash": fixture.end_hash.to_bytea_hex()
    }])
}

fn digest_fetch_body_with_hash(fixture: &DigestFetchFixture, stored_digest_hash: &str) -> Value {
    let mut body = digest_fetch_body(fixture);
    body[0]["stored_digest_hash"] = Value::String(stored_digest_hash.to_owned());
    body
}

fn digest_fetch_body_with_signature(fixture: &DigestFetchFixture, sbc_signature: &str) -> Value {
    let mut body = digest_fetch_body(fixture);
    body[0]["sbc_signature"] = Value::String(sbc_signature.to_owned());
    body
}

fn digest_fetch_body_without_public_key(fixture: &DigestFetchFixture) -> Value {
    let mut body = digest_fetch_body(fixture);
    body[0]["public_key"] = Value::Null;
    body
}

fn corrupt_signature_hex(signature_hex: &str) -> String {
    let mut corrupted = signature_hex.to_owned();
    let replacement = if signature_hex.starts_with("00") {
        "01"
    } else {
        "00"
    };
    corrupted.replace_range(0..2, replacement);
    corrupted
}

async fn mock_digest_fetch(body: Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/rest/v1/rpc/rpc_fetch_monthly_digest_for_verification",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    server
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
    let notification_sink = AnyNotificationSink::Dummy(DummyNotificationSink::new());
    let incident_recorder = Arc::new(IncidentRecorder::new(
        supabase_client.clone(),
        ledger_appender.clone(),
        "dummy",
    ));
    let incident_dispatcher = Arc::new(IncidentDispatcher::new(
        Arc::new(notification_sink),
        audit_recorder.clone(),
    ));
    let readiness_state = ReadinessState::new();
    let siem_forwarding = Arc::new(SiemForwardingService::new(
        SiemForwarder::new(
            AnySiemSink::InMemory(InMemorySiemSink::new()),
            LocalSiemFallbackBuffer::new(unique_temp_path("siem-buffer")),
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
        incident_detector: IncidentDetector::new(),
        siem_forwarding,
        audit_fallback_store,
        readiness_state,
        health_readiness_poll_interval: Duration::from_secs(30),
        siem_long_failure_threshold: Duration::from_secs(900),
        http_handler_timeout: Duration::from_secs(75),
        http_rate_limit_requests: 300,
        http_rate_limit_window: Duration::from_secs(60),
        scheduler_status: SchedulerStatusState::default(),
    })
}

async fn mock_scheduler_supabase() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/v1/ledger_chain_state"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "last_sequence_no": 0,
            "last_entry_hash": "\\x0000000000000000000000000000000000000000000000000000000000000000"
        }])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/v1/rpc/rpc_append_ledger_entry"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "ledger_entry_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "sequence_no": 1,
            "entry_hash": "\\x1111111111111111111111111111111111111111111111111111111111111111",
            "chain_last_sequence_no": 1,
            "chain_last_entry_hash": "\\x1111111111111111111111111111111111111111111111111111111111111111",
            "replayed": false
        }])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/rest/v1/rpc/rpc_append_audit_event"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;
    server
}

#[test]
fn monthly_due_respects_day_and_hour() {
    assert!(monthly_due(dt(2026, Month::June, 1, 3), 1, 3));
    assert!(monthly_due(dt(2026, Month::June, 1, 4), 1, 3));
    assert!(!monthly_due(dt(2026, Month::June, 1, 2), 1, 3));
    assert!(!monthly_due(dt(2026, Month::June, 2, 3), 1, 3));
}

#[test]
fn quarterly_due_only_runs_on_quarter_boundary_months() {
    assert!(quarterly_due(dt(2026, Month::April, 1, 4), 1, 4));
    assert!(!quarterly_due(dt(2026, Month::May, 1, 4), 1, 4));
    assert!(!quarterly_due(dt(2026, Month::April, 1, 3), 1, 4));
}

#[test]
fn daily_due_respects_hour_boundary() {
    assert!(!daily_due(dt(2026, Month::June, 1, 3), 4));
    assert!(daily_due(dt(2026, Month::June, 1, 4), 4));
    assert!(daily_due(dt(2026, Month::June, 1, 5), 4));
    assert!(daily_due(dt(2026, Month::June, 1, 23), 4));
}

#[test]
fn daily_period_key_encodes_year_month_day() {
    assert_eq!(daily_period_key(dt(2026, Month::June, 1, 4)), "2026-06-01");
    assert_eq!(
        daily_period_key(dt(2025, Month::December, 31, 23)),
        "2025-12-31"
    );
}

#[test]
fn scheduled_job_name_includes_new_v02_jobs() {
    assert_eq!(
        ScheduledJobName::MonthlyTimestampingObtain.as_str(),
        "monthly_timestamping_obtain"
    );
    assert_eq!(
        ScheduledJobName::DailyEnvelopeLazyMigration.as_str(),
        "daily_envelope_lazy_migration"
    );
    assert_eq!(
        ScheduledJobName::SiemBufferFlush.as_str(),
        "siem_buffer_flush"
    );
}

#[test]
fn map_envelope_migration_error_classifies_retryable_conflict() {
    use crate::server::key_rotation::KeyRotationCliError;
    use crate::server::supabase::SupabaseRpcError;

    // 1340 abort 契約の 40001 retryable conflict は専用 error_code に分類し、
    // 汎用 Supabase 失敗 (`envelope_migration_supabase_failed`) と区別する。
    assert_eq!(
        map_envelope_migration_error(&KeyRotationCliError::EnvelopeMigrationConflict),
        "envelope_migration_conflict_retryable"
    );
    assert_ne!(
        map_envelope_migration_error(&KeyRotationCliError::EnvelopeMigrationConflict),
        map_envelope_migration_error(&KeyRotationCliError::Supabase(
            SupabaseRpcError::EmptyResult
        ))
    );

    // 残りのバリアントのマッピングも回帰固定する（網羅性の担保）。
    assert_eq!(
        map_envelope_migration_error(&KeyRotationCliError::Supabase(
            SupabaseRpcError::EmptyResult
        )),
        "envelope_migration_supabase_failed"
    );
    assert_eq!(
        map_envelope_migration_error(&KeyRotationCliError::Config("boom".to_owned())),
        "envelope_migration_config_invalid"
    );
    assert_eq!(
        map_envelope_migration_error(&KeyRotationCliError::Audit("boom".to_owned())),
        "envelope_migration_audit_failed"
    );
    assert_eq!(
        map_envelope_migration_error(&KeyRotationCliError::Crypto("boom".to_owned())),
        "envelope_migration_crypto_failed"
    );
    assert_eq!(
        map_envelope_migration_error(&KeyRotationCliError::Usage("boom".to_owned())),
        "envelope_migration_failed"
    );
}

#[test]
fn scheduled_job_specs_use_task_12_cron_and_timeouts() {
    let specs = SCHEDULED_JOB_SPECS
        .iter()
        .map(|spec| (spec.name.as_str(), spec.cron, spec.timeout.as_secs()))
        .collect::<Vec<_>>();

    assert_eq!(
        specs,
        vec![
            ("monthly_hash_chain_verify", "0 0 2 1 * *", 30 * 60),
            ("monthly_signature_verify", "0 30 2 1 * *", 30 * 60),
            ("monthly_digest_generate", "0 0 3 1 * *", 30 * 60),
            ("monthly_archive_upload", "0 30 3 1 * *", 30 * 60),
            ("monthly_timestamping_obtain", "0 0 4 1 * *", 30 * 60),
            ("daily_envelope_lazy_migration", "0 0 4 * * *", 2 * 60 * 60),
            (
                "quarterly_restore_drill_reminder",
                "0 0 5 1 1,4,7,10 *",
                30 * 60
            ),
            (
                "quarterly_signing_key_review_reminder",
                "0 10 5 1 1,4,7,10 *",
                5 * 60
            ),
            (
                "quarterly_auditor_privilege_review_reminder",
                "0 20 5 1 1,4,7,10 *",
                5 * 60
            ),
            ("siem_buffer_flush", "0 */5 * * * *", 2 * 60),
        ]
    );
}

#[tokio::test]
async fn fetch_signed_digest_accepts_verified_materials() {
    let fixture = digest_fetch_fixture();
    let server = mock_digest_fetch(digest_fetch_body(&fixture)).await;
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        server.uri(),
        "service-role-key",
        "publishable-key",
    );

    let digest = fetch_signed_digest(&client, &fixture.period)
        .await
        .expect("valid digest materials should be accepted");

    assert_eq!(digest.period.as_str(), fixture.period.as_str());
    assert_eq!(digest.digest_hash.to_hex(), fixture.digest_hash_hex);
    assert_eq!(
        digest.sbc_signature.to_lower_hex(),
        fixture.sbc_signature_hex
    );
}

#[tokio::test]
async fn fetch_signed_digest_rejects_stored_hash_mismatch() {
    let fixture = digest_fetch_fixture();
    let server = mock_digest_fetch(digest_fetch_body_with_hash(&fixture, &"00".repeat(32))).await;
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        server.uri(),
        "service-role-key",
        "publishable-key",
    );

    let result = fetch_signed_digest(&client, &fixture.period).await;

    assert!(matches!(result, Err("monthly_digest_hash_mismatch")));
}

#[tokio::test]
async fn fetch_signed_digest_rejects_invalid_sbc_signature() {
    let fixture = digest_fetch_fixture();
    let corrupted_signature = corrupt_signature_hex(&fixture.sbc_signature_hex);
    let server = mock_digest_fetch(digest_fetch_body_with_signature(
        &fixture,
        &corrupted_signature,
    ))
    .await;
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        server.uri(),
        "service-role-key",
        "publishable-key",
    );

    let result = fetch_signed_digest(&client, &fixture.period).await;

    assert!(matches!(result, Err("monthly_digest_signature_invalid")));
}

#[tokio::test]
async fn fetch_signed_digest_rejects_missing_public_key() {
    let fixture = digest_fetch_fixture();
    let server = mock_digest_fetch(digest_fetch_body_without_public_key(&fixture)).await;
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        server.uri(),
        "service-role-key",
        "publishable-key",
    );

    let result = fetch_signed_digest(&client, &fixture.period).await;

    assert!(matches!(
        result,
        Err("monthly_digest_unknown_signature_key")
    ));
}

#[tokio::test]
async fn fetch_signed_digest_invalid_hash_prevents_timestamping_externalization()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = digest_fetch_fixture();
    let server = mock_digest_fetch(digest_fetch_body_with_hash(&fixture, &"00".repeat(32))).await;
    let state = test_app_state(
        &server.uri(),
        unique_temp_path("invalid-digest-timestamp-audit"),
    )?;
    let local_archive_dir = unique_temp_path("invalid-digest-token-archive");
    let config = test_scheduler_config(
        local_archive_dir.clone(),
        None,
        Some(Arc::new(AnyTimestampingProvider::LocalDummy(
            InMemoryTimestampingService::new(),
        ))),
    );
    let spec = SCHEDULED_JOB_SPECS
        .iter()
        .copied()
        .find(|spec| spec.name == ScheduledJobName::MonthlyTimestampingObtain)
        .expect("timestamping spec exists");

    let result = run_job_body(&state, &config, spec).await;

    assert!(matches!(result, Err("monthly_digest_hash_mismatch")));
    assert!(
        !local_archive_dir.try_exists()?,
        "timestamping token archive must not be created for unverified digest"
    );
    Ok(())
}

#[tokio::test]
async fn fetch_signed_digest_invalid_hash_prevents_archive_externalization()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = digest_fetch_fixture();
    let server = mock_digest_fetch(digest_fetch_body_with_hash(&fixture, &"00".repeat(32))).await;
    let state = test_app_state(
        &server.uri(),
        unique_temp_path("invalid-digest-archive-audit"),
    )?;
    let archive_dir = unique_temp_path("invalid-digest-archive-backend");
    let archive_backend =
        AnyArchiveBackend::LocalFile(LocalFileArchiveBackend::new(archive_dir.clone()));
    let config = test_scheduler_config(
        unique_temp_path("invalid-digest-archive-local-fallback"),
        Some(Arc::new(archive_backend)),
        None,
    );
    let spec = SCHEDULED_JOB_SPECS
        .iter()
        .copied()
        .find(|spec| spec.name == ScheduledJobName::MonthlyArchiveUpload)
        .expect("archive spec exists");

    let result = run_job_body(&state, &config, spec).await;

    assert!(matches!(result, Err("monthly_digest_hash_mismatch")));
    assert!(
        !archive_dir.try_exists()?,
        "archive backend must not be created for unverified digest"
    );
    Ok(())
}

#[test]
fn scheduler_runtime_state_assigns_distinct_locks_for_new_jobs() {
    let runtime_state = SchedulerRuntimeState::new();
    let timestamping_lock_ptr = std::ptr::from_ref::<JobLock>(
        runtime_state.lock_for(ScheduledJobName::MonthlyTimestampingObtain),
    );
    let envelope_lock_ptr = std::ptr::from_ref::<JobLock>(
        runtime_state.lock_for(ScheduledJobName::DailyEnvelopeLazyMigration),
    );
    let archive_lock_ptr = std::ptr::from_ref::<JobLock>(
        runtime_state.lock_for(ScheduledJobName::MonthlyArchiveUpload),
    );
    let siem_flush_lock_ptr =
        std::ptr::from_ref::<JobLock>(runtime_state.lock_for(ScheduledJobName::SiemBufferFlush));
    assert_ne!(timestamping_lock_ptr, envelope_lock_ptr);
    assert_ne!(timestamping_lock_ptr, archive_lock_ptr);
    assert_ne!(envelope_lock_ptr, archive_lock_ptr);
    assert_ne!(siem_flush_lock_ptr, archive_lock_ptr);
    assert_ne!(siem_flush_lock_ptr, envelope_lock_ptr);
}

#[test]
fn siem_buffer_flush_long_failure_incident_uses_scheduler_source() {
    let input = crate::server::incident::siem_long_failure_incident_input("siem_buffer_flush");

    assert_eq!(
        input.incident_type,
        crate::incident::IncidentType::SiemLongFailure
    );
    assert_eq!(input.detection_source, "siem_buffer_flush");
    assert_eq!(input.dedupe_key, "siem-long-failure");
    assert_eq!(input.error_code, "siem_long_outage");
}

#[tokio::test]
async fn archive_backend_none_persists_timestamping_token_to_local_file()
-> Result<(), Box<dyn std::error::Error>> {
    let local_archive_dir = unique_temp_path("local-token-fallback");
    let config = test_scheduler_config(local_archive_dir.clone(), None, None);
    let period = test_period();
    let token = test_token();

    persist_timestamping_token_to_archive(&config, &period, &token)
        .await
        .map_err(std::io::Error::other)?;

    let stored = fs::read(token_path(&local_archive_dir, &period))?;
    assert_eq!(stored, token.as_bytes());
    Ok(())
}

#[tokio::test]
async fn configured_archive_backend_takes_precedence_over_local_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    let configured_archive_dir = unique_temp_path("configured-token-archive");
    let fallback_archive_dir = unique_temp_path("fallback-token-archive");
    let archive_backend =
        AnyArchiveBackend::LocalFile(LocalFileArchiveBackend::new(configured_archive_dir.clone()));
    let config = test_scheduler_config(
        fallback_archive_dir.clone(),
        Some(Arc::new(archive_backend)),
        None,
    );
    let period = test_period();
    let token = test_token();

    persist_timestamping_token_to_archive(&config, &period, &token)
        .await
        .map_err(std::io::Error::other)?;

    let configured_stored = fs::read(token_path(&configured_archive_dir, &period))?;
    assert_eq!(configured_stored, token.as_bytes());
    assert!(
        !token_path(&fallback_archive_dir, &period).try_exists()?,
        "fallback local archive must not be used when archive_backend is configured"
    );
    Ok(())
}

#[tokio::test]
async fn local_fallback_persist_error_is_not_silent_success()
-> Result<(), Box<dyn std::error::Error>> {
    let parent = unique_temp_path("local-token-fallback-parent");
    fs::create_dir_all(&parent)?;
    let local_archive_file = parent.join("archive-file");
    fs::write(&local_archive_file, b"not a directory")?;
    let config = test_scheduler_config(local_archive_file, None, None);
    let period = test_period();
    let token = test_token();

    let result = persist_timestamping_token_to_archive(&config, &period, &token).await;

    assert_eq!(result, Err("timestamping_token_archive_persist_failed"));
    Ok(())
}

#[tokio::test]
async fn monthly_timestamping_job_with_no_archive_backend_persists_token_to_local_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    let supabase = mock_scheduler_supabase().await;
    let state = test_app_state(&supabase.uri(), unique_temp_path("job-audit-fallback"))?;
    let local_archive_dir = unique_temp_path("job-token-fallback");
    let config = test_scheduler_config(
        local_archive_dir.clone(),
        None,
        Some(Arc::new(AnyTimestampingProvider::LocalDummy(
            InMemoryTimestampingService::new(),
        ))),
    );
    let signed_digest = test_signed_monthly_digest();
    let period = signed_digest.period.clone();

    let token = run_monthly_timestamping_obtain_job(&state, &config, signed_digest)
        .await
        .map_err(std::io::Error::other)?;

    let stored = fs::read(token_path(&local_archive_dir, &period))?;
    assert_eq!(stored, token.as_bytes());
    Ok(())
}

#[tokio::test]
async fn monthly_timestamping_job_archive_persist_error_is_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let supabase = mock_scheduler_supabase().await;
    let state = test_app_state(&supabase.uri(), unique_temp_path("job-persist-fail-audit"))?;
    let parent = unique_temp_path("job-persist-fail-parent");
    fs::create_dir_all(&parent)?;
    let local_archive_file = parent.join("archive-file");
    fs::write(&local_archive_file, b"not a directory")?;
    let config = test_scheduler_config(
        local_archive_file,
        None,
        Some(Arc::new(AnyTimestampingProvider::LocalDummy(
            InMemoryTimestampingService::new(),
        ))),
    );

    let result =
        run_monthly_timestamping_obtain_job(&state, &config, test_signed_monthly_digest()).await;

    assert_eq!(result, Err("timestamping_token_archive_persist_failed"));
    Ok(())
}

#[tokio::test]
async fn run_once_per_period_marks_new_jobs_distinctly() {
    let mut runtime_state = SchedulerRuntimeState::new();
    let timestamping_key = JobRunKey {
        job_name: ScheduledJobName::MonthlyTimestampingObtain,
        period_key: "2026-05".to_owned(),
    };
    let envelope_key = JobRunKey {
        job_name: ScheduledJobName::DailyEnvelopeLazyMigration,
        period_key: "2026-05-29".to_owned(),
    };

    let first = run_once_per_period(&mut runtime_state, timestamping_key.clone(), async {
        Ok::<_, &str>("ok")
    })
    .await;
    let second = run_once_per_period(&mut runtime_state, envelope_key.clone(), async {
        Ok::<_, &str>("ok")
    })
    .await;
    let third = run_once_per_period(&mut runtime_state, timestamping_key.clone(), async {
        Ok::<_, &str>("ok")
    })
    .await;

    assert_eq!(first, Ok(Some("ok")));
    assert_eq!(second, Ok(Some("ok")));
    assert_eq!(third, Ok(None));
    assert!(runtime_state.completed.contains(&timestamping_key));
    assert!(runtime_state.completed.contains(&envelope_key));
}

#[test]
fn previous_month_period_wraps_year() {
    assert_eq!(
        previous_month_period(dt(2026, Month::June, 1, 3))
            .unwrap()
            .as_str(),
        "2026-05"
    );
    assert_eq!(
        previous_month_period(dt(2026, Month::January, 1, 3))
            .unwrap()
            .as_str(),
        "2025-12"
    );
}

#[test]
fn job_lock_prevents_reentry_until_guard_drops() {
    let lock = JobLock::new();
    let first = lock.try_enter();
    assert!(first.is_some());
    assert!(lock.try_enter().is_none());
    drop(first);
    assert!(lock.try_enter().is_some());
}

#[tokio::test]
async fn run_once_per_period_does_not_complete_failed_job() {
    let mut runtime_state = SchedulerRuntimeState::new();
    let key = JobRunKey {
        job_name: ScheduledJobName::MonthlyDigestGenerate,
        period_key: "2026-05".to_owned(),
    };

    let result = run_once_per_period(&mut runtime_state, key.clone(), async {
        Err::<(), _>("synthetic_failure")
    })
    .await;

    assert_eq!(result, Err("synthetic_failure"));
    assert!(!runtime_state.completed.contains(&key));
}

#[tokio::test]
async fn run_once_per_period_returns_none_for_completed_job() {
    let mut runtime_state = SchedulerRuntimeState::new();
    let key = JobRunKey {
        job_name: ScheduledJobName::MonthlyArchiveUpload,
        period_key: "2026-05".to_owned(),
    };

    let first =
        run_once_per_period(&mut runtime_state, key.clone(), async { Ok::<_, &str>(7) }).await;
    let second = run_once_per_period(&mut runtime_state, key, async { Ok::<_, &str>(11) }).await;

    assert_eq!(first, Ok(Some(7)));
    assert_eq!(second, Ok(None));
}

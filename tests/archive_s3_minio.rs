//! minio に対する実 E2E テスト（`#[ignore]` 付き）。
//!
//! CI では skip。手元で minio を起動して以下を実行する:
//!
//! ```sh
//! docker run -d --name mipsorcu-minio -p 9000:9000 minio/minio \
//!     server /data --console-address ":9001"
//! mc alias set local http://localhost:9000 minioadmin minioadmin
//! mc mb --with-lock local/mipsorcu-archive
//! mc retention set --default GOVERNANCE 7d local/mipsorcu-archive
//!
//! MIPSORCU_TEST_MINIO_ENDPOINT=http://localhost:9000 \
//!   MIPSORCU_TEST_MINIO_BUCKET=mipsorcu-archive \
//!   MIPSORCU_TEST_MINIO_ACCESS_KEY_ID=minioadmin \
//!   MIPSORCU_TEST_MINIO_SECRET_ACCESS_KEY=minioadmin \
//!   cargo test --test archive_s3_minio -- --ignored
//! ```
//!
//! 検証内容:
//! - 実 minio bucket に Object Lock 付き PUT が成功する
//! - 同一キーへの再 PUT が `archive_export_overwrite_rejected` で拒否される
//! - 不正な認証情報で `archive_export_unauthenticated` を返す

use std::time::{SystemTime, UNIX_EPOCH};

use mipsorcu::{
    ArchiveBackend, ArchiveBackendError, ArchiveExportPackage, ArchiveObjectKey, DigestHash,
    LedgerHash, LedgerSequenceNo, LedgerSignature, LedgerSignatureKeyVersion, MonthlyDigestPeriod,
    S3ArchiveBackendConfig, S3ImmutableArchiveBackend, S3ObjectLockMode, SignedMonthlyDigest,
    SourceEventAt, build_monthly_digest_canonical_form,
};

const ENV_ENDPOINT: &str = "MIPSORCU_TEST_MINIO_ENDPOINT";
const ENV_BUCKET: &str = "MIPSORCU_TEST_MINIO_BUCKET";
const ENV_ACCESS_KEY_ID: &str = "MIPSORCU_TEST_MINIO_ACCESS_KEY_ID";
const ENV_SECRET_ACCESS_KEY: &str = "MIPSORCU_TEST_MINIO_SECRET_ACCESS_KEY";
const ENV_REGION: &str = "MIPSORCU_TEST_MINIO_REGION";

struct MinioEnv {
    endpoint: String,
    bucket: String,
    access_key_id: String,
    secret_access_key: String,
    region: String,
}

fn require_minio_env() -> Option<MinioEnv> {
    let endpoint = std::env::var(ENV_ENDPOINT).ok()?;
    let bucket = std::env::var(ENV_BUCKET).ok()?;
    let access_key_id = std::env::var(ENV_ACCESS_KEY_ID).ok()?;
    let secret_access_key = std::env::var(ENV_SECRET_ACCESS_KEY).ok()?;
    let region = std::env::var(ENV_REGION).unwrap_or_else(|_| "us-east-1".to_owned());
    Some(MinioEnv {
        endpoint,
        bucket,
        access_key_id,
        secret_access_key,
        region,
    })
}

fn unique_period_for_test() -> MonthlyDigestPeriod {
    // 過去日付の YYYY-MM をテスト実行ごとに別個にする（minio bucket に
    // Object Lock 付きで PUT したオブジェクトは retention 経過まで削除不可。
    // 共有名で衝突しないよう epoch ベースでローテートする）。
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    // months since unix epoch（粗く mod で循環）
    let month_index = (secs / (30 * 24 * 60 * 60)) as u32;
    let year = 2000 + (month_index / 12) % 100;
    let month = (month_index % 12) + 1;
    let period_str = format!("{year:04}-{month:02}");
    MonthlyDigestPeriod::parse(&period_str).expect("period parse must succeed")
}

fn make_test_digest(period: MonthlyDigestPeriod) -> SignedMonthlyDigest {
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
    .expect("canonical form must build");

    let digest_hash = DigestHash::from_canonical_bytes(&canonical_bytes);
    let sbc_signature = LedgerSignature::from_bytes(&[0u8; 64]).expect("valid sig");

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

fn make_config(env: &MinioEnv) -> S3ArchiveBackendConfig {
    S3ArchiveBackendConfig::new(
        env.endpoint.clone(),
        env.region.clone(),
        env.bucket.clone(),
        env.access_key_id.clone(),
        env.secret_access_key.clone(),
        None,
        S3ObjectLockMode::Governance,
        1,
    )
    .expect("config must build")
    .with_retry_base_millis(100)
    .with_max_retries(2)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a running minio instance with object lock enabled"]
async fn minio_put_object_succeeds_with_object_lock() {
    let Some(env) = require_minio_env() else {
        panic!(
            "set {ENV_ENDPOINT}, {ENV_BUCKET}, {ENV_ACCESS_KEY_ID}, {ENV_SECRET_ACCESS_KEY} to run"
        );
    };
    let period = unique_period_for_test();
    let digest = make_test_digest(period.clone());
    let package = ArchiveExportPackage::from_digest(&digest).expect("package must build");
    let key = ArchiveObjectKey::for_monthly_digest(&period).expect("key must build");

    let backend = S3ImmutableArchiveBackend::new(make_config(&env), reqwest::Client::new());
    backend
        .put_object(&key, &package)
        .await
        .expect("first PUT must succeed against minio");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a running minio instance with object lock enabled"]
async fn minio_overwrite_rejected_when_forbid_overwrite() {
    let Some(env) = require_minio_env() else {
        panic!(
            "set {ENV_ENDPOINT}, {ENV_BUCKET}, {ENV_ACCESS_KEY_ID}, {ENV_SECRET_ACCESS_KEY} to run"
        );
    };
    let period = unique_period_for_test();
    let digest = make_test_digest(period.clone());
    let package = ArchiveExportPackage::from_digest(&digest).expect("package must build");
    let key = ArchiveObjectKey::for_monthly_digest(&period).expect("key must build");

    let backend = S3ImmutableArchiveBackend::new(make_config(&env), reqwest::Client::new());
    // 1st PUT must succeed
    backend
        .put_object(&key, &package)
        .await
        .expect("first PUT must succeed");

    // 2nd PUT must be rejected by If-None-Match: *
    let result = backend.put_object(&key, &package).await;
    match result {
        Err(ArchiveBackendError::BackendFailed { code }) => {
            assert_eq!(code, "archive_export_overwrite_rejected");
        }
        other => panic!("expected overwrite rejection, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a running minio instance"]
async fn minio_invalid_credentials_classified_as_unauthenticated() {
    let Some(env) = require_minio_env() else {
        panic!(
            "set {ENV_ENDPOINT}, {ENV_BUCKET}, {ENV_ACCESS_KEY_ID}, {ENV_SECRET_ACCESS_KEY} to run"
        );
    };
    let period = unique_period_for_test();
    let digest = make_test_digest(period.clone());
    let package = ArchiveExportPackage::from_digest(&digest).expect("package must build");
    let key = ArchiveObjectKey::for_monthly_digest(&period).expect("key must build");

    let config = S3ArchiveBackendConfig::new(
        env.endpoint.clone(),
        env.region.clone(),
        env.bucket.clone(),
        "invalid-access-key".to_owned(),
        "invalid-secret-key-with-enough-length-to-pass-validation".to_owned(),
        None,
        S3ObjectLockMode::Governance,
        1,
    )
    .expect("config must build")
    .with_max_retries(0);

    let backend = S3ImmutableArchiveBackend::new(config, reqwest::Client::new());
    let result = backend.put_object(&key, &package).await;
    match result {
        Err(ArchiveBackendError::BackendFailed { code }) => {
            assert_eq!(code, "archive_export_unauthenticated");
        }
        other => panic!("expected unauthenticated, got {other:?}"),
    }
}

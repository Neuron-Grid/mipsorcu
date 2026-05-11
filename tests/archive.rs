use mipsorcu::{
    ARCHIVE_SCHEMA_VERSION, ArchiveBackend, ArchiveBackendError, ArchiveExportPackage,
    ArchiveObjectKey, ArchiveVerifyOutcome, DigestHash, InMemoryArchiveBackend, LedgerHash,
    LedgerSequenceNo, LedgerSignature, LedgerSignatureKeyVersion, MonthlyDigestPeriod,
    SignedMonthlyDigest, SourceEventAt, build_monthly_digest_canonical_form,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn make_test_digest() -> SignedMonthlyDigest {
    let period = MonthlyDigestPeriod::parse("2026-05").expect("valid period");
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

fn make_package() -> ArchiveExportPackage {
    ArchiveExportPackage::from_digest(&make_test_digest()).expect("package build must succeed")
}

fn make_key() -> ArchiveObjectKey {
    ArchiveObjectKey::for_monthly_digest(&MonthlyDigestPeriod::parse("2026-05").unwrap())
        .expect("key build must succeed")
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchiveObjectKey validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn archive_object_key_rejects_empty_string() {
    let result = ArchiveObjectKey::new("");
    assert!(matches!(result, Err(ArchiveBackendError::InvalidKey { .. })));
}

#[test]
fn archive_object_key_rejects_257_char_key() {
    let long_key = "a".repeat(257);
    let result = ArchiveObjectKey::new(long_key);
    assert!(matches!(result, Err(ArchiveBackendError::InvalidKey { .. })));
}

#[test]
fn archive_object_key_accepts_256_char_key() {
    let max_key = "a".repeat(256);
    let result = ArchiveObjectKey::new(max_key);
    assert!(result.is_ok());
}

#[test]
fn archive_object_key_for_monthly_digest_format() {
    let period = MonthlyDigestPeriod::parse("2026-05").unwrap();
    let key = ArchiveObjectKey::for_monthly_digest(&period).unwrap();
    assert_eq!(key.as_str(), "digests/2026-05/digest.json");
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchiveExportPackage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn archive_export_package_builds_from_test_digest() {
    let digest = make_test_digest();
    let result = ArchiveExportPackage::from_digest(&digest);
    assert!(result.is_ok(), "from_digest must succeed for valid digest");
}

#[test]
fn archive_export_package_to_json_contains_schema_version() {
    let package = make_package();
    let bytes = package.to_json_bytes().expect("to_json_bytes must succeed");
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).expect("must be valid JSON");
    assert_eq!(
        value["archive_schema_version"].as_u64(),
        Some(u64::from(ARCHIVE_SCHEMA_VERSION)),
    );
}

#[test]
fn archive_export_package_to_json_digest_is_object() {
    let package = make_package();
    let bytes = package.to_json_bytes().expect("to_json_bytes must succeed");
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).expect("must be valid JSON");
    assert!(
        value["digest"].is_object(),
        "digest field must be a JSON object, not a string"
    );
}

#[test]
fn archive_export_package_to_json_sbc_signature_is_hex() {
    let package = make_package();
    let bytes = package.to_json_bytes().expect("to_json_bytes must succeed");
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).expect("must be valid JSON");
    let sig = value["sbc_signature"].as_str().expect("sbc_signature must be a string");
    assert_eq!(sig.len(), 128, "sbc_signature must be 128-char hex");
    assert!(
        sig.chars().all(|c| c.is_ascii_hexdigit()),
        "sbc_signature must be hex"
    );
}

#[test]
fn archive_export_package_to_json_is_stable() {
    let digest = make_test_digest();
    let p1 = ArchiveExportPackage::from_digest(&digest).unwrap();
    let p2 = ArchiveExportPackage::from_digest(&digest).unwrap();
    assert_eq!(
        p1.to_json_bytes().unwrap(),
        p2.to_json_bytes().unwrap(),
        "to_json_bytes must be deterministic"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// InMemoryArchiveBackend round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn in_memory_backend_put_and_verify_valid() -> TestResult {
    let backend = InMemoryArchiveBackend::new();
    let key = make_key();
    let package = make_package();

    backend.put_object(&key, &package).await?;
    let outcome = backend.verify_object(&key, &package).await?;
    assert_eq!(outcome, ArchiveVerifyOutcome::Valid);
    Ok(())
}

#[tokio::test]
async fn in_memory_backend_verify_not_found_before_put() -> TestResult {
    let backend = InMemoryArchiveBackend::new();
    let key = make_key();
    let package = make_package();

    let outcome = backend.verify_object(&key, &package).await?;
    assert_eq!(outcome, ArchiveVerifyOutcome::NotFound);
    Ok(())
}

#[tokio::test]
async fn in_memory_backend_list_objects_returns_put_keys() -> TestResult {
    let backend = InMemoryArchiveBackend::new();
    let key = make_key();
    let package = make_package();

    assert!(backend.list_objects().await?.is_empty());
    backend.put_object(&key, &package).await?;
    let keys = backend.list_objects().await?;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].as_str(), key.as_str());
    Ok(())
}

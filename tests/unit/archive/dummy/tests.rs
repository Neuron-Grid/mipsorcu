use super::*;
use crate::archive::export::ArchiveExportPackage;
use crate::ledger::{
    DigestHash, LedgerHash, LedgerSequenceNo, LedgerSignature, LedgerSignatureKeyVersion,
    MonthlyDigestPeriod, SignedMonthlyDigest, build_monthly_digest_canonical_form,
};
use crate::types::SourceEventAt;

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
    .expect("build");

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
    ArchiveExportPackage::from_digest(&make_test_digest()).expect("package build")
}

fn make_key() -> ArchiveObjectKey {
    ArchiveObjectKey::for_monthly_digest(&MonthlyDigestPeriod::parse("2026-05").unwrap())
        .expect("key build")
}

#[tokio::test]
async fn in_memory_put_then_verify_valid() {
    let backend = InMemoryArchiveBackend::new();
    let key = make_key();
    let package = make_package();

    backend
        .put_object(&key, &package)
        .await
        .expect("put must succeed");
    let outcome = backend
        .verify_object(&key, &package)
        .await
        .expect("verify must succeed");
    assert_eq!(outcome, ArchiveVerifyOutcome::Valid);
}

#[tokio::test]
async fn in_memory_verify_not_found_before_put() {
    let backend = InMemoryArchiveBackend::new();
    let key = make_key();
    let package = make_package();

    let outcome = backend
        .verify_object(&key, &package)
        .await
        .expect("verify must succeed");
    assert_eq!(outcome, ArchiveVerifyOutcome::NotFound);
}

#[tokio::test]
async fn in_memory_list_objects_returns_put_keys() {
    let backend = InMemoryArchiveBackend::new();
    let key = make_key();
    let package = make_package();

    assert!(backend.list_objects().await.unwrap().is_empty());
    backend.put_object(&key, &package).await.unwrap();
    let keys = backend.list_objects().await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].as_str(), key.as_str());
}

#[tokio::test]
async fn in_memory_put_twice_overwrites() {
    let backend = InMemoryArchiveBackend::new();
    let key = make_key();
    let package = make_package();

    backend.put_object(&key, &package).await.unwrap();
    backend.put_object(&key, &package).await.unwrap();
    assert_eq!(backend.len(), 1);
}

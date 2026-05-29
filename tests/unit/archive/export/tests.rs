use super::*;
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

#[test]
fn from_digest_produces_valid_package() {
    let digest = make_test_digest();
    let package = ArchiveExportPackage::from_digest(&digest).expect("package build must succeed");
    assert_eq!(package.digest_hash_hex(), digest.digest_hash.to_hex());
}

#[test]
fn to_json_bytes_is_valid_json() {
    let digest = make_test_digest();
    let package = ArchiveExportPackage::from_digest(&digest).unwrap();
    let bytes = package.to_json_bytes().unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("must be valid JSON");
    assert!(parsed.is_object());
}

#[test]
fn to_json_bytes_contains_schema_version() {
    let digest = make_test_digest();
    let package = ArchiveExportPackage::from_digest(&digest).unwrap();
    let bytes = package.to_json_bytes().unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        parsed["archive_schema_version"].as_u64(),
        Some(u64::from(ARCHIVE_SCHEMA_VERSION))
    );
}

#[test]
fn to_json_bytes_digest_field_is_object() {
    let digest = make_test_digest();
    let package = ArchiveExportPackage::from_digest(&digest).unwrap();
    let bytes = package.to_json_bytes().unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        parsed["digest"].is_object(),
        "digest field must be an object, not a string"
    );
}

#[test]
fn to_json_bytes_digest_hash_matches() {
    let digest = make_test_digest();
    let expected_hex = digest.digest_hash.to_hex();
    let package = ArchiveExportPackage::from_digest(&digest).unwrap();
    let bytes = package.to_json_bytes().unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["digest_hash"].as_str(), Some(expected_hex.as_str()));
}

#[test]
fn to_json_bytes_sbc_signature_is_128_char_hex() {
    let digest = make_test_digest();
    let package = ArchiveExportPackage::from_digest(&digest).unwrap();
    let bytes = package.to_json_bytes().unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let sig = parsed["sbc_signature"]
        .as_str()
        .expect("sbc_signature must be string");
    assert_eq!(
        sig.len(),
        128,
        "sbc_signature must be 128-char hex (64 bytes)"
    );
    assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn to_json_bytes_is_stable() {
    let digest = make_test_digest();
    let package = ArchiveExportPackage::from_digest(&digest).unwrap();
    let bytes1 = package.to_json_bytes().unwrap();
    let bytes2 = package.to_json_bytes().unwrap();
    assert_eq!(bytes1, bytes2, "to_json_bytes must be deterministic");
}

#[test]
fn to_json_bytes_keys_are_alphabetical() {
    let digest = make_test_digest();
    let package = ArchiveExportPackage::from_digest(&digest).unwrap();
    let bytes = package.to_json_bytes().unwrap();
    let json_str = std::str::from_utf8(&bytes).expect("valid UTF-8");

    // Search from after each previous key's position to avoid false matches
    // inside the nested `digest` sub-object (e.g. "signature_key_version"
    // appears in the canonical form before the top-level occurrence).
    let expected_keys = [
        "archive_schema_version",
        "digest",
        "digest_hash",
        "sbc_signature",
        "signature_key_version",
    ];
    let mut search_from = 0usize;
    for key in &expected_keys {
        let pattern = format!("\"{key}\"");
        let relative_pos = json_str[search_from..]
            .find(pattern.as_str())
            .unwrap_or_else(|| panic!("key {key} not found after position {search_from}"));
        search_from += relative_pos + pattern.len();
    }
}

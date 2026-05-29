use super::*;
use crate::ledger::hash::LedgerHash;
use crate::ledger::ids::LedgerSequenceNo;
use crate::ledger::signature::LedgerSignatureKeyVersion;
use crate::types::SourceEventAt;

fn make_test_period() -> MonthlyDigestPeriod {
    MonthlyDigestPeriod::parse("2026-05").expect("valid period")
}

fn make_test_generated_at() -> SourceEventAt {
    SourceEventAt::parse("2026-06-01T00:00:00Z").expect("valid timestamp")
}

fn make_test_hash(byte: u8) -> LedgerHash {
    LedgerHash::from_bytes(&[byte; 32]).expect("valid hash")
}

fn make_test_key_version() -> LedgerSignatureKeyVersion {
    LedgerSignatureKeyVersion::new(1).expect("valid key version")
}

fn make_canonical_bytes() -> DigestCanonicalBytes {
    build_monthly_digest_canonical_form(
        &make_test_period(),
        LedgerSequenceNo::new(1).expect("valid seq"),
        LedgerSequenceNo::new(42).expect("valid seq"),
        make_test_hash(0xaa),
        make_test_hash(0xbb),
        42,
        &make_test_generated_at(),
        make_test_key_version(),
    )
    .expect("canonical form build must succeed")
}

#[test]
fn canonical_form_is_valid_json() {
    let bytes = make_canonical_bytes();
    let parsed: serde_json::Value =
        serde_json::from_slice(bytes.as_bytes()).expect("must be valid JSON");
    assert!(parsed.is_object());
}

#[test]
fn canonical_form_keys_are_alphabetical() {
    let bytes = make_canonical_bytes();
    let json_str = std::str::from_utf8(bytes.as_bytes()).expect("valid UTF-8");

    // JSON キーの出現順序がアルファベット順であることを確認
    let expected_keys = [
        "digest_generated_at",
        "digest_schema_version",
        "end_entry_hash",
        "end_sequence_no",
        "entry_count",
        "generated_by",
        "hash_algorithm",
        "signature_algorithm",
        "signature_key_version",
        "start_entry_hash",
        "start_sequence_no",
        "target_year_month",
    ];

    let mut positions = expected_keys.iter().map(|key| {
        json_str
            .find(&format!("\"{key}\""))
            .unwrap_or_else(|| panic!("key {key:?} not found in canonical form"))
    });

    let mut prev = positions.next().expect("at least one key");
    for pos in positions {
        assert!(
            pos > prev,
            "keys are not in alphabetical order in canonical form"
        );
        prev = pos;
    }
}

#[test]
fn canonical_form_is_stable() {
    let bytes1 = make_canonical_bytes();
    let bytes2 = make_canonical_bytes();
    assert_eq!(bytes1, bytes2, "canonical form must be stable across calls");
}

#[test]
fn canonical_form_has_no_extra_whitespace() {
    let bytes = make_canonical_bytes();
    let json_str = std::str::from_utf8(bytes.as_bytes()).expect("valid UTF-8");
    // compact JSON: no spaces after colons or commas
    assert!(
        !json_str.contains(": "),
        "canonical form must not have spaces after colon"
    );
    assert!(
        !json_str.contains(", "),
        "canonical form must not have spaces after comma"
    );
}

#[test]
fn canonical_form_contains_correct_schema_version() {
    let bytes = make_canonical_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
    assert_eq!(
        parsed["digest_schema_version"].as_u64(),
        Some(u64::from(DIGEST_SCHEMA_VERSION_V1))
    );
}

#[test]
fn canonical_form_contains_correct_generated_by() {
    let bytes = make_canonical_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
    assert_eq!(parsed["generated_by"].as_str(), Some(DIGEST_GENERATED_BY));
}

#[test]
fn digest_hash_is_sha3_256_of_canonical_bytes() {
    let bytes = make_canonical_bytes();
    let hash = DigestHash::from_canonical_bytes(&bytes);
    assert_eq!(hash.to_hex().len(), 64);
}

#[test]
fn monthly_digest_period_parse_valid() {
    assert!(MonthlyDigestPeriod::parse("2026-05").is_ok());
    assert!(MonthlyDigestPeriod::parse("2024-01").is_ok());
    assert!(MonthlyDigestPeriod::parse("9999-12").is_ok());
}

#[test]
fn monthly_digest_period_parse_invalid() {
    assert!(MonthlyDigestPeriod::parse("2026-00").is_err()); // month 0
    assert!(MonthlyDigestPeriod::parse("2026-13").is_err()); // month 13
    assert!(MonthlyDigestPeriod::parse("2026-5").is_err()); // not zero-padded
    assert!(MonthlyDigestPeriod::parse("202605").is_err()); // no dash
    assert!(MonthlyDigestPeriod::parse("2026/05").is_err()); // wrong separator
    assert!(MonthlyDigestPeriod::parse("").is_err()); // empty
    assert!(MonthlyDigestPeriod::parse("abcd-ef").is_err()); // not digits
}

#[test]
fn canonical_form_matches_adr_sample_structure() {
    // サンプル JSON との構造的整合性を確認する
    let bytes = build_monthly_digest_canonical_form(
        &MonthlyDigestPeriod::parse("2026-05").unwrap(),
        LedgerSequenceNo::new(109).unwrap(),
        LedgerSequenceNo::new(150).unwrap(),
        LedgerHash::from_hex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2")
            .unwrap(),
        LedgerHash::from_hex("8f2c1b3e9d0a4f5c6b7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b")
            .unwrap(),
        42,
        &SourceEventAt::parse("2026-06-01T00:00:00Z").unwrap(),
        LedgerSignatureKeyVersion::new(1).unwrap(),
    )
    .unwrap();

    let parsed: serde_json::Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
    assert_eq!(parsed["target_year_month"].as_str(), Some("2026-05"));
    assert_eq!(parsed["start_sequence_no"].as_u64(), Some(109));
    assert_eq!(parsed["end_sequence_no"].as_u64(), Some(150));
    assert_eq!(parsed["entry_count"].as_u64(), Some(42));
    assert_eq!(
        parsed["hash_algorithm"].as_str(),
        Some(LEDGER_HASH_ALGORITHM_SHA3_256)
    );
    assert_eq!(
        parsed["signature_algorithm"].as_str(),
        Some(LEDGER_SIGNATURE_ALGORITHM_ED25519)
    );
    assert_eq!(parsed["generated_by"].as_str(), Some(DIGEST_GENERATED_BY));
    assert_eq!(
        parsed["digest_schema_version"].as_u64(),
        Some(u64::from(DIGEST_SCHEMA_VERSION_V1))
    );
}

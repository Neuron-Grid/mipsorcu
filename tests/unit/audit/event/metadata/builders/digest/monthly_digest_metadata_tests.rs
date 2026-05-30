use super::*;
use crate::audit::{AuditAction, AuditResult};
use crate::ledger::{
    LedgerHash, LedgerSequenceNo, LedgerSignatureKeyVersion, MonthlyDigestPeriod,
    build_monthly_digest_canonical_form,
};
use crate::types::SourceEventAt;

fn make_period() -> MonthlyDigestPeriod {
    MonthlyDigestPeriod::parse("2026-05").unwrap()
}

fn make_source_event_at() -> SourceEventAt {
    SourceEventAt::parse("2026-06-01T00:00:00Z").unwrap()
}

fn make_digest_hash() -> DigestHash {
    let canonical = build_monthly_digest_canonical_form(
        &make_period(),
        LedgerSequenceNo::new(1).unwrap(),
        LedgerSequenceNo::new(42).unwrap(),
        LedgerHash::from_bytes(&[0xaa; 32]).unwrap(),
        LedgerHash::from_bytes(&[0xbb; 32]).unwrap(),
        42,
        &make_source_event_at(),
        LedgerSignatureKeyVersion::new(1).unwrap(),
    )
    .unwrap();
    DigestHash::from_canonical_bytes(&canonical)
}

#[test]
fn generate_failure_metadata_contains_only_allowed_keys() {
    let metadata =
        MonthlyDigestGenerateMetadata::new(&make_period(), "append_failed", make_source_event_at())
            .build()
            .unwrap();
    let value = metadata.as_value();
    assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
    assert_eq!(value["error_code"].as_str(), Some("append_failed"));
    assert_eq!(
        value["source_event_at"].as_str(),
        Some("2026-06-01T00:00:00Z")
    );
    assert_eq!(value.as_object().unwrap().len(), 3);
    metadata
        .validate_allowlist_for_action(AuditAction::MonthlyDigestGenerate, AuditResult::Failure)
        .unwrap();
}

#[test]
fn verify_failure_metadata_contains_only_allowed_keys() {
    let metadata = MonthlyDigestVerifyMetadata::new(
        &make_period(),
        "signature_invalid",
        make_source_event_at(),
    )
    .build()
    .unwrap();
    let value = metadata.as_value();
    assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
    assert_eq!(value["error_code"].as_str(), Some("signature_invalid"));
    assert_eq!(
        value["source_event_at"].as_str(),
        Some("2026-06-01T00:00:00Z")
    );
    assert_eq!(value["verify_result"].as_str(), Some("invalid"));
    assert_eq!(value.as_object().unwrap().len(), 4);
    metadata
        .validate_allowlist_for_action(AuditAction::MonthlyDigestVerify, AuditResult::Failure)
        .unwrap();
}

#[test]
fn generate_success_metadata_contains_only_allowed_keys() {
    let digest_hash = make_digest_hash();
    let metadata = MonthlyDigestGenerateMetadata::success(
        &make_period(),
        LedgerSequenceNo::new(1).unwrap(),
        LedgerSequenceNo::new(42).unwrap(),
        42,
        LedgerSignatureKeyVersion::new(1).unwrap(),
        digest_hash,
        make_source_event_at(),
    )
    .build()
    .unwrap();
    let value = metadata.as_value();
    assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
    assert_eq!(value["start_sequence_no"].as_u64(), Some(1));
    assert_eq!(value["end_sequence_no"].as_u64(), Some(42));
    assert_eq!(value["entry_count"].as_u64(), Some(42));
    assert_eq!(value["signature_key_version"].as_u64(), Some(1));
    assert_eq!(
        value["digest_hash"].as_str(),
        Some(digest_hash.to_hex().as_str())
    );
    assert_eq!(
        value["source_event_at"].as_str(),
        Some("2026-06-01T00:00:00Z")
    );
    assert!(value.get("error_code").is_none());
    assert_eq!(value.as_object().unwrap().len(), 7);
    metadata
        .validate_allowlist_for_action(AuditAction::MonthlyDigestGenerate, AuditResult::Success)
        .unwrap();
}

#[test]
fn verify_success_metadata_contains_only_allowed_keys() {
    let metadata = MonthlyDigestVerifyMetadata::success(&make_period(), make_source_event_at())
        .build()
        .unwrap();
    let value = metadata.as_value();
    assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
    assert_eq!(value["verify_result"].as_str(), Some("valid"));
    assert_eq!(
        value["source_event_at"].as_str(),
        Some("2026-06-01T00:00:00Z")
    );
    assert!(value.get("error_code").is_none());
    assert_eq!(value.as_object().unwrap().len(), 3);
    metadata
        .validate_allowlist_for_action(AuditAction::MonthlyDigestVerify, AuditResult::Success)
        .unwrap();
}

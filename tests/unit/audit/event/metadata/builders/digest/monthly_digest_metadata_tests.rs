use super::*;
use crate::audit::{AuditAction, AuditResult};
use crate::ledger::MonthlyDigestPeriod;
use crate::types::SourceEventAt;

fn make_period() -> MonthlyDigestPeriod {
    MonthlyDigestPeriod::parse("2026-05").unwrap()
}

fn make_source_event_at() -> SourceEventAt {
    SourceEventAt::parse("2026-06-01T00:00:00Z").unwrap()
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

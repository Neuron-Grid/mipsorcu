use super::*;
use crate::ledger::MonthlyDigestPeriod;
use crate::types::SourceEventAt;

fn make_period() -> MonthlyDigestPeriod {
    MonthlyDigestPeriod::parse("2026-05").unwrap()
}

fn make_source_event_at() -> SourceEventAt {
    SourceEventAt::parse("2026-06-01T00:00:00Z").unwrap()
}

#[test]
fn success_metadata_contains_timestamp_token_hash() {
    let metadata = DigestTimestampingMetadata::new(&make_period(), make_source_event_at())
        .with_digest_hash(&"a".repeat(64))
        .with_timestamp_token_hash(&"b".repeat(64))
        .build()
        .expect("build must succeed");
    let value = metadata.as_value();
    assert_eq!(
        value["timestamp_token_hash"].as_str(),
        Some(&*"b".repeat(64))
    );
    assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
    assert!(value.get("error_code").is_none());
}

#[test]
fn failure_metadata_contains_error_code() {
    let metadata = DigestTimestampingMetadata::new(&make_period(), make_source_event_at())
        .with_error_code("backend_failed")
        .build()
        .expect("build must succeed");
    let value = metadata.as_value();
    assert_eq!(value["error_code"].as_str(), Some("backend_failed"));
    assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
    assert!(value.get("timestamp_token_hash").is_none());
}

#[test]
fn required_target_year_month_always_present() {
    let metadata = DigestTimestampingMetadata::new(&make_period(), make_source_event_at())
        .build()
        .expect("build must succeed");
    let value = metadata.as_value();
    assert!(value.get("target_year_month").is_some());
    assert!(value.get("source_event_at").is_some());
}

#[test]
fn digest_hash_is_optional_and_set_when_provided() {
    let metadata = DigestTimestampingMetadata::new(&make_period(), make_source_event_at())
        .with_digest_hash(&"c".repeat(64))
        .build()
        .expect("build must succeed");
    let value = metadata.as_value();
    assert_eq!(value["digest_hash"].as_str(), Some(&*"c".repeat(64)));
}

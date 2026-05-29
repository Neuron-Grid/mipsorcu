use super::*;
use crate::archive::backend::ArchiveObjectKey;
use crate::ledger::MonthlyDigestPeriod;
use crate::types::SourceEventAt;

fn make_period() -> MonthlyDigestPeriod {
    MonthlyDigestPeriod::parse("2026-05").unwrap()
}

fn make_source_event_at() -> SourceEventAt {
    SourceEventAt::parse("2026-06-01T00:00:00Z").unwrap()
}

fn make_archive_key() -> ArchiveObjectKey {
    ArchiveObjectKey::for_monthly_digest(&make_period()).unwrap()
}

#[test]
fn success_metadata_contains_archive_key() {
    let key = make_archive_key();
    let metadata = ArchiveExportMetadata::new(&make_period(), make_source_event_at())
        .with_archive_key(&key)
        .build()
        .expect("build must succeed");
    let value = metadata.as_value();
    assert_eq!(value["archive_key"].as_str(), Some(key.as_str()));
    assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
    assert!(value.get("error_code").is_none());
}

#[test]
fn failure_metadata_contains_error_code() {
    let metadata = ArchiveExportMetadata::new(&make_period(), make_source_event_at())
        .with_error_code("backend_failed")
        .build()
        .expect("build must succeed");
    let value = metadata.as_value();
    assert_eq!(value["error_code"].as_str(), Some("backend_failed"));
    assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
    assert!(value.get("archive_key").is_none());
}

#[test]
fn digest_hash_is_included_when_set() {
    let metadata = ArchiveExportMetadata::new(&make_period(), make_source_event_at())
        .with_digest_hash("abcd1234")
        .build()
        .expect("build must succeed");
    let value = metadata.as_value();
    assert_eq!(value["digest_hash"].as_str(), Some("abcd1234"));
}

#[test]
fn required_target_year_month_always_present() {
    let metadata = ArchiveExportMetadata::new(&make_period(), make_source_event_at())
        .build()
        .expect("build must succeed");
    let value = metadata.as_value();
    assert!(value.get("target_year_month").is_some());
    assert!(value.get("source_event_at").is_some());
}

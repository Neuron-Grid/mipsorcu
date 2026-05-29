use super::*;

#[test]
fn minimum_metadata_contains_error_code_only() {
    let metadata = SiemForwardFailureMetadata::new("siem_backend_failed")
        .build()
        .expect("build must succeed");
    let value = metadata.as_value();
    assert_eq!(value["error_code"].as_str(), Some("siem_backend_failed"));
    assert!(value.get("event_type").is_none());
    assert!(value.get("event_count").is_none());
    assert!(value.get(SOURCE_EVENT_AT_KEY).is_none());
}

#[test]
fn full_metadata_contains_all_optional_keys() {
    let source_event_at = SourceEventAt::parse("2026-05-11T00:00:00Z").unwrap();
    let metadata = SiemForwardFailureMetadata::new("siem_backend_failed")
        .with_event_type("decrypt")
        .with_event_count(7)
        .with_source_event_at(source_event_at)
        .build()
        .expect("build must succeed");
    let value = metadata.as_value();
    assert_eq!(value["event_type"].as_str(), Some("decrypt"));
    assert_eq!(value["event_count"].as_u64(), Some(7));
    assert_eq!(
        value[SOURCE_EVENT_AT_KEY].as_str(),
        Some("2026-05-11T00:00:00Z")
    );
}

use super::*;
use crate::types::SecretString;

#[test]
fn otlp_attribute_uses_string_value() {
    let attribute = otlp_attribute("event.id", "abc");
    assert_eq!(attribute["key"], "event.id");
    assert_eq!(attribute["value"]["stringValue"], "abc");
}

#[test]
fn auth_token_secret_is_redacted_in_debug() {
    let token = SecretString::new("token-value").expect("non-empty token");
    let rendered = format!("{token:?}");
    assert!(!rendered.contains("token-value"));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn source_event_at_parses_rfc3339_to_nanoseconds() {
    let nanos = source_event_at_to_unix_nano("2026-05-29T03:00:00Z");
    // 2026-05-29T03:00:00Z = 1780023600 sec since epoch
    assert_eq!(nanos, "1780023600000000000");
}

#[test]
fn source_event_at_falls_back_to_zero_on_invalid_input() {
    assert_eq!(source_event_at_to_unix_nano("not-a-date"), "0");
}

use super::*;

#[test]
fn unix_seconds_parses_rfc3339() {
    let seconds = source_event_at_to_unix_seconds("2026-05-29T03:00:00Z");
    assert!((seconds - 1_780_023_600.0).abs() < f64::EPSILON);
}

#[test]
fn unix_seconds_falls_back_to_zero_on_invalid_input() {
    let seconds = source_event_at_to_unix_seconds("not-a-date");
    assert_eq!(seconds, 0.0);
}

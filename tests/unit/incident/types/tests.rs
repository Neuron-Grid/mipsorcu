use serde_json::Value;

use crate::ledger::MonthlyDigestPeriod;

use super::{IncidentNotificationPayload, IncidentRecordInput, IncidentSeverity, IncidentType};

#[test]
fn notification_payload_serializes_only_non_secret_fields() {
    let period = MonthlyDigestPeriod::parse("2026-05").expect("valid test period");
    let input = IncidentRecordInput::new(
        IncidentType::MonthlyDigestMismatch,
        IncidentSeverity::High,
        "monthly_digest_verify",
        "monthly_digest_mismatch:monthly_digest_verify:2026-05",
        "monthly_digest_hash_mismatch",
    )
    .with_target_sequence_no(42)
    .with_target_year_month(period);

    let payload = IncidentNotificationPayload::from_input(&input);
    let value = serde_json::to_value(&payload).expect("payload should serialize");
    let object = value.as_object().expect("payload should be an object");
    let rendered = value.to_string();

    assert_eq!(
        object.get("incident_type").and_then(Value::as_str),
        Some("monthly_digest_mismatch")
    );
    assert_eq!(object.get("severity").and_then(Value::as_str), Some("high"));
    assert_eq!(
        object.get("target_year_month").and_then(Value::as_str),
        Some("2026-05")
    );
    assert_eq!(
        object.get("target_sequence_no").and_then(Value::as_u64),
        Some(42)
    );

    for forbidden_marker in [
        "plaintext",
        "master_key",
        "data_key",
        "jwt",
        "authorization",
        "request_body",
        "response_body",
        "ciphertext",
        "encrypted_data_key",
    ] {
        assert!(!rendered.contains(forbidden_marker));
    }
}

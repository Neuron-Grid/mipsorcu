use serde_json::json;

use super::*;

#[test]
fn restore_test_trigger_rejects_missing_value() {
    let metadata = json!({
        "phase": "verify",
        "sample_count": 1,
        "duration_ms": 0
    });

    let result = restore_test_trigger(&metadata);

    assert!(matches!(
        result,
        Err(crate::LedgerError::InvalidPayloadField { key, .. }) if key == "trigger"
    ));
}

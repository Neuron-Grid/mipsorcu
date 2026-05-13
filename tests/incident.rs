use mipsorcu::{
    AuditAction, AuditEvent, AuditEventError, AuditEventId, AuditEventParts, AuditMetadata,
    AuditResult, IncidentDetectedMetadata, LedgerEntryType, LedgerError, LedgerPayload,
    MonthlyDigestPeriod, RequestId, SourceEventAt,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AUDIT_EVENT_ID: &str = "11111111-1111-4111-8111-111111111111";
const REQUEST_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SOURCE_EVENT_AT: &str = "2026-06-01T03:00:00Z";

#[test]
fn incident_detected_audit_action_is_failure_only() -> TestResult {
    let metadata = valid_incident_metadata()?;

    let result = AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::parse(AUDIT_EVENT_ID)?,
        request_id: RequestId::parse(REQUEST_ID)?,
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::IncidentDetected,
        target_secret_id: None,
        result: AuditResult::Success,
        key_version: None,
        metadata_json: metadata,
    });

    assert!(matches!(
        result,
        Err(AuditEventError::FailureOnlyActionSuccessNotAllowed {
            action: AuditAction::IncidentDetected
        })
    ));

    Ok(())
}

#[test]
fn incident_detected_metadata_accepts_required_and_optional_keys() -> TestResult {
    let period = MonthlyDigestPeriod::parse("2026-05")?;
    let metadata = IncidentDetectedMetadata::new(
        "hash_chain_mismatch",
        "critical",
        "ledger_hash_chain_full_verify",
        "hash_chain_mismatch:ledger_hash_chain_full_verify:2026-05",
        "dummy",
        "sent",
        "ledger_entry_hash_mismatch",
        SourceEventAt::parse(SOURCE_EVENT_AT)?,
    )
    .with_source_event_id(AUDIT_EVENT_ID)
    .with_target_sequence_no(42)
    .with_target_year_month(period)
    .build()?;

    metadata.validate_allowlist_for_action(AuditAction::IncidentDetected, AuditResult::Failure)?;
    assert_eq!(
        metadata.as_value()["incident_type"],
        json!("hash_chain_mismatch")
    );
    assert_eq!(metadata.as_value()["target_sequence_no"], json!(42));
    assert_eq!(metadata.as_value()["target_year_month"], json!("2026-05"));

    Ok(())
}

#[test]
fn incident_detected_metadata_rejects_missing_and_invalid_values() -> TestResult {
    let missing_required = AuditMetadata::new(json!({
        "severity": "critical",
        "detection_source": "ledger_hash_chain_full_verify",
        "dedupe_key": "hash_chain_mismatch:ledger_hash_chain_full_verify",
        "notification_sink": "dummy",
        "notification_result": "sent",
        "error_code": "ledger_entry_hash_mismatch",
        "source_event_at": SOURCE_EVENT_AT
    }))?;
    assert!(matches!(
        missing_required
            .validate_allowlist_for_action(AuditAction::IncidentDetected, AuditResult::Failure),
        Err(AuditEventError::MissingMetadataKey {
            key: "incident_type"
        })
    ));

    for (key, value) in [
        ("severity", json!("urgent")),
        ("notification_result", json!("queued")),
        ("target_year_month", json!("2026-13")),
    ] {
        let mut metadata = valid_incident_metadata()?;
        let object = metadata
            .as_value()
            .as_object()
            .ok_or(AuditEventError::MetadataMustBeObject)?;
        let mut object = object.clone();
        object.insert(key.to_owned(), value);
        metadata = AuditMetadata::new(json!(object))?;

        assert!(matches!(
            metadata
                .validate_allowlist_for_action(AuditAction::IncidentDetected, AuditResult::Failure),
            Err(AuditEventError::InvalidMetadataValue { .. })
        ));
    }

    Ok(())
}

#[test]
fn incident_detected_ledger_payload_matches_sql_constraints() -> TestResult {
    let payload = LedgerPayload::new(
        LedgerEntryType::IncidentDetected,
        json!({
            "incident_type": "hash_chain_mismatch",
            "severity": "critical",
            "detection_source": "ledger_hash_chain_full_verify",
            "dedupe_key": "hash_chain_mismatch:ledger_hash_chain_full_verify",
            "notification_sink": "dummy",
            "notification_result": "sent",
            "target_sequence_no": 42,
            "target_year_month": "2026-05"
        }),
    )?;

    assert_eq!(payload.entry_type(), LedgerEntryType::IncidentDetected);
    assert_eq!(payload.as_value()["notification_result"], json!("sent"));

    Ok(())
}

#[test]
fn incident_detected_ledger_payload_rejects_invalid_schema() {
    let missing_required = LedgerPayload::new(
        LedgerEntryType::IncidentDetected,
        json!({
            "severity": "critical",
            "detection_source": "ledger_hash_chain_full_verify",
            "dedupe_key": "hash_chain_mismatch:ledger_hash_chain_full_verify",
            "notification_sink": "dummy",
            "notification_result": "sent"
        }),
    );
    assert!(matches!(
        missing_required,
        Err(LedgerError::InvalidPayloadField { .. })
    ));

    for payload in [
        json!({
            "incident_type": "unknown",
            "severity": "critical",
            "detection_source": "ledger_hash_chain_full_verify",
            "dedupe_key": "hash_chain_mismatch:ledger_hash_chain_full_verify",
            "notification_sink": "dummy",
            "notification_result": "sent"
        }),
        json!({
            "incident_type": "hash_chain_mismatch",
            "severity": "urgent",
            "detection_source": "ledger_hash_chain_full_verify",
            "dedupe_key": "hash_chain_mismatch:ledger_hash_chain_full_verify",
            "notification_sink": "dummy",
            "notification_result": "sent"
        }),
        json!({
            "incident_type": "hash_chain_mismatch",
            "severity": "critical",
            "detection_source": "ledger_hash_chain_full_verify",
            "dedupe_key": "hash_chain_mismatch:ledger_hash_chain_full_verify",
            "notification_sink": "dummy",
            "notification_result": "queued"
        }),
        json!({
            "incident_type": "hash_chain_mismatch",
            "severity": "critical",
            "detection_source": "ledger_hash_chain_full_verify",
            "dedupe_key": "hash_chain_mismatch:ledger_hash_chain_full_verify",
            "notification_sink": "dummy",
            "notification_result": "sent",
            "target_year_month": "2026-13"
        }),
    ] {
        let result = LedgerPayload::new(LedgerEntryType::IncidentDetected, payload);
        assert!(matches!(
            result,
            Err(LedgerError::InvalidPayloadField { .. })
        ));
    }
}

fn valid_incident_metadata() -> Result<AuditMetadata, AuditEventError> {
    IncidentDetectedMetadata::new(
        "hash_chain_mismatch",
        "critical",
        "ledger_hash_chain_full_verify",
        "hash_chain_mismatch:ledger_hash_chain_full_verify",
        "dummy",
        "sent",
        "ledger_entry_hash_mismatch",
        SourceEventAt::parse(SOURCE_EVENT_AT).map_err(|_| AuditEventError::InvalidSourceEventAt)?,
    )
    .build()
}

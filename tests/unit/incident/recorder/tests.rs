use crate::incident::{
    DummyNotificationSink, FailingNotificationSink, IncidentRecordInput, IncidentSeverity,
    IncidentType, NotificationResult,
};
use crate::ledger::MonthlyDigestPeriod;

use super::{
    archive_incident_input, archive_incident_type, audit_ui_forbidden_operation_input, dedupe_key,
    deliver_notification, digest_timestamping_incident_input, digest_timestamping_incident_type,
    ledger_payload_contains_forbidden_key, ledger_secret_leak_suspected_input,
    monthly_digest_incident_type, non_auditor_ledger_read_input, scheduler_incident_type,
    severity_for_incident,
};

#[tokio::test]
async fn failed_sink_maps_to_failed_notification_result() {
    let sink = FailingNotificationSink::new("backend_down");
    let input = IncidentRecordInput::new(
        IncidentType::HashChainMismatch,
        IncidentSeverity::Critical,
        "ledger_hash_chain_full_verify",
        "hash_chain_mismatch:ledger_hash_chain_full_verify",
        "ledger_entry_hash_mismatch",
    );

    let result = deliver_notification(&sink, &input).await;

    assert_eq!(result, NotificationResult::Failed);
}

#[tokio::test]
async fn dummy_sink_maps_to_sent_notification_result_and_keeps_payload() {
    let sink = DummyNotificationSink::new();
    let input = IncidentRecordInput::new(
        IncidentType::SequenceGap,
        IncidentSeverity::High,
        "ledger_hash_chain_full_verify",
        "sequence_gap:ledger_hash_chain_full_verify",
        "ledger_sequence_gap",
    );

    let result = deliver_notification(&sink, &input).await;

    assert_eq!(result, NotificationResult::Sent);
    assert_eq!(sink.payload_count(), 1);
    assert_eq!(sink.payloads()[0].incident_type, IncidentType::SequenceGap);
}

#[test]
fn scheduler_error_codes_map_to_incident_types() {
    assert_eq!(
        scheduler_incident_type("ledger_entry_hash_mismatch"),
        Some(IncidentType::HashChainMismatch)
    );
    assert_eq!(
        scheduler_incident_type("ledger_previous_hash_mismatch"),
        Some(IncidentType::HashChainMismatch)
    );
    assert_eq!(
        scheduler_incident_type("ledger_chain_head_mismatch"),
        Some(IncidentType::HashChainMismatch)
    );
    assert_eq!(
        scheduler_incident_type("ledger_sequence_gap"),
        Some(IncidentType::SequenceGap)
    );
    assert_eq!(
        scheduler_incident_type("ledger_signature_invalid"),
        Some(IncidentType::SignatureMismatch)
    );
    assert_eq!(
        scheduler_incident_type("ledger_signature_key_missing"),
        Some(IncidentType::UnknownSignatureKey)
    );
    assert_eq!(
        scheduler_incident_type("ledger_payload_forbidden_key"),
        Some(IncidentType::LedgerSecretLeakSuspected)
    );
    assert_eq!(scheduler_incident_type("other_error"), None);
}

#[test]
fn monthly_digest_error_codes_map_to_incident_types() {
    assert_eq!(
        monthly_digest_incident_type("monthly_digest_hash_mismatch"),
        Some(IncidentType::MonthlyDigestMismatch)
    );
    assert_eq!(
        monthly_digest_incident_type("monthly_digest_unknown_signature_key"),
        Some(IncidentType::UnknownSignatureKey)
    );
    assert_eq!(
        monthly_digest_incident_type("chain_signature_invalid"),
        Some(IncidentType::MonthlyDigestMismatch)
    );
    assert_eq!(monthly_digest_incident_type("network_down"), None);
}

#[test]
fn severity_and_dedupe_key_are_stable() {
    assert_eq!(
        severity_for_incident(IncidentType::HashChainMismatch),
        IncidentSeverity::Critical
    );
    assert_eq!(
        severity_for_incident(IncidentType::SiemLongFailure),
        IncidentSeverity::Medium
    );
    assert_eq!(
        severity_for_incident(IncidentType::SiemBufferOverflow),
        IncidentSeverity::High
    );

    let period = MonthlyDigestPeriod::parse("2026-05").expect("valid test period");
    assert_eq!(
        dedupe_key(
            IncidentType::MonthlyDigestMismatch,
            "monthly_digest_verify",
            Some(&period)
        ),
        "monthly_digest_mismatch:monthly_digest_verify:2026-05"
    );
}

#[test]
fn missing_t14_error_codes_map_to_incident_types() {
    assert_eq!(
        digest_timestamping_incident_type("digest_timestamping_token_hash_mismatch"),
        Some(IncidentType::DigestTimestampingMismatch)
    );
    assert_eq!(
        digest_timestamping_incident_type("digest_timestamped_append_failed"),
        Some(IncidentType::DigestTimestampingMismatch)
    );
    assert_eq!(
        archive_incident_type("archive_export_content_mismatch"),
        Some(IncidentType::ArchiveExportMismatch)
    );
    assert_eq!(archive_incident_type("network_down"), None);

    let period = MonthlyDigestPeriod::parse("2026-05").expect("valid test period");
    let timestamping = digest_timestamping_incident_input(
        "digest_timestamping_verify",
        "digest_timestamping_token_hash_mismatch",
        &period,
    )
    .expect("timestamping incident input");
    assert_eq!(
        timestamping.incident_type,
        IncidentType::DigestTimestampingMismatch
    );
    assert_eq!(timestamping.target_year_month, Some(period.clone()));

    let archive = archive_incident_input(
        "archive_export_verify",
        "archive_export_content_mismatch",
        &period,
    )
    .expect("archive incident input");
    assert_eq!(archive.incident_type, IncidentType::ArchiveExportMismatch);
    assert_eq!(archive.target_year_month, Some(period));
}

#[test]
fn t14_manual_detection_inputs_are_stable_and_non_secret() {
    let non_auditor = non_auditor_ledger_read_input("auditor_api_ledger_read");
    assert_eq!(
        non_auditor.incident_type,
        IncidentType::NonAuditorLedgerRead
    );
    assert_eq!(non_auditor.error_code, "non_auditor_ledger_read");

    let forbidden = audit_ui_forbidden_operation_input("audit_ui", "decrypt secret");
    assert_eq!(
        forbidden.incident_type,
        IncidentType::AuditUiForbiddenOperation
    );
    assert_eq!(forbidden.error_code, "audit_ui_forbidden_operation");
    assert!(forbidden.dedupe_key.contains("decrypt_secret"));

    let leak = ledger_secret_leak_suspected_input("ledger_payload_scan", Some(42));
    assert_eq!(leak.incident_type, IncidentType::LedgerSecretLeakSuspected);
    assert_eq!(leak.target_sequence_no, Some(42));
}

#[test]
fn ledger_secret_leak_scan_detects_forbidden_keys_recursively() {
    let value = serde_json::json!({
        "outer": [{"plaintext": "redacted"}],
    });
    assert!(ledger_payload_contains_forbidden_key(&value));

    let safe = serde_json::json!({
        "incident_type": "hash_chain_mismatch",
        "severity": "critical",
    });
    assert!(!ledger_payload_contains_forbidden_key(&safe));
}

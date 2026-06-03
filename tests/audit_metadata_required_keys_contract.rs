use std::collections::BTreeSet;

use mipsorcu::{AuditAction, AuditEventError, AuditMetadata, AuditResult};
use serde_json::{Map, Value, json};

#[derive(Clone)]
struct AuditMetadataContract {
    name: &'static str,
    action: AuditAction,
    result: AuditResult,
    metadata_json: Value,
    required_keys: &'static [&'static str],
}

#[test]
fn canonical_audit_metadata_is_accepted_for_all_rust_actions() {
    for contract in canonical_contracts() {
        assert_contract_is_accepted(&contract);
    }
}

#[test]
fn removing_any_required_metadata_key_is_rejected() {
    for contract in canonical_contracts() {
        for missing_key in contract.required_keys {
            let mut object = metadata_object(&contract);
            assert!(
                object.remove(*missing_key).is_some(),
                "{} fixture should contain required key {missing_key}",
                contract.name
            );

            let metadata = AuditMetadata::new(Value::Object(object)).unwrap_or_else(|error| {
                panic!(
                    "{} metadata without {missing_key} should still be structurally buildable: {error:?}",
                    contract.name
                )
            });
            let result = metadata.validate_allowlist_for_action(contract.action, contract.result);
            assert!(
                matches!(
                    result,
                    Err(AuditEventError::MissingMetadataKey { key }) if key == *missing_key
                ),
                "{} without {missing_key} should be rejected as a missing required key, got {result:?}",
                contract.name
            );
        }
    }
}

#[test]
fn canonical_contracts_cover_all_rust_audit_actions() {
    let expected = all_actions()
        .into_iter()
        .map(AuditAction::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let covered = canonical_contracts()
        .into_iter()
        .map(|contract| contract.action.as_str().to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        expected, covered,
        "every Rust AuditAction must have canonical metadata coverage"
    );
}

#[test]
fn envelope_migration_required_key_contract_is_guarded_in_rust() {
    let migrated = AuditMetadataContract {
        name: "key_rotation_envelope_migrated canonical metadata",
        action: AuditAction::KeyRotationEnvelopeMigrated,
        result: AuditResult::Success,
        metadata_json: json!({
            "batch_size": 1,
            "success_count": 1,
            "failure_count": 0,
            "source_event_at": "2026-06-01T02:00:00Z"
        }),
        required_keys: &[
            "batch_size",
            "success_count",
            "failure_count",
            "source_event_at",
        ],
    };
    let failed = AuditMetadataContract {
        name: "key_rotation_envelope_failed canonical metadata",
        action: AuditAction::KeyRotationEnvelopeFailed,
        result: AuditResult::Failure,
        metadata_json: json!({
            "secret_version_id": "55555555-5555-4555-8555-555555555555",
            "version": 1,
            "error_code": "aad_context_mismatch",
            "source_event_at": "2026-06-01T02:00:00Z"
        }),
        required_keys: &[
            "secret_version_id",
            "version",
            "error_code",
            "source_event_at",
        ],
    };

    assert_contract_is_accepted(&migrated);
    assert_contract_is_accepted(&failed);
    assert_missing_key_is_rejected(&migrated, "batch_size");
    assert_missing_key_is_rejected(&failed, "error_code");
}

fn assert_contract_is_accepted(contract: &AuditMetadataContract) {
    let metadata = AuditMetadata::new(contract.metadata_json.clone()).unwrap_or_else(|error| {
        panic!(
            "{} canonical metadata should be structurally valid: {error:?}",
            contract.name
        )
    });
    let result = metadata.validate_allowlist_for_action(contract.action, contract.result);
    assert!(
        result.is_ok(),
        "{} canonical metadata should be accepted, got {result:?}",
        contract.name
    );
}

fn assert_missing_key_is_rejected(contract: &AuditMetadataContract, missing_key: &'static str) {
    let mut object = metadata_object(contract);
    assert!(
        object.remove(missing_key).is_some(),
        "{} fixture should contain required key {missing_key}",
        contract.name
    );

    let metadata = AuditMetadata::new(Value::Object(object)).unwrap_or_else(|error| {
        panic!(
            "{} metadata without {missing_key} should still be structurally buildable: {error:?}",
            contract.name
        )
    });
    let result = metadata.validate_allowlist_for_action(contract.action, contract.result);
    assert!(
        matches!(
            result,
            Err(AuditEventError::MissingMetadataKey { key }) if key == missing_key
        ),
        "{} without {missing_key} should be rejected as a missing required key, got {result:?}",
        contract.name
    );
}

fn metadata_object(contract: &AuditMetadataContract) -> Map<String, Value> {
    contract
        .metadata_json
        .as_object()
        .cloned()
        .unwrap_or_else(|| panic!("{} metadata fixture must be a JSON object", contract.name))
}

fn all_actions() -> Vec<AuditAction> {
    vec![
        AuditAction::EncryptCreate,
        AuditAction::EncryptRotate,
        AuditAction::Decrypt,
        AuditAction::VersionPurge,
        AuditAction::IntegrityCheck,
        AuditAction::RestoreTest,
        AuditAction::AuthFailure,
        AuditAction::KeyRotationStart,
        AuditAction::KeyRotationReencrypt,
        AuditAction::KeyRotationComplete,
        AuditAction::KeyRotationEnvelopeMigrated,
        AuditAction::KeyRotationEnvelopeFailed,
        AuditAction::SignatureKeyCreated,
        AuditAction::SignatureKeyActivated,
        AuditAction::SignatureKeyRetired,
        AuditAction::MonthlyDigestGenerate,
        AuditAction::MonthlyDigestVerify,
        AuditAction::ArchiveExport,
        AuditAction::DigestTimestamping,
        AuditAction::SiemForwardFailure,
        AuditAction::SiemEventForwarded,
        AuditAction::SiemEventFailed,
        AuditAction::SiemBufferFlushed,
        AuditAction::AuditReportGenerate,
        AuditAction::AuditUiRead,
        AuditAction::SchedulerJob,
        AuditAction::SchedulerJobStarted,
        AuditAction::SchedulerJobCompleted,
        AuditAction::SchedulerJobFailed,
        AuditAction::SchedulerJobSkipped,
        AuditAction::IncidentDetected,
        AuditAction::SecretAliasCreate,
        AuditAction::SecretAliasUpdate,
        AuditAction::SecretAliasDelete,
        AuditAction::SecretAliasList,
    ]
}

fn canonical_contracts() -> Vec<AuditMetadataContract> {
    vec![
        AuditMetadataContract {
            name: "encrypt_create failure",
            action: AuditAction::EncryptCreate,
            result: AuditResult::Failure,
            metadata_json: json!({
                "version": 1,
                "secret_version_id": "11111111-1111-4111-8111-111111111111",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["version", "secret_version_id", "source_event_at"],
        },
        AuditMetadataContract {
            name: "encrypt_rotate failure",
            action: AuditAction::EncryptRotate,
            result: AuditResult::Failure,
            metadata_json: json!({
                "version": 2,
                "secret_version_id": "22222222-2222-4222-8222-222222222222",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["version", "secret_version_id", "source_event_at"],
        },
        AuditMetadataContract {
            name: "decrypt success",
            action: AuditAction::Decrypt,
            result: AuditResult::Success,
            metadata_json: json!({
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["source_event_at"],
        },
        AuditMetadataContract {
            name: "decrypt failure",
            action: AuditAction::Decrypt,
            result: AuditResult::Failure,
            metadata_json: json!({
                "attempted_secret_id": "33333333-3333-4333-8333-333333333333",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["source_event_at"],
        },
        AuditMetadataContract {
            name: "version_purge failure",
            action: AuditAction::VersionPurge,
            result: AuditResult::Failure,
            metadata_json: json!({
                "version": 1,
                "secret_version_id": "44444444-4444-4444-8444-444444444444",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["version", "secret_version_id", "source_event_at"],
        },
        AuditMetadataContract {
            name: "integrity_check success",
            action: AuditAction::IntegrityCheck,
            result: AuditResult::Success,
            metadata_json: json!({
                "check_name": "mvp_integrity_check",
                "checked_secret_count": 0,
                "checked_secret_version_count": 0,
                "checked_audit_event_count": 0,
                "duration_ms": 0,
                "violation_count": 0,
                "violation_summary": {
                    "current_version_invalid": 0,
                    "version_invalid": 0,
                    "retention_exceeded": 0,
                    "ciphertext_empty": 0,
                    "encrypted_data_key_empty": 0,
                    "nonce_length_invalid": 0,
                    "algorithm_invalid": 0,
                    "nonce_duplicate": 0,
                    "aad_keys_invalid": 0,
                    "aad_row_mismatch": 0,
                    "created_at_mismatch": 0,
                    "audit_action_invalid": 0,
                    "audit_result_invalid": 0,
                    "audit_metadata_not_object": 0,
                    "audit_metadata_forbidden_key": 0,
                    "audit_source_event_at_invalid": 0
                },
                "trigger": "cli",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "check_name",
                "checked_secret_count",
                "checked_secret_version_count",
                "checked_audit_event_count",
                "duration_ms",
                "violation_count",
                "violation_summary",
                "trigger",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "restore_test success",
            action: AuditAction::RestoreTest,
            result: AuditResult::Success,
            metadata_json: json!({
                "phase": "verify",
                "sample_count": 1,
                "trigger": "cli",
                "duration_ms": 0,
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "phase",
                "sample_count",
                "trigger",
                "duration_ms",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "auth_failure failure",
            action: AuditAction::AuthFailure,
            result: AuditResult::Failure,
            metadata_json: json!({
                "error_code": "jwt_invalid",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["error_code", "source_event_at"],
        },
        AuditMetadataContract {
            name: "key_rotation_start success",
            action: AuditAction::KeyRotationStart,
            result: AuditResult::Success,
            metadata_json: json!({
                "old_key_version": 1,
                "new_key_version": 2,
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["old_key_version", "new_key_version", "source_event_at"],
        },
        AuditMetadataContract {
            name: "key_rotation_reencrypt success",
            action: AuditAction::KeyRotationReencrypt,
            result: AuditResult::Success,
            metadata_json: json!({
                "old_key_version": 1,
                "new_key_version": 2,
                "batch_size": 1,
                "processed_count": 1,
                "remaining_count": 0,
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "old_key_version",
                "new_key_version",
                "batch_size",
                "processed_count",
                "remaining_count",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "key_rotation_complete success",
            action: AuditAction::KeyRotationComplete,
            result: AuditResult::Success,
            metadata_json: json!({
                "old_key_version": 1,
                "new_key_version": 2,
                "remaining_count": 0,
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "old_key_version",
                "new_key_version",
                "remaining_count",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "key_rotation_envelope_migrated canonical metadata",
            action: AuditAction::KeyRotationEnvelopeMigrated,
            result: AuditResult::Success,
            metadata_json: json!({
                "batch_size": 1,
                "success_count": 1,
                "failure_count": 0,
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "batch_size",
                "success_count",
                "failure_count",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "key_rotation_envelope_failed canonical metadata",
            action: AuditAction::KeyRotationEnvelopeFailed,
            result: AuditResult::Failure,
            metadata_json: json!({
                "secret_version_id": "55555555-5555-4555-8555-555555555555",
                "version": 1,
                "error_code": "aad_context_mismatch",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "secret_version_id",
                "version",
                "error_code",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "signature_key_created success",
            action: AuditAction::SignatureKeyCreated,
            result: AuditResult::Success,
            metadata_json: json!({
                "signature_key_version": 1,
                "public_key_fingerprint": "a".repeat(64),
                "created_at": "2026-06-01T02:00:00Z",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "signature_key_version",
                "public_key_fingerprint",
                "created_at",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "signature_key_activated success",
            action: AuditAction::SignatureKeyActivated,
            result: AuditResult::Success,
            metadata_json: json!({
                "signature_key_version": 1,
                "public_key_fingerprint": "b".repeat(64),
                "activated_at": "2026-06-01T02:00:00Z",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "signature_key_version",
                "public_key_fingerprint",
                "activated_at",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "signature_key_retired success",
            action: AuditAction::SignatureKeyRetired,
            result: AuditResult::Success,
            metadata_json: json!({
                "signature_key_version": 1,
                "public_key_fingerprint": "c".repeat(64),
                "retired_at": "2026-06-01T02:00:00Z",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "signature_key_version",
                "public_key_fingerprint",
                "retired_at",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "monthly_digest_generate success",
            action: AuditAction::MonthlyDigestGenerate,
            result: AuditResult::Success,
            metadata_json: json!({
                "target_year_month": "2026-06",
                "start_sequence_no": 1,
                "end_sequence_no": 1,
                "entry_count": 1,
                "signature_key_version": 1,
                "digest_hash": "d".repeat(64),
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "target_year_month",
                "start_sequence_no",
                "end_sequence_no",
                "entry_count",
                "signature_key_version",
                "digest_hash",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "monthly_digest_generate failure",
            action: AuditAction::MonthlyDigestGenerate,
            result: AuditResult::Failure,
            metadata_json: json!({
                "target_year_month": "2026-06",
                "error_code": "digest_generation_failed",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["target_year_month", "error_code", "source_event_at"],
        },
        AuditMetadataContract {
            name: "monthly_digest_verify success",
            action: AuditAction::MonthlyDigestVerify,
            result: AuditResult::Success,
            metadata_json: json!({
                "target_year_month": "2026-06",
                "verify_result": "valid",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["target_year_month", "verify_result", "source_event_at"],
        },
        AuditMetadataContract {
            name: "monthly_digest_verify failure",
            action: AuditAction::MonthlyDigestVerify,
            result: AuditResult::Failure,
            metadata_json: json!({
                "target_year_month": "2026-06",
                "verify_result": "invalid",
                "error_code": "digest_verify_failed",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "target_year_month",
                "verify_result",
                "error_code",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "archive_export success",
            action: AuditAction::ArchiveExport,
            result: AuditResult::Success,
            metadata_json: json!({
                "target_year_month": "2026-06",
                "archive_key": "archive-2026-06",
                "digest_hash": "e".repeat(64),
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["target_year_month", "source_event_at"],
        },
        AuditMetadataContract {
            name: "archive_export failure",
            action: AuditAction::ArchiveExport,
            result: AuditResult::Failure,
            metadata_json: json!({
                "target_year_month": "2026-06",
                "error_code": "archive_export_failed",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["target_year_month", "source_event_at"],
        },
        AuditMetadataContract {
            name: "digest_timestamping success",
            action: AuditAction::DigestTimestamping,
            result: AuditResult::Success,
            metadata_json: json!({
                "target_year_month": "2026-06",
                "digest_hash": "f".repeat(64),
                "timestamp_token_hash": "1".repeat(64),
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["target_year_month", "source_event_at"],
        },
        AuditMetadataContract {
            name: "digest_timestamping failure",
            action: AuditAction::DigestTimestamping,
            result: AuditResult::Failure,
            metadata_json: json!({
                "target_year_month": "2026-06",
                "error_code": "timestamping_failed",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["target_year_month", "source_event_at"],
        },
        AuditMetadataContract {
            name: "siem_forward_failure failure",
            action: AuditAction::SiemForwardFailure,
            result: AuditResult::Failure,
            metadata_json: json!({
                "error_code": "siem_forward_failed",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["error_code", "source_event_at"],
        },
        AuditMetadataContract {
            name: "siem_event_forwarded success",
            action: AuditAction::SiemEventForwarded,
            result: AuditResult::Success,
            metadata_json: json!({
                "exporter_kind": "splunk_hec",
                "batch_size": 1,
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["exporter_kind", "batch_size", "source_event_at"],
        },
        AuditMetadataContract {
            name: "siem_event_failed failure",
            action: AuditAction::SiemEventFailed,
            result: AuditResult::Failure,
            metadata_json: json!({
                "exporter_kind": "splunk_hec",
                "error_code": "siem_http_503",
                "buffered": true,
                "batch_size": 1,
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "exporter_kind",
                "error_code",
                "buffered",
                "batch_size",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "siem_buffer_flushed success",
            action: AuditAction::SiemBufferFlushed,
            result: AuditResult::Success,
            metadata_json: json!({
                "flushed_count": 1,
                "buffer_remaining_bytes": 0,
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["flushed_count", "buffer_remaining_bytes", "source_event_at"],
        },
        AuditMetadataContract {
            name: "audit_report_generate success",
            action: AuditAction::AuditReportGenerate,
            result: AuditResult::Success,
            metadata_json: json!({
                "format": "json",
                "period_start": "2026-06-01T00:00:00Z",
                "period_end": "2026-07-01T00:00:00Z",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["format", "period_start", "period_end", "source_event_at"],
        },
        AuditMetadataContract {
            name: "audit_report_generate failure",
            action: AuditAction::AuditReportGenerate,
            result: AuditResult::Failure,
            metadata_json: json!({
                "format": "markdown",
                "period_start": "2026-06-01T00:00:00Z",
                "period_end": "2026-07-01T00:00:00Z",
                "error_code": "audit_report_failed",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["format", "period_start", "period_end", "source_event_at"],
        },
        AuditMetadataContract {
            name: "audit_ui_read success",
            action: AuditAction::AuditUiRead,
            result: AuditResult::Success,
            metadata_json: json!({
                "endpoint": "/v1/audit/events",
                "method": "GET",
                "resource": "audit_events",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["endpoint", "method", "resource", "source_event_at"],
        },
        AuditMetadataContract {
            name: "audit_ui_read failure",
            action: AuditAction::AuditUiRead,
            result: AuditResult::Failure,
            metadata_json: json!({
                "endpoint": "/v1/audit/events",
                "method": "GET",
                "resource": "audit_events",
                "error_code": "audit_ui_denied",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["endpoint", "method", "resource", "source_event_at"],
        },
        AuditMetadataContract {
            name: "scheduler_job success",
            action: AuditAction::SchedulerJob,
            result: AuditResult::Success,
            metadata_json: json!({
                "job_name": "monthly_digest_generate",
                "trigger": "background",
                "duration_ms": 0,
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["job_name", "trigger", "duration_ms", "source_event_at"],
        },
        AuditMetadataContract {
            name: "scheduler_job failure",
            action: AuditAction::SchedulerJob,
            result: AuditResult::Failure,
            metadata_json: json!({
                "job_name": "monthly_digest_generate",
                "trigger": "background",
                "duration_ms": 0,
                "error_code": "scheduler_job_failed",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["job_name", "trigger", "duration_ms", "source_event_at"],
        },
        AuditMetadataContract {
            name: "scheduler_job_started success",
            action: AuditAction::SchedulerJobStarted,
            result: AuditResult::Success,
            metadata_json: json!({
                "job_name": "monthly_digest_generate",
                "scheduled_at": "2026-06-01T02:00:00Z",
                "started_at": "2026-06-01T02:00:01Z",
                "source_event_at": "2026-06-01T02:00:01Z"
            }),
            required_keys: &["job_name", "scheduled_at", "started_at", "source_event_at"],
        },
        AuditMetadataContract {
            name: "scheduler_job_completed success",
            action: AuditAction::SchedulerJobCompleted,
            result: AuditResult::Success,
            metadata_json: json!({
                "job_name": "monthly_digest_generate",
                "started_at": "2026-06-01T02:00:01Z",
                "completed_at": "2026-06-01T02:00:02Z",
                "duration_ms": 1000,
                "result_summary": { "status": "ok" },
                "source_event_at": "2026-06-01T02:00:02Z"
            }),
            required_keys: &[
                "job_name",
                "started_at",
                "completed_at",
                "duration_ms",
                "result_summary",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "scheduler_job_failed failure",
            action: AuditAction::SchedulerJobFailed,
            result: AuditResult::Failure,
            metadata_json: json!({
                "job_name": "monthly_digest_generate",
                "started_at": "2026-06-01T02:00:01Z",
                "failed_at": "2026-06-01T02:00:02Z",
                "error_code": "scheduler_job_timeout",
                "retry_count": 0,
                "source_event_at": "2026-06-01T02:00:02Z"
            }),
            required_keys: &[
                "job_name",
                "started_at",
                "failed_at",
                "error_code",
                "retry_count",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "scheduler_job_skipped success",
            action: AuditAction::SchedulerJobSkipped,
            result: AuditResult::Success,
            metadata_json: json!({
                "job_name": "monthly_digest_generate",
                "skipped_at": "2026-06-01T02:00:01Z",
                "reason": "lock_not_acquired",
                "source_event_at": "2026-06-01T02:00:01Z"
            }),
            required_keys: &["job_name", "skipped_at", "reason", "source_event_at"],
        },
        AuditMetadataContract {
            name: "incident_detected failure",
            action: AuditAction::IncidentDetected,
            result: AuditResult::Failure,
            metadata_json: json!({
                "incident_type": "hash_chain_mismatch",
                "severity": "high",
                "detection_source": "monthly_digest_verify",
                "dedupe_key": "incident-2026-06",
                "notification_sink": "audit_ops",
                "notification_result": "sent",
                "error_code": "monthly_digest_hash_mismatch",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "incident_type",
                "severity",
                "detection_source",
                "dedupe_key",
                "notification_sink",
                "notification_result",
                "error_code",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "secret_alias_create success",
            action: AuditAction::SecretAliasCreate,
            result: AuditResult::Success,
            metadata_json: json!({
                "alias_fingerprint": "2".repeat(64),
                "alias_fingerprint_key_version": 1,
                "alias_fingerprint_schema_version": 1,
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "alias_fingerprint",
                "alias_fingerprint_key_version",
                "alias_fingerprint_schema_version",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "secret_alias_create failure",
            action: AuditAction::SecretAliasCreate,
            result: AuditResult::Failure,
            metadata_json: json!({
                "error_code": "alias_create_failed",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["source_event_at"],
        },
        AuditMetadataContract {
            name: "secret_alias_update success",
            action: AuditAction::SecretAliasUpdate,
            result: AuditResult::Success,
            metadata_json: json!({
                "old_alias_fingerprint": "3".repeat(64),
                "new_alias_fingerprint": "4".repeat(64),
                "alias_fingerprint_key_version": 1,
                "alias_fingerprint_schema_version": 1,
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "old_alias_fingerprint",
                "new_alias_fingerprint",
                "alias_fingerprint_key_version",
                "alias_fingerprint_schema_version",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "secret_alias_update failure",
            action: AuditAction::SecretAliasUpdate,
            result: AuditResult::Failure,
            metadata_json: json!({
                "error_code": "alias_update_failed",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["source_event_at"],
        },
        AuditMetadataContract {
            name: "secret_alias_delete success",
            action: AuditAction::SecretAliasDelete,
            result: AuditResult::Success,
            metadata_json: json!({
                "alias_fingerprint": "5".repeat(64),
                "alias_fingerprint_key_version": 1,
                "alias_fingerprint_schema_version": 1,
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &[
                "alias_fingerprint",
                "alias_fingerprint_key_version",
                "alias_fingerprint_schema_version",
                "source_event_at",
            ],
        },
        AuditMetadataContract {
            name: "secret_alias_delete failure",
            action: AuditAction::SecretAliasDelete,
            result: AuditResult::Failure,
            metadata_json: json!({
                "error_code": "alias_delete_failed",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["source_event_at"],
        },
        AuditMetadataContract {
            name: "secret_alias_list success",
            action: AuditAction::SecretAliasList,
            result: AuditResult::Success,
            metadata_json: json!({
                "result_count": 0,
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["result_count", "source_event_at"],
        },
        AuditMetadataContract {
            name: "secret_alias_list failure",
            action: AuditAction::SecretAliasList,
            result: AuditResult::Failure,
            metadata_json: json!({
                "error_code": "alias_list_failed",
                "source_event_at": "2026-06-01T02:00:00Z"
            }),
            required_keys: &["source_event_at"],
        },
    ]
}

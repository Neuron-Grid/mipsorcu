use mipsorcu::{AuditAction, AuditMetadata, AuditResult};

#[test]
fn rust_allowlist_rejects_unknown_key() {
    // decrypt success: source_event_at のみ
    let metadata =
        serde_json::json!({ "source_event_at": "2026-04-08T12:00:00Z", "unknown_key": "value" });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result = audit.validate_allowlist_for_action(AuditAction::Decrypt, AuditResult::Success);
    assert!(
        matches!(
            result,
            Err(mipsorcu::AuditEventError::UnknownMetadataKey { .. })
        ),
        "unknown key in decrypt success should be rejected, got {result:?}"
    );
}

#[test]
fn rust_allowlist_rejects_decrypt_success_missing_source_event_at() {
    let metadata = AuditMetadata::empty();
    let result = metadata.validate_allowlist_for_action(AuditAction::Decrypt, AuditResult::Success);
    assert!(
        matches!(
            result,
            Err(mipsorcu::AuditEventError::MissingMetadataKey {
                key: "source_event_at"
            })
        ),
        "empty metadata should fail because source_event_at is required: {result:?}"
    );
}

#[test]
fn rust_allowlist_accepts_known_keys_per_action() {
    // encrypt_create success は write_success_only なので rust 側 validation step で落ちるが、
    // allowlist structurally allowlist は version/secret_version_id/source_event_at のみが OK
    let metadata = serde_json::json!({
        "version": 1,
        "secret_version_id": "550e8400-e29b-41d4-a716-446655440000",
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::EncryptCreate, AuditResult::Failure);
    assert!(
        result.is_ok(),
        "valid encrypt_create keys should pass: {result:?}"
    );
}

#[test]
fn rust_allowlist_rejects_integrity_check_unknown_summary_key() {
    let metadata = serde_json::json!({
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
            "audit_source_event_at_invalid": 0,
            "unknown_summary_key": 1
        },
        "trigger": "startup",
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::IntegrityCheck, AuditResult::Success);
    assert!(
        matches!(
            result,
            Err(mipsorcu::AuditEventError::UnknownMetadataKey { .. })
        ),
        "unknown violation_summary key should be rejected: {result:?}"
    );
}

#[test]
fn rust_allowlist_accepts_decrypt_failure_with_attempted_secret_id() {
    let metadata = serde_json::json!({
        "attempted_secret_id": "550e8400-e29b-41d4-a716-446655440000",
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result = audit.validate_allowlist_for_action(AuditAction::Decrypt, AuditResult::Failure);
    assert!(
        result.is_ok(),
        "decrypt failure with attempted_secret_id should pass: {result:?}"
    );
}

#[test]
fn rust_allowlist_rejects_decrypt_failure_without_attempted_secret_id_unknown() {
    let metadata = serde_json::json!({
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result = audit.validate_allowlist_for_action(AuditAction::Decrypt, AuditResult::Failure);
    // attempted_secret_id は任意なのでなくても OK
    assert!(
        result.is_ok(),
        "decrypt failure with only source_event_at should pass: {result:?}"
    );
}

#[test]
fn rust_allowlist_accepts_secret_alias_metadata() {
    let create_metadata = serde_json::json!({
        "alias_fingerprint": "aa".repeat(32),
        "alias_fingerprint_key_version": 1,
        "alias_fingerprint_schema_version": 1,
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let create_audit = AuditMetadata::new(create_metadata).unwrap();
    assert!(
        create_audit
            .validate_allowlist_for_action(AuditAction::SecretAliasCreate, AuditResult::Success)
            .is_ok()
    );

    let update_metadata = serde_json::json!({
        "old_alias_fingerprint": "aa".repeat(32),
        "new_alias_fingerprint": "bb".repeat(32),
        "alias_fingerprint_key_version": 1,
        "alias_fingerprint_schema_version": 1,
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let update_audit = AuditMetadata::new(update_metadata).unwrap();
    assert!(
        update_audit
            .validate_allowlist_for_action(AuditAction::SecretAliasUpdate, AuditResult::Success)
            .is_ok()
    );

    let list_metadata = serde_json::json!({
        "result_count": 3,
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let list_audit = AuditMetadata::new(list_metadata).unwrap();
    assert!(
        list_audit
            .validate_allowlist_for_action(AuditAction::SecretAliasList, AuditResult::Success)
            .is_ok()
    );
}

#[test]
fn rust_allowlist_rejects_invalid_secret_alias_metadata() {
    let metadata = serde_json::json!({
        "alias_fingerprint": "aa".repeat(31),
        "alias_fingerprint_key_version": 1,
        "alias_fingerprint_schema_version": 1,
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::SecretAliasCreate, AuditResult::Success);
    assert!(
        matches!(
            result,
            Err(mipsorcu::AuditEventError::InvalidMetadataValue {
                key: "alias_fingerprint"
            })
        ),
        "invalid alias fingerprint should be rejected: {result:?}"
    );
}

#[test]
fn rust_allowlist_accepts_secret_alias_failure_without_fingerprint() {
    for action in [
        AuditAction::SecretAliasCreate,
        AuditAction::SecretAliasUpdate,
        AuditAction::SecretAliasDelete,
        AuditAction::SecretAliasList,
    ] {
        let metadata = serde_json::json!({
            "source_event_at": "2026-04-08T12:00:00Z"
        });
        let audit = AuditMetadata::new(metadata).unwrap();
        let result = audit.validate_allowlist_for_action(action, AuditResult::Failure);

        assert!(
            result.is_ok(),
            "{action:?} failure should accept source_event_at-only metadata: {result:?}"
        );
    }
}

#[test]
fn rust_allowlist_rejects_secret_alias_success_with_error_code() {
    let metadata = serde_json::json!({
        "alias_fingerprint": "aa".repeat(32),
        "alias_fingerprint_key_version": 1,
        "alias_fingerprint_schema_version": 1,
        "error_code": "should_only_appear_on_failure",
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::SecretAliasCreate, AuditResult::Success);

    assert!(
        matches!(
            result,
            Err(mipsorcu::AuditEventError::InvalidMetadataValue { key: "error_code" })
        ),
        "secret_alias_create success should reject error_code: {result:?}"
    );
}

#[test]
fn rust_allowlist_accepts_scheduler_lifecycle_metadata() {
    let started = AuditMetadata::new(serde_json::json!({
        "job_name": "monthly_hash_chain_verify",
        "scheduled_at": "2026-04-08T12:00:00Z",
        "started_at": "2026-04-08T12:00:01Z",
        "source_event_at": "2026-04-08T12:00:01Z"
    }))
    .unwrap();
    assert!(
        started
            .validate_allowlist_for_action(AuditAction::SchedulerJobStarted, AuditResult::Success)
            .is_ok()
    );

    let completed = AuditMetadata::new(serde_json::json!({
        "job_name": "monthly_hash_chain_verify",
        "started_at": "2026-04-08T12:00:01Z",
        "completed_at": "2026-04-08T12:00:02Z",
        "duration_ms": 1000,
        "result_summary": { "valid": true },
        "source_event_at": "2026-04-08T12:00:02Z"
    }))
    .unwrap();
    assert!(
        completed
            .validate_allowlist_for_action(AuditAction::SchedulerJobCompleted, AuditResult::Success)
            .is_ok()
    );

    let failed = AuditMetadata::new(serde_json::json!({
        "job_name": "monthly_hash_chain_verify",
        "started_at": "2026-04-08T12:00:01Z",
        "failed_at": "2026-04-08T12:00:02Z",
        "error_code": "scheduler_job_timeout",
        "retry_count": 0,
        "source_event_at": "2026-04-08T12:00:02Z"
    }))
    .unwrap();
    assert!(
        failed
            .validate_allowlist_for_action(AuditAction::SchedulerJobFailed, AuditResult::Failure)
            .is_ok()
    );

    let skipped = AuditMetadata::new(serde_json::json!({
        "job_name": "monthly_hash_chain_verify",
        "skipped_at": "2026-04-08T12:00:01Z",
        "reason": "lock_not_acquired",
        "source_event_at": "2026-04-08T12:00:01Z"
    }))
    .unwrap();
    assert!(
        skipped
            .validate_allowlist_for_action(AuditAction::SchedulerJobSkipped, AuditResult::Success)
            .is_ok()
    );
}

#[test]
fn rust_allowlist_rejects_scheduler_lifecycle_invalid_values() {
    let retry = AuditMetadata::new(serde_json::json!({
        "job_name": "monthly_hash_chain_verify",
        "started_at": "2026-04-08T12:00:01Z",
        "failed_at": "2026-04-08T12:00:02Z",
        "error_code": "scheduler_job_failed",
        "retry_count": "one",
        "source_event_at": "2026-04-08T12:00:02Z"
    }))
    .unwrap();
    assert!(matches!(
        retry.validate_allowlist_for_action(AuditAction::SchedulerJobFailed, AuditResult::Failure),
        Err(mipsorcu::AuditEventError::InvalidMetadataValue { key: "retry_count" })
    ));

    let reason = AuditMetadata::new(serde_json::json!({
        "job_name": "monthly_hash_chain_verify",
        "skipped_at": "2026-04-08T12:00:01Z",
        "reason": "maintenance",
        "source_event_at": "2026-04-08T12:00:01Z"
    }))
    .unwrap();
    assert!(matches!(
        reason
            .validate_allowlist_for_action(AuditAction::SchedulerJobSkipped, AuditResult::Success),
        Err(mipsorcu::AuditEventError::InvalidMetadataValue { key: "reason" })
    ));
}

#[test]
fn rust_allowlist_accepts_siem_operational_metadata() {
    let forwarded = AuditMetadata::new(serde_json::json!({
        "exporter_kind": "splunk_hec",
        "batch_size": 100,
        "source_event_at": "2026-04-08T12:00:00Z"
    }))
    .unwrap();
    assert!(
        forwarded
            .validate_allowlist_for_action(AuditAction::SiemEventForwarded, AuditResult::Success)
            .is_ok()
    );

    let failed = AuditMetadata::new(serde_json::json!({
        "exporter_kind": "splunk_hec",
        "error_code": "siem_splunk_http_503",
        "buffered": true,
        "batch_size": 3,
        "source_event_at": "2026-04-08T12:00:00Z"
    }))
    .unwrap();
    assert!(
        failed
            .validate_allowlist_for_action(AuditAction::SiemEventFailed, AuditResult::Failure)
            .is_ok()
    );

    let flushed = AuditMetadata::new(serde_json::json!({
        "flushed_count": 3,
        "buffer_remaining_bytes": 1048576,
        "source_event_at": "2026-04-08T12:00:00Z"
    }))
    .unwrap();
    assert!(
        flushed
            .validate_allowlist_for_action(AuditAction::SiemBufferFlushed, AuditResult::Success)
            .is_ok()
    );
}

#[test]
fn rust_allowlist_rejects_invalid_siem_operational_metadata() {
    let exporter_kind = AuditMetadata::new(serde_json::json!({
        "exporter_kind": "webhook",
        "batch_size": 1,
        "source_event_at": "2026-04-08T12:00:00Z"
    }))
    .unwrap();
    assert!(matches!(
        exporter_kind
            .validate_allowlist_for_action(AuditAction::SiemEventForwarded, AuditResult::Success),
        Err(mipsorcu::AuditEventError::InvalidMetadataValue {
            key: "exporter_kind"
        })
    ));

    let buffered = AuditMetadata::new(serde_json::json!({
        "exporter_kind": "splunk_hec",
        "error_code": "siem_splunk_http_503",
        "buffered": "true",
        "batch_size": 1,
        "source_event_at": "2026-04-08T12:00:00Z"
    }))
    .unwrap();
    assert!(matches!(
        buffered.validate_allowlist_for_action(AuditAction::SiemEventFailed, AuditResult::Failure),
        Err(mipsorcu::AuditEventError::InvalidMetadataValue { key: "buffered" })
    ));

    let batch_size = AuditMetadata::new(serde_json::json!({
        "exporter_kind": "splunk_hec",
        "batch_size": 0,
        "source_event_at": "2026-04-08T12:00:00Z"
    }))
    .unwrap();
    assert!(matches!(
        batch_size
            .validate_allowlist_for_action(AuditAction::SiemEventForwarded, AuditResult::Success),
        Err(mipsorcu::AuditEventError::InvalidMetadataValue { key: "batch_size" })
    ));
}

#[test]
fn rust_allowlist_accepts_siem_buffer_overflow_incident_notification_category() {
    let metadata = AuditMetadata::new(serde_json::json!({
        "incident_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "category": "siem_buffer_overflow",
        "notifier_kind": "webhook",
        "duration_ms": 25,
        "source_event_at": "2026-06-01T02:00:00Z"
    }))
    .unwrap();

    assert!(
        metadata
            .validate_allowlist_for_action(
                AuditAction::IncidentNotificationSent,
                AuditResult::Success
            )
            .is_ok()
    );
}

// ─── Parity: Rust ↔ SQL same case, same accept/reject ───

#[test]
fn rust_parity_integrity_check_success_valid() {
    let metadata = serde_json::json!({
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
        "trigger": "startup",
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::IntegrityCheck, AuditResult::Success);
    assert!(
        result.is_ok(),
        "integrity_check success with full allowlist should pass: {result:?}"
    );
}

#[test]
fn rust_parity_integrity_check_violation_summary_non_object() {
    let metadata = serde_json::json!({
        "check_name": "mvp_integrity_check",
        "checked_secret_count": 0,
        "checked_secret_version_count": 0,
        "checked_audit_event_count": 0,
        "duration_ms": 0,
        "violation_count": 0,
        "violation_summary": "not_an_object",
        "trigger": "startup",
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::IntegrityCheck, AuditResult::Success);
    assert!(
        matches!(
            result,
            Err(mipsorcu::AuditEventError::ViolationSummaryMustBeObject)
        ),
        "integrity_check violation_summary non-object should be rejected, got {result:?}"
    );
}

#[test]
fn rust_parity_restore_test_success_valid() {
    let metadata = serde_json::json!({
        "phase": "verify",
        "sample_count": 5,
        "trigger": "background",
        "duration_ms": 100,
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::RestoreTest, AuditResult::Success);
    assert!(
        result.is_ok(),
        "restore_test success with allowlist keys should pass: {result:?}"
    );
}

#[test]
fn rust_parity_restore_test_failure_valid() {
    let metadata = serde_json::json!({
        "phase": "verify",
        "sample_count": 0,
        "trigger": "cli",
        "duration_ms": 0,
        "error_code": "sample_fetch_failed",
        "failed_version": null,
        "reason": "no_current_secret_versions",
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::RestoreTest, AuditResult::Failure);
    assert!(
        result.is_ok(),
        "restore_test failure with all optional keys should pass: {result:?}"
    );
}

#[test]
fn rust_parity_auth_failure_failure_valid() {
    let metadata = serde_json::json!({
        "error_code": "authorization_header_missing",
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::AuthFailure, AuditResult::Failure);
    assert!(
        result.is_ok(),
        "auth_failure with allowlist keys should pass: {result:?}"
    );
}

#[test]
fn rust_parity_auth_failure_unknown_key() {
    let metadata = serde_json::json!({
        "error_code": "bad",
        "source_event_at": "2026-04-08T12:00:00Z",
        "extra": "bad"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::AuthFailure, AuditResult::Failure);
    assert!(
        matches!(
            result,
            Err(mipsorcu::AuditEventError::UnknownMetadataKey { .. })
        ),
        "auth_failure with unknown key should be rejected, got {result:?}"
    );
}

#[test]
fn rust_parity_key_rotation_start_valid() {
    let metadata = serde_json::json!({
        "old_key_version": 1,
        "new_key_version": 2,
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::KeyRotationStart, AuditResult::Success);
    assert!(
        result.is_ok(),
        "key_rotation_start with allowlist keys should pass: {result:?}"
    );
}

#[test]
fn rust_parity_key_rotation_reencrypt_valid() {
    let metadata = serde_json::json!({
        "old_key_version": 1,
        "new_key_version": 2,
        "batch_size": 100,
        "processed_count": 50,
        "remaining_count": 50,
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result = audit
        .validate_allowlist_for_action(AuditAction::KeyRotationReencrypt, AuditResult::Success);
    assert!(
        result.is_ok(),
        "key_rotation_reencrypt with allowlist keys should pass: {result:?}"
    );
}

#[test]
fn rust_parity_key_rotation_complete_valid() {
    let metadata = serde_json::json!({
        "old_key_version": 1,
        "new_key_version": 2,
        "remaining_count": 0,
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::KeyRotationComplete, AuditResult::Success);
    assert!(
        result.is_ok(),
        "key_rotation_complete with allowlist keys should pass: {result:?}"
    );
}

#[test]
fn rust_parity_metadata_non_object_rejected() {
    let result = AuditMetadata::new(serde_json::json!("not_an_object"));
    assert!(
        matches!(result, Err(mipsorcu::AuditEventError::MetadataMustBeObject)),
        "non-object metadata should be rejected, got {result:?}"
    );
}

#[test]
fn rust_parity_forbidden_key_nested_inside_object() {
    let metadata = serde_json::json!({
        "nested": [{"plaintext": "leak"}],
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let result = AuditMetadata::new(metadata);
    assert!(
        matches!(
            result,
            Err(mipsorcu::AuditEventError::ForbiddenMetadataKey { .. })
        ),
        "nested forbidden key should be rejected, got {result:?}"
    );
}

#[test]
fn rust_parity_invalid_source_event_at() {
    // non-canonical offset
    let metadata = serde_json::json!({ "source_event_at": "2026-04-08T12:00:00+00:00" });
    let result = AuditMetadata::new(metadata);
    assert!(
        matches!(result, Err(mipsorcu::AuditEventError::InvalidSourceEventAt)),
        "non-canonical source_event_at should be rejected, got {result:?}"
    );
}

#[test]
fn rust_parity_decrypt_success_valid() {
    let metadata = serde_json::json!({
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result = audit.validate_allowlist_for_action(AuditAction::Decrypt, AuditResult::Success);
    assert!(
        result.is_ok(),
        "decrypt success with source_event_at only should pass: {result:?}"
    );
}

#[test]
fn rust_parity_decrypt_failure_valid() {
    let metadata = serde_json::json!({
        "attempted_secret_id": "550e8400-e29b-41d4-a716-446655440000",
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result = audit.validate_allowlist_for_action(AuditAction::Decrypt, AuditResult::Failure);
    assert!(
        result.is_ok(),
        "decrypt failure with attempted_secret_id should pass: {result:?}"
    );
}

#[test]
fn rust_parity_encrypt_create_failure_valid() {
    let metadata = serde_json::json!({
        "version": 1,
        "secret_version_id": "550e8400-e29b-41d4-a716-446655440000",
        "source_event_at": "2026-04-08T12:00:00Z"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::EncryptCreate, AuditResult::Failure);
    assert!(
        result.is_ok(),
        "encrypt_create failure with allowlist keys should pass: {result:?}"
    );
}

#[test]
fn rust_parity_encrypt_create_failure_unknown_key() {
    let metadata = serde_json::json!({
        "version": 1,
        "source_event_at": "2026-04-08T12:00:00Z",
        "extra": "bad"
    });
    let audit = AuditMetadata::new(metadata).unwrap();
    let result =
        audit.validate_allowlist_for_action(AuditAction::EncryptCreate, AuditResult::Failure);
    assert!(
        matches!(
            result,
            Err(mipsorcu::AuditEventError::UnknownMetadataKey { .. })
        ),
        "encrypt_create failure with unknown key should be rejected, got {result:?}"
    );
}

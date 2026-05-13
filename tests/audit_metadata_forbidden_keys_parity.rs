use std::collections::{BTreeSet, HashMap};
use std::fs;

use mipsorcu::{
    AuditAction, AuditMetadata, AuditResult, FORBIDDEN_AUDIT_METADATA_KEYS,
    INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST,
};

const LATEST_SIEM_MIGRATION_PATH: &str =
    "supabase/migrations/1000_add_scheduler_job_audit_and_ledger.sql";
// allowlist 正本: 全 action を含む更新版の函数定義を持つ。
// allowlist_parity / forbidden_key_parity / violation_summary_parity はこちらを参照する。
// 新 action を追加する場合は、このパスの migration を更新すること。
const FORBIDDEN_START_MARKER: &str = "-- FORBIDDEN_AUDIT_METADATA_KEYS_START";
const FORBIDDEN_END_MARKER: &str = "-- FORBIDDEN_AUDIT_METADATA_KEYS_END";
const ALLOWLIST_START_MARKER: &str = "-- ACTION_ALLOWLIST_START";
const ALLOWLIST_END_MARKER: &str = "-- ACTION_ALLOWLIST_END";

#[test]
fn forbidden_keys_parity_between_rust_and_sql() {
    let migration = fs::read_to_string(LATEST_SIEM_MIGRATION_PATH)
        .expect("forbidden-keys migration should be readable");
    let sql_keys = extract_sql_forbidden_keys(&migration);
    let rust_keys = FORBIDDEN_AUDIT_METADATA_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(sql_keys, rust_keys);
}

#[test]
fn allowlist_parity_between_rust_and_sql() {
    // 最新の allowlist migration が audit_metadata_has_unknown_key_for_action の最新定義を持つ。
    // 新 action を追加する場合は最新 migration の ACTION_ALLOWLIST_START/END 内と
    // rust_allowlist_for_action_result（このファイル内）の両方を更新すること。
    let migration = fs::read_to_string(LATEST_SIEM_MIGRATION_PATH)
        .expect("allowlist migration should be readable");
    let sql_allowlist = extract_sql_allowlist(&migration);

    // Rust 側 allowlist を action+result ごとに構成
    for action in all_actions() {
        for result in [AuditResult::Success, AuditResult::Failure] {
            let rust_allowed = rust_allowlist_for_action_result(action, result);

            if action.is_write_success_only() && result == AuditResult::Success {
                // write-success-only action は Rust 側で事前排除されるため allowlist なし
                continue;
            }

            // SQL 側: decrypt 以外は result で区別しない。decrypt だけ decrypt:success / decrypt:failure
            let sql_key = if action == AuditAction::Decrypt {
                format!("{}:{}", action.as_str(), result.as_str())
            } else {
                action.as_str().to_owned()
            };

            let sql_allowed = sql_allowlist
                .get(&sql_key)
                .unwrap_or_else(|| panic!("SQL allowlist should contain entry for {sql_key}"));

            assert_eq!(
                rust_allowed, *sql_allowed,
                "Rust/SQL allowlist mismatch for {sql_key} (action={action:?}, result={result:?})"
            );
        }
    }
}

#[test]
fn integrity_check_violation_summary_allowlist_parity() {
    // 最新 migration は完全な関数定義（violation_summary キーを含む）を保持する。
    let migration = fs::read_to_string(LATEST_SIEM_MIGRATION_PATH)
        .expect("allowlist migration should be readable");
    let sql_summary = extract_sql_violation_summary_keys(&migration);
    let rust_summary = INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST
        .iter()
        .map(|k| (*k).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(rust_summary, sql_summary);
}

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

fn all_actions() -> Vec<AuditAction> {
    vec![
        AuditAction::EncryptCreate,
        AuditAction::EncryptRotate,
        AuditAction::VersionPurge,
        AuditAction::Decrypt,
        AuditAction::IntegrityCheck,
        AuditAction::RestoreTest,
        AuditAction::AuthFailure,
        AuditAction::KeyRotationStart,
        AuditAction::KeyRotationReencrypt,
        AuditAction::KeyRotationComplete,
        AuditAction::SignatureKeyCreated,
        AuditAction::SignatureKeyActivated,
        AuditAction::SignatureKeyRetired,
        AuditAction::MonthlyDigestGenerate,
        AuditAction::MonthlyDigestVerify,
        AuditAction::ArchiveExport,
        AuditAction::DigestTimestamping,
        AuditAction::SiemForwardFailure,
        AuditAction::AuditReportGenerate,
        AuditAction::SchedulerJob,
        AuditAction::IncidentDetected,
    ]
}

fn rust_allowlist_for_action_result(action: AuditAction, result: AuditResult) -> BTreeSet<String> {
    // AuditMetadata::validate_allowlist_for_action と同一ロジック
    let mut keys = match action {
        AuditAction::EncryptCreate | AuditAction::EncryptRotate | AuditAction::VersionPurge => {
            vec!["version", "secret_version_id", "source_event_at"]
        }
        AuditAction::Decrypt => {
            if result == AuditResult::Failure {
                vec!["attempted_secret_id", "source_event_at"]
            } else {
                vec!["source_event_at"]
            }
        }
        AuditAction::IntegrityCheck => {
            vec![
                "check_name",
                "checked_secret_count",
                "checked_secret_version_count",
                "checked_audit_event_count",
                "duration_ms",
                "violation_count",
                "violation_summary",
                "trigger",
                "error_code",
                "source_event_at",
            ]
        }
        AuditAction::RestoreTest => {
            vec![
                "phase",
                "sample_count",
                "trigger",
                "duration_ms",
                "error_code",
                "failed_version",
                "reason",
                "source_event_at",
            ]
        }
        AuditAction::AuthFailure => {
            vec!["error_code", "source_event_at"]
        }
        AuditAction::KeyRotationStart => {
            vec!["old_key_version", "new_key_version", "source_event_at"]
        }
        AuditAction::KeyRotationReencrypt => {
            vec![
                "old_key_version",
                "new_key_version",
                "batch_size",
                "processed_count",
                "remaining_count",
                "source_event_at",
            ]
        }
        AuditAction::KeyRotationComplete => {
            vec![
                "old_key_version",
                "new_key_version",
                "remaining_count",
                "source_event_at",
            ]
        }
        AuditAction::SignatureKeyCreated => {
            vec![
                "created_at",
                "public_key_fingerprint",
                "signature_key_version",
                "source_event_at",
            ]
        }
        AuditAction::SignatureKeyActivated => {
            vec![
                "activated_at",
                "public_key_fingerprint",
                "signature_key_version",
                "source_event_at",
            ]
        }
        AuditAction::SignatureKeyRetired => {
            vec![
                "public_key_fingerprint",
                "retired_at",
                "signature_key_version",
                "source_event_at",
            ]
        }
        // 月次 digest 生成失敗時の監査記録
        AuditAction::MonthlyDigestGenerate => {
            vec!["error_code", "target_year_month", "source_event_at"]
        }
        // 月次 digest 検証失敗時の監査記録
        AuditAction::MonthlyDigestVerify => {
            vec!["error_code", "target_year_month", "source_event_at"]
        }
        // archive export（成功・失敗両方を記録、allowlist は result 共通）
        AuditAction::ArchiveExport => {
            vec![
                "archive_key",
                "digest_hash",
                "error_code",
                "source_event_at",
                "target_year_month",
            ]
        }
        // digest timestamping（成功・失敗両方を記録、allowlist は result 共通）
        AuditAction::DigestTimestamping => {
            vec![
                "digest_hash",
                "error_code",
                "source_event_at",
                "target_year_month",
                "timestamp_token_hash",
            ]
        }
        // SIEM forward failure（failure-only）
        AuditAction::SiemForwardFailure => {
            vec!["error_code", "event_count", "event_type", "source_event_at"]
        }
        // audit report generation（成功・失敗両方を記録）
        AuditAction::AuditReportGenerate => {
            vec![
                "error_code",
                "format",
                "period_end",
                "period_start",
                "source_event_at",
            ]
        }
        AuditAction::SchedulerJob => {
            vec![
                "duration_ms",
                "error_code",
                "job_name",
                "source_event_at",
                "target_year_month",
                "trigger",
            ]
        }
        AuditAction::IncidentDetected => {
            vec![
                "dedupe_key",
                "detection_source",
                "error_code",
                "incident_type",
                "notification_result",
                "notification_sink",
                "source_event_at",
                "source_event_id",
                "target_sequence_no",
                "target_year_month",
                "severity",
            ]
        }
    };
    keys.sort();
    keys.into_iter().map(|s| s.to_owned()).collect()
}

fn extract_sql_forbidden_keys(sql: &str) -> BTreeSet<String> {
    let (_, after_start) = sql
        .split_once(FORBIDDEN_START_MARKER)
        .expect("start marker should exist in migration");
    let (key_block, _) = after_start
        .split_once(FORBIDDEN_END_MARKER)
        .expect("end marker should exist in migration");

    let mut keys = BTreeSet::new();
    let mut current = String::new();
    let mut in_quote = false;

    for ch in key_block.chars() {
        match (in_quote, ch) {
            (false, '\'') => in_quote = true,
            (true, '\'') => {
                keys.insert(std::mem::take(&mut current));
                in_quote = false;
            }
            (true, _) => current.push(ch),
            (false, _) => {}
        }
    }

    assert!(
        !in_quote,
        "migration key block contains an unterminated string"
    );

    keys
}

fn extract_sql_allowlist(sql: &str) -> HashMap<String, BTreeSet<String>> {
    let (_, after_start) = sql
        .split_once(ALLOWLIST_START_MARKER)
        .expect("allowlist start marker should exist");
    let (block, _) = after_start
        .split_once(ALLOWLIST_END_MARKER)
        .expect("allowlist end marker should exist");

    let mut result: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut current_actions: Vec<String> = Vec::new();
    let mut current_keys: Vec<String> = Vec::new();
    let mut in_decrypt_failure = false;
    let mut in_array_parse = false;

    for line in block.lines() {
        let trimmed = line.trim();

        // when 節: シングルクォートで囲まれたアクション名をすべて抽出
        if trimmed.starts_with("when ") {
            current_actions.clear();
            let parts: Vec<&str> = trimmed.split('\'').collect();
            for i in (1..parts.len()).step_by(2) {
                if !parts[i].is_empty() {
                    current_actions.push(parts[i].to_owned());
                }
            }
            in_decrypt_failure = false;
        }

        // decrypt action 内の result 分岐
        if current_actions.contains(&"decrypt".to_owned()) {
            if trimmed.starts_with("if p_result = '") && trimmed.contains("'failure'") {
                in_decrypt_failure = true;
            } else if trimmed == "else" {
                in_decrypt_failure = false;
            }
        }

        // array 定義: 複数行にわたる場合もある
        if trimmed.contains("v_allowed_keys := array[") {
            in_array_parse = true;
            let start = trimmed.find("array[").unwrap_or(0) + "array[".len();
            if trimmed.ends_with("];") {
                // 一行完結
                let end = trimmed.rfind("];").unwrap_or(trimmed.len());
                parse_array_keys(&trimmed[start..end], &mut current_keys);
                // 登録
                if !current_actions.is_empty() && !current_keys.is_empty() {
                    for action in &current_actions {
                        let key = if *action == "decrypt" {
                            if in_decrypt_failure {
                                "decrypt:failure".to_owned()
                            } else {
                                "decrypt:success".to_owned()
                            }
                        } else {
                            action.clone()
                        };
                        result.insert(key, current_keys.iter().cloned().collect());
                    }
                }
                current_keys.clear();
                in_array_parse = false;
            } else {
                // 複数行の開始
                parse_array_keys(&trimmed[start..], &mut current_keys);
            }
        } else if in_array_parse {
            // 配列の中間行または終了行
            if trimmed.ends_with("];") {
                let end = trimmed.rfind("];").unwrap_or(trimmed.len());
                parse_array_keys(&trimmed[..end], &mut current_keys);
                // 登録
                if !current_actions.is_empty() && !current_keys.is_empty() {
                    for action in &current_actions {
                        let key = if *action == "decrypt" {
                            if in_decrypt_failure {
                                "decrypt:failure".to_owned()
                            } else {
                                "decrypt:success".to_owned()
                            }
                        } else {
                            action.clone()
                        };
                        result.insert(key, current_keys.iter().cloned().collect());
                    }
                }
                current_keys.clear();
                in_array_parse = false;
            } else {
                parse_array_keys(trimmed, &mut current_keys);
            }
        }
    }

    result
}

fn parse_array_keys(text: &str, out: &mut Vec<String>) {
    let mut current = String::new();
    let mut in_quote = false;

    for ch in text.chars() {
        match (in_quote, ch) {
            (false, '\'') => in_quote = true,
            (true, '\'') => {
                out.push(std::mem::take(&mut current));
                in_quote = false;
            }
            (true, _) => current.push(ch),
            (false, _) => {}
        }
    }
}

fn extract_sql_violation_summary_keys(sql: &str) -> BTreeSet<String> {
    let (_, after_start) = sql
        .split_once(ALLOWLIST_START_MARKER)
        .expect("allowlist start marker should exist");
    let (block, _) = after_start
        .split_once(ALLOWLIST_END_MARKER)
        .expect("allowlist end marker should exist");

    let mut keys = BTreeSet::new();
    let mut found_summary_section = false;

    for line in block.lines() {
        let trimmed = line.trim();
        if trimmed.contains("v_violation_summary_keys") {
            found_summary_section = true;
        }
        if found_summary_section {
            // 行末の ]; を探して抜ける
            if trimmed.ends_with("];") || trimmed.ends_with("]") {
                found_summary_section = false;
            }
            // 引用符で囲まれたキーを抽出
            let mut current = String::new();
            let mut in_quote = false;
            for ch in trimmed.chars() {
                match (in_quote, ch) {
                    (false, '\'') => in_quote = true,
                    (true, '\'') => {
                        keys.insert(std::mem::take(&mut current));
                        in_quote = false;
                    }
                    (true, _) => current.push(ch),
                    (false, _) => {}
                }
            }
        }
    }

    keys
}

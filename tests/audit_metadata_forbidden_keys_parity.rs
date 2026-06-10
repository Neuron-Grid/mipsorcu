use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use mipsorcu::{
    AuditAction, AuditMetadata, AuditResult, FORBIDDEN_AUDIT_METADATA_KEYS,
    FORBIDDEN_LEDGER_PAYLOAD_KEYS, INCIDENT_NOTIFICATION_CATEGORY_ALLOWLIST,
    INCIDENT_SEVERITY_ALLOWLIST, INCIDENT_TYPE_ALLOWLIST,
    INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST, NOTIFICATION_RESULT_ALLOWLIST,
    NOTIFIER_KIND_ALLOWLIST, required_metadata_keys,
};

// このガードは固定パスを参照しない。SQL の「実効最新定義」を、マーカー
// （-- *_ALLOWLIST_START/END）を含む辞書順最後の migration として自動発見する
// （latest_migration_containing）。1 世代前の migration を読む陳腐化を構造的に防ぐため、
// 最新定義がマーカーを保持していることをメタテスト（*_definition_carries_*_markers）で
// 強制する。再定義する migration は完全再掲＋マーカー保持が不変条件（docs/coding-rules.md §14）。
//
// マーカーは「行全体（前後空白除去後の完全一致）がマーカー文字列である行」だけを採用する
// （has_marker_line / marker_block）。ヘッダや `comment on` の散文中に綴られた
// "-- ACTION_ALLOWLIST_START/END" のような言及は行全体一致でないため検出・抽出窓に
// 影響しない。これにより 1 ファイルへ複数ガードを再掲する consolidation（1440）でも、
// 散文が抽出窓を広げて誤抽出する事故（bug-05 同類の silent drift 見逃し）を構造的に防ぐ。
const FORBIDDEN_START_MARKER: &str = "-- FORBIDDEN_AUDIT_METADATA_KEYS_START";
const FORBIDDEN_END_MARKER: &str = "-- FORBIDDEN_AUDIT_METADATA_KEYS_END";
const LEDGER_FORBIDDEN_START_MARKER: &str = "-- FORBIDDEN_LEDGER_PAYLOAD_KEYS_START";
const LEDGER_FORBIDDEN_END_MARKER: &str = "-- FORBIDDEN_LEDGER_PAYLOAD_KEYS_END";
const ALLOWLIST_START_MARKER: &str = "-- ACTION_ALLOWLIST_START";
const ALLOWLIST_END_MARKER: &str = "-- ACTION_ALLOWLIST_END";
const INCIDENT_TYPE_START_MARKER: &str = "-- INCIDENT_TYPE_ALLOWLIST_START";
const INCIDENT_TYPE_END_MARKER: &str = "-- INCIDENT_TYPE_ALLOWLIST_END";
const INCIDENT_CATEGORY_START_MARKER: &str = "-- INCIDENT_CATEGORY_ALLOWLIST_START";
const INCIDENT_CATEGORY_END_MARKER: &str = "-- INCIDENT_CATEGORY_ALLOWLIST_END";
const NOTIFIER_KIND_START_MARKER: &str = "-- NOTIFIER_KIND_ALLOWLIST_START";
const NOTIFIER_KIND_END_MARKER: &str = "-- NOTIFIER_KIND_ALLOWLIST_END";
const SEVERITY_START_MARKER: &str = "-- SEVERITY_ALLOWLIST_START";
const SEVERITY_END_MARKER: &str = "-- SEVERITY_ALLOWLIST_END";
const NOTIFICATION_RESULT_START_MARKER: &str = "-- NOTIFICATION_RESULT_ALLOWLIST_START";
const NOTIFICATION_RESULT_END_MARKER: &str = "-- NOTIFICATION_RESULT_ALLOWLIST_END";
const REQUIRED_KEY_START_MARKER: &str = "-- REQUIRED_KEY_START";
const REQUIRED_KEY_END_MARKER: &str = "-- REQUIRED_KEY_END";

// SQL 側ガード関数名（実効最新定義の自動発見・メタテスト用）。
const UNKNOWN_KEY_FN: &str = "audit_metadata_has_unknown_key_for_action";
const FORBIDDEN_KEY_FN: &str = "audit_metadata_has_forbidden_key";
const INVALID_VALUE_FN: &str = "audit_metadata_has_invalid_value_for_action";
const INCIDENT_TYPE_FN: &str = "incident_type_allowed";
const SEVERITY_FN: &str = "incident_severity_allowed";
const NOTIFICATION_RESULT_FN: &str = "incident_notification_result_allowed";
const REQUIRED_KEY_FN: &str = "audit_metadata_has_missing_required_key_for_action";

#[test]
fn forbidden_keys_parity_between_rust_and_sql() {
    let migration = read_latest_migration_containing(FORBIDDEN_START_MARKER);
    let sql_keys = extract_sql_forbidden_keys(&migration);
    let rust_keys = FORBIDDEN_AUDIT_METADATA_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(sql_keys, rust_keys);
}

#[test]
fn forbidden_keys_parity_between_audit_metadata_and_ledger_payload() {
    let migration = read_latest_migration_containing(FORBIDDEN_START_MARKER);
    let sql_audit_keys = extract_sql_forbidden_keys(&migration);
    let sql_ledger_keys = extract_sql_keys_between(
        &migration,
        LEDGER_FORBIDDEN_START_MARKER,
        LEDGER_FORBIDDEN_END_MARKER,
    );
    let rust_audit_keys = FORBIDDEN_AUDIT_METADATA_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect::<BTreeSet<_>>();
    let rust_ledger_keys = FORBIDDEN_LEDGER_PAYLOAD_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(rust_audit_keys, sql_audit_keys);
    assert_eq!(rust_ledger_keys, sql_ledger_keys);
    assert_eq!(rust_audit_keys, rust_ledger_keys);
}

#[test]
fn allowlist_parity_between_rust_and_sql() {
    // SQL 実効最新の allowlist 定義（ACTION_ALLOWLIST マーカーを持つ辞書順最後の migration）を
    // 自動発見する。新 action / キーを追加する場合は最新 migration の ACTION_ALLOWLIST_START/END 内と
    // rust_allowlist_for_action_result（このファイル内）の両方を更新すること。
    let migration = read_latest_migration_containing(ALLOWLIST_START_MARKER);
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
    // 実効最新の allowlist 定義は violation_summary キーも保持する。
    let migration = read_latest_migration_containing(ALLOWLIST_START_MARKER);
    let sql_summary = extract_sql_violation_summary_keys(&migration);
    let rust_summary = INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST
        .iter()
        .map(|k| (*k).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(rust_summary, sql_summary);
}

// ─── Meta-guards: 実効最新定義がマーカーを保持しているか（陳腐化再発防止の核心） ───

#[test]
fn latest_unknown_key_definition_carries_allowlist_markers() {
    // 「ガード関数 audit_metadata_has_unknown_key_for_action の最新定義を持つ migration」が
    // 「ACTION_ALLOWLIST_START を持つ migration」と一致することを保証する。将来 delegating 再定義を
    // マーカー無しで足すと、両者がずれて必ず mismatch で落ちる（= 陳腐化を検知できる）。
    assert_eq!(
        latest_migration_defining_function(UNKNOWN_KEY_FN),
        latest_migration_containing(ALLOWLIST_START_MARKER),
        "audit_metadata_has_unknown_key_for_action の最新定義がマーカー付き完全 allowlist を保持していない。\
         再定義する migration は ACTION_ALLOWLIST_START/END 込みで全 action を完全再掲すること（docs/coding-rules.md §14）。"
    );
}

#[test]
fn latest_forbidden_key_definition_carries_forbidden_markers() {
    assert_eq!(
        latest_migration_defining_function(FORBIDDEN_KEY_FN),
        latest_migration_containing(FORBIDDEN_START_MARKER),
        "audit_metadata_has_forbidden_key の最新定義が FORBIDDEN_AUDIT_METADATA_KEYS マーカーを保持していない。"
    );
}

#[test]
fn latest_value_guard_definitions_carry_value_markers() {
    assert_eq!(
        latest_migration_defining_function(INCIDENT_TYPE_FN),
        latest_migration_containing(INCIDENT_TYPE_START_MARKER),
        "incident_type_allowed の最新定義が INCIDENT_TYPE_ALLOWLIST マーカーを保持していない。"
    );
    assert_eq!(
        latest_migration_defining_function(INVALID_VALUE_FN),
        latest_migration_containing(INCIDENT_CATEGORY_START_MARKER),
        "audit_metadata_has_invalid_value_for_action の最新定義が INCIDENT_CATEGORY_ALLOWLIST マーカーを保持していない。"
    );
    assert_eq!(
        latest_migration_defining_function(INVALID_VALUE_FN),
        latest_migration_containing(NOTIFIER_KIND_START_MARKER),
        "audit_metadata_has_invalid_value_for_action の最新定義が NOTIFIER_KIND_ALLOWLIST マーカーを保持していない。"
    );
    assert_eq!(
        latest_migration_defining_function(SEVERITY_FN),
        latest_migration_containing(SEVERITY_START_MARKER),
        "incident_severity_allowed の最新定義が SEVERITY_ALLOWLIST マーカーを保持していない。\
         再定義する migration は SEVERITY_ALLOWLIST_START/END 込みで全値を完全再掲すること（docs/coding-rules.md §14.3）。"
    );
    assert_eq!(
        latest_migration_defining_function(NOTIFICATION_RESULT_FN),
        latest_migration_containing(NOTIFICATION_RESULT_START_MARKER),
        "incident_notification_result_allowed の最新定義が NOTIFICATION_RESULT_ALLOWLIST マーカーを保持していない。\
         再定義する migration は NOTIFICATION_RESULT_ALLOWLIST_START/END 込みで全値を完全再掲すること（docs/coding-rules.md §14.3）。"
    );
}

// ─── 値 enum parity: Rust const ↔ SQL リテラルリスト（追加-A の解消） ───

#[test]
fn incident_type_allowlist_parity_between_rust_and_sql() {
    let migration = read_latest_migration_containing(INCIDENT_TYPE_START_MARKER);
    let sql = extract_sql_keys_between(
        &migration,
        INCIDENT_TYPE_START_MARKER,
        INCIDENT_TYPE_END_MARKER,
    );
    let rust = INCIDENT_TYPE_ALLOWLIST
        .iter()
        .map(|k| (*k).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(rust, sql);
}

#[test]
fn incident_notification_category_allowlist_parity_between_rust_and_sql() {
    let migration = read_latest_migration_containing(INCIDENT_CATEGORY_START_MARKER);
    let sql = extract_sql_keys_between(
        &migration,
        INCIDENT_CATEGORY_START_MARKER,
        INCIDENT_CATEGORY_END_MARKER,
    );
    let rust = INCIDENT_NOTIFICATION_CATEGORY_ALLOWLIST
        .iter()
        .map(|k| (*k).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(rust, sql);
}

#[test]
fn notifier_kind_allowlist_parity_between_rust_and_sql() {
    let migration = read_latest_migration_containing(NOTIFIER_KIND_START_MARKER);
    let sql = extract_sql_keys_between(
        &migration,
        NOTIFIER_KIND_START_MARKER,
        NOTIFIER_KIND_END_MARKER,
    );
    let rust = NOTIFIER_KIND_ALLOWLIST
        .iter()
        .map(|k| (*k).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(rust, sql);
}

#[test]
fn incident_severity_allowlist_parity_between_rust_and_sql() {
    let migration = read_latest_migration_containing(SEVERITY_START_MARKER);
    let sql = extract_sql_keys_between(&migration, SEVERITY_START_MARKER, SEVERITY_END_MARKER);
    let rust = INCIDENT_SEVERITY_ALLOWLIST
        .iter()
        .map(|k| (*k).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(rust, sql);
}

#[test]
fn notification_result_allowlist_parity_between_rust_and_sql() {
    let migration = read_latest_migration_containing(NOTIFICATION_RESULT_START_MARKER);
    let sql = extract_sql_keys_between(
        &migration,
        NOTIFICATION_RESULT_START_MARKER,
        NOTIFICATION_RESULT_END_MARKER,
    );
    let rust = NOTIFICATION_RESULT_ALLOWLIST
        .iter()
        .map(|k| (*k).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(rust, sql);
}

// ─── 必須キー parity: Rust required_metadata_keys ↔ SQL 実効定義（bug-05 二次ギャップの解消） ───

#[test]
fn required_keys_parity_between_rust_and_sql() {
    // SQL 実効最新の必須キー定義（-- REQUIRED_KEY マーカーを持つ辞書順最後の migration）を
    // 自動発見し、action+result ごとの base 必須キー集合を抽出する。Rust 真値は
    // mipsorcu::required_metadata_keys（いずれも source_event_at を含まない base 集合）。
    // source_event_at は SQL 側ではマーカー外の p_require_source_event_at 分岐で付与されるため
    // 抽出対象に入らず、両者とも base 同士で比較する。
    let migration = read_latest_migration_containing(REQUIRED_KEY_START_MARKER);
    let sql_required = extract_sql_required_keys(&migration);

    for action in all_actions() {
        for result in [AuditResult::Success, AuditResult::Failure] {
            let rust_required = required_metadata_keys(action, result)
                .iter()
                .map(|key| (*key).to_owned())
                .collect::<BTreeSet<_>>();

            let sql_key = format!("{}:{}", action.as_str(), result.as_str());
            let sql_allowed = sql_required.get(&sql_key).unwrap_or_else(|| {
                panic!("SQL required-key definition should contain entry for {sql_key}")
            });

            assert_eq!(
                rust_required, *sql_allowed,
                "Rust/SQL required-key mismatch for {sql_key} (action={action:?}, result={result:?})"
            );
        }
    }
}

#[test]
fn latest_required_key_definition_carries_required_markers() {
    // 「ガード関数 audit_metadata_has_missing_required_key_for_action の最新定義を持つ migration」が
    // 「REQUIRED_KEY_START を持つ migration」と一致することを保証する。将来 delegating 再定義を
    // マーカー無しで足すと、両者がずれて必ず mismatch で落ちる（= 陳腐化を検知できる）。
    assert_eq!(
        latest_migration_defining_function(REQUIRED_KEY_FN),
        latest_migration_containing(REQUIRED_KEY_START_MARKER),
        "audit_metadata_has_missing_required_key_for_action の最新定義がマーカー付き完全必須キー集合を保持していない。\
         再定義する migration は REQUIRED_KEY_START/END 込みで全 action を完全再掲すること（docs/coding-rules.md §14）。"
    );
}

// ─── 再発防止: マーカーは独立行のみ採用し、散文中の綴りで抽出窓を汚染しない ───

#[test]
fn has_marker_line_requires_standalone_line() {
    // 散文中の "-- ACTION_ALLOWLIST_START/END" は行全体一致でないため採用しない。
    assert!(!has_marker_line(
        "--   restates allowlist with -- ACTION_ALLOWLIST_START/END markers preserved\n",
        ALLOWLIST_START_MARKER
    ));
    // インデント付きでも、trim 後に完全一致する独立行は採用する。
    assert!(has_marker_line(
        "    -- ACTION_ALLOWLIST_START\n",
        ALLOWLIST_START_MARKER
    ));
}

#[test]
fn marker_block_ignores_prose_mentions() {
    // bug-05 consolidation 由来の脆さ（コメント散文中のマーカー綴りが split_once の境界に
    // 採られて抽出窓を広げ、誤抽出＝silent drift 見逃しを招く）に対する構造的ガード。
    // ヘッダと comment on が両マーカーを散文で綴っても、独立行マーカーに挟まれた領域だけを返す。
    let sql = "\
-- header prose mentions -- ACTION_ALLOWLIST_START/END markers preserved
create or replace function public.f(p_action text) returns boolean as $$
begin
    -- ACTION_ALLOWLIST_START
    case p_action
        when 'a' then v_allowed_keys := array['real_key'];
    end case;
    -- ACTION_ALLOWLIST_END
    return false;
end;
$$;
comment on function public.f(text) is 'restates allowlist with -- ACTION_ALLOWLIST_START/END markers';
";
    let block = marker_block(sql, ALLOWLIST_START_MARKER, ALLOWLIST_END_MARKER);
    assert!(
        block.contains("real_key"),
        "実マーカー間の本体を抽出すること"
    );
    assert!(
        !block.contains("header prose"),
        "ヘッダ散文を抽出窓に含めないこと"
    );
    assert!(
        !block.contains("comment on"),
        "comment on 散文を抽出窓に含めないこと"
    );
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
        AuditAction::IncidentNotificationSent,
        AuditAction::IncidentNotificationFailed,
        AuditAction::IncidentNotificationSuppressed,
        AuditAction::SecretAliasCreate,
        AuditAction::SecretAliasUpdate,
        AuditAction::SecretAliasDelete,
        AuditAction::SecretAliasList,
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
        AuditAction::KeyRotationEnvelopeMigrated => {
            vec![
                "batch_size",
                "success_count",
                "failure_count",
                "source_event_at",
            ]
        }
        AuditAction::KeyRotationEnvelopeFailed => {
            vec![
                "secret_version_id",
                "version",
                "error_code",
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
        // 月次 digest 生成（成功・失敗両方を記録、allowlist は result 共通の union）
        AuditAction::MonthlyDigestGenerate => {
            vec![
                "digest_hash",
                "end_sequence_no",
                "entry_count",
                "error_code",
                "signature_key_version",
                "start_sequence_no",
                "target_year_month",
                "source_event_at",
            ]
        }
        // 月次 digest 検証（成功・失敗両方を記録、allowlist は result 共通）
        AuditAction::MonthlyDigestVerify => {
            vec![
                "error_code",
                "target_year_month",
                "verify_result",
                "source_event_at",
            ]
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
        AuditAction::SiemEventForwarded => {
            vec!["exporter_kind", "batch_size", "source_event_at"]
        }
        AuditAction::SiemEventFailed => {
            vec![
                "exporter_kind",
                "error_code",
                "buffered",
                "batch_size",
                "source_event_at",
            ]
        }
        AuditAction::SiemBufferFlushed => {
            vec!["flushed_count", "buffer_remaining_bytes", "source_event_at"]
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
        AuditAction::SchedulerJobStarted => {
            vec!["job_name", "scheduled_at", "source_event_at", "started_at"]
        }
        AuditAction::SchedulerJobCompleted => {
            vec![
                "completed_at",
                "duration_ms",
                "job_name",
                "result_summary",
                "source_event_at",
                "started_at",
            ]
        }
        AuditAction::SchedulerJobFailed => {
            vec![
                "error_code",
                "failed_at",
                "job_name",
                "retry_count",
                "source_event_at",
                "started_at",
            ]
        }
        AuditAction::SchedulerJobSkipped => {
            vec!["job_name", "reason", "skipped_at", "source_event_at"]
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
        AuditAction::IncidentNotificationSent => {
            vec![
                "category",
                "duration_ms",
                "incident_id",
                "notifier_kind",
                "source_event_at",
            ]
        }
        AuditAction::IncidentNotificationFailed => {
            vec![
                "category",
                "error_code",
                "incident_id",
                "notifier_kind",
                "retry_count",
                "source_event_at",
            ]
        }
        AuditAction::IncidentNotificationSuppressed => {
            vec![
                "category",
                "incident_id",
                "reason",
                "source_event_at",
                "suppressed_count",
                "window_remaining_sec",
            ]
        }
        AuditAction::SecretAliasCreate => {
            vec![
                "alias_fingerprint",
                "alias_fingerprint_key_version",
                "alias_fingerprint_schema_version",
                "error_code",
                "source_event_at",
            ]
        }
        AuditAction::SecretAliasUpdate => {
            vec![
                "old_alias_fingerprint",
                "new_alias_fingerprint",
                "alias_fingerprint_key_version",
                "alias_fingerprint_schema_version",
                "error_code",
                "source_event_at",
            ]
        }
        AuditAction::SecretAliasDelete => {
            vec![
                "alias_fingerprint",
                "alias_fingerprint_key_version",
                "alias_fingerprint_schema_version",
                "error_code",
                "source_event_at",
            ]
        }
        AuditAction::SecretAliasList => {
            vec!["error_code", "result_count", "source_event_at"]
        }
        AuditAction::AuditUiRead => {
            vec![
                "endpoint",
                "method",
                "resource",
                "result_count",
                "period_start",
                "period_end",
                "start_sequence_no",
                "end_sequence_no",
                "target_year_month",
                "error_code",
                "source_event_at",
            ]
        }
    };
    keys.sort();
    keys.into_iter().map(|s| s.to_owned()).collect()
}

fn migration_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(Path::new("supabase/migrations"))
        .expect("supabase/migrations should be readable")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("sql"))
        .collect();
    // 4 桁ゼロパディング連番のため、辞書順 == 適用順（実効最新 = 辞書順最後）。
    paths.sort();
    paths
}

/// `content` 内に「行全体（前後空白除去後）が `marker` に完全一致する行」が 1 つでもあるか。
/// 散文中の同綴り（コメントの "-- FOO_START/END" 等）は行全体一致でないため採用しない。
fn has_marker_line(content: &str, marker: &str) -> bool {
    content.lines().any(|line| line.trim() == marker)
}

/// `marker` を独立行として持つ辞書順最後の migration（= 実効最新の定義を持つファイル）を返す。
fn latest_migration_containing(marker: &str) -> PathBuf {
    migration_paths()
        .into_iter()
        .rfind(|path| {
            fs::read_to_string(path)
                .map(|content| has_marker_line(&content, marker))
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no migration has a standalone marker line {marker}"))
}

/// `start_marker` / `end_marker` が「行全体」になっている行に挟まれた領域を返す。
/// 散文中の同綴りは行全体一致でないため境界に採用されない。1 ファイルに複数ガードを
/// 再掲しても（consolidation）、ヘッダ／`comment on` の散文が抽出窓を広げて誤抽出する事故を
/// 構造的に防ぐ。返値はマーカー行自身を含まない、間の各行を改行付きで連結した文字列。
fn marker_block(sql: &str, start_marker: &str, end_marker: &str) -> String {
    let mut block = String::new();
    let mut in_block = false;

    for line in sql.lines() {
        let trimmed = line.trim();
        if trimmed == start_marker {
            assert!(!in_block, "duplicate start marker line {start_marker}");
            in_block = true;
            continue;
        }
        if trimmed == end_marker {
            assert!(
                in_block,
                "end marker line {end_marker} appears before start marker line {start_marker}"
            );
            return block;
        }
        if in_block {
            block.push_str(line);
            block.push('\n');
        }
    }

    panic!("standalone marker block {start_marker}..{end_marker} not found in migration");
}

/// `create [or replace] function public.<fn_name>(` を含む辞書順最後の migration を返す。
/// `_before_NNNN` 委譲版（別名）・`alter ... rename`・`comment on` 行は定義として数えない。
fn latest_migration_defining_function(fn_name: &str) -> PathBuf {
    let needle = format!("function public.{fn_name}(");
    migration_paths()
        .into_iter()
        .rfind(|path| {
            fs::read_to_string(path)
                .map(|content| {
                    content
                        .lines()
                        .any(|line| line.contains("create") && line.contains(&needle))
                })
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no migration defines function {fn_name}"))
}

fn read_latest_migration_containing(needle: &str) -> String {
    let path = latest_migration_containing(needle);
    fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("migration {} should be readable", path.display()))
}

fn extract_sql_forbidden_keys(sql: &str) -> BTreeSet<String> {
    extract_sql_keys_between(sql, FORBIDDEN_START_MARKER, FORBIDDEN_END_MARKER)
}

fn extract_sql_keys_between(sql: &str, start_marker: &str, end_marker: &str) -> BTreeSet<String> {
    let key_block = marker_block(sql, start_marker, end_marker);

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
    let block = marker_block(sql, ALLOWLIST_START_MARKER, ALLOWLIST_END_MARKER);

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

/// `-- REQUIRED_KEY_START/END` 内の `case p_action` を解析し、`<action>:<result>` →
/// base 必須キー集合（`source_event_at` 抜き）の写像を返す。
///
/// - `when '<a>', '<b>' then` の複数 action をまとめて拾う。
/// - result 分岐（`if p_result = 'success' then ... else ... end if`）を持つ arm は
///   success / failure を別集合として登録する。分岐の無い arm は両 result に同じ集合を登録する。
/// - `v_summary_required_keys := array[...]`（integrity_check の violation_summary 必須キー）は
///   `v_required_keys :=` で始まらないため自然に無視される（本テストの対象は top-level 必須キー）。
/// - すべての必須キー配列は単一行（`...];` で完結）である前提。
fn extract_sql_required_keys(sql: &str) -> HashMap<String, BTreeSet<String>> {
    let block = marker_block(sql, REQUIRED_KEY_START_MARKER, REQUIRED_KEY_END_MARKER);

    let mut result: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut current_actions: Vec<String> = Vec::new();
    // None = arm が result で分岐しない（両 result に適用）。Some(r) = いま if p_result 分岐の r 側。
    let mut current_result: Option<&'static str> = None;

    for line in block.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("when ") {
            current_actions.clear();
            let parts: Vec<&str> = trimmed.split('\'').collect();
            for i in (1..parts.len()).step_by(2) {
                if !parts[i].is_empty() {
                    current_actions.push(parts[i].to_owned());
                }
            }
            current_result = None;
        } else if trimmed.starts_with("if p_result = '") {
            current_result = if trimmed.contains("'success'") {
                Some("success")
            } else {
                Some("failure")
            };
        } else if trimmed == "else" {
            // result 分岐内の else だけ反転する。case 末尾の `else return true;` は
            // 直前の `end if` で current_result が None に戻っているため反転しない。
            current_result = match current_result {
                Some("success") => Some("failure"),
                Some("failure") => Some("success"),
                other => other,
            };
        } else if trimmed.starts_with("end if") {
            current_result = None;
        } else if trimmed.contains("v_required_keys := array[") {
            let mut keys = Vec::new();
            parse_array_keys(trimmed, &mut keys);
            let set: BTreeSet<String> = keys.into_iter().collect();
            for action in &current_actions {
                match current_result {
                    Some(r) => {
                        result.insert(format!("{action}:{r}"), set.clone());
                    }
                    None => {
                        result.insert(format!("{action}:success"), set.clone());
                        result.insert(format!("{action}:failure"), set.clone());
                    }
                }
            }
        }
    }

    result
}

fn extract_sql_violation_summary_keys(sql: &str) -> BTreeSet<String> {
    let block = marker_block(sql, ALLOWLIST_START_MARKER, ALLOWLIST_END_MARKER);

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

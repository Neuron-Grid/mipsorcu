use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use mipsorcu::{
    AuditAction, AuditResult, FORBIDDEN_AUDIT_METADATA_KEYS, FORBIDDEN_LEDGER_PAYLOAD_KEYS,
    INCIDENT_NOTIFICATION_CATEGORY_ALLOWLIST, INCIDENT_SEVERITY_ALLOWLIST, INCIDENT_TYPE_ALLOWLIST,
    INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST, NOTIFICATION_RESULT_ALLOWLIST,
    NOTIFIER_KIND_ALLOWLIST, required_metadata_keys,
};

#[path = "support/sql_cutoff_parity/audit_metadata_expectations.rs"]
mod audit_metadata_expectations;
#[path = "support/sql_cutoff_parity/audit_metadata_runtime_tests.rs"]
mod audit_metadata_runtime_tests;
#[path = "support/sql_cutoff_parity/hard_gate_contract_tests.rs"]
mod hard_gate_contract_tests;
#[path = "support/sql_cutoff_parity/mod.rs"]
pub mod sql_cutoff_parity;

use audit_metadata_expectations::{all_actions, rust_allowlist_for_action_result};
use sql_cutoff_parity::definitions::latest_definition;
use sql_cutoff_parity::fixture::ThrowawayMigrationRoot;
use sql_cutoff_parity::markers::{
    LEGACY_MARKER_FAMILIES, MarkerFamily, has_standalone_marker, latest_effective_occurrence,
    marker_occurrences_in_migration,
};
use sql_cutoff_parity::migrations::{MigrationFile, read_migrations};
use sql_cutoff_parity::resolver::resolve_from_environment;

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
const LEDGER_FORBIDDEN_KEY_FN: &str = "ledger_payload_has_forbidden_key";
const INVALID_VALUE_FN: &str = "audit_metadata_has_invalid_value_for_action";
const INCIDENT_TYPE_FN: &str = "incident_type_allowed";
const SEVERITY_FN: &str = "incident_severity_allowed";
const NOTIFICATION_RESULT_FN: &str = "incident_notification_result_allowed";
const REQUIRED_KEY_FN: &str = "audit_metadata_has_missing_required_key_for_action";

#[test]
fn forbidden_keys_parity_between_rust_and_sql() {
    let context = candidate_assertion_context();
    let migration = read_latest_migration_containing(FORBIDDEN_START_MARKER);
    let sql_keys = extract_sql_forbidden_keys(&migration);
    let rust_keys = FORBIDDEN_AUDIT_METADATA_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        sql_keys, rust_keys,
        "forbidden-key parity drifted ({context})"
    );
}

#[test]
fn forbidden_keys_parity_between_audit_metadata_and_ledger_payload() {
    let context = candidate_assertion_context();
    let audit_migration = read_latest_migration_containing(FORBIDDEN_START_MARKER);
    let ledger_migration = read_latest_migration_containing(LEDGER_FORBIDDEN_START_MARKER);
    let sql_audit_keys = extract_sql_forbidden_keys(&audit_migration);
    let sql_ledger_keys = extract_sql_keys_between(
        &ledger_migration,
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

    assert_eq!(
        rust_audit_keys, sql_audit_keys,
        "audit forbidden-key parity drifted ({context})"
    );
    assert_eq!(
        rust_ledger_keys, sql_ledger_keys,
        "ledger forbidden-key parity drifted ({context})"
    );
    assert_eq!(
        rust_audit_keys, rust_ledger_keys,
        "Rust audit/ledger forbidden-key sets drifted ({context})"
    );
}

#[test]
fn allowlist_parity_between_rust_and_sql() {
    let context = candidate_assertion_context();
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
                "Rust/SQL allowlist mismatch for {sql_key} (action={action:?}, result={result:?}; {context})"
            );
        }
    }
}

#[test]
fn integrity_check_violation_summary_allowlist_parity() {
    let context = candidate_assertion_context();
    // 実効最新の allowlist 定義は violation_summary キーも保持する。
    let migration = read_latest_migration_containing(ALLOWLIST_START_MARKER);
    let sql_summary = extract_sql_violation_summary_keys(&migration);
    let rust_summary = INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST
        .iter()
        .map(|k| (*k).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(
        rust_summary, sql_summary,
        "integrity summary allowlist parity drifted ({context})"
    );
}

// ─── Meta-guards: 実効最新定義がマーカーを保持しているか（陳腐化再発防止の核心） ───

#[test]
fn latest_unknown_key_definition_carries_allowlist_markers() {
    let context = candidate_assertion_context();
    // 「ガード関数 audit_metadata_has_unknown_key_for_action の最新定義を持つ migration」が
    // 「ACTION_ALLOWLIST_START を持つ migration」と一致することを保証する。将来 delegating 再定義を
    // マーカー無しで足すと、両者がずれて必ず mismatch で落ちる（= 陳腐化を検知できる）。
    assert_eq!(
        latest_migration_defining_function(UNKNOWN_KEY_FN),
        latest_migration_containing(ALLOWLIST_START_MARKER),
        "audit_metadata_has_unknown_key_for_action の最新定義がマーカー付き完全 allowlist を保持していない。\
         再定義する migration は ACTION_ALLOWLIST_START/END 込みで全 action を完全再掲すること（docs/coding-rules.md §14）。\
         candidate context: {context}"
    );
}

#[test]
fn latest_forbidden_key_definition_carries_forbidden_markers() {
    let context = candidate_assertion_context();
    assert_eq!(
        latest_migration_defining_function(FORBIDDEN_KEY_FN),
        latest_migration_containing(FORBIDDEN_START_MARKER),
        "audit_metadata_has_forbidden_key の最新定義が FORBIDDEN_AUDIT_METADATA_KEYS マーカーを保持していない。candidate context: {context}"
    );
}

#[test]
fn latest_ledger_forbidden_key_definition_carries_ledger_markers() {
    let resolved = resolve_from_environment(Path::new(env!("CARGO_MANIFEST_DIR")), None, None)
        .unwrap_or_else(|error| panic!("candidate migration resolution failed: {error}"));
    let context = resolved.assertion_context();
    assert_marker_owner_matches(
        resolved.root(),
        LEDGER_FORBIDDEN_KEY_FN,
        LEDGER_FORBIDDEN_START_MARKER,
    )
    .unwrap_or_else(|error| panic!("{error}; candidate context: {context}"));
}

#[test]
fn ledger_guard_redefinition_without_marker_is_rejected() {
    let fixture = ThrowawayMigrationRoot::new("ledger-marker-mutation")
        .unwrap_or_else(|error| panic!("ledger mutation fixture must be creatable: {error}"));
    fixture
        .write_migration(
            "0100_guard_with_marker.sql",
            "\
create or replace function public.ledger_payload_has_forbidden_key(p_payload jsonb)\n\
returns boolean language sql as $$ select false $$;\n\
-- FORBIDDEN_LEDGER_PAYLOAD_KEYS_START\n\
select 'fixture_value';\n\
-- FORBIDDEN_LEDGER_PAYLOAD_KEYS_END\n",
        )
        .unwrap_or_else(|error| panic!("ledger marker fixture must be writable: {error}"));
    fixture
        .write_migration(
            "0200_guard_without_marker.sql",
            "\
create or replace function public.ledger_payload_has_forbidden_key(p_payload jsonb)\n\
returns boolean language sql as $$ select true $$;\n",
        )
        .unwrap_or_else(|error| panic!("ledger mutation fixture must be writable: {error}"));

    let result = assert_marker_owner_matches(
        fixture.path(),
        LEDGER_FORBIDDEN_KEY_FN,
        LEDGER_FORBIDDEN_START_MARKER,
    );

    assert!(
        result.is_err(),
        "a later ledger guard definition without a moved marker must make the hard gate red"
    );
    fixture
        .close()
        .unwrap_or_else(|error| panic!("ledger mutation fixture cleanup must succeed: {error}"));
}

#[test]
fn latest_value_guard_definitions_carry_value_markers() {
    let context = candidate_assertion_context();
    assert_eq!(
        latest_migration_defining_function(INCIDENT_TYPE_FN),
        latest_migration_containing(INCIDENT_TYPE_START_MARKER),
        "incident_type_allowed の最新定義が INCIDENT_TYPE_ALLOWLIST マーカーを保持していない。candidate context: {context}"
    );
    assert_eq!(
        latest_migration_defining_function(INVALID_VALUE_FN),
        latest_migration_containing(INCIDENT_CATEGORY_START_MARKER),
        "audit_metadata_has_invalid_value_for_action の最新定義が INCIDENT_CATEGORY_ALLOWLIST マーカーを保持していない。candidate context: {context}"
    );
    assert_eq!(
        latest_migration_defining_function(INVALID_VALUE_FN),
        latest_migration_containing(NOTIFIER_KIND_START_MARKER),
        "audit_metadata_has_invalid_value_for_action の最新定義が NOTIFIER_KIND_ALLOWLIST マーカーを保持していない。candidate context: {context}"
    );
    assert_eq!(
        latest_migration_defining_function(SEVERITY_FN),
        latest_migration_containing(SEVERITY_START_MARKER),
        "incident_severity_allowed の最新定義が SEVERITY_ALLOWLIST マーカーを保持していない。\
         再定義する migration は SEVERITY_ALLOWLIST_START/END 込みで全値を完全再掲すること（docs/coding-rules.md §14.3）。\
         candidate context: {context}"
    );
    assert_eq!(
        latest_migration_defining_function(NOTIFICATION_RESULT_FN),
        latest_migration_containing(NOTIFICATION_RESULT_START_MARKER),
        "incident_notification_result_allowed の最新定義が NOTIFICATION_RESULT_ALLOWLIST マーカーを保持していない。\
         再定義する migration は NOTIFICATION_RESULT_ALLOWLIST_START/END 込みで全値を完全再掲すること（docs/coding-rules.md §14.3）。\
         candidate context: {context}"
    );
}

// ─── 値 enum parity: Rust const ↔ SQL リテラルリスト（追加-A の解消） ───

#[test]
fn incident_type_allowlist_parity_between_rust_and_sql() {
    let context = candidate_assertion_context();
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

    assert_eq!(rust, sql, "incident type parity drifted ({context})");
}

#[test]
fn incident_notification_category_allowlist_parity_between_rust_and_sql() {
    let context = candidate_assertion_context();
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

    assert_eq!(
        rust, sql,
        "incident notification category parity drifted ({context})"
    );
}

#[test]
fn notifier_kind_allowlist_parity_between_rust_and_sql() {
    let context = candidate_assertion_context();
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

    assert_eq!(rust, sql, "notifier-kind parity drifted ({context})");
}

#[test]
fn incident_severity_allowlist_parity_between_rust_and_sql() {
    let context = candidate_assertion_context();
    let migration = read_latest_migration_containing(SEVERITY_START_MARKER);
    let sql = extract_sql_keys_between(&migration, SEVERITY_START_MARKER, SEVERITY_END_MARKER);
    let rust = INCIDENT_SEVERITY_ALLOWLIST
        .iter()
        .map(|k| (*k).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(rust, sql, "incident severity parity drifted ({context})");
}

#[test]
fn notification_result_allowlist_parity_between_rust_and_sql() {
    let context = candidate_assertion_context();
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

    assert_eq!(rust, sql, "notification result parity drifted ({context})");
}

// ─── 必須キー parity: Rust required_metadata_keys ↔ SQL 実効定義（bug-05 二次ギャップの解消） ───

#[test]
fn required_keys_parity_between_rust_and_sql() {
    let context = candidate_assertion_context();
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
                "Rust/SQL required-key mismatch for {sql_key} (action={action:?}, result={result:?}; {context})"
            );
        }
    }
}

#[test]
fn latest_required_key_definition_carries_required_markers() {
    let context = candidate_assertion_context();
    // 「ガード関数 audit_metadata_has_missing_required_key_for_action の最新定義を持つ migration」が
    // 「REQUIRED_KEY_START を持つ migration」と一致することを保証する。将来 delegating 再定義を
    // マーカー無しで足すと、両者がずれて必ず mismatch で落ちる（= 陳腐化を検知できる）。
    assert_eq!(
        latest_migration_defining_function(REQUIRED_KEY_FN),
        latest_migration_containing(REQUIRED_KEY_START_MARKER),
        "audit_metadata_has_missing_required_key_for_action の最新定義がマーカー付き完全必須キー集合を保持していない。\
         再定義する migration は REQUIRED_KEY_START/END 込みで全 action を完全再掲すること（docs/coding-rules.md §14）。\
         candidate context: {context}"
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

/// `content` 内に「行全体（前後空白除去後）が `marker` に完全一致する行」が 1 つでもあるか。
/// 散文中の同綴り（コメントの "-- FOO_START/END" 等）は行全体一致でないため採用しない。
fn has_marker_line(content: &str, marker: &str) -> bool {
    has_standalone_marker(content, marker)
}

/// `marker` を独立行として持つ辞書順最後の migration（= 実効最新の定義を持つファイル）を返す。
fn latest_migration_containing(marker: &str) -> std::path::PathBuf {
    let (migrations, context) = resolved_candidate_migrations()
        .unwrap_or_else(|error| panic!("candidate migration resolution failed: {error}"));
    let family = marker_family(marker)
        .unwrap_or_else(|error| panic!("marker family lookup failed ({context}): {error}"));
    latest_effective_occurrence(&migrations, family)
        .unwrap_or_else(|error| panic!("effective marker lookup failed ({context}): {error}"))
        .path
}

/// `start_marker` / `end_marker` が「行全体」になっている行に挟まれた領域を返す。
/// 散文中の同綴りは行全体一致でないため境界に採用されない。1 ファイルに複数ガードを
/// 再掲しても（consolidation）、ヘッダ／`comment on` の散文が抽出窓を広げて誤抽出する事故を
/// 構造的に防ぐ。返値はマーカー行自身を含まない、間の各行を改行付きで連結した文字列。
fn marker_block(sql: &str, start_marker: &'static str, end_marker: &'static str) -> String {
    let family = MarkerFamily {
        name: "INLINE_TEST_MARKER",
        start: start_marker,
        end: end_marker,
    };
    let migration = MigrationFile {
        ordinal: 0,
        path: std::path::PathBuf::from("0000_inline_marker_fixture.sql"),
        basename: "0000_inline_marker_fixture.sql".to_owned(),
        timestamp: "0000".to_owned(),
        sql: sql.to_owned(),
    };
    let occurrences = marker_occurrences_in_migration(&migration, family)
        .unwrap_or_else(|error| panic!("inline marker parser rejected the fixture: {error}"));
    assert_eq!(
        occurrences.len(),
        1,
        "inline marker fixture must contain exactly one {start_marker}..{end_marker} block"
    );
    occurrences
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("validated inline marker occurrence must exist"))
        .payload
}

/// exact canonical identity で実効最新 CREATE FUNCTION carrier を返す。
fn latest_migration_defining_function(fn_name: &str) -> std::path::PathBuf {
    let (migrations, context) = resolved_candidate_migrations()
        .unwrap_or_else(|error| panic!("candidate migration resolution failed: {error}"));
    let identity = guard_identity(fn_name)
        .unwrap_or_else(|error| panic!("guard identity lookup failed ({context}): {error}"));
    latest_definition(&migrations, identity)
        .unwrap_or_else(|error| panic!("effective definition lookup failed ({context}): {error}"))
        .path
}

fn assert_marker_owner_matches(root: &Path, fn_name: &str, marker: &str) -> Result<(), String> {
    let migrations = read_migrations(root)?;
    let identity = guard_identity(fn_name)?;
    let family = marker_family(marker)?;
    let definition_path = latest_definition(&migrations, identity)?.path;
    let marker_path = latest_effective_occurrence(&migrations, family)?.path;
    if definition_path == marker_path {
        return Ok(());
    }

    Err(format!(
        "latest definition of {fn_name} is in {}, but latest standalone marker {marker} is in {}",
        definition_path.display(),
        marker_path.display()
    ))
}

fn read_latest_migration_containing(needle: &str) -> String {
    let (migrations, context) = resolved_candidate_migrations()
        .unwrap_or_else(|error| panic!("candidate migration resolution failed: {error}"));
    let family = marker_family(needle)
        .unwrap_or_else(|error| panic!("marker family lookup failed ({context}): {error}"));
    let occurrence = latest_effective_occurrence(&migrations, family)
        .unwrap_or_else(|error| panic!("effective marker lookup failed ({context}): {error}"));
    migrations
        .into_iter()
        .find(|migration| migration.path == occurrence.path)
        .unwrap_or_else(|| {
            panic!(
                "effective marker carrier {} is outside the resolved candidate ({context})",
                occurrence.path.display()
            )
        })
        .sql
}

fn resolved_candidate_migrations() -> Result<(Vec<MigrationFile>, String), String> {
    let resolved = resolve_from_environment(Path::new(env!("CARGO_MANIFEST_DIR")), None, None)
        .map_err(|error| error.to_string())?;
    let context = resolved.assertion_context().to_owned();
    let migrations = read_migrations(resolved.root())?;
    Ok((migrations, context))
}

fn candidate_assertion_context() -> String {
    resolve_from_environment(Path::new(env!("CARGO_MANIFEST_DIR")), None, None)
        .unwrap_or_else(|error| panic!("candidate migration resolution failed: {error}"))
        .assertion_context()
        .to_owned()
}

fn marker_family(start_marker: &str) -> Result<MarkerFamily, String> {
    LEGACY_MARKER_FAMILIES
        .into_iter()
        .find(|family| family.start == start_marker)
        .ok_or_else(|| format!("unknown parity marker start line {start_marker}"))
}

fn guard_identity(fn_name: &str) -> Result<&'static str, String> {
    match fn_name {
        UNKNOWN_KEY_FN => Ok("public.audit_metadata_has_unknown_key_for_action(text,text,jsonb)"),
        FORBIDDEN_KEY_FN => Ok("public.audit_metadata_has_forbidden_key(jsonb)"),
        LEDGER_FORBIDDEN_KEY_FN => Ok("public.ledger_payload_has_forbidden_key(jsonb)"),
        INVALID_VALUE_FN => {
            Ok("public.audit_metadata_has_invalid_value_for_action(text,text,jsonb)")
        }
        INCIDENT_TYPE_FN => Ok("public.incident_type_allowed(text)"),
        SEVERITY_FN => Ok("public.incident_severity_allowed(text)"),
        NOTIFICATION_RESULT_FN => Ok("public.incident_notification_result_allowed(text)"),
        REQUIRED_KEY_FN => {
            Ok("public.audit_metadata_has_missing_required_key_for_action(text,text,jsonb,boolean)")
        }
        _ => Err(format!("unknown parity guard function {fn_name}")),
    }
}

fn extract_sql_forbidden_keys(sql: &str) -> BTreeSet<String> {
    extract_sql_keys_between(sql, FORBIDDEN_START_MARKER, FORBIDDEN_END_MARKER)
}

fn extract_sql_keys_between(
    sql: &str,
    start_marker: &'static str,
    end_marker: &'static str,
) -> BTreeSet<String> {
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

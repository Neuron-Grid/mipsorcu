use std::path::Path;

#[path = "support/sql_cutoff_parity/mod.rs"]
pub mod sql_cutoff_parity;

use mipsorcu::audit::AuditTrigger;

use sql_cutoff_parity::fixture::ThrowawayMigrationRoot;
use sql_cutoff_parity::resolver::{SqlCutoffProfile, resolve_from_environment};
use sql_cutoff_parity::trigger_vocabulary::{
    arrow_operator_baseline_trigger_fixture_sql, block_commented_baseline_trigger_fixture_sql,
    commented_branch_header_baseline_trigger_fixture_sql,
    line_commented_baseline_trigger_fixture_sql, missing_then_baseline_trigger_fixture_sql,
    mutated_baseline_trigger_fixture_sql, nested_control_baseline_trigger_fixture_sql,
    not_equal_branch_header_baseline_trigger_fixture_sql,
    perform_expression_baseline_trigger_fixture_sql,
    post_branch_vocabulary_baseline_trigger_fixture_sql, rust_trigger_vocabulary,
    string_literal_only_baseline_trigger_fixture_sql, valid_baseline_trigger_fixture_sql,
    validate_trigger_vocabulary,
};

#[test]
fn selected_candidate_trigger_vocabulary_matches_rust() {
    let resolved = resolve_from_environment(Path::new(env!("CARGO_MANIFEST_DIR")), None, None)
        .unwrap_or_else(|error| panic!("SQL cutoff candidate must resolve: {error}"));
    validate_trigger_vocabulary(
        resolved.root(),
        resolved.profile(),
        resolved.assertion_context(),
        &rust_trigger_vocabulary(),
    )
    .unwrap_or_else(|error| panic!("selected trigger vocabulary parity must hold: {error}"));
}

#[test]
fn baseline_trigger_marker_contract_and_body_parity_are_accepted() {
    let fixture = ThrowawayMigrationRoot::new("trigger-valid")
        .unwrap_or_else(|error| panic!("valid trigger fixture should be creatable: {error}"));
    fixture
        .write_migration(
            "0100_v020_baseline.sql",
            &valid_baseline_trigger_fixture_sql(),
        )
        .unwrap_or_else(|error| panic!("valid trigger fixture should be writable: {error}"));

    validate_trigger_vocabulary(
        fixture.path(),
        SqlCutoffProfile::BaselineV02,
        "explicit valid baseline trigger fixture; candidate root only",
        &rust_trigger_vocabulary(),
    )
    .unwrap_or_else(|error| panic!("valid baseline trigger fixture should pass: {error}"));
    fixture
        .close()
        .unwrap_or_else(|error| panic!("valid trigger fixture cleanup must succeed: {error}"));
}

#[test]
fn baseline_body_literal_mutation_with_unchanged_marker_is_rejected() {
    let fixture = ThrowawayMigrationRoot::new("trigger-body-mutation")
        .unwrap_or_else(|error| panic!("trigger mutation fixture should be creatable: {error}"));
    fixture
        .write_migration(
            "0100_v020_baseline.sql",
            &mutated_baseline_trigger_fixture_sql(),
        )
        .unwrap_or_else(|error| panic!("trigger mutation fixture should be writable: {error}"));

    let result = validate_trigger_vocabulary(
        fixture.path(),
        SqlCutoffProfile::BaselineV02,
        "explicit mutated baseline trigger fixture; candidate root only",
        &rust_trigger_vocabulary(),
    );
    assert!(
        result.is_err(),
        "changing an owner body literal while leaving both marker payloads unchanged must make the hard gate red"
    );
    fixture
        .close()
        .unwrap_or_else(|error| panic!("trigger mutation fixture cleanup must succeed: {error}"));
}

#[test]
fn baseline_comment_only_predicates_with_unchanged_vocabulary_are_rejected() {
    for (fixture_name, sql) in [
        (
            "trigger-line-comment-only",
            line_commented_baseline_trigger_fixture_sql(),
        ),
        (
            "trigger-block-comment-only",
            block_commented_baseline_trigger_fixture_sql(),
        ),
    ] {
        let fixture = ThrowawayMigrationRoot::new(fixture_name)
            .unwrap_or_else(|error| panic!("comment-only fixture should be creatable: {error}"));
        fixture
            .write_migration("0100_v020_baseline.sql", &sql)
            .unwrap_or_else(|error| panic!("comment-only fixture should be writable: {error}"));

        let result = validate_trigger_vocabulary(
            fixture.path(),
            SqlCutoffProfile::BaselineV02,
            "explicit comment-only baseline fixture; candidate root only",
            &rust_trigger_vocabulary(),
        );
        assert!(
            result.is_err(),
            "{fixture_name}: vocabulary left only in a SQL comment must not satisfy the effective NOT IN predicate gate"
        );
        fixture.close().unwrap_or_else(|error| {
            panic!("{fixture_name}: comment-only fixture cleanup must succeed: {error}")
        });
    }
}

#[test]
fn baseline_string_literal_only_predicate_is_rejected() {
    let fixture = ThrowawayMigrationRoot::new("trigger-string-literal-only")
        .unwrap_or_else(|error| panic!("string-literal fixture should be creatable: {error}"));
    fixture
        .write_migration(
            "0100_v020_baseline.sql",
            &string_literal_only_baseline_trigger_fixture_sql(),
        )
        .unwrap_or_else(|error| panic!("string-literal fixture should be writable: {error}"));

    let result = validate_trigger_vocabulary(
        fixture.path(),
        SqlCutoffProfile::BaselineV02,
        "explicit string-literal-only baseline fixture; candidate root only",
        &rust_trigger_vocabulary(),
    );
    assert!(
        result.is_err(),
        "vocabulary left only in a SQL single-quoted literal must not satisfy the effective NOT IN predicate gate"
    );
    fixture
        .close()
        .unwrap_or_else(|error| panic!("string-literal fixture cleanup must succeed: {error}"));
}

#[test]
fn baseline_commented_trigger_branch_header_is_rejected() {
    let fixture = ThrowawayMigrationRoot::new("trigger-commented-branch-header")
        .unwrap_or_else(|error| panic!("commented-header fixture should be creatable: {error}"));
    fixture
        .write_migration(
            "0100_v020_baseline.sql",
            &commented_branch_header_baseline_trigger_fixture_sql(),
        )
        .unwrap_or_else(|error| panic!("commented-header fixture should be writable: {error}"));

    let result = validate_trigger_vocabulary(
        fixture.path(),
        SqlCutoffProfile::BaselineV02,
        "explicit commented-header baseline fixture; candidate root only",
        &rust_trigger_vocabulary(),
    );
    assert!(
        result.is_err(),
        "a trigger comparison left only in a SQL comment must not create an effective branch"
    );
    fixture
        .close()
        .unwrap_or_else(|error| panic!("commented-header fixture cleanup must succeed: {error}"));
}

#[test]
fn baseline_not_equal_trigger_branch_header_is_rejected() {
    let fixture = ThrowawayMigrationRoot::new("trigger-not-equal-branch-header")
        .unwrap_or_else(|error| panic!("not-equal-header fixture should be creatable: {error}"));
    fixture
        .write_migration(
            "0100_v020_baseline.sql",
            &not_equal_branch_header_baseline_trigger_fixture_sql(),
        )
        .unwrap_or_else(|error| panic!("not-equal-header fixture should be writable: {error}"));

    let result = validate_trigger_vocabulary(
        fixture.path(),
        SqlCutoffProfile::BaselineV02,
        "explicit not-equal-header baseline fixture; candidate root only",
        &rust_trigger_vocabulary(),
    );
    assert!(
        result.is_err(),
        "v_key != 'trigger' must not satisfy the exact trigger branch equality contract"
    );
    fixture
        .close()
        .unwrap_or_else(|error| panic!("not-equal-header fixture cleanup must succeed: {error}"));
}

#[test]
fn baseline_non_header_trigger_comparisons_are_rejected() {
    for (fixture_name, sql) in [
        (
            "trigger-perform-expression",
            perform_expression_baseline_trigger_fixture_sql(),
        ),
        (
            "trigger-missing-then",
            missing_then_baseline_trigger_fixture_sql(),
        ),
        (
            "trigger-arrow-operator",
            arrow_operator_baseline_trigger_fixture_sql(),
        ),
    ] {
        let fixture = ThrowawayMigrationRoot::new(fixture_name)
            .unwrap_or_else(|error| panic!("non-header fixture should be creatable: {error}"));
        fixture
            .write_migration("0100_v020_baseline.sql", &sql)
            .unwrap_or_else(|error| panic!("non-header fixture should be writable: {error}"));

        let result = validate_trigger_vocabulary(
            fixture.path(),
            SqlCutoffProfile::BaselineV02,
            "explicit non-header baseline fixture; candidate root only",
            &rust_trigger_vocabulary(),
        );
        assert!(
            result.is_err(),
            "{fixture_name}: only exact IF|ELSIF v_key = 'trigger' THEN may create a trigger branch"
        );
        fixture.close().unwrap_or_else(|error| {
            panic!("{fixture_name}: non-header fixture cleanup must succeed: {error}")
        });
    }
}

#[test]
fn baseline_vocabulary_after_matching_end_if_is_rejected() {
    let fixture = ThrowawayMigrationRoot::new("trigger-post-branch-vocabulary")
        .unwrap_or_else(|error| panic!("post-branch fixture should be creatable: {error}"));
    fixture
        .write_migration(
            "0100_v020_baseline.sql",
            &post_branch_vocabulary_baseline_trigger_fixture_sql(),
        )
        .unwrap_or_else(|error| panic!("post-branch fixture should be writable: {error}"));

    let result = validate_trigger_vocabulary(
        fixture.path(),
        SqlCutoffProfile::BaselineV02,
        "explicit post-branch baseline fixture; candidate root only",
        &rust_trigger_vocabulary(),
    );
    assert!(
        result.is_err(),
        "a NOT IN list after the target branch matching END IF must not satisfy body parity"
    );
    fixture
        .close()
        .unwrap_or_else(|error| panic!("post-branch fixture cleanup must succeed: {error}"));
}

#[test]
fn baseline_nested_if_and_quoted_fake_control_tokens_are_accepted() {
    let fixture = ThrowawayMigrationRoot::new("trigger-nested-control")
        .unwrap_or_else(|error| panic!("nested-control fixture should be creatable: {error}"));
    fixture
        .write_migration(
            "0100_v020_baseline.sql",
            &nested_control_baseline_trigger_fixture_sql(),
        )
        .unwrap_or_else(|error| panic!("nested-control fixture should be writable: {error}"));

    validate_trigger_vocabulary(
        fixture.path(),
        SqlCutoffProfile::BaselineV02,
        "explicit nested-control baseline fixture; candidate root only",
        &rust_trigger_vocabulary(),
    )
    .unwrap_or_else(|error| panic!("nested-control fixture should pass: {error}"));
    fixture
        .close()
        .unwrap_or_else(|error| panic!("nested-control fixture cleanup must succeed: {error}"));
}

#[test]
fn baseline_orphan_end_marker_is_rejected() {
    let fixture = ThrowawayMigrationRoot::new("trigger-orphan-end")
        .unwrap_or_else(|error| panic!("orphan marker fixture should be creatable: {error}"));
    let sql = format!(
        "-- TRIGGER_VOCABULARY_END\n{}",
        valid_baseline_trigger_fixture_sql()
    );
    fixture
        .write_migration("0100_v020_baseline.sql", &sql)
        .unwrap_or_else(|error| panic!("orphan marker fixture should be writable: {error}"));

    let result = validate_trigger_vocabulary(
        fixture.path(),
        SqlCutoffProfile::BaselineV02,
        "explicit orphan-marker baseline fixture; candidate root only",
        &rust_trigger_vocabulary(),
    );
    assert!(
        result.is_err(),
        "an orphan TRIGGER_VOCABULARY END marker must make the hard gate red"
    );
    fixture
        .close()
        .unwrap_or_else(|error| panic!("orphan marker fixture cleanup must succeed: {error}"));
}

#[test]
fn rust_audit_trigger_rejects_scheduled() {
    assert!(
        AuditTrigger::parse("scheduled").is_err(),
        "scheduled must be rejected to match SQL vocabulary"
    );
}

#[test]
fn rust_audit_trigger_rejects_unknown_values() {
    for unknown in ["scheduled", "manual", "auto", "cron", ""] {
        assert!(
            AuditTrigger::parse(unknown).is_err(),
            "unknown trigger '{unknown}' must be rejected"
        );
    }
}

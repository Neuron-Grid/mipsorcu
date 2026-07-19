use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt::Display;
use std::num::NonZeroU16;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::sql_cutoff_parity::{
    definitions::latest_definition,
    fixture::ThrowawayMigrationRoot,
    guards::{MARKER_GUARD_SPECS, validate_guard_inventory},
    markers::validate_profile_marker_inventory,
    migrations::read_migrations,
    pg_prove_local_socket_v1::{
        JOBS, LOCALHOST_TCP_HOST, LocalhostTcpEndpoint, PROFILE_ID, PgConnectionTarget,
        RunEndpoint, SUITE_TIMEOUT, SUITE_TIMEOUT_SECONDS, SUPPORT_RELATIVE_PATH, TEST_FILES,
        UnixSocketEndpoint, build_invocation, checked_counter_add, parse_pg_prove_result,
        select_run_endpoint, validate_suite,
    },
    resolver::{
        ResolverEnvironment, ResolverInputs, SqlCutoffProfile, resolve, resolve_from_environment,
    },
};

const EXPECTED_GUARD_IDENTITIES: [&str; 8] = [
    "public.audit_metadata_has_forbidden_key(jsonb)",
    "public.audit_metadata_has_invalid_value_for_action(text,text,jsonb)",
    "public.audit_metadata_has_missing_required_key_for_action(text,text,jsonb,boolean)",
    "public.audit_metadata_has_unknown_key_for_action(text,text,jsonb)",
    "public.incident_notification_result_allowed(text)",
    "public.incident_severity_allowed(text)",
    "public.incident_type_allowed(text)",
    "public.ledger_payload_has_forbidden_key(jsonb)",
];

#[test]
fn selected_candidate_has_the_profile_marker_and_guard_inventory() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let selected = must_ok(
        resolve_from_environment(manifest_dir, None, None),
        "current SQL cutoff candidate should resolve",
    );
    let context = selected.assertion_context().to_owned();
    let migrations = must_ok(
        read_migrations(selected.root()),
        "current SQL cutoff candidate should be readable",
    );
    let marker_inventory = must_ok(
        validate_profile_marker_inventory(&migrations, selected.profile()),
        &format!("current marker inventory should match; {context}"),
    );
    let guard_inventory = must_ok(
        validate_guard_inventory(&migrations, selected.profile()),
        &format!("current guard inventory should match; {context}"),
    );

    let expected_physical_count = match selected.profile() {
        SqlCutoffProfile::LegacyHead1460 => 9,
        SqlCutoffProfile::BaselineV02 => 11,
    };
    let expected_family_count = match selected.profile() {
        SqlCutoffProfile::LegacyHead1460 => 9,
        SqlCutoffProfile::BaselineV02 => 10,
    };
    assert_eq!(
        marker_inventory.len(),
        expected_family_count,
        "profile marker-family count drifted; {context}"
    );
    assert_eq!(
        marker_inventory
            .iter()
            .map(|entry| entry.occurrences)
            .sum::<usize>(),
        expected_physical_count,
        "profile physical marker count drifted; {context}"
    );
    assert_exact_guard_inventory(&guard_inventory, &context);
}

#[test]
fn synthetic_baseline_has_ten_families_eleven_blocks_and_eight_guards() {
    let fixture = must_ok(
        ThrowawayMigrationRoot::new("baseline-green"),
        "baseline fixture should be created",
    );
    must_write(&fixture, "1000_baseline.sql", &baseline_sql(None));
    let migrations = must_ok(
        read_migrations(fixture.path()),
        "baseline fixture should be readable",
    );

    let marker_inventory = must_ok(
        validate_profile_marker_inventory(&migrations, SqlCutoffProfile::BaselineV02),
        "synthetic baseline marker inventory should pass",
    );
    let guard_inventory = must_ok(
        validate_guard_inventory(&migrations, SqlCutoffProfile::BaselineV02),
        "synthetic baseline guard inventory should pass",
    );

    assert_eq!(marker_inventory.len(), 10);
    assert_eq!(
        marker_inventory
            .iter()
            .map(|entry| entry.occurrences)
            .sum::<usize>(),
        11
    );
    assert_exact_guard_inventory(&guard_inventory, "synthetic baseline");
    must_close(fixture);
}

#[test]
fn missing_marker_family_fails_closed() {
    let fixture = must_ok(
        ThrowawayMigrationRoot::new("marker-missing"),
        "missing-marker fixture should be created",
    );
    must_write(
        &fixture,
        "1000_baseline.sql",
        &baseline_sql(Some("FORBIDDEN_LEDGER_PAYLOAD_KEYS")),
    );
    let migrations = must_ok(
        read_migrations(fixture.path()),
        "missing-marker fixture should be readable",
    );

    assert!(
        validate_profile_marker_inventory(&migrations, SqlCutoffProfile::BaselineV02).is_err(),
        "a missing baseline marker family must be red"
    );
    assert!(
        validate_guard_inventory(&migrations, SqlCutoffProfile::BaselineV02).is_err(),
        "guard validation must not bypass missing marker presence"
    );
    must_close(fixture);
}

#[test]
fn later_guard_redefinition_without_marker_fails_closed() {
    let fixture = must_ok(
        ThrowawayMigrationRoot::new("guard-drift"),
        "guard-drift fixture should be created",
    );
    must_write(&fixture, "1000_baseline.sql", &baseline_sql(None));
    must_write(
        &fixture,
        "1010_guard_redefinition.sql",
        &guard_definition("audit_metadata_has_forbidden_key", "p_metadata jsonb"),
    );
    let migrations = must_ok(
        read_migrations(fixture.path()),
        "guard-drift fixture should be readable",
    );

    assert!(
        validate_profile_marker_inventory(&migrations, SqlCutoffProfile::BaselineV02).is_ok(),
        "the mutation must leave the marker inventory unchanged"
    );
    assert!(
        validate_guard_inventory(&migrations, SqlCutoffProfile::BaselineV02).is_err(),
        "a later owner redefinition without its marker must be red"
    );
    must_close(fixture);
}

#[test]
fn same_carrier_later_guard_redefinition_without_marker_fails_closed() {
    let fixture = must_ok(
        ThrowawayMigrationRoot::new("same-carrier-guard-drift"),
        "same-carrier guard-drift fixture should be created",
    );
    let mut sql = baseline_sql(None);
    sql.push_str(&guard_definition(
        "ledger_payload_has_forbidden_key",
        "p_payload jsonb",
    ));
    must_write(&fixture, "1000_baseline.sql", &sql);
    let migrations = must_ok(
        read_migrations(fixture.path()),
        "same-carrier guard-drift fixture should be readable",
    );

    assert!(
        validate_profile_marker_inventory(&migrations, SqlCutoffProfile::BaselineV02).is_ok(),
        "same-carrier redefinition must leave the marker inventory unchanged"
    );
    assert!(
        validate_guard_inventory(&migrations, SqlCutoffProfile::BaselineV02).is_err(),
        "a marker in an earlier same-file owner body must not bind to the latest markerless body"
    );
    must_close(fixture);
}

#[test]
fn later_guard_drop_with_marker_left_behind_fails_closed() {
    let fixture = must_ok(
        ThrowawayMigrationRoot::new("guard-drop"),
        "guard-drop fixture should be created",
    );
    must_write(&fixture, "1000_baseline.sql", &baseline_sql(None));
    must_write(
        &fixture,
        "1010_guard_drop.sql",
        "drop function public.audit_metadata_has_forbidden_key(jsonb);\n",
    );
    let migrations = must_ok(
        read_migrations(fixture.path()),
        "guard-drop fixture should be readable",
    );

    assert!(
        validate_profile_marker_inventory(&migrations, SqlCutoffProfile::BaselineV02).is_ok(),
        "the mutation must leave the marker inventory unchanged"
    );
    assert!(
        validate_guard_inventory(&migrations, SqlCutoffProfile::BaselineV02).is_err(),
        "a later DROP of a marker owner must make the hard gate red"
    );
    must_close(fixture);
}

#[test]
fn later_ledger_guard_rename_with_marker_left_behind_fails_closed() {
    let fixture = must_ok(
        ThrowawayMigrationRoot::new("ledger-guard-rename"),
        "ledger rename fixture should be created",
    );
    must_write(&fixture, "1000_baseline.sql", &baseline_sql(None));
    must_write(
        &fixture,
        "1010_guard_rename.sql",
        "alter function public.ledger_payload_has_forbidden_key(jsonb)\n    rename to ledger_payload_has_forbidden_key_renamed;\n",
    );
    let migrations = must_ok(
        read_migrations(fixture.path()),
        "ledger rename fixture should be readable",
    );

    assert!(
        validate_profile_marker_inventory(&migrations, SqlCutoffProfile::BaselineV02).is_ok(),
        "the rename mutation must leave the marker inventory unchanged"
    );
    assert!(
        validate_guard_inventory(&migrations, SqlCutoffProfile::BaselineV02).is_err(),
        "renaming a marker owner away must make the hard gate red"
    );
    let renamed = must_ok(
        latest_definition(
            &migrations,
            "public.ledger_payload_has_forbidden_key_renamed(jsonb)",
        ),
        "the renamed identity should retain the effective CREATE body",
    );
    assert_eq!(
        renamed.identity,
        "public.ledger_payload_has_forbidden_key_renamed(jsonb)"
    );
    assert!(renamed.body.contains("return false;"));
    must_close(fixture);
}

#[test]
fn definition_locator_tracks_rename_away_and_back_and_ignores_pseudo_sql() {
    let fixture = must_ok(
        ThrowawayMigrationRoot::new("definition-rename-chain"),
        "rename-chain fixture should be created",
    );
    must_write(
        &fixture,
        "1000_create.sql",
        &guard_definition("contract_guard", "p_payload jsonb"),
    );
    must_write(
        &fixture,
        "1010_pseudo.sql",
        "-- alter function public.contract_guard(jsonb) rename to ignored_comment;\ndo $body$\nbegin\n    perform 'alter function public.contract_guard(jsonb) rename to ignored_body';\nend\n$body$;\nselect 'alter function public.contract_guard(jsonb) rename to ignored_string';\n",
    );
    must_write(
        &fixture,
        "1020_rename_away.sql",
        "alter function public.contract_guard(jsonb) rename to contract_guard_snapshot;\n",
    );
    must_write(
        &fixture,
        "1030_rename_back.sql",
        "alter function public.contract_guard_snapshot(jsonb) rename to contract_guard;\n",
    );
    let migrations = must_ok(
        read_migrations(fixture.path()),
        "rename-chain fixture should be readable",
    );

    assert!(
        latest_definition(&migrations[..2], "public.contract_guard(jsonb)").is_ok(),
        "comment/string/dollar-body pseudo SQL must not rename the function"
    );
    assert!(
        latest_definition(&migrations[..3], "public.contract_guard(jsonb)").is_err(),
        "the source identity must be absent after rename-away"
    );
    let renamed = must_ok(
        latest_definition(&migrations[..3], "public.contract_guard_snapshot(jsonb)"),
        "the target identity should resolve after rename-away",
    );
    assert_eq!(renamed.migration_basename, "1000_create.sql");
    assert!(
        latest_definition(&migrations, "public.contract_guard_snapshot(jsonb)").is_err(),
        "the temporary target must be absent after rename-back"
    );
    assert!(
        latest_definition(&migrations, "public.contract_guard(jsonb)").is_ok(),
        "the original identity must resolve after rename-back"
    );
    must_close(fixture);
}

#[test]
fn definition_locator_rejects_ambiguous_or_malformed_rename_forms() {
    let mutations = [
        "alter function if exists public.contract_guard(jsonb) rename to renamed;\n",
        "alter function contract_guard(jsonb) rename to renamed;\n",
        "alter function public.contract_guard rename to renamed;\n",
        "alter function public.contract_guard(jsonb) rename renamed;\n",
        "alter function public.contract_guard(jsonb) rename to public.renamed;\n",
        "alter function public.missing_guard(jsonb) rename to renamed;\n",
    ];
    for (index, mutation) in mutations.into_iter().enumerate() {
        let fixture = must_ok(
            ThrowawayMigrationRoot::new(&format!("malformed-rename-{index}")),
            "malformed rename fixture should be created",
        );
        must_write(
            &fixture,
            "1000_create.sql",
            &guard_definition("contract_guard", "p_payload jsonb"),
        );
        must_write(&fixture, "1010_mutation.sql", mutation);
        let migrations = must_ok(
            read_migrations(fixture.path()),
            "malformed rename fixture should be readable",
        );
        assert!(
            latest_definition(&migrations, "public.contract_guard(jsonb)").is_err(),
            "rename mutation {index} must fail closed: {mutation}"
        );
        must_close(fixture);
    }
}

#[test]
fn explicit_candidate_is_isolated_from_a_different_active_root_both_ways() {
    let active_relative = Path::new("supabase/migrations");
    let candidate_relative = Path::new("candidate");

    let positive_sandbox = must_ok(
        ThrowawayMigrationRoot::new("isolation-positive"),
        "positive isolation sandbox should be created",
    );
    must_write_in(
        &positive_sandbox,
        active_relative,
        "1000_baseline.sql",
        &baseline_sql(Some("ACTION_ALLOWLIST")),
    );
    must_write_in(
        &positive_sandbox,
        candidate_relative,
        "1000_baseline.sql",
        &baseline_sql(None),
    );
    let positive = resolve_explicit(
        positive_sandbox.path(),
        candidate_relative,
        SqlCutoffProfile::BaselineV02,
    );
    let positive_migrations = must_ok(
        read_migrations(positive.root()),
        "positive candidate should be readable",
    );
    assert!(
        validate_guard_inventory(&positive_migrations, positive.profile()).is_ok(),
        "valid candidate must remain green despite a different invalid active root"
    );
    let positive_active_migrations = must_ok(
        read_migrations(&positive_sandbox.path().join(active_relative)),
        "invalid active fixture should be readable independently",
    );
    assert!(
        validate_guard_inventory(&positive_active_migrations, SqlCutoffProfile::BaselineV02)
            .is_err(),
        "the default active marker set in the positive sandbox must actually be invalid"
    );

    let negative_sandbox = must_ok(
        ThrowawayMigrationRoot::new("isolation-negative"),
        "negative isolation sandbox should be created",
    );
    must_write_in(
        &negative_sandbox,
        active_relative,
        "1000_baseline.sql",
        &baseline_sql(None),
    );
    must_write_in(
        &negative_sandbox,
        candidate_relative,
        "1000_baseline.sql",
        &baseline_sql(Some("ACTION_ALLOWLIST")),
    );
    let negative = resolve_explicit(
        negative_sandbox.path(),
        candidate_relative,
        SqlCutoffProfile::BaselineV02,
    );
    let negative_migrations = must_ok(
        read_migrations(negative.root()),
        "negative candidate should be readable",
    );
    assert!(
        validate_guard_inventory(&negative_migrations, negative.profile()).is_err(),
        "invalid candidate must remain red despite a different valid active root"
    );
    let negative_active_migrations = must_ok(
        read_migrations(&negative_sandbox.path().join(active_relative)),
        "valid active fixture should be readable independently",
    );
    assert!(
        validate_guard_inventory(&negative_active_migrations, SqlCutoffProfile::BaselineV02)
            .is_ok(),
        "the default active marker set in the negative sandbox must actually be valid"
    );

    must_close(positive_sandbox);
    must_close(negative_sandbox);
}

#[test]
fn resolver_contract_is_pure_complete_and_fail_closed() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let formal_missing = ResolverInputs::new(
        manifest_dir.clone(),
        None,
        None,
        ResolverEnvironment::new(None, None, Some("1".to_owned())),
    );
    assert!(
        resolve(&formal_missing).is_err(),
        "formal mode must reject an unspecified root and profile"
    );

    let non_formal_defaults = ResolverInputs::new(
        manifest_dir.clone(),
        None,
        None,
        ResolverEnvironment::new(None, None, None),
    );
    let defaulted = must_ok(
        resolve(&non_formal_defaults),
        "non-formal local execution should resolve documented defaults",
    );
    assert!(defaulted.used_non_formal_defaults());
    assert_eq!(defaulted.profile(), SqlCutoffProfile::LegacyHead1460);
    assert!(
        defaulted
            .assertion_context()
            .contains("non-formal defaults used:"),
        "default use must be visible in every caller's assertion context"
    );

    let fixture = must_ok(
        ThrowawayMigrationRoot::new("resolver-contract"),
        "resolver fixture should be created",
    );
    must_write(&fixture, "1000_contract.sql", "select true;\n");
    let root_only = ResolverInputs::new(
        manifest_dir.clone(),
        Some(fixture.path().to_path_buf()),
        None,
        ResolverEnvironment::new(None, None, None),
    );
    assert!(
        resolve(&root_only).is_err(),
        "a non-formal root without a profile must be red"
    );
    let profile_only = ResolverInputs::new(
        manifest_dir.clone(),
        None,
        Some(SqlCutoffProfile::BaselineV02),
        ResolverEnvironment::new(None, None, None),
    );
    assert!(
        resolve(&profile_only).is_err(),
        "a non-formal profile without a root must be red"
    );
    let profile_mismatch = ResolverInputs::new(
        manifest_dir,
        Some(fixture.path().to_path_buf()),
        Some(SqlCutoffProfile::BaselineV02),
        ResolverEnvironment::new(
            Some(fixture.path().to_path_buf()),
            Some(SqlCutoffProfile::LegacyHead1460.as_str().to_owned()),
            None,
        ),
    );
    assert!(
        resolve(&profile_mismatch).is_err(),
        "an explicit/environment profile mismatch must be red"
    );
    must_close(fixture);
}

#[test]
fn resolver_rejects_an_explicit_environment_root_mismatch() {
    let explicit = must_ok(
        ThrowawayMigrationRoot::new("resolver-explicit"),
        "explicit-root fixture should be created",
    );
    let environment = must_ok(
        ThrowawayMigrationRoot::new("resolver-environment"),
        "environment-root fixture should be created",
    );
    must_write(&explicit, "1000_contract.sql", "select true;\n");
    must_write(&environment, "1000_contract.sql", "select true;\n");

    let inputs = ResolverInputs::new(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        Some(explicit.path().to_path_buf()),
        Some(SqlCutoffProfile::BaselineV02),
        ResolverEnvironment::new(
            Some(environment.path().to_path_buf()),
            Some(SqlCutoffProfile::BaselineV02.as_str().to_owned()),
            Some("1".to_owned()),
        ),
    );
    assert!(
        resolve(&inputs).is_err(),
        "different explicit and environment roots must be red after canonicalization"
    );
    must_close(explicit);
    must_close(environment);
}

#[test]
fn pg_prove_profile_freezes_the_actual_suite_endpoint_and_invocation() {
    let suite_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("supabase/tests");
    let suite = must_ok(
        validate_suite(&suite_root),
        "the frozen 22-file pgTAP suite should validate",
    );
    assert_eq!(PROFILE_ID, "pg-prove-local-socket-v1");
    assert_eq!(TEST_FILES.len(), 22);
    assert_eq!(suite.test_files().len(), 22);
    assert_eq!(JOBS, 1);
    assert_eq!(SUITE_TIMEOUT_SECONDS, 900);
    assert_eq!(SUITE_TIMEOUT, Duration::from_secs(900));
    assert_eq!(suite.support_file(), suite_root.join(SUPPORT_RELATIVE_PATH));
    assert!(
        suite
            .test_files()
            .iter()
            .all(|path| path != suite.support_file()),
        "_support/common.psql must be included by tests, not passed to pg_prove"
    );

    let port = NonZeroU16::MIN;
    let unix_endpoint = must_ok(
        UnixSocketEndpoint::new(std::env::temp_dir(), port),
        "an absolute Unix-socket directory should be accepted",
    );
    let fallback = LocalhostTcpEndpoint::new(port);
    assert_eq!(
        select_run_endpoint(Some(unix_endpoint.clone()), fallback),
        RunEndpoint::UnixSocket(unix_endpoint.clone()),
        "a verified Unix socket must take precedence"
    );
    assert_eq!(
        select_run_endpoint(None, fallback),
        RunEndpoint::LocalhostTcp(fallback),
        "the fallback must be localhost-limited TCP"
    );

    let connection = must_ok(
        PgConnectionTarget::new("cutoff_test", "cutoff_runner"),
        "simple non-secret connection identifiers should be accepted",
    );
    let unix_invocation = build_invocation(
        &suite,
        &RunEndpoint::UnixSocket(unix_endpoint.clone()),
        &connection,
    );
    assert_eq!(unix_invocation.program(), "pg_prove");
    assert_eq!(unix_invocation.suite_timeout(), SUITE_TIMEOUT);
    assert_eq!(
        argument_after(unix_invocation.arguments(), "--host"),
        Some(unix_endpoint.directory().as_os_str())
    );
    assert_eq!(
        argument_after(unix_invocation.arguments(), "--jobs"),
        Some(OsStr::new("1"))
    );
    assert!(
        !unix_invocation
            .arguments()
            .iter()
            .any(|argument| argument == suite.support_file().as_os_str()),
        "the support include must not be an invocation input"
    );
    assert_invocation_has_exact_test_inputs(unix_invocation.arguments(), &suite_root);

    let tcp_invocation =
        build_invocation(&suite, &RunEndpoint::LocalhostTcp(fallback), &connection);
    assert_eq!(
        argument_after(tcp_invocation.arguments(), "--host"),
        Some(OsStr::new(LOCALHOST_TCP_HOST))
    );
}

#[cfg(unix)]
#[test]
fn pg_prove_suite_rejects_a_symlinked_support_include() {
    let suite = must_ok(
        ThrowawayMigrationRoot::new("pgtap-suite-symlink"),
        "pgTAP symlink suite should be created",
    );
    for file in TEST_FILES {
        must_ok(
            suite.write_file(Path::new(file), "\\ir _support/common.psql\nselect true;\n"),
            "pgTAP fixture file should be written",
        );
    }
    must_ok(
        suite.create_directory(Path::new("_support")),
        "pgTAP fixture support directory should be created",
    );
    let outside = must_ok(
        ThrowawayMigrationRoot::new("pgtap-support-outside"),
        "outside support fixture should be created",
    );
    let outside_file = must_ok(
        outside.write_file(Path::new("common.psql"), "select true;\n"),
        "outside support file should be written",
    );
    std::os::unix::fs::symlink(&outside_file, suite.path().join("_support/common.psql"))
        .unwrap_or_else(|error| panic!("support symlink fixture should be created: {error}"));

    assert!(
        validate_suite(suite.path()).is_err(),
        "a symlinked support include must not enter the frozen pgTAP suite"
    );
    must_close(suite);
    must_close(outside);
}

#[test]
fn pg_prove_result_parser_accepts_complete_tuples_and_rejects_incomplete_runs() {
    let complete = synthetic_pg_prove_output(TEST_FILES.len());
    let result = must_ok(
        parse_pg_prove_result(0, &complete),
        "complete synthetic pg_prove output should parse",
    );
    assert_eq!(result.profile_id, PROFILE_ID);
    assert_eq!(result.total_files, 22);
    assert_eq!(result.total_tests, 22);
    assert_eq!(result.files.len(), 22);
    assert_eq!(result.files[0].executed, 1);
    assert_eq!(result.files[0].passed, 1);
    assert_eq!(result.files[0].failed, 0);
    assert_eq!(result.files[0].skipped, 1);
    assert_eq!(result.files[0].todo, 0);
    assert_eq!(result.files[1].executed, 1);
    assert_eq!(result.files[1].passed, 1);
    assert_eq!(result.files[1].failed, 0);
    assert_eq!(result.files[1].skipped, 0);
    assert_eq!(result.files[1].todo, 1);

    let missing = synthetic_pg_prove_output(TEST_FILES.len() - 1);
    assert!(
        parse_pg_prove_result(0, &missing).is_err(),
        "missing per-file tuples must be red"
    );
    assert!(
        parse_pg_prove_result(1, &complete).is_err(),
        "a non-zero pg_prove exit must be red"
    );
    let bailed = format!("{complete}Bail out! contract fixture\n");
    assert!(
        parse_pg_prove_result(0, &bailed).is_err(),
        "a TAP bailout must be red"
    );
    assert!(
        parse_pg_prove_result(0, &synthetic_zero_test_pg_prove_output()).is_err(),
        "a nominally passing file with zero executed assertions must be red"
    );
}

#[test]
fn pg_prove_result_parser_counter_overflow_fails_closed() {
    assert_eq!(
        checked_counter_add(41, 1, "fixture count"),
        Ok(42),
        "ordinary evidence counter addition must remain deterministic"
    );
    assert!(
        checked_counter_add(usize::MAX, 1, "fixture count").is_err(),
        "evidence counter overflow must become an explicit parser error"
    );
}

fn assert_exact_guard_inventory(
    inventory: &[crate::sql_cutoff_parity::guards::GuardInventoryEntry],
    context: &str,
) {
    assert_eq!(
        inventory.len(),
        9,
        "marker-to-guard inventory must retain nine mappings; {context}"
    );
    let actual = inventory
        .iter()
        .map(|entry| entry.owner_identity)
        .collect::<BTreeSet<_>>();
    let expected = EXPECTED_GUARD_IDENTITIES
        .into_iter()
        .collect::<BTreeSet<_>>();
    let declared = MARKER_GUARD_SPECS
        .iter()
        .map(|spec| spec.owner_identity)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual, expected,
        "effective eight-guard set drifted; {context}"
    );
    assert_eq!(
        declared, expected,
        "canonical marker owner declarations drifted; {context}"
    );
}

fn resolve_explicit(
    manifest_dir: &Path,
    candidate_root: &Path,
    profile: SqlCutoffProfile,
) -> crate::sql_cutoff_parity::resolver::ResolvedMigrationRoot {
    let inputs = ResolverInputs::new(
        manifest_dir.to_path_buf(),
        Some(candidate_root.to_path_buf()),
        Some(profile),
        ResolverEnvironment::new(None, None, None),
    );
    must_ok(resolve(&inputs), "explicit candidate should resolve")
}

fn baseline_sql(omitted_family: Option<&str>) -> String {
    let guard_specs: [(&[&str], &str, &str); 8] = [
        (
            &["FORBIDDEN_AUDIT_METADATA_KEYS"],
            "audit_metadata_has_forbidden_key",
            "p_metadata jsonb",
        ),
        (
            &["FORBIDDEN_LEDGER_PAYLOAD_KEYS"],
            "ledger_payload_has_forbidden_key",
            "p_payload jsonb",
        ),
        (
            &["ACTION_ALLOWLIST"],
            "audit_metadata_has_unknown_key_for_action",
            "p_action text, p_result text, p_metadata jsonb",
        ),
        (
            &["REQUIRED_KEY"],
            "audit_metadata_has_missing_required_key_for_action",
            "p_action text, p_result text, p_metadata jsonb, p_is_legacy boolean",
        ),
        (
            &["NOTIFIER_KIND_ALLOWLIST", "INCIDENT_CATEGORY_ALLOWLIST"],
            "audit_metadata_has_invalid_value_for_action",
            "p_action text, p_result text, p_metadata jsonb",
        ),
        (
            &["INCIDENT_TYPE_ALLOWLIST"],
            "incident_type_allowed",
            "p_incident_type text",
        ),
        (
            &["SEVERITY_ALLOWLIST"],
            "incident_severity_allowed",
            "p_severity text",
        ),
        (
            &["NOTIFICATION_RESULT_ALLOWLIST"],
            "incident_notification_result_allowed",
            "p_notification_result text",
        ),
    ];
    let mut sql = String::new();
    for (families, name, arguments) in guard_specs {
        let markers = families
            .iter()
            .filter(|family| omitted_family != Some(**family))
            .map(|family| marker_block(family))
            .collect::<String>();
        sql.push_str(&guard_definition_with_markers(name, arguments, &markers));
    }
    sql.push_str(&marker_block("TRIGGER_VOCABULARY"));
    sql.push_str(&marker_block("TRIGGER_VOCABULARY"));
    sql
}

fn marker_block(family: &str) -> String {
    format!("-- {family}_START\n-- contract-fixture-payload\n-- {family}_END\n")
}

fn guard_definition(name: &str, arguments: &str) -> String {
    guard_definition_with_markers(name, arguments, "")
}

fn guard_definition_with_markers(name: &str, arguments: &str, markers: &str) -> String {
    format!(
        "create or replace function public.{name}({arguments})\nreturns boolean\nlanguage plpgsql\nas $function$\n{markers}begin\n    return false;\nend\n$function$;\n"
    )
}

fn must_write(fixture: &ThrowawayMigrationRoot, basename: &str, sql: &str) {
    if let Err(error) = fixture.write_migration(basename, sql) {
        panic!("fixture migration {basename} should be written: {error}");
    }
}

fn must_write_in(
    fixture: &ThrowawayMigrationRoot,
    relative_root: &Path,
    basename: &str,
    sql: &str,
) {
    if let Err(error) = fixture.write_migration_in(relative_root, basename, sql) {
        panic!(
            "fixture migration {}/{} should be written: {error}",
            relative_root.display(),
            basename
        );
    }
}

fn must_close(fixture: ThrowawayMigrationRoot) {
    if let Err(error) = fixture.close() {
        panic!("fixture should be removed: {error}");
    }
}

fn must_ok<T, E>(result: Result<T, E>, context: &str) -> T
where
    E: Display,
{
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error}"),
    }
}

fn argument_after<'a>(arguments: &'a [std::ffi::OsString], option: &str) -> Option<&'a OsStr> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == OsStr::new(option))
        .map(|pair| pair[1].as_os_str())
}

fn assert_invocation_has_exact_test_inputs(arguments: &[std::ffi::OsString], root: &Path) {
    let expected = TEST_FILES
        .iter()
        .map(|file| root.join(file))
        .collect::<Vec<_>>();
    let actual = arguments
        .iter()
        .filter_map(|argument| {
            let path = Path::new(argument);
            (path.extension() == Some(OsStr::new("sql"))).then(|| path.to_path_buf())
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

fn synthetic_pg_prove_output(file_count: usize) -> String {
    let mut output = String::new();
    for (index, file) in TEST_FILES.iter().take(file_count).enumerate() {
        output.push_str(file);
        output.push_str(" ..\n");
        match index {
            0 => output.push_str("ok 1 - fixture skip # SKIP contract\n"),
            1 => output.push_str("not ok 1 - fixture todo # TODO contract\n"),
            _ => output.push_str("ok 1 - fixture pass\n"),
        }
        output.push_str("1..1\nok\n");
    }
    output.push_str("All tests successful.\n");
    output.push_str(&format!("Files={file_count}, Tests={file_count}\n"));
    output.push_str("Result: PASS\n");
    output
}

fn synthetic_zero_test_pg_prove_output() -> String {
    let mut output = String::new();
    for (index, file) in TEST_FILES.iter().enumerate() {
        output.push_str(file);
        output.push_str(" ..\n");
        if index == 0 {
            output.push_str("1..0\nok\n");
        } else {
            output.push_str("ok 1 - fixture pass\n1..1\nok\n");
        }
    }
    output.push_str("All tests successful.\n");
    output.push_str(&format!(
        "Files={}, Tests={}\n",
        TEST_FILES.len(),
        TEST_FILES.len() - 1
    ));
    output.push_str("Result: PASS\n");
    output
}

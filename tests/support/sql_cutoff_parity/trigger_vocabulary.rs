//! SQL-derived `AuditTrigger` vocabulary parity for cutoff candidates.

use std::collections::BTreeSet;
use std::ops::Range;
use std::path::{Path, PathBuf};

use mipsorcu::audit::AuditTrigger;

use super::definitions::{
    FunctionDefinition, definitions_in_migration, dollar_quoted_ranges, latest_definition,
    quoted_literals,
};
use super::markers::{MarkerOccurrence, TRIGGER_VOCABULARY_FAMILY, marker_occurrences};
use super::migrations::{MigrationFile, read_migrations};
use super::resolver::SqlCutoffProfile;
use super::trigger_sql_lexer::{effective_not_in_literal_lists, trigger_branch_ranges};

const TRIGGER_OWNER_PREFIX: &str = "-- TRIGGER_VOCABULARY_OWNER: ";
const AUDIT_OWNER: &str =
    "public.audit_metadata_has_invalid_value_for_action_before_1330(text,text,jsonb)";
const LEDGER_OWNER: &str = "public.ledger_payload_schema_is_valid(text,jsonb)";
const TRIGGER_OWNERS: [&str; 2] = [AUDIT_OWNER, LEDGER_OWNER];

#[derive(Debug)]
struct OwnedTriggerMarker {
    owner: String,
    path: PathBuf,
    raw_payload: String,
    adjacent_definition_start: usize,
}

/// Returns the canonical Rust vocabulary without a duplicated string allowlist.
#[must_use]
pub fn rust_trigger_vocabulary() -> BTreeSet<String> {
    [
        AuditTrigger::Startup,
        AuditTrigger::Background,
        AuditTrigger::Cli,
    ]
    .into_iter()
    .map(AuditTrigger::as_str)
    .map(str::to_owned)
    .collect()
}

/// Validates SQL body literals and the profile-specific trigger marker contract.
///
/// Only `migration_root` is read. `assertion_context` is included in every
/// returned failure so non-formal resolver defaults remain visible.
pub fn validate_trigger_vocabulary(
    migration_root: &Path,
    profile: SqlCutoffProfile,
    assertion_context: &str,
    rust_values: &BTreeSet<String>,
) -> Result<(), String> {
    if assertion_context.trim().is_empty() {
        return Err("trigger vocabulary validation requires resolver assertion context".to_owned());
    }
    validate_trigger_vocabulary_inner(migration_root, profile, rust_values)
        .map_err(|error| format!("{assertion_context}: {error}"))
}

/// Builds a valid baseline carrier with two identical trigger marker payloads.
#[must_use]
pub fn valid_baseline_trigger_fixture_sql() -> String {
    baseline_trigger_fixture(
        "if v_key = 'trigger' then",
        "if (v_val #>> '{}') not in ('background', 'cli', 'startup') then return true; end if;",
        "if v_key = 'trigger' then",
        "if (v_value #>> '{}') not in ('background', 'cli', 'startup') then return false; end if;",
    )
}

/// Builds a baseline carrier whose ledger body drifts while markers stay fixed.
#[must_use]
pub fn mutated_baseline_trigger_fixture_sql() -> String {
    baseline_trigger_fixture(
        "if v_key = 'trigger' then",
        "if (v_val #>> '{}') not in ('background', 'cli', 'startup') then return true; end if;",
        "if v_key = 'trigger' then",
        "if (v_value #>> '{}') not in ('background', 'cli', 'mutated') then return false; end if;",
    )
}

/// Builds a baseline carrier whose audit predicate exists only in a line comment.
#[must_use]
pub fn line_commented_baseline_trigger_fixture_sql() -> String {
    baseline_trigger_fixture(
        "if v_key = 'trigger' then",
        "-- if (v_val #>> '{}') not in ('background', 'cli', 'startup') then return true; end if;",
        "if v_key = 'trigger' then",
        "if (v_value #>> '{}') not in ('background', 'cli', 'startup') then return false; end if;",
    )
}

/// Builds a baseline carrier whose ledger predicate exists only in a block comment.
#[must_use]
pub fn block_commented_baseline_trigger_fixture_sql() -> String {
    baseline_trigger_fixture(
        "if v_key = 'trigger' then",
        "if (v_val #>> '{}') not in ('background', 'cli', 'startup') then return true; end if;",
        "if v_key = 'trigger' then",
        "/* if (v_value #>> '{}') not in ('background', 'cli', 'startup') then return false; end if; */",
    )
}

/// Builds a baseline carrier whose ledger predicate exists only in a SQL string literal.
#[must_use]
pub fn string_literal_only_baseline_trigger_fixture_sql() -> String {
    baseline_trigger_fixture(
        "if v_key = 'trigger' then",
        "if (v_val #>> '{}') not in ('background', 'cli', 'startup') then return true; end if;",
        "if v_key = 'trigger' then",
        "perform 'not in (''background'', ''cli'', ''startup'')';",
    )
}

/// Builds a baseline carrier whose audit trigger branch header is commented out.
#[must_use]
pub fn commented_branch_header_baseline_trigger_fixture_sql() -> String {
    baseline_trigger_fixture(
        "-- if v_key = 'trigger' then",
        "if (v_val #>> '{}') not in ('background', 'cli', 'startup') then return true; end if;",
        "if v_key = 'trigger' then",
        "if (v_value #>> '{}') not in ('background', 'cli', 'startup') then return false; end if;",
    )
}

/// Builds a baseline carrier whose ledger header uses inequality, not equality.
#[must_use]
pub fn not_equal_branch_header_baseline_trigger_fixture_sql() -> String {
    baseline_trigger_fixture(
        "if v_key = 'trigger' then",
        "if (v_val #>> '{}') not in ('background', 'cli', 'startup') then return true; end if;",
        "if v_key != 'trigger' then",
        "if (v_value #>> '{}') not in ('background', 'cli', 'startup') then return false; end if;",
    )
}

/// Builds a baseline carrier with a non-branch trigger comparison expression.
#[must_use]
pub fn perform_expression_baseline_trigger_fixture_sql() -> String {
    baseline_trigger_fixture(
        "perform v_key = 'trigger';\n    if true then",
        "if (v_val #>> '{}') not in ('background', 'cli', 'startup') then return true; end if;",
        "if v_key = 'trigger' then",
        "if (v_value #>> '{}') not in ('background', 'cli', 'startup') then return false; end if;",
    )
}

/// Builds a baseline carrier whose audit trigger header lacks `THEN`.
#[must_use]
pub fn missing_then_baseline_trigger_fixture_sql() -> String {
    baseline_trigger_fixture(
        "if v_key = 'trigger'",
        "if (v_val #>> '{}') not in ('background', 'cli', 'startup') then return true; end if;",
        "if v_key = 'trigger' then",
        "if (v_value #>> '{}') not in ('background', 'cli', 'startup') then return false; end if;",
    )
}

/// Builds a baseline carrier whose audit trigger header uses adjacent `=>`.
#[must_use]
pub fn arrow_operator_baseline_trigger_fixture_sql() -> String {
    baseline_trigger_fixture(
        "if v_key => 'trigger' then",
        "if (v_val #>> '{}') not in ('background', 'cli', 'startup') then return true; end if;",
        "if v_key = 'trigger' then",
        "if (v_value #>> '{}') not in ('background', 'cli', 'startup') then return false; end if;",
    )
}

/// Builds a carrier with the old vocabulary only after the target `END IF`.
#[must_use]
pub fn post_branch_vocabulary_baseline_trigger_fixture_sql() -> String {
    baseline_trigger_fixture(
        "if v_key = 'trigger' then",
        "null;\n    end if;\n    if true then\n        if (v_val #>> '{}') not in ('background', 'cli', 'startup') then return true; end if;",
        "if v_key = 'trigger' then",
        "if (v_value #>> '{}') not in ('background', 'cli', 'startup') then return false; end if;",
    )
}

/// Builds a valid carrier with nested IF and fake control tokens in quoted regions.
#[must_use]
pub fn nested_control_baseline_trigger_fixture_sql() -> String {
    baseline_trigger_fixture(
        "if v_key = 'trigger' then",
        "if true then\n            -- END IF; ELSE\n            perform 'END IF; ELSIF';\n            perform $fake$END IF; ELSE$fake$;\n            /* END IF; */\n            if (v_val #>> '{}') not in ('background', 'cli', 'startup') then return true; end if;\n        end if;",
        "if v_key = 'trigger' then",
        "if true then\n            perform 'END IF; ELSE';\n            if (v_value #>> '{}') not in ('background', 'cli', 'startup') then return false; end if;\n        end if;",
    )
}

fn validate_trigger_vocabulary_inner(
    migration_root: &Path,
    profile: SqlCutoffProfile,
    rust_values: &BTreeSet<String>,
) -> Result<(), String> {
    let migrations = read_migrations(migration_root)?;
    let marker_occurrences = marker_occurrences(&migrations, TRIGGER_VOCABULARY_FAMILY)?;
    let owner_header_count = trigger_owner_header_count(&migrations);

    match profile {
        SqlCutoffProfile::LegacyHead1460 => {
            if !marker_occurrences.is_empty() || owner_header_count != 0 {
                return Err(format!(
                    "legacy-head-1460 requires zero TRIGGER_VOCABULARY blocks and owner headers; found {} blocks and {owner_header_count} headers",
                    marker_occurrences.len()
                ));
            }
            validate_effective_owner_bodies(&migrations, rust_values)
        }
        SqlCutoffProfile::BaselineV02 => validate_baseline(
            &migrations,
            marker_occurrences,
            owner_header_count,
            rust_values,
        ),
    }
}

fn validate_effective_owner_bodies(
    migrations: &[MigrationFile],
    rust_values: &BTreeSet<String>,
) -> Result<(), String> {
    for owner in TRIGGER_OWNERS {
        let definition = latest_definition(migrations, owner)?;
        let body_values = extract_trigger_literals(&definition.body)?;
        if &body_values != rust_values {
            return Err(format!(
                "effective trigger body/Rust mismatch for {} in {}",
                definition.identity,
                definition.path.display()
            ));
        }
    }
    Ok(())
}

fn validate_baseline(
    migrations: &[MigrationFile],
    marker_occurrences: Vec<MarkerOccurrence>,
    owner_header_count: usize,
    rust_values: &BTreeSet<String>,
) -> Result<(), String> {
    if marker_occurrences.len() != 2 {
        return Err(format!(
            "baseline-v0.2 requires exactly 2 physical TRIGGER_VOCABULARY blocks; found {}",
            marker_occurrences.len()
        ));
    }
    if owner_header_count != 2 {
        return Err(format!(
            "baseline-v0.2 requires exactly 2 TRIGGER_VOCABULARY owner headers; found {owner_header_count}"
        ));
    }

    let occurrences = marker_occurrences
        .iter()
        .map(|occurrence| attach_owner_and_definition(migrations, occurrence))
        .collect::<Result<Vec<_>, _>>()?;
    validate_exact_owners(&occurrences)?;

    let first_payload = occurrences
        .first()
        .ok_or_else(|| "trigger marker disappeared after exact count validation".to_owned())?
        .raw_payload
        .as_bytes();
    if occurrences
        .iter()
        .any(|occurrence| occurrence.raw_payload.as_bytes() != first_payload)
    {
        return Err(
            "the two TRIGGER_VOCABULARY payloads must be byte-for-byte identical".to_owned(),
        );
    }

    let marker_values = parse_canonical_marker_payload(
        &occurrences
            .first()
            .ok_or_else(|| "trigger marker disappeared after exact count validation".to_owned())?
            .raw_payload,
    )?;
    if &marker_values != rust_values {
        return Err(
            "TRIGGER_VOCABULARY marker payload does not match Rust AuditTrigger".to_owned(),
        );
    }

    for occurrence in occurrences {
        let definition = latest_definition(migrations, &occurrence.owner)?;
        if definition.path != occurrence.path
            || definition.start != occurrence.adjacent_definition_start
        {
            return Err(format!(
                "TRIGGER_VOCABULARY owner {} does not identify its effective latest definition",
                occurrence.owner
            ));
        }
        let body_values = extract_trigger_literals(&definition.body)?;
        if body_values != marker_values || &body_values != rust_values {
            return Err(format!(
                "trigger body literals, marker payload, and Rust enum must match for {}",
                occurrence.owner
            ));
        }
    }
    Ok(())
}

fn attach_owner_and_definition(
    migrations: &[MigrationFile],
    occurrence: &MarkerOccurrence,
) -> Result<OwnedTriggerMarker, String> {
    let migration = migrations
        .iter()
        .find(|migration| {
            migration.ordinal == occurrence.migration_ordinal && migration.path == occurrence.path
        })
        .ok_or_else(|| {
            format!(
                "TRIGGER_VOCABULARY carrier {} is outside the supplied candidate",
                occurrence.path.display()
            )
        })?;
    let (header_range, header) = previous_line(&migration.sql, occurrence.block_range.start)?;
    let owner = header
        .trim()
        .strip_prefix(TRIGGER_OWNER_PREFIX)
        .ok_or_else(|| {
            format!(
                "TRIGGER_VOCABULARY START in {} must have an immediately preceding standalone owner header",
                migration.path.display()
            )
        })?
        .to_owned();
    if header.trim() != format!("{TRIGGER_OWNER_PREFIX}{owner}") {
        return Err(format!(
            "TRIGGER_VOCABULARY owner header in {} is not canonical",
            migration.path.display()
        ));
    }

    let marker_with_header = header_range.start..occurrence.block_range.end;
    let dollar_bodies = dollar_quoted_ranges(&migration.sql)?;
    if dollar_bodies
        .iter()
        .any(|body| ranges_overlap(&body.quoted_range, &marker_with_header))
    {
        return Err(format!(
            "TRIGGER_VOCABULARY owner header and block for {owner} must be outside dollar-quoted bodies"
        ));
    }

    let definition_start = skip_ascii_whitespace(&migration.sql, occurrence.block_range.end);
    let definition = adjacent_owned_definition(migration, definition_start, &owner)?;
    Ok(OwnedTriggerMarker {
        owner,
        path: migration.path.clone(),
        raw_payload: occurrence.payload.clone(),
        adjacent_definition_start: definition.start,
    })
}

fn adjacent_owned_definition(
    migration: &MigrationFile,
    definition_start: usize,
    owner: &str,
) -> Result<FunctionDefinition, String> {
    definitions_in_migration(migration)?
        .into_iter()
        .find(|definition| definition.start == definition_start && definition.identity == owner)
        .ok_or_else(|| {
            format!(
                "TRIGGER_VOCABULARY block for {owner} in {} must be immediately adjacent to that owner function section",
                migration.path.display()
            )
        })
}

fn validate_exact_owners(occurrences: &[OwnedTriggerMarker]) -> Result<(), String> {
    let owners = occurrences
        .iter()
        .map(|occurrence| occurrence.owner.clone())
        .collect::<BTreeSet<_>>();
    let expected = TRIGGER_OWNERS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if owners != expected || owners.len() != occurrences.len() {
        return Err(format!(
            "TRIGGER_VOCABULARY owner headers must identify the exact two canonical functions; found {owners:?}"
        ));
    }
    Ok(())
}

fn trigger_owner_header_count(migrations: &[MigrationFile]) -> usize {
    migrations
        .iter()
        .flat_map(|migration| migration.sql.lines())
        .filter(|line| line.trim().starts_with(TRIGGER_OWNER_PREFIX))
        .count()
}

fn parse_canonical_marker_payload(payload: &str) -> Result<BTreeSet<String>, String> {
    let values = payload
        .lines()
        .map(|line| {
            line.trim()
                .strip_prefix("-- ")
                .ok_or_else(|| "TRIGGER_VOCABULARY payload lines must use '-- <value>'".to_owned())
                .map(str::to_owned)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.is_empty() || values.iter().any(String::is_empty) {
        return Err("TRIGGER_VOCABULARY payload must contain non-empty values".to_owned());
    }
    let mut sorted = values.clone();
    sorted.sort();
    if values != sorted {
        return Err("TRIGGER_VOCABULARY payload must use canonical lexical order".to_owned());
    }
    let unique = values.iter().cloned().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err("TRIGGER_VOCABULARY payload must not contain duplicates".to_owned());
    }
    Ok(unique)
}

fn extract_trigger_literals(body: &str) -> Result<BTreeSet<String>, String> {
    let branch_ranges = trigger_branch_ranges(body)?;
    if branch_ranges.len() != 1 {
        return Err(format!(
            "effective function body must contain exactly one trigger value branch; found {}",
            branch_ranges.len()
        ));
    }
    let branch_range = branch_ranges
        .first()
        .ok_or_else(|| "trigger branch disappeared after exact count validation".to_owned())?;
    let branch = body
        .get(branch_range.clone())
        .ok_or_else(|| "trigger branch byte range does not fit function body".to_owned())?;
    let literal_lists = effective_not_in_literal_lists(branch)?;
    if literal_lists.len() != 1 {
        return Err(format!(
            "trigger branch must contain exactly one explicit NOT IN list; found {}",
            literal_lists.len()
        ));
    }
    let list_range = literal_lists
        .first()
        .ok_or_else(|| "NOT IN literal list disappeared after exact count validation".to_owned())?;
    let list = branch
        .get(list_range.clone())
        .ok_or_else(|| "trigger NOT IN literal range is invalid".to_owned())?;
    parse_sql_literal_list(list)
}

fn parse_sql_literal_list(list: &str) -> Result<BTreeSet<String>, String> {
    let literals = quoted_literals(list)?;
    if literals.is_empty() {
        return Err("trigger NOT IN literal list must not be empty".to_owned());
    }
    let mut cursor = 0usize;
    let mut values = Vec::with_capacity(literals.len());
    for (index, literal) in literals.iter().enumerate() {
        let separator = list
            .get(cursor..literal.range.start)
            .ok_or_else(|| "trigger literal separator range is invalid".to_owned())?;
        if index == 0 {
            if !separator.trim().is_empty() {
                return Err("trigger NOT IN list contains a non-literal token".to_owned());
            }
        } else if separator.trim() != "," {
            return Err("trigger NOT IN literals must be comma-separated".to_owned());
        }
        cursor = literal.range.end;
        values.push(literal.value.clone());
    }
    let tail = list
        .get(cursor..)
        .ok_or_else(|| "trigger literal tail range is invalid".to_owned())?;
    if !tail.trim().is_empty() {
        return Err("trigger NOT IN list contains a trailing non-literal token".to_owned());
    }
    let unique = values.iter().cloned().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err("trigger NOT IN literal list contains a duplicate value".to_owned());
    }
    Ok(unique)
}

fn previous_line(sql: &str, before: usize) -> Result<(Range<usize>, &str), String> {
    let prefix = sql
        .get(..before)
        .ok_or_else(|| "marker start byte range does not fit carrier SQL".to_owned())?;
    let without_lf = prefix.strip_suffix('\n').unwrap_or(prefix);
    let content_end = without_lf
        .strip_suffix('\r')
        .map_or(without_lf.len(), str::len);
    let line_start = without_lf[..content_end]
        .rfind('\n')
        .map_or(0, |offset| offset.saturating_add(1));
    let line = sql
        .get(line_start..line_start.saturating_add(content_end - line_start))
        .ok_or_else(|| "owner header byte range does not fit carrier SQL".to_owned())?;
    Ok((line_start..before, line))
}

fn skip_ascii_whitespace(sql: &str, mut index: usize) -> usize {
    let bytes = sql.as_bytes();
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index = index.saturating_add(1);
    }
    index
}

fn ranges_overlap(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}

fn baseline_trigger_fixture(
    audit_header: &str,
    audit_predicate: &str,
    ledger_header: &str,
    ledger_predicate: &str,
) -> String {
    format!(
        "\
-- TRIGGER_VOCABULARY_OWNER: {AUDIT_OWNER}\n\
-- TRIGGER_VOCABULARY_START\n\
-- background\n\
-- cli\n\
-- startup\n\
-- TRIGGER_VOCABULARY_END\n\
create or replace function public.audit_metadata_has_invalid_value_for_action_before_1330(\n\
    p_action text, p_result text, p_metadata_json jsonb\n\
) returns boolean language plpgsql as $audit$\n\
begin\n\
    {audit_header}\n\
        {audit_predicate}\n\
    end if;\n\
    return false;\n\
end;\n\
$audit$;\n\
-- TRIGGER_VOCABULARY_OWNER: {LEDGER_OWNER}\n\
-- TRIGGER_VOCABULARY_START\n\
-- background\n\
-- cli\n\
-- startup\n\
-- TRIGGER_VOCABULARY_END\n\
create or replace function public.ledger_payload_schema_is_valid(\n\
    p_entry_type text, p_payload jsonb\n\
) returns boolean language plpgsql as $ledger$\n\
begin\n\
    {ledger_header}\n\
        {ledger_predicate}\n\
    end if;\n\
    return true;\n\
end;\n\
$ledger$;\n"
    )
}

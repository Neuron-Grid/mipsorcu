//! Rust audit-ui RPC calls must exist in the explicitly selected migration candidate.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[path = "support/sql_cutoff_parity/mod.rs"]
pub mod sql_cutoff_parity;

use sql_cutoff_parity::definitions::effective_definitions;
use sql_cutoff_parity::fixture::ThrowawayMigrationRoot;
use sql_cutoff_parity::migrations::read_migrations;
use sql_cutoff_parity::resolver::resolve_from_environment;

const AUDIT_UI_RPC_SOURCE: &str = "src/server/supabase/audit_ui_rpc.rs";
const EXPECTED_AUDIT_UI_RPCS: [&str; 6] = [
    "rpc_audit_ui_audit_events",
    "rpc_audit_ui_integrity_status",
    "rpc_audit_ui_ledger_entries",
    "rpc_audit_ui_secret_inventory",
    "rpc_audit_ui_verification_failures",
    "rpc_verify_ledger_hash_chain",
];

#[test]
fn exact_audit_ui_rpc_inventory_is_defined_in_candidate_migrations() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let resolved = resolve_from_environment(manifest_dir, None, None)
        .unwrap_or_else(|error| panic!("SQL cutoff candidate resolution failed: {error}"));
    let context = resolved.assertion_context();
    let source_path = manifest_dir.join(AUDIT_UI_RPC_SOURCE);

    validate_source_path(&source_path).unwrap_or_else(|error| {
        panic!("audit-ui RPC source existence guard failed ({context}): {error}")
    });
    let source = fs::read_to_string(&source_path).unwrap_or_else(|error| {
        panic!(
            "audit-ui RPC source {} must be readable UTF-8 ({context}): {error}",
            source_path.display()
        )
    });
    let rpc_names = extract_post_rpc_names(&source)
        .unwrap_or_else(|error| panic!("audit-ui RPC call parser failed ({context}): {error}"));
    let expected = EXPECTED_AUDIT_UI_RPCS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let actual = rpc_names.iter().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        rpc_names.len(),
        actual.len(),
        "audit-ui RPC source contains duplicate calls in its six-item inventory ({context})"
    );
    assert_eq!(
        actual, expected,
        "audit-ui RPC source inventory must remain the exact six planned calls ({context})"
    );

    let migrations = read_migrations(resolved.root())
        .unwrap_or_else(|error| panic!("candidate migration read failed ({context}): {error}"));
    let missing = expected
        .iter()
        .filter(|rpc| {
            !rpc_is_effectively_defined(&migrations, rpc).unwrap_or_else(|error| {
                panic!("candidate effective definition scan failed ({context}): {error}")
            })
        })
        .cloned()
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "audit-ui RPCs called from {} but absent from candidate root {}: {missing:?} ({context})",
        source_path.display(),
        resolved.root().display()
    );
}

#[test]
fn later_rpc_drop_is_not_treated_as_an_effective_definition() {
    let fixture = ThrowawayMigrationRoot::new("audit-ui-rpc-drop")
        .unwrap_or_else(|error| panic!("audit-ui DROP fixture must be creatable: {error}"));
    fixture
        .write_migration(
            "1000_create_rpc.sql",
            "create function public.rpc_fixture() returns boolean language sql as $$ select true $$;\n",
        )
        .unwrap_or_else(|error| panic!("audit-ui CREATE fixture must be writable: {error}"));
    fixture
        .write_migration("1010_drop_rpc.sql", "drop function public.rpc_fixture();\n")
        .unwrap_or_else(|error| panic!("audit-ui DROP fixture must be writable: {error}"));
    let migrations = read_migrations(fixture.path())
        .unwrap_or_else(|error| panic!("audit-ui DROP fixture must be readable: {error}"));

    assert_eq!(
        rpc_is_effectively_defined(&migrations, "rpc_fixture"),
        Ok(false),
        "a later DROP FUNCTION must remove an RPC from the effective candidate state"
    );
    fixture
        .close()
        .unwrap_or_else(|error| panic!("audit-ui DROP fixture cleanup must succeed: {error}"));
}

#[test]
fn rpc_renamed_into_the_expected_name_is_effectively_defined() {
    let fixture = ThrowawayMigrationRoot::new("audit-ui-rpc-rename")
        .unwrap_or_else(|error| panic!("audit-ui RENAME fixture must be creatable: {error}"));
    fixture
        .write_migration(
            "1000_create_rpc.sql",
            "create function public.rpc_fixture_before() returns boolean language sql as $$ select true $$;\n",
        )
        .unwrap_or_else(|error| panic!("audit-ui CREATE fixture must be writable: {error}"));
    fixture
        .write_migration(
            "1010_rename_rpc.sql",
            "alter function public.rpc_fixture_before() rename to rpc_fixture;\n",
        )
        .unwrap_or_else(|error| panic!("audit-ui RENAME fixture must be writable: {error}"));
    let migrations = read_migrations(fixture.path())
        .unwrap_or_else(|error| panic!("audit-ui RENAME fixture must be readable: {error}"));

    assert_eq!(
        rpc_is_effectively_defined(&migrations, "rpc_fixture"),
        Ok(true),
        "a function renamed into an expected RPC name must remain effective"
    );
    assert_eq!(
        rpc_is_effectively_defined(&migrations, "rpc_fixture_before"),
        Ok(false),
        "the rename source must no longer remain effective"
    );
    fixture
        .close()
        .unwrap_or_else(|error| panic!("audit-ui RENAME fixture cleanup must succeed: {error}"));
}

#[test]
fn post_rpc_parser_handles_multiline_calls_and_rejects_truncation() {
    let source = "// client.post_rpc(\"ignored_comment\", &params);\n\
        let ignored = \"client.post_rpc(\\\"ignored_string\\\", &params)\";\n\
        client.post_rpc(\n    /* direct argument */ \"rpc_one\",\n    &params\n);\n\
        client.post_rpc(\"rpc_two\", &params);";
    assert_eq!(
        extract_post_rpc_names(source),
        Ok(vec!["rpc_one".to_owned(), "rpc_two".to_owned()])
    );
    assert!(
        extract_post_rpc_names("client.post_rpc(\"unterminated").is_err(),
        "a truncated RPC literal must fail closed"
    );
    assert!(
        extract_post_rpc_names("client.post_rpc(dynamic_name, \"rpc_one\", &params);").is_err(),
        "a dynamic first argument must not be rescued by a later expected string"
    );
}

fn validate_source_path(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{} must exist: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{} must be a direct regular file, not a symlink",
            path.display()
        ));
    }
    Ok(())
}

fn rpc_is_effectively_defined(
    migrations: &[sql_cutoff_parity::migrations::MigrationFile],
    rpc_name: &str,
) -> Result<bool, String> {
    let expected_name = format!("public.{rpc_name}");
    let identities = effective_definitions(migrations)?
        .into_iter()
        .map(|definition| definition.identity)
        .filter(|identity| {
            identity
                .split_once('(')
                .is_some_and(|(name, _)| name == expected_name)
        })
        .collect::<BTreeSet<_>>();
    Ok(!identities.is_empty())
}

/// Extracts a direct canonical string literal used as the first `post_rpc` argument.
fn extract_post_rpc_names(source: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let bytes = source.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"//") {
            cursor = skip_rust_line_comment(bytes, cursor);
            continue;
        }
        if bytes[cursor..].starts_with(b"/*") {
            cursor = skip_rust_block_comment(bytes, cursor)?;
            continue;
        }
        if let Some(end) = raw_rust_string_end(source, cursor)? {
            cursor = end;
            continue;
        }
        if bytes[cursor] == b'"' {
            cursor = skip_rust_quoted_string(bytes, cursor)?;
            continue;
        }
        if bytes[cursor] == b'\'' {
            cursor = skip_rust_char_or_lifetime(bytes, cursor)?;
            continue;
        }
        if is_rust_identifier_start(bytes[cursor]) {
            let identifier_start = cursor;
            cursor += 1;
            while cursor < bytes.len() && is_rust_identifier_continue(bytes[cursor]) {
                cursor += 1;
            }
            if &source[identifier_start..cursor] != "post_rpc" {
                continue;
            }
            let call_start = identifier_start;
            cursor = skip_rust_trivia(bytes, cursor)?;
            if bytes.get(cursor) != Some(&b'(') {
                continue;
            }
            cursor += 1;
            cursor = skip_rust_trivia(bytes, cursor)?;
            if bytes.get(cursor) != Some(&b'"') {
                return Err(format!(
                    "post_rpc call at byte {call_start} must use a direct string literal as its first argument"
                ));
            }
            let (name, after_name) = parse_rpc_name_literal(source, cursor, call_start)?;
            cursor = skip_rust_trivia(bytes, after_name)?;
            if bytes.get(cursor) != Some(&b',') {
                return Err(format!(
                    "post_rpc call at byte {call_start} must terminate its first argument with a comma"
                ));
            }
            names.push(name);
            cursor += 1;
            continue;
        }
        cursor += 1;
    }
    if names.is_empty() {
        return Err(format!(
            "no post_rpc calls found in expected source {}",
            PathBuf::from(AUDIT_UI_RPC_SOURCE).display()
        ));
    }
    Ok(names)
}

fn parse_rpc_name_literal(
    source: &str,
    opening_quote: usize,
    call_start: usize,
) -> Result<(String, usize), String> {
    let bytes = source.as_bytes();
    let mut cursor = opening_quote + 1;
    let name_start = cursor;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'"' => {
                let name = &source[name_start..cursor];
                if name.is_empty()
                    || !name.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
                {
                    return Err(format!(
                        "post_rpc call at byte {call_start} has a non-canonical RPC name"
                    ));
                }
                return Ok((name.to_owned(), cursor + 1));
            }
            b'\\' => {
                return Err(format!(
                    "post_rpc call at byte {call_start} must not escape its canonical RPC name"
                ));
            }
            byte if !byte.is_ascii() || byte.is_ascii_control() => {
                return Err(format!(
                    "post_rpc call at byte {call_start} has a non-ASCII RPC name"
                ));
            }
            _ => cursor += 1,
        }
    }
    Err(format!(
        "post_rpc call at byte {call_start} has an unterminated name"
    ))
}

fn skip_rust_trivia(bytes: &[u8], mut cursor: usize) -> Result<usize, String> {
    loop {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if bytes
            .get(cursor..)
            .is_some_and(|rest| rest.starts_with(b"//"))
        {
            cursor = skip_rust_line_comment(bytes, cursor);
        } else if bytes
            .get(cursor..)
            .is_some_and(|rest| rest.starts_with(b"/*"))
        {
            cursor = skip_rust_block_comment(bytes, cursor)?;
        } else {
            return Ok(cursor);
        }
    }
}

fn skip_rust_line_comment(bytes: &[u8], mut cursor: usize) -> usize {
    cursor += 2;
    while cursor < bytes.len() && bytes[cursor] != b'\n' {
        cursor += 1;
    }
    cursor
}

fn skip_rust_block_comment(bytes: &[u8], mut cursor: usize) -> Result<usize, String> {
    let mut depth = 1usize;
    cursor += 2;
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"/*") {
            depth = depth
                .checked_add(1)
                .ok_or_else(|| "Rust block-comment nesting overflow".to_owned())?;
            cursor += 2;
        } else if bytes[cursor..].starts_with(b"*/") {
            depth -= 1;
            cursor += 2;
            if depth == 0 {
                return Ok(cursor);
            }
        } else {
            cursor += 1;
        }
    }
    Err("unterminated Rust block comment while parsing post_rpc calls".to_owned())
}

fn skip_rust_quoted_string(bytes: &[u8], mut cursor: usize) -> Result<usize, String> {
    cursor += 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => {
                cursor = cursor
                    .checked_add(2)
                    .ok_or_else(|| "Rust string offset overflow".to_owned())?;
            }
            b'"' => return Ok(cursor + 1),
            _ => cursor += 1,
        }
    }
    Err("unterminated Rust string while parsing post_rpc calls".to_owned())
}

fn skip_rust_char_or_lifetime(bytes: &[u8], cursor: usize) -> Result<usize, String> {
    let Some(first) = bytes.get(cursor + 1) else {
        return Err("trailing Rust apostrophe while parsing post_rpc calls".to_owned());
    };
    if *first == b'\\' {
        if bytes.get(cursor + 3) == Some(&b'\'') {
            return Ok(cursor + 4);
        }
        return Err("malformed escaped Rust character literal".to_owned());
    }
    if bytes.get(cursor + 2) == Some(&b'\'') {
        return Ok(cursor + 3);
    }
    Ok(cursor + 1)
}

fn raw_rust_string_end(source: &str, cursor: usize) -> Result<Option<usize>, String> {
    let bytes = source.as_bytes();
    if bytes.get(cursor) != Some(&b'r') {
        return Ok(None);
    }
    let mut quote = cursor + 1;
    while bytes.get(quote) == Some(&b'#') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return Ok(None);
    }
    let hashes = quote - cursor - 1;
    let closing = format!("\"{}", "#".repeat(hashes));
    let content_start = quote + 1;
    source[content_start..]
        .find(&closing)
        .map(|relative| content_start + relative + closing.len())
        .map(Some)
        .ok_or_else(|| "unterminated raw Rust string while parsing post_rpc calls".to_owned())
}

fn is_rust_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_rust_identifier_continue(byte: u8) -> bool {
    is_rust_identifier_start(byte) || byte.is_ascii_digit()
}

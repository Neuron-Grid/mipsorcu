use std::collections::BTreeSet;
use std::fs;

use mipsorcu::FORBIDDEN_AUDIT_METADATA_KEYS;

const MIGRATION_PATH: &str = "supabase/migrations/300_create_audit_event_guards_and_rpc.sql";
const START_MARKER: &str = "-- FORBIDDEN_AUDIT_METADATA_KEYS_START";
const END_MARKER: &str = "-- FORBIDDEN_AUDIT_METADATA_KEYS_END";

#[test]
fn forbidden_keys_parity_between_rust_and_sql() {
    let migration =
        fs::read_to_string(MIGRATION_PATH).expect("forbidden-keys migration should be readable");
    let sql_keys = extract_sql_keys(&migration);
    let rust_keys = FORBIDDEN_AUDIT_METADATA_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(sql_keys, rust_keys);
}

fn extract_sql_keys(sql: &str) -> BTreeSet<String> {
    let (_, after_start) = sql
        .split_once(START_MARKER)
        .expect("start marker should exist in migration");
    let (key_block, _) = after_start
        .split_once(END_MARKER)
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

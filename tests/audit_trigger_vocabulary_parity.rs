use std::collections::HashSet;
use mipsorcu::audit::AuditTrigger;

/// Rust 側 AuditTrigger の語彙が SQL 側の許容値と一致することを検証
#[test]
fn rust_audit_trigger_values_match_sql_allowlist() {
    let rust_values: HashSet<&str> =
        [AuditTrigger::Startup, AuditTrigger::Background, AuditTrigger::Cli]
            .iter()
            .map(|t| t.as_str())
            .collect();

    let expected: HashSet<&str> = ["startup", "background", "cli"].iter().cloned().collect();

    assert_eq!(
        rust_values, expected,
        "Rust AuditTrigger values must be exactly startup, background, cli"
    );
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
            "unknown trigger '{}' must be rejected",
            unknown
        );
    }
}

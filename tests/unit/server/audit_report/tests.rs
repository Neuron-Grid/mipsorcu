use super::*;

#[test]
fn json_output_does_not_include_secret_material_words() {
    let report = populated_report();
    let output = render_json(&report).expect("json rendering succeeds");

    assert_no_forbidden_markers(&output);
    assert!(output.ends_with('\n'));
    assert!(output.contains("\"signature_verification\""));
    assert!(output.contains("\"verification_failures\""));
}

#[test]
fn markdown_output_does_not_include_secret_material_words() {
    let report = populated_report();
    let output = render_markdown(&report);

    assert_no_forbidden_markers(&output);
    assert!(output.contains("Signature verification valid"));
    assert!(output.contains("Signature verification detail"));
    assert!(output.contains("Verification failures"));
    assert!(output.contains("Monthly digests"));
}

fn assert_no_forbidden_markers(output: &str) {
    for forbidden in [
        "plaintext",
        "master_key",
        "data_key",
        "encrypted_data_key",
        "ciphertext",
        "service_role",
        "jwt",
        "authorization",
        "request_body",
        "response_body",
    ] {
        assert!(
            !output.contains(forbidden),
            "audit report output must not contain forbidden marker: {forbidden}"
        );
    }
}

fn populated_report() -> AuditReportJson {
    AuditReportJson {
        audit_event_count: 3,
        hash_chain_verification: crate::server::supabase::HashChainVerificationSummary {
            checked_count: 2,
            detail: None,
            valid: true,
        },
        integrity_check_status: CheckStatus {
            latest_result: Some("success".to_owned()),
            performed: true,
            total_count: 1,
        },
        integrity_checks: vec![crate::server::supabase::IntegrityCheckReportItem {
            checked_audit_event_count: 3,
            checked_secret_count: 1,
            checked_secret_version_count: 1,
            duration_ms: 12,
            occurred_at: "2026-05-01T02:00:00Z".to_owned(),
            result: "success".to_owned(),
            trigger: Some("cli".to_owned()),
            violation_count: 0,
        }],
        ledger_entry_count: 2,
        monthly_digests: vec![crate::server::supabase::MonthlyDigestReportItem {
            digest_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            end_sequence_no: 2,
            entry_count: 2,
            sequence_no: 2,
            start_sequence_no: 1,
            target_year_month: "2026-05".to_owned(),
        }],
        period_end: "2026-05-02T00:00:00Z".to_owned(),
        period_start: "2026-05-01T00:00:00Z".to_owned(),
        restore_test_status: CheckStatus {
            latest_result: Some("success".to_owned()),
            performed: true,
            total_count: 1,
        },
        restore_tests: vec![crate::server::supabase::RestoreTestReportItem {
            duration_ms: 34,
            occurred_at: "2026-05-01T03:00:00Z".to_owned(),
            result: "success".to_owned(),
            sample_count: 4,
            trigger: Some("cli".to_owned()),
        }],
        secret_count: 1,
        sequence_end: Some(2),
        sequence_start: Some(1),
        signature_key_versions: vec![crate::server::supabase::SignatureKeyVersionReportItem {
            key_version: 1,
            status: "active".to_owned(),
        }],
        signature_verification: SignatureVerificationSummary {
            checked_count: 2,
            detail: Some("signature_invalid at sequence 2".to_owned()),
            valid: false,
        },
        verification_failures: vec![crate::server::supabase::VerificationFailureReportItem {
            code: "signature_invalid".to_owned(),
            occurred_at: "2026-05-01T01:00:00Z".to_owned(),
            sequence_no: Some(2),
            source: "ledger_signature".to_owned(),
        }],
    }
}

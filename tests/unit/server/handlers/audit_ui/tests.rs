use super::*;

/// `AuditAction::parse` は canonical 文字列の厳密一致のみ受理し、`as_str()` はその
/// canonical 値を返す（[action.rs] 確認済み）。したがって受理される入力では
/// `parse(s).as_str() == s` が成立し、RPC へ canonical 値を送っても wire 値は不変。
/// このテストはその逆写像性（wire 同一性）の回帰ガード。
#[test]
fn audit_action_parse_is_strict_inverse_of_as_str() {
    for value in [
        "decrypt",
        "encrypt_create",
        "encrypt_rotate",
        "monthly_digest_generate",
        "audit_ui_read",
        "secret_alias_list",
        "scheduler_job",
    ] {
        let parsed = AuditAction::parse(value).expect("known action parses");
        assert_eq!(parsed.as_str(), value);
    }
}

#[test]
fn audit_result_parse_is_strict_inverse_of_as_str() {
    for value in ["success", "failure"] {
        let parsed = AuditResult::parse(value).expect("known result parses");
        assert_eq!(parsed.as_str(), value);
    }
}

#[test]
fn ledger_entry_type_parse_is_strict_inverse_of_as_str() {
    for value in [
        "secret_created",
        "secret_decrypted",
        "monthly_digest",
        "incident_detected",
    ] {
        let parsed = LedgerEntryType::parse(value).expect("known entry_type parses");
        assert_eq!(parsed.as_str(), value);
    }
}

#[test]
fn parse_optional_audit_action_none_is_none() {
    assert_eq!(parse_optional_audit_action(None).expect("ok"), None);
}

#[test]
fn parse_optional_audit_action_parses_known_value() {
    assert_eq!(
        parse_optional_audit_action(Some("decrypt")).expect("ok"),
        Some(AuditAction::Decrypt)
    );
}

#[test]
fn parse_optional_audit_action_rejects_unknown_value() {
    assert!(matches!(
        parse_optional_audit_action(Some("not_an_action")),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn parse_optional_result_none_is_none() {
    assert_eq!(parse_optional_result(None).expect("ok"), None);
}

#[test]
fn parse_optional_result_parses_known_values() {
    assert_eq!(
        parse_optional_result(Some("success")).expect("ok"),
        Some(AuditResult::Success)
    );
    assert_eq!(
        parse_optional_result(Some("failure")).expect("ok"),
        Some(AuditResult::Failure)
    );
}

#[test]
fn parse_optional_result_rejects_unknown_value() {
    assert!(matches!(
        parse_optional_result(Some("maybe")),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn parse_optional_ledger_entry_type_none_is_none() {
    assert_eq!(parse_optional_ledger_entry_type(None).expect("ok"), None);
}

#[test]
fn parse_optional_ledger_entry_type_parses_known_value() {
    assert_eq!(
        parse_optional_ledger_entry_type(Some("secret_created")).expect("ok"),
        Some(LedgerEntryType::SecretCreated)
    );
}

#[test]
fn parse_optional_ledger_entry_type_rejects_unknown_value() {
    assert!(matches!(
        parse_optional_ledger_entry_type(Some("not_a_real_type")),
        Err(ApiError::BadRequest(_))
    ));
}

/// 送信される wire 値（`parse(...).as_str()`）が入力と一致することを、handler が
/// RPC へ渡すマッピングと同じ式で確認する。
#[test]
fn normalized_wire_value_matches_input_for_accepted_action() {
    let action = parse_optional_audit_action(Some("monthly_digest_generate")).expect("ok");
    assert_eq!(
        action.map(|action| action.as_str().to_owned()),
        Some("monthly_digest_generate".to_owned())
    );
}

#[test]
fn normalized_wire_value_matches_input_for_accepted_ledger_entry_type() {
    let entry_type = parse_optional_ledger_entry_type(Some("monthly_digest")).expect("ok");
    assert_eq!(
        entry_type.map(|entry_type| entry_type.as_str().to_owned()),
        Some("monthly_digest".to_owned())
    );
}

#[test]
fn audit_ui_ledger_entries_params_serializes_entry_type_as_canonical_string() {
    let params = AuditUiLedgerEntriesParams {
        p_limit: 100,
        p_offset: 0,
        p_start_sequence_no: None,
        p_end_sequence_no: None,
        p_entry_type: Some(LedgerEntryType::SecretCreated),
        p_result: None,
    };

    let value = serde_json::to_value(&params).expect("params should serialize");
    assert_eq!(value["p_entry_type"], serde_json::json!("secret_created"));
}

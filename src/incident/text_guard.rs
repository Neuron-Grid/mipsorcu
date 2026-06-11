/// incident 通知の自由文（summary / affected_component / triage_url / correlation_id）へ
/// 秘密語が混入していないか部分一致 `contains` で弾く多層防御の禁止語集合。
///
/// 監査メタデータ forbidden 正本 `crate::FORBIDDEN_AUDIT_METADATA_KEYS` を**部分一致でカバー**
/// （正本の各語が自由文に現れたら必ず弾かれる）することが不変条件であり、その整合は
/// `tests/incident_text_guard_forbidden_parity.rs` の parity test で恒久強制する。正本へ語を
/// 追加したら本集合も追従する必要がある（追従漏れは parity test が CI で落とす。bug-07 参照）。
pub const FORBIDDEN_NOTIFICATION_TEXT: &[&str] = &[
    "alias_decryption_key",
    "alias_encryption_key",
    "alias_fingerprint_key",
    "authorization",
    "bearer_token",
    "ciphertext",
    "data_key",
    "decrypt_result",
    "decrypted",
    "ed25519_private_key",
    "encrypted_data_key",
    "jwt",
    "kek_value",
    "ledger_signing_key",
    "master_key",
    "nonce",
    "passphrase",
    "password",
    "plain_text",
    "plaintext",
    "raw_jwt",
    "request_body",
    "response_body",
    "secret_body",
    "secret_key",
    "secret_value",
    "service_role",
    "signature_private_key",
    "token",
    "wrapped_dek",
];

pub(super) fn validate_non_secret_text(value: &str, max_len: usize) -> Result<(), ()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() != value.len() || value.len() > max_len {
        return Err(());
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_graphic() || character == ' ')
    {
        return Err(());
    }
    let lower = value.to_ascii_lowercase();
    if FORBIDDEN_NOTIFICATION_TEXT
        .iter()
        .any(|forbidden| lower.contains(forbidden))
    {
        return Err(());
    }
    Ok(())
}

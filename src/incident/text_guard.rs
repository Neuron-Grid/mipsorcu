const FORBIDDEN_NOTIFICATION_TEXT: &[&str] = &[
    "alias_decryption_key",
    "alias_encryption_key",
    "authorization",
    "bearer_token",
    "ciphertext",
    "data_key",
    "decrypted",
    "encrypted_data_key",
    "jwt",
    "kek_value",
    "master_key",
    "nonce",
    "passphrase",
    "password",
    "plain_text",
    "plaintext",
    "raw_jwt",
    "request_body",
    "response_body",
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

use super::*;

#[test]
fn hmac_sha3_256_signature_is_64_char_lowercase_hex() {
    let secret = b"this-is-a-test-secret-32-bytes!!";
    let body = b"{\"foo\":\"bar\"}";
    let signature = compute_signature_hex(secret, body).expect("hmac ok");
    assert_eq!(signature.len(), 64);
    assert!(
        signature
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
    );
}

#[test]
fn hmac_signature_is_deterministic_for_identical_inputs() {
    let secret = b"deterministic-secret-value-32by!";
    let body = b"identical body";
    let first = compute_signature_hex(secret, body).expect("hmac ok");
    let second = compute_signature_hex(secret, body).expect("hmac ok");
    assert_eq!(first, second);
}

#[test]
fn hmac_signature_changes_when_body_changes() {
    let secret = b"secret-value-for-diff-check-32b!";
    let first = compute_signature_hex(secret, b"body-one").expect("hmac ok");
    let second = compute_signature_hex(secret, b"body-two").expect("hmac ok");
    assert_ne!(first, second);
}

#[test]
fn webhook_sink_reports_kind_name() {
    let secret = SecretString::new("test-secret").expect("secret");
    let sink = WebhookNotificationSink::new(
        reqwest::Client::builder().build().expect("client"),
        "https://example.invalid/incident",
        secret,
    );
    assert_eq!(sink.sink_name(), "webhook");
}

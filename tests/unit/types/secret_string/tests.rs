use super::*;

#[test]
fn new_accepts_non_empty_ascii() {
    let secret = SecretString::new("hello").expect("non-empty ascii must succeed");
    assert_eq!(secret.expose_secret(), "hello");
    assert_eq!(secret.len(), 5);
    assert!(!secret.is_empty());
}

#[test]
fn new_rejects_empty() {
    assert_eq!(SecretString::new(""), Err(SecretStringError::Empty));
}

#[test]
fn new_rejects_null_byte() {
    let value = "abc\0def";
    assert_eq!(
        SecretString::new(value),
        Err(SecretStringError::ContainsNullByte)
    );
}

#[test]
fn debug_does_not_leak_value() {
    let secret = SecretString::new("super-secret-token").expect("ok");
    let rendered = format!("{secret:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("super-secret-token"));
}

#[test]
fn zeroize_in_place_clears_internal_buffer_without_unsafe_observation() {
    let mut secret = SecretString::new("temporary-token").expect("ok");
    secret.zeroize_in_place();
    assert!(secret.as_bytes().iter().all(|byte| *byte == 0));
}

use super::*;

#[test]
fn dek_plaintext_zeroize_path_clears_bytes_without_unsafe_observation() {
    let mut dek = DekPlaintext::from_bytes([7u8; DATA_KEY_LENGTH]);

    dek.zeroize_in_place();

    assert_eq!(dek.as_bytes(), &[0u8; DATA_KEY_LENGTH]);
}

#[test]
fn dek_plaintext_debug_redacts_material() {
    let dek = DekPlaintext::from_bytes([7u8; DATA_KEY_LENGTH]);

    let rendered = format!("{dek:?}");

    assert_eq!(rendered, "DekPlaintext(<redacted>)");
    assert!(!rendered.contains("7, 7"));
}

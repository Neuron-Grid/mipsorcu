use super::*;

#[test]
fn token_new_rejects_empty() {
    let error = TimestampingToken::new(Vec::new()).expect_err("empty must be rejected");
    assert!(matches!(
        error,
        TimestampingServiceError::InvalidResponse { .. }
    ));
}

#[test]
fn token_new_accepts_one_byte() {
    let token = TimestampingToken::new(vec![0x01]).expect("one byte must be accepted");
    assert_eq!(token.len(), 1);
    assert!(!token.is_empty());
}

#[test]
fn token_new_rejects_oversize() {
    let bytes = vec![0u8; TIMESTAMPING_TOKEN_MAX_LENGTH + 1];
    let error = TimestampingToken::new(bytes).expect_err("oversize must be rejected");
    assert!(matches!(
        error,
        TimestampingServiceError::InvalidResponse { .. }
    ));
}

#[test]
fn token_debug_redacts_contents() {
    let token = TimestampingToken::new(vec![0xaa, 0xbb, 0xcc]).unwrap();
    let debug = format!("{token:?}");
    assert!(debug.contains("len"));
    assert!(!debug.contains("aa"));
    assert!(!debug.contains("bb"));
}

#[test]
fn token_hash_is_sha3_256() {
    let token = TimestampingToken::new(b"abc".to_vec()).unwrap();
    let hash = TimestampingTokenHash::from_token(&token);
    // SHA3-256("abc")
    assert_eq!(
        hash.to_hex(),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
}

#[test]
fn token_hash_hex_is_64_char_lowercase() {
    let token = TimestampingToken::new(vec![0x42; 100]).unwrap();
    let hex = TimestampingTokenHash::from_token(&token).to_hex();
    assert_eq!(hex.len(), 64);
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    );
}

#[test]
fn token_hash_is_deterministic() {
    let token = TimestampingToken::new(vec![0x01, 0x02, 0x03]).unwrap();
    let hash1 = TimestampingTokenHash::from_token(&token);
    let hash2 = TimestampingTokenHash::from_token(&token);
    assert_eq!(hash1, hash2);
}

#[test]
fn token_hash_differs_for_different_tokens() {
    let token_a = TimestampingToken::new(vec![0x01]).unwrap();
    let token_b = TimestampingToken::new(vec![0x02]).unwrap();
    let hash_a = TimestampingTokenHash::from_token(&token_a);
    let hash_b = TimestampingTokenHash::from_token(&token_b);
    assert_ne!(hash_a, hash_b);
}

#[test]
fn error_display_backend_failed() {
    let error = TimestampingServiceError::BackendFailed {
        code: "network".to_owned(),
    };
    assert_eq!(format!("{error}"), "timestamping backend failed: network");
}

#[test]
fn error_display_invalid_response() {
    let error = TimestampingServiceError::InvalidResponse {
        reason: "empty payload",
    };
    assert_eq!(
        format!("{error}"),
        "timestamping invalid response: empty payload"
    );
}

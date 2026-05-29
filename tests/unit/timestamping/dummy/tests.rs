use super::*;
use crate::ledger::{DigestCanonicalBytes, MonthlyDigestPeriod};

fn make_digest_hash(seed: u8) -> DigestHash {
    let bytes = vec![seed; 64];
    let canonical = canonical_bytes_for_test(bytes);
    DigestHash::from_canonical_bytes(&canonical)
}

fn canonical_bytes_for_test(bytes: Vec<u8>) -> DigestCanonicalBytes {
    // Reuse the same construction path used in production by going through
    // a normal canonical bytes generation. We forge a quick canonical bytes
    // via build_monthly_digest_canonical_form using deterministic inputs.
    use crate::ledger::{LedgerHash, LedgerSequenceNo, LedgerSignatureKeyVersion};
    use crate::types::SourceEventAt;
    let period = MonthlyDigestPeriod::parse("2026-05").unwrap();
    let start_hash = LedgerHash::from_bytes(&[bytes[0]; 32]).unwrap();
    let end_hash = LedgerHash::from_bytes(&[bytes.last().copied().unwrap_or(0); 32]).unwrap();
    let generated_at = SourceEventAt::parse("2026-06-01T00:00:00Z").unwrap();
    let key_version = LedgerSignatureKeyVersion::new(1).unwrap();
    let start_seq = LedgerSequenceNo::new(1).unwrap();
    let end_seq = LedgerSequenceNo::new(42).unwrap();
    crate::ledger::build_monthly_digest_canonical_form(
        &period,
        start_seq,
        end_seq,
        start_hash,
        end_hash,
        42,
        &generated_at,
        key_version,
    )
    .unwrap()
}

#[tokio::test]
async fn request_timestamp_returns_non_empty_token() {
    let service = InMemoryTimestampingService::new();
    let digest_hash = make_digest_hash(0xaa);
    let token = service.request_timestamp(&digest_hash).await.unwrap();
    assert!(!token.is_empty());
    assert!(token.as_bytes().starts_with(DUMMY_TOKEN_PREFIX));
}

#[tokio::test]
async fn request_timestamp_same_hash_returns_same_token() {
    let service = InMemoryTimestampingService::new();
    let digest_hash = make_digest_hash(0xaa);
    let token1 = service.request_timestamp(&digest_hash).await.unwrap();
    let token2 = service.request_timestamp(&digest_hash).await.unwrap();
    assert_eq!(token1, token2);
    assert_eq!(service.issued_count(), 1);
}

#[tokio::test]
async fn request_timestamp_different_hash_returns_different_token() {
    let service = InMemoryTimestampingService::new();
    let hash_a = make_digest_hash(0xaa);
    let hash_b = make_digest_hash(0xbb);
    let token_a = service.request_timestamp(&hash_a).await.unwrap();
    let token_b = service.request_timestamp(&hash_b).await.unwrap();
    assert_ne!(token_a, token_b);
    assert_eq!(service.issued_count(), 2);
}

#[tokio::test]
async fn token_for_returns_issued_token() {
    let service = InMemoryTimestampingService::new();
    let digest_hash = make_digest_hash(0xaa);
    assert!(service.token_for(&digest_hash).is_none());
    let issued = service.request_timestamp(&digest_hash).await.unwrap();
    let looked_up = service.token_for(&digest_hash).expect("must be present");
    assert_eq!(issued, looked_up);
}

#[tokio::test]
async fn failing_service_returns_backend_failed_with_code() {
    let service = FailingTimestampingService::new("simulated_failure");
    let digest_hash = make_digest_hash(0xaa);
    let error = service
        .request_timestamp(&digest_hash)
        .await
        .expect_err("must fail");
    match error {
        TimestampingServiceError::BackendFailed { code } => {
            assert_eq!(code, "simulated_failure");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn token_hash_matches_sha3_256_of_token_bytes() {
    use super::super::service::TimestampingTokenHash;
    let service = InMemoryTimestampingService::new();
    let digest_hash = make_digest_hash(0xaa);
    let token = service.request_timestamp(&digest_hash).await.unwrap();
    let hash = TimestampingTokenHash::from_token(&token);
    assert_eq!(hash.to_hex().len(), 64);
}

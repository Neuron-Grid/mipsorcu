//! `RetryingTimestampingService` の retry / fallback / deadline テスト。
//!
//! `#[tokio::test(start_paused = true)]` で時計を停止し、backoff の sleep を
//! 実時間待ちなしで進める。

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::*;

use crate::ledger::{
    DigestHash, LedgerHash, LedgerSequenceNo, LedgerSignatureKeyVersion, MonthlyDigestPeriod,
    build_monthly_digest_canonical_form,
};
use crate::timestamping::{TimestampVerification, VerifiedTimestamp};
use crate::types::SourceEventAt;

/// 先頭 `fail_times` 回は失敗し、それ以降は成功する scripted backend。
/// 呼び出し回数を外部から観測するため counter を共有する。
struct ScriptedBackend {
    fail_times: u32,
    calls: Arc<AtomicU32>,
}

impl ScriptedBackend {
    fn new(fail_times: u32, calls: Arc<AtomicU32>) -> Self {
        Self { fail_times, calls }
    }
}

impl TimestampingService for ScriptedBackend {
    async fn request_timestamp(
        &self,
        _digest_hash: &DigestHash,
    ) -> Result<TimestampingToken, TimestampingServiceError> {
        let nth = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if nth <= self.fail_times {
            Err(TimestampingServiceError::BackendFailed {
                code: "scripted_fail".to_owned(),
            })
        } else {
            TimestampingToken::new(b"DUMMY-TST-V1:ok".to_vec())
        }
    }

    async fn verify_timestamp(
        &self,
        _token: &TimestampingToken,
        _expected_hash: &DigestHash,
    ) -> Result<TimestampVerification, TimestampingServiceError> {
        Ok(TimestampVerification::Valid(VerifiedTimestamp::default()))
    }

    fn provider_kind(&self) -> TimestampingProviderKind {
        TimestampingProviderKind::Rfc3161
    }
}

fn test_digest_hash() -> DigestHash {
    let period = MonthlyDigestPeriod::parse("2026-05").unwrap();
    let canonical = build_monthly_digest_canonical_form(
        &period,
        LedgerSequenceNo::new(1).unwrap(),
        LedgerSequenceNo::new(42).unwrap(),
        LedgerHash::from_bytes(&[0xaa; 32]).unwrap(),
        LedgerHash::from_bytes(&[0xbb; 32]).unwrap(),
        42,
        &SourceEventAt::parse("2026-06-01T00:00:00Z").unwrap(),
        LedgerSignatureKeyVersion::new(1).unwrap(),
    )
    .unwrap();
    DigestHash::from_canonical_bytes(&canonical)
}

fn policy() -> TimestampingRetryPolicy {
    TimestampingRetryPolicy {
        max_attempts_per_url: 3,
        base_delay: Duration::from_secs(2),
        max_total: Duration::from_secs(600),
    }
}

#[tokio::test(start_paused = true)]
async fn retries_same_url_until_success() {
    let calls = Arc::new(AtomicU32::new(0));
    let backend = ScriptedBackend::new(2, calls.clone());
    let service = RetryingTimestampingService::new(vec![backend], policy());

    let result = service.request_timestamp(&test_digest_hash()).await;

    assert!(result.is_ok());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "should succeed on the 3rd attempt"
    );
}

#[tokio::test(start_paused = true)]
async fn falls_back_to_next_url_after_exhausting_first() {
    let first = Arc::new(AtomicU32::new(0));
    let second = Arc::new(AtomicU32::new(0));
    let service = RetryingTimestampingService::new(
        vec![
            ScriptedBackend::new(u32::MAX, first.clone()),
            ScriptedBackend::new(0, second.clone()),
        ],
        policy(),
    );

    let result = service.request_timestamp(&test_digest_hash()).await;

    assert!(result.is_ok());
    assert_eq!(
        first.load(Ordering::SeqCst),
        3,
        "first URL retried up to the cap"
    );
    assert_eq!(
        second.load(Ordering::SeqCst),
        1,
        "second URL succeeded on first try"
    );
}

#[tokio::test(start_paused = true)]
async fn all_urls_failing_returns_error_after_full_fallback() {
    let first = Arc::new(AtomicU32::new(0));
    let second = Arc::new(AtomicU32::new(0));
    let service = RetryingTimestampingService::new(
        vec![
            ScriptedBackend::new(u32::MAX, first.clone()),
            ScriptedBackend::new(u32::MAX, second.clone()),
        ],
        policy(),
    );

    let result = service.request_timestamp(&test_digest_hash()).await;

    assert!(matches!(
        result,
        Err(TimestampingServiceError::BackendFailed { .. })
    ));
    assert_eq!(first.load(Ordering::SeqCst), 3);
    assert_eq!(second.load(Ordering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn empty_backends_returns_configuration_error() {
    let service: RetryingTimestampingService<ScriptedBackend> =
        RetryingTimestampingService::new(Vec::new(), policy());

    let error = service
        .request_timestamp(&test_digest_hash())
        .await
        .expect_err("no backends configured");

    match error {
        TimestampingServiceError::BackendFailed { code } => {
            assert_eq!(code, "rfc3161_no_tsa_url_configured");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn zero_deadline_stops_before_any_attempt() {
    let calls = Arc::new(AtomicU32::new(0));
    let mut policy = policy();
    policy.max_total = Duration::ZERO;
    let service =
        RetryingTimestampingService::new(vec![ScriptedBackend::new(0, calls.clone())], policy);

    let result = service.request_timestamp(&test_digest_hash()).await;

    assert!(result.is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "deadline check precedes the attempt"
    );
}

#[tokio::test(start_paused = true)]
async fn verify_delegates_to_first_backend() {
    let service = RetryingTimestampingService::new(
        vec![ScriptedBackend::new(0, Arc::new(AtomicU32::new(0)))],
        policy(),
    );
    let token = TimestampingToken::new(b"whatever".to_vec()).unwrap();
    let outcome = service
        .verify_timestamp(&token, &test_digest_hash())
        .await
        .unwrap();
    assert!(matches!(outcome, TimestampVerification::Valid(_)));
}

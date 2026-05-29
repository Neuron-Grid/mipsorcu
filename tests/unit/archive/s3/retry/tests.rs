use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

#[tokio::test(start_paused = true)]
async fn returns_immediately_on_success() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_clone = attempts.clone();
    let result: Result<u32, _> = run_with_backoff(3, Duration::from_millis(1), move || {
        let attempts_clone = attempts_clone.clone();
        async move {
            attempts_clone.fetch_add(1, Ordering::SeqCst);
            Ok(42u32)
        }
    })
    .await;
    assert_eq!(result.unwrap(), 42);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn retries_retriable_errors_up_to_max() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_clone = attempts.clone();
    let result: Result<u32, _> = run_with_backoff(2, Duration::from_millis(1), move || {
        let attempts_clone = attempts_clone.clone();
        async move {
            attempts_clone.fetch_add(1, Ordering::SeqCst);
            Err(S3BackendError::ServerError { status: 503 })
        }
    })
    .await;
    assert!(matches!(
        result,
        Err(S3BackendError::ServerError { status: 503 })
    ));
    // initial attempt + 2 retries = 3 total
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn does_not_retry_non_retriable() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_clone = attempts.clone();
    let result: Result<u32, _> = run_with_backoff(5, Duration::from_millis(1), move || {
        let attempts_clone = attempts_clone.clone();
        async move {
            attempts_clone.fetch_add(1, Ordering::SeqCst);
            Err(S3BackendError::OverwriteRejected)
        }
    })
    .await;
    assert!(matches!(result, Err(S3BackendError::OverwriteRejected)));
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn succeeds_after_retry() {
    let attempts = Arc::new(AtomicU32::new(0));
    let attempts_clone = attempts.clone();
    let result: Result<u32, _> = run_with_backoff(3, Duration::from_millis(1), move || {
        let attempts_clone = attempts_clone.clone();
        async move {
            let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
            if count < 2 {
                Err(S3BackendError::Network("connection reset".to_owned()))
            } else {
                Ok(7u32)
            }
        }
    })
    .await;
    assert_eq!(result.unwrap(), 7);
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[test]
fn backoff_delay_doubles() {
    let base = Duration::from_millis(100);
    assert_eq!(backoff_delay(base, 0), Duration::from_millis(100));
    assert_eq!(backoff_delay(base, 1), Duration::from_millis(200));
    assert_eq!(backoff_delay(base, 2), Duration::from_millis(400));
}

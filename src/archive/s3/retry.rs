//! 指数バックオフ inline リトライ。
//!
//! retriable error（接続失敗 / 5xx / 408 / 429）のみリトライし、non-retriable
//! は即時失敗する。永続キューは持たない（T13 で実装）。

use std::time::Duration;

use super::error::S3BackendError;

/// 指数バックオフでリトライする。
///
/// - `max_retries == 0` の場合は 1 回だけ試行する
/// - 各リトライ間隔は `base * 2^attempt`（attempt は 0 から）
/// - `S3BackendError::is_retriable() == false` のエラーは即座に返す
pub async fn run_with_backoff<F, Fut, T>(
    max_retries: u32,
    base: Duration,
    mut operation: F,
) -> Result<T, S3BackendError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, S3BackendError>>,
{
    let mut attempt: u32 = 0;
    loop {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                if !error.is_retriable() || attempt >= max_retries {
                    return Err(error);
                }
                let delay = backoff_delay(base, attempt);
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
        }
    }
}

fn backoff_delay(base: Duration, attempt: u32) -> Duration {
    let multiplier = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
    let nanos = u64::try_from(base.as_nanos())
        .ok()
        .and_then(|nanos| nanos.checked_mul(multiplier))
        .unwrap_or(u64::MAX);
    Duration::from_nanos(nanos)
}

#[cfg(test)]
mod tests {
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
}

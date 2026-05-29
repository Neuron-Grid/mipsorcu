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
#[path = "../../../tests/unit/archive/s3/retry/tests.rs"]
mod tests;

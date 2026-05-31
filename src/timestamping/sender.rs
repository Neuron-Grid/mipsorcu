//! 複数 TSA への順次 fallback + 指数 backoff retry を担う sender（task-11、ADR-0040）。
//!
//! [`RetryingTimestampingService`] は複数の backend（1 TSA URL = 1 backend）を
//! **順次 fallback** し、各 backend を指数 backoff で最大回数まで retry する。
//! 並列送信は行わない（v0.2.0 制約）。
//!
//! retry policy（ADR-0040 / task-11）:
//! - 各 URL ごとに最大 `max_attempts_per_url` 回（既定 3 回）
//! - 試行間隔は `base_delay * 2^attempt` の指数 backoff
//! - 全 URL・全試行を通じた総時間上限 `max_total`（既定 10 分）
//!
//! `verify_timestamp` は token 内の情報のみで完結するオフライン検証であり、
//! URL・retry に依存しないため先頭 backend に委譲する。

use std::time::Duration;

use tokio::time::Instant;

use crate::ledger::DigestHash;

use super::service::{
    TimestampVerification, TimestampingProviderKind, TimestampingService, TimestampingServiceError,
    TimestampingToken,
};

/// timestamping の retry / fallback policy。
#[derive(Debug, Clone)]
pub struct TimestampingRetryPolicy {
    /// 1 TSA URL あたりの最大試行回数。
    pub max_attempts_per_url: u32,
    /// 指数 backoff の初期間隔。
    pub base_delay: Duration,
    /// 全 URL・全試行を通じた総時間上限。
    pub max_total: Duration,
}

impl Default for TimestampingRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts_per_url: 3,
            base_delay: Duration::from_secs(2),
            max_total: Duration::from_secs(600),
        }
    }
}

/// 複数 backend を順次 fallback + retry する wrapper。
///
/// `backends` は fallback 順（先頭優先）の backend 列。各要素は単一 TSA URL を
/// 担う [`super::rfc3161::Rfc3161TimestampingService`] を想定するが、`TimestampingService`
/// を実装する任意の型でよい（テストで scripted backend を差し込める）。
pub struct RetryingTimestampingService<S> {
    backends: Vec<S>,
    policy: TimestampingRetryPolicy,
}

impl<S: TimestampingService> RetryingTimestampingService<S> {
    pub fn new(backends: Vec<S>, policy: TimestampingRetryPolicy) -> Self {
        Self { backends, policy }
    }

    /// backend 数（設定された TSA URL 数）。
    pub fn backend_count(&self) -> usize {
        self.backends.len()
    }
}

impl<S: TimestampingService> TimestampingService for RetryingTimestampingService<S> {
    async fn request_timestamp(
        &self,
        digest_hash: &DigestHash,
    ) -> Result<TimestampingToken, TimestampingServiceError> {
        if self.backends.is_empty() {
            return Err(TimestampingServiceError::BackendFailed {
                code: "rfc3161_no_tsa_url_configured".to_owned(),
            });
        }

        let deadline = Instant::now() + self.policy.max_total;
        let mut last_error: Option<TimestampingServiceError> = None;

        for (tsa_index, backend) in self.backends.iter().enumerate() {
            for attempt in 0..self.policy.max_attempts_per_url {
                if Instant::now() >= deadline {
                    return Err(
                        last_error.unwrap_or(TimestampingServiceError::BackendFailed {
                            code: "rfc3161_retry_deadline_exceeded".to_owned(),
                        }),
                    );
                }

                match backend.request_timestamp(digest_hash).await {
                    Ok(token) => return Ok(token),
                    Err(error) => {
                        tracing::warn!(
                            tsa_index,
                            attempt = attempt + 1,
                            max_attempts = self.policy.max_attempts_per_url,
                            error = %error,
                            "timestamping request attempt failed; will retry or fall back"
                        );
                        last_error = Some(error);

                        let is_last_attempt = attempt + 1 >= self.policy.max_attempts_per_url;
                        if !is_last_attempt {
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            if remaining.is_zero() {
                                break;
                            }
                            let delay =
                                backoff_delay(self.policy.base_delay, attempt).min(remaining);
                            tokio::time::sleep(delay).await;
                        }
                    }
                }
            }
        }

        Err(
            last_error.unwrap_or(TimestampingServiceError::BackendFailed {
                code: "rfc3161_all_tsa_failed".to_owned(),
            }),
        )
    }

    async fn verify_timestamp(
        &self,
        token: &TimestampingToken,
        expected_hash: &DigestHash,
    ) -> Result<TimestampVerification, TimestampingServiceError> {
        match self.backends.first() {
            Some(backend) => backend.verify_timestamp(token, expected_hash).await,
            None => Err(TimestampingServiceError::BackendFailed {
                code: "rfc3161_no_tsa_url_configured".to_owned(),
            }),
        }
    }

    fn provider_kind(&self) -> TimestampingProviderKind {
        self.backends
            .first()
            .map_or(TimestampingProviderKind::Rfc3161, |backend| {
                backend.provider_kind()
            })
    }
}

/// `base * 2^attempt` の指数 backoff 間隔（overflow は飽和）。
/// `src/archive/s3/retry.rs` と同方式。
fn backoff_delay(base: Duration, attempt: u32) -> Duration {
    let multiplier = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
    let nanos = u64::try_from(base.as_nanos())
        .ok()
        .and_then(|nanos| nanos.checked_mul(multiplier))
        .unwrap_or(u64::MAX);
    Duration::from_nanos(nanos)
}

#[cfg(test)]
#[path = "../../tests/unit/timestamping/sender/tests.rs"]
mod tests;

//! `S3ImmutableArchiveBackend` — `ArchiveBackend` trait の production 実装。
//!
//! 信頼境界ノート: `put_object` の引数型は trait 経由で `&ArchiveExportPackage`
//! 固定。`Plaintext` / `MasterKey` / `DataKey` / `RawJwt` を型レベルで受け取
//! れない構造を維持する。
//!
//! env から読んだ S3 アクセスキーは本 backend 内部の `S3ArchiveBackendConfig`
//! にのみ保持する。Supabase へは絶対に渡さない。`Debug` で credentials を
//! `<redacted>` 化することでログ経由の漏洩を防ぐ。

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use crate::archive::backend::{
    ArchiveBackend, ArchiveBackendError, ArchiveObjectKey, ArchiveVerifyOutcome,
};
use crate::archive::export::ArchiveExportPackage;

use super::client::{HeadOutcome, PutOutcome, S3HttpClient};
use super::config::S3ArchiveBackendConfig;
use super::retry::run_with_backoff;

/// 現在時刻取得関数。テストでは固定時刻を注入する。
type NowFn = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;

#[derive(Clone)]
pub struct S3ImmutableArchiveBackend {
    config: Arc<S3ArchiveBackendConfig>,
    http: reqwest::Client,
    now: NowFn,
}

impl S3ImmutableArchiveBackend {
    pub fn new(config: S3ArchiveBackendConfig, http: reqwest::Client) -> Self {
        Self {
            config: Arc::new(config),
            http,
            now: Arc::new(OffsetDateTime::now_utc),
        }
    }

    /// テスト用: 現在時刻を固定するコンストラクタ。
    #[doc(hidden)]
    pub fn new_with_clock(
        config: S3ArchiveBackendConfig,
        http: reqwest::Client,
        now: impl Fn() -> OffsetDateTime + Send + Sync + 'static,
    ) -> Self {
        Self {
            config: Arc::new(config),
            http,
            now: Arc::new(now),
        }
    }

    pub fn config(&self) -> &S3ArchiveBackendConfig {
        &self.config
    }

    fn http_client(&self) -> S3HttpClient<'_> {
        S3HttpClient {
            config: &self.config,
            http: &self.http,
        }
    }

    fn retry_settings(&self) -> (u32, Duration) {
        (
            self.config.max_retries(),
            Duration::from_millis(self.config.retry_base_millis()),
        )
    }
}

impl std::fmt::Debug for S3ImmutableArchiveBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("S3ImmutableArchiveBackend")
            .field("config", &self.config)
            .finish()
    }
}

impl ArchiveBackend for S3ImmutableArchiveBackend {
    async fn put_object(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
    ) -> Result<(), ArchiveBackendError> {
        let body = package.to_json_bytes()?;
        let (max_retries, base) = self.retry_settings();
        let key_str = key.as_str().to_owned();

        run_with_backoff(max_retries, base, || {
            let body = body.clone();
            let key_str = key_str.clone();
            let now = (self.now)();
            async move {
                match self.http_client().put_object(&key_str, body, now).await? {
                    PutOutcome::Created => Ok(()),
                }
            }
        })
        .await
        .map_err(ArchiveBackendError::from)
    }

    async fn verify_object(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
    ) -> Result<ArchiveVerifyOutcome, ArchiveBackendError> {
        let expected = package.to_json_bytes()?;
        let (max_retries, base) = self.retry_settings();
        let key_str = key.as_str().to_owned();

        let stored = run_with_backoff(max_retries, base, || {
            let key_str = key_str.clone();
            let now = (self.now)();
            async move { self.http_client().get_object_bytes(&key_str, now).await }
        })
        .await
        .map_err(ArchiveBackendError::from)?;

        match stored {
            None => Ok(ArchiveVerifyOutcome::NotFound),
            Some(bytes) if bytes == expected => Ok(ArchiveVerifyOutcome::Valid),
            Some(_) => Ok(ArchiveVerifyOutcome::ContentMismatch),
        }
    }

    async fn list_objects(&self) -> Result<Vec<ArchiveObjectKey>, ArchiveBackendError> {
        // S3 LIST は ListObjectsV2 で実装可能だが、本 backend での list の用途
        // は限定的（運用者向け検証）。MVP 範囲では未実装とし、上位 use case の
        // 検証経路は HEAD/GET (`verify_object`) を使う。先回り実装回避のため
        // ここでは明示的 `BackendFailed` を返す。
        Err(ArchiveBackendError::BackendFailed {
            code: "archive_export_list_unimplemented".to_owned(),
        })
    }
}

/// `verify_object` で HEAD のみを行いたい場合の補助 API（運用診断用）。
impl S3ImmutableArchiveBackend {
    pub async fn object_exists(&self, key: &ArchiveObjectKey) -> Result<bool, ArchiveBackendError> {
        let (max_retries, base) = self.retry_settings();
        let key_str = key.as_str().to_owned();
        let outcome = run_with_backoff(max_retries, base, || {
            let key_str = key_str.clone();
            let now = (self.now)();
            async move { self.http_client().head_object(&key_str, now).await }
        })
        .await
        .map_err(ArchiveBackendError::from)?;
        Ok(matches!(outcome, HeadOutcome::Found))
    }
}

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
use crate::archive::opaque::ArchiveOpaqueObject;

use super::client::{HeadOutcome, PutOutcome, S3HttpClient};
use super::config::S3ArchiveBackendConfig;
use super::error::S3BackendError;
use super::queue::{ArchivePutOrQueueOutcome, LocalArchiveQueue, ResendArchiveSummary};
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

    async fn put_object_bytes(
        &self,
        key: &ArchiveObjectKey,
        body: Vec<u8>,
    ) -> Result<(), ArchiveBackendError> {
        match self.put_object_bytes_strict(key, body.clone()).await {
            Ok(()) => Ok(()),
            Err(S3BackendError::OverwriteRejected) => {
                self.verify_existing_object_bytes(key, body).await
            }
            Err(error) => Err(ArchiveBackendError::from(error)),
        }
    }

    async fn put_object_bytes_strict(
        &self,
        key: &ArchiveObjectKey,
        body: Vec<u8>,
    ) -> Result<(), S3BackendError> {
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
    }

    async fn get_object_bytes_with_retry(
        &self,
        key: &ArchiveObjectKey,
    ) -> Result<Option<Vec<u8>>, S3BackendError> {
        let (max_retries, base) = self.retry_settings();
        let key_str = key.as_str().to_owned();

        run_with_backoff(max_retries, base, || {
            let key_str = key_str.clone();
            let now = (self.now)();
            async move { self.http_client().get_object_bytes(&key_str, now).await }
        })
        .await
    }

    async fn verify_existing_object_bytes(
        &self,
        key: &ArchiveObjectKey,
        expected: Vec<u8>,
    ) -> Result<(), ArchiveBackendError> {
        match self
            .get_object_bytes_with_retry(key)
            .await
            .map_err(ArchiveBackendError::from)?
        {
            Some(bytes) if bytes == expected => Ok(()),
            Some(_) => Err(ArchiveBackendError::BackendFailed {
                code: "archive_export_content_mismatch".to_owned(),
            }),
            None => Err(ArchiveBackendError::BackendFailed {
                code: "archive_export_not_found".to_owned(),
            }),
        }
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
        self.put_object_bytes(key, body).await
    }

    async fn verify_object(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
    ) -> Result<ArchiveVerifyOutcome, ArchiveBackendError> {
        let expected = package.to_json_bytes()?;
        let stored = self
            .get_object_bytes_with_retry(key)
            .await
            .map_err(ArchiveBackendError::from)?;

        match stored {
            None => Ok(ArchiveVerifyOutcome::NotFound),
            Some(bytes) if bytes == expected => Ok(ArchiveVerifyOutcome::Valid),
            Some(_) => Ok(ArchiveVerifyOutcome::ContentMismatch),
        }
    }

    async fn list_objects(&self) -> Result<Vec<ArchiveObjectKey>, ArchiveBackendError> {
        let (max_retries, base) = self.retry_settings();
        let mut token: Option<String> = None;
        let mut keys = Vec::new();

        loop {
            let token_for_request = token.clone();
            let page = run_with_backoff(max_retries, base, || {
                let token_for_request = token_for_request.clone();
                let now = (self.now)();
                async move {
                    self.http_client()
                        .list_objects_v2(token_for_request.as_deref(), now)
                        .await
                }
            })
            .await
            .map_err(ArchiveBackendError::from)?;

            for raw_key in page.keys {
                keys.push(ArchiveObjectKey::new(raw_key)?);
            }

            match page.next_continuation_token {
                Some(next) if !next.is_empty() => token = Some(next),
                _ => break,
            }
        }

        Ok(keys)
    }

    async fn put_opaque_object(
        &self,
        key: &ArchiveObjectKey,
        object: &ArchiveOpaqueObject,
    ) -> Result<(), ArchiveBackendError> {
        // digest と同じ Object Lock / overwrite 拒否 / 指数 backoff 経路を再利用する。
        self.put_object_bytes(key, object.as_bytes().to_vec()).await
    }

    async fn get_opaque_object(
        &self,
        key: &ArchiveObjectKey,
    ) -> Result<Option<Vec<u8>>, ArchiveBackendError> {
        self.get_object_bytes_with_retry(key)
            .await
            .map_err(ArchiveBackendError::from)
    }
}

/// `verify_object` で HEAD のみを行いたい場合の補助 API（運用診断用）。
impl S3ImmutableArchiveBackend {
    /// Attempts to PUT an object; if the backend returns a retriable failure
    /// after inline retries, persists the non-secret archive payload to a local
    /// queue for later resend.
    pub async fn put_object_or_enqueue(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
        queue: &LocalArchiveQueue,
    ) -> Result<ArchivePutOrQueueOutcome, ArchiveBackendError> {
        match self.put_object(key, package).await {
            Ok(()) => Ok(ArchivePutOrQueueOutcome::PutSucceeded),
            Err(ArchiveBackendError::BackendFailed { code })
                if retriable_archive_backend_code(&code) =>
            {
                let queue = queue.clone();
                let key = key.clone();
                let payload = package.to_json_bytes()?;
                tokio::task::spawn_blocking(move || queue.append_pending_bytes(&key, payload))
                    .await
                    .map_err(|_| ArchiveBackendError::BackendFailed {
                        code: "archive_export_queue_join_failed".to_owned(),
                    })?
                    .map_err(ArchiveBackendError::from)?;
                Ok(ArchivePutOrQueueOutcome::Queued)
            }
            Err(error) => Err(error),
        }
    }

    /// Resends all pending archive queue records and appends sent markers for
    /// successful deliveries. Failures are counted and left pending.
    pub async fn resend_queued_objects(
        &self,
        queue: &LocalArchiveQueue,
    ) -> Result<ResendArchiveSummary, ArchiveBackendError> {
        let queue_for_read = queue.clone();
        let pending = tokio::task::spawn_blocking(move || queue_for_read.pending_objects())
            .await
            .map_err(|_| ArchiveBackendError::BackendFailed {
                code: "archive_export_queue_join_failed".to_owned(),
            })?
            .map_err(ArchiveBackendError::from)?;

        let mut summary = ResendArchiveSummary {
            attempted: pending.len(),
            sent: 0,
            failed: 0,
        };

        for queued in pending {
            match self
                .put_object_bytes(&queued.key, queued.payload.clone())
                .await
            {
                Ok(()) => {
                    let queue_for_mark = queue.clone();
                    let queued_for_mark = queued.clone();
                    match tokio::task::spawn_blocking(move || {
                        queue_for_mark.mark_sent(&queued_for_mark)
                    })
                    .await
                    {
                        Ok(Ok(())) => summary.sent += 1,
                        _ => summary.failed += 1,
                    }
                }
                Err(_) => summary.failed += 1,
            }
        }

        Ok(summary)
    }
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

fn retriable_archive_backend_code(code: &str) -> bool {
    matches!(
        code,
        "archive_export_network_failed" | "archive_export_server_error"
    )
}

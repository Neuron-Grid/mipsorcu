//! `SiemForwarder` — sink + buffer + 警告状態の合成レイヤ。
//!
//! 設計上の重要ポイント:
//!
//! 1. **`forward()` は `Result` を返さない**。代わりに [`SiemForwardOutcome`]
//!    （`SentDirect` / `Buffered` / `BufferingFailed`）を返す。これにより
//!    呼び出し側で `?` による失敗伝播が型レベルで不可能になり、
//!    「SIEM 送信失敗で secret 保存・復号が失敗しない」を構造的に強制する。
//! 2. **長期失敗状態は `SiemForwarderStatus` に持つ**。`forward()` が失敗した
//!    時点で `failure_since` が記録され、`resend_pending` が成功した時点で
//!    クリアされる。ヘルスチェック層は `SiemForwarderStatus::is_long_failure`
//!    を呼ぶことで警告判定できる。
//! 3. **失敗監査ヘルパ `build_siem_forward_failure_audit_event` を提供**する。
//!    これは `AuditEvent` を構築するのみで Supabase 送信は行わない
//!    （SIEM 統合範囲では Supabase migration を投入しないため）。後続タスクで
//!    `SupabaseClient::call_append_audit_event` 等に渡すことを想定する。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use time::OffsetDateTime;

use crate::audit::{
    AuditAction, AuditEvent, AuditEventError, AuditEventId, AuditEventParts, AuditResult,
    RequestId, SiemBufferFlushedMetadata, SiemEventFailedMetadata, SiemEventForwardedMetadata,
    SiemForwardFailureMetadata,
};
use crate::types::SourceEventAt;

use super::buffer::LocalSiemFallbackBuffer;
use super::event::SiemEvent;
use super::sink::{
    ForwardReceipt, SIEM_MAX_BATCH_SIZE, SiemExporterKind, SiemSink, SiemSinkError,
    validate_batch_size,
};

const DEFAULT_SIEM_RETRY_MAX_ATTEMPTS: u8 = 3;
const DEFAULT_SIEM_RETRY_INITIAL_DELAY: Duration = Duration::from_secs(1);
const DEFAULT_SIEM_RETRY_MAX_DELAY: Duration = Duration::from_secs(60);

/// `SiemForwarder::forward()` の結果分類。
///
/// `Result` 型を意図的に避けることで「SIEM 送信失敗を `?` で主要操作に伝播する」
/// コードパスを構造的に排除する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiemForwardOutcome {
    /// sink への直接送信が成功した。
    SentDirect,
    /// sink 送信は失敗したが、ローカル buffer に積み込まれた（再送可能）。
    Buffered { sink_error_code: String },
    /// sink 送信失敗 + buffer 書き出しも失敗した（最も深刻）。ログ済み。
    BufferingFailed { sink_error_code: String },
}

impl SiemForwardOutcome {
    pub fn is_direct_success(&self) -> bool {
        matches!(self, Self::SentDirect)
    }
}

/// 再送 batch のサマリ。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SiemResendSummary {
    pub attempted: usize,
    pub sent: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SiemRetryPolicy {
    max_attempts: u8,
    initial_delay: Duration,
    max_delay: Duration,
}

impl SiemRetryPolicy {
    pub fn production_default() -> Self {
        Self {
            max_attempts: DEFAULT_SIEM_RETRY_MAX_ATTEMPTS,
            initial_delay: DEFAULT_SIEM_RETRY_INITIAL_DELAY,
            max_delay: DEFAULT_SIEM_RETRY_MAX_DELAY,
        }
    }

    pub fn no_retry() -> Self {
        Self {
            max_attempts: 1,
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(max_attempts: u8, initial_delay: Duration, max_delay: Duration) -> Self {
        Self {
            max_attempts,
            initial_delay,
            max_delay,
        }
    }

    pub fn max_attempts(self) -> u8 {
        self.max_attempts
    }
}

impl Default for SiemRetryPolicy {
    fn default() -> Self {
        Self::production_default()
    }
}

/// SIEM 送信の連続失敗状態。ヘルスチェック層が長期失敗を検出する基盤を提供する。
#[derive(Debug, Clone, Default)]
pub struct SiemForwarderStatus {
    inner: Arc<Mutex<SiemForwarderStatusInner>>,
}

#[derive(Debug, Default, Clone, Copy)]
struct SiemForwarderStatusInner {
    failure_since: Option<OffsetDateTime>,
    last_failure_code: Option<u128>, // not used externally; placeholder for future
}

impl SiemForwarderStatus {
    pub fn new() -> Self {
        Self::default()
    }

    /// 現在の `failure_since` を返す（None なら直近の `forward`/`resend` が成功している）。
    pub fn failure_since(&self) -> Option<OffsetDateTime> {
        self.with_read(|state| state.failure_since)
    }

    /// 指定した `now` 時点で `failure_since` からの経過が `threshold` を超えていれば true。
    pub fn is_long_failure(&self, now: OffsetDateTime, threshold: Duration) -> bool {
        let Some(failure_since) = self.failure_since() else {
            return false;
        };
        let Ok(threshold) = time::Duration::try_from(threshold) else {
            return false;
        };
        now - failure_since >= threshold
    }

    fn record_failure(&self, now: OffsetDateTime) {
        self.with_write(|state| {
            if state.failure_since.is_none() {
                state.failure_since = Some(now);
            }
        });
    }

    fn clear(&self) {
        self.with_write(|state| {
            state.failure_since = None;
            state.last_failure_code = None;
        });
    }

    fn with_read<T>(&self, read: impl FnOnce(&SiemForwarderStatusInner) -> T) -> T {
        match self.inner.lock() {
            Ok(guard) => read(&guard),
            Err(poisoned) => read(&poisoned.into_inner()),
        }
    }

    fn with_write(&self, write: impl FnOnce(&mut SiemForwarderStatusInner)) {
        match self.inner.lock() {
            Ok(mut guard) => write(&mut guard),
            Err(poisoned) => write(&mut poisoned.into_inner()),
        }
    }
}

/// 監査・検証イベントを SIEM へ転送するハブ。
///
/// 現時点では `AppState` への配線・use case からの呼び出しを行わない。
/// 単体・統合テストで挙動を検証し、後続タスクで runtime 配線する。
#[derive(Debug, Clone)]
pub struct SiemForwarder<S: SiemSink> {
    sink: Arc<S>,
    buffer: LocalSiemFallbackBuffer,
    status: SiemForwarderStatus,
    retry_policy: SiemRetryPolicy,
}

impl<S: SiemSink> SiemForwarder<S> {
    pub fn new(sink: S, buffer: LocalSiemFallbackBuffer) -> Self {
        Self::new_with_retry_policy(sink, buffer, SiemRetryPolicy::production_default())
    }

    pub fn new_with_retry_policy(
        sink: S,
        buffer: LocalSiemFallbackBuffer,
        retry_policy: SiemRetryPolicy,
    ) -> Self {
        Self {
            sink: Arc::new(sink),
            buffer,
            status: SiemForwarderStatus::new(),
            retry_policy,
        }
    }

    pub fn status(&self) -> SiemForwarderStatus {
        self.status.clone()
    }

    pub fn buffer(&self) -> &LocalSiemFallbackBuffer {
        &self.buffer
    }

    pub fn exporter_kind(&self) -> SiemExporterKind {
        self.sink.exporter_kind()
    }

    /// SIEM へ event を転送する。失敗は呼び出し側に伝播せず、buffer または
    /// ログに退避される。
    pub async fn forward(&self, event: &SiemEvent) -> SiemForwardOutcome {
        self.forward_batch(std::slice::from_ref(event)).await
    }

    pub async fn forward_batch(&self, batch: &[SiemEvent]) -> SiemForwardOutcome {
        if batch.is_empty() {
            return SiemForwardOutcome::SentDirect;
        }

        if let Err(error) = validate_batch_size(batch.len()) {
            return self.handle_send_failure(batch, error).await;
        }

        match self.send_batch_with_retry(batch).await {
            Ok(_) => {
                self.status.clear();
                SiemForwardOutcome::SentDirect
            }
            Err(error) => self.handle_send_failure(batch, error).await,
        }
    }

    /// 過去の `pending` event を順に再送する。再送結果のサマリを返す。
    pub async fn resend_pending(&self) -> SiemResendSummary {
        self.resend_pending_batch(SIEM_MAX_BATCH_SIZE).await
    }

    pub async fn resend_pending_batch(&self, limit: usize) -> SiemResendSummary {
        let buffer = self.buffer.clone();
        let pending = tokio::task::spawn_blocking(move || buffer.pending_batch(limit)).await;
        let pending = match pending {
            Ok(Ok(events)) => events,
            Ok(Err(error)) => {
                tracing::error!(
                    error = %error,
                    "siem forwarder: failed to read pending events from local buffer"
                );
                return SiemResendSummary::default();
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "siem forwarder: spawn_blocking join failed while reading pending events"
                );
                return SiemResendSummary::default();
            }
        };

        let attempted = pending.len();
        if attempted == 0 {
            return SiemResendSummary::default();
        }

        match self.send_batch_with_retry(&pending).await {
            Ok(_) => {}
            Err(error) => {
                let code = sink_error_code(&error);
                tracing::warn!(
                    attempted,
                    error_code = %code,
                    "siem forwarder: resend batch failed; events remain pending"
                );
                return SiemResendSummary {
                    attempted,
                    sent: 0,
                    failed: attempted,
                };
            }
        }

        let mut sent = 0usize;
        let mut failed = 0usize;
        for event in pending {
            let buffer = self.buffer.clone();
            let sent_event = event.clone();
            let mark_result =
                tokio::task::spawn_blocking(move || buffer.mark_sent(&sent_event)).await;
            match mark_result {
                Ok(Ok(())) => {
                    sent += 1;
                }
                Ok(Err(error)) => {
                    tracing::error!(
                        event_id = event.event_id(),
                        error = %error,
                        "siem forwarder: mark_sent failed; event will be retried"
                    );
                    failed += 1;
                }
                Err(error) => {
                    tracing::error!(
                        event_id = event.event_id(),
                        error = %error,
                        "siem forwarder: spawn_blocking join failed during mark_sent"
                    );
                    failed += 1;
                }
            }
        }

        if sent > 0 {
            let buffer = self.buffer.clone();
            match tokio::task::spawn_blocking(move || buffer.compact()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(
                        error = %error,
                        "siem forwarder: buffer compaction failed after resend"
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "siem forwarder: spawn_blocking join failed during buffer compaction"
                    );
                }
            }
        }

        if failed == 0 && attempted > 0 {
            self.status.clear();
        }

        SiemResendSummary {
            attempted,
            sent,
            failed,
        }
    }

    async fn handle_send_failure(
        &self,
        batch: &[SiemEvent],
        error: SiemSinkError,
    ) -> SiemForwardOutcome {
        let code = sink_error_code(&error);
        self.status.record_failure(OffsetDateTime::now_utc());

        tracing::warn!(
            batch_size = batch.len(),
            error_code = %code,
            "siem forwarder: direct send failed; persisting to local buffer"
        );

        let buffer = self.buffer.clone();
        let buffered_events = batch.to_vec();
        let join_result =
            tokio::task::spawn_blocking(move || append_pending_batch(&buffer, &buffered_events))
                .await;
        match join_result {
            Ok(Ok(())) => SiemForwardOutcome::Buffered {
                sink_error_code: code,
            },
            Ok(Err(error)) => {
                tracing::error!(
                    batch_size = batch.len(),
                    error = %error,
                    "siem forwarder: append_pending failed; event is lost from buffer"
                );
                SiemForwardOutcome::BufferingFailed {
                    sink_error_code: code,
                }
            }
            Err(error) => {
                tracing::error!(
                    batch_size = batch.len(),
                    error = %error,
                    "siem forwarder: spawn_blocking join failed while appending pending"
                );
                SiemForwardOutcome::BufferingFailed {
                    sink_error_code: code,
                }
            }
        }
    }

    async fn send_batch_with_retry(
        &self,
        batch: &[SiemEvent],
    ) -> Result<ForwardReceipt, SiemSinkError> {
        let max_attempts = self.retry_policy.max_attempts.max(1);
        let mut attempt = 1u8;
        let mut delay = self.retry_policy.initial_delay;

        loop {
            match self.sink.send_batch(batch).await {
                Ok(receipt) => return Ok(receipt),
                Err(error) if attempt >= max_attempts => return Err(error),
                Err(error) => {
                    let code = sink_error_code(&error);
                    tracing::warn!(
                        attempt,
                        max_attempts,
                        error_code = %code,
                        "siem forwarder: send attempt failed; retrying"
                    );
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    delay = delay.saturating_mul(2).min(self.retry_policy.max_delay);
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }
}

fn append_pending_batch(
    buffer: &LocalSiemFallbackBuffer,
    events: &[SiemEvent],
) -> Result<(), super::buffer::LocalSiemBufferError> {
    for event in events {
        buffer.append_pending(event)?;
    }
    Ok(())
}

/// `SiemSinkError` を `audit_events.metadata_json.error_code` 用の安定文字列に
/// 変換する。`request_timestamping_for_digest::backend_error_code` と同じ
/// 方針で、未知の backend 文字列を `audit_events` に流出させない。
fn sink_error_code(error: &SiemSinkError) -> String {
    match error {
        SiemSinkError::BackendFailed { code } => {
            if code.starts_with("siem_") {
                code.clone()
            } else {
                "siem_backend_failed".to_owned()
            }
        }
        SiemSinkError::InvalidResponse { .. } => "siem_invalid_response".to_owned(),
    }
}

/// SIEM 転送失敗の `AuditEvent` を構築する（Supabase 送信はしない）。
///
/// SIEM 統合範囲では Supabase migration を投入しないため、本関数は `AuditEvent` を
/// 構築するのみで、呼び出し側で `LocalSiemFallbackBuffer` への補助記録や
/// 後続タスクでの `rpc_append_audit_event` 呼び出しに使う。
///
/// `request_id` は元の監査と紐付ける。`event_type` には転送しようとした
/// `AuditAction::as_str()` の文字列を渡す。
pub fn build_siem_forward_failure_audit_event(
    request_id: RequestId,
    event_type: &str,
    error_code: &str,
    event_count: Option<u64>,
) -> Result<AuditEvent, AuditEventError> {
    let mut builder = SiemForwardFailureMetadata::new(error_code).with_event_type(event_type);
    if let Some(count) = event_count {
        builder = builder.with_event_count(count);
    }
    let metadata = builder.build()?.with_current_source_event_at()?;

    AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::generate()?,
        request_id,
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::SiemForwardFailure,
        target_secret_id: None,
        result: AuditResult::Failure,
        key_version: None,
        metadata_json: metadata,
    })
}

pub fn build_siem_event_forwarded_audit_event(
    request_id: RequestId,
    exporter_kind: SiemExporterKind,
    batch_size: usize,
) -> Result<AuditEvent, AuditEventError> {
    let source_event_at =
        SourceEventAt::now_utc().map_err(|_| AuditEventError::SourceEventAtUnavailable)?;
    let metadata = SiemEventForwardedMetadata::new(
        exporter_kind.as_str(),
        usize_to_u64("batch_size", batch_size)?,
        source_event_at,
    )
    .build()?;

    AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::generate()?,
        request_id,
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::SiemEventForwarded,
        target_secret_id: None,
        result: AuditResult::Success,
        key_version: None,
        metadata_json: metadata,
    })
}

pub fn build_siem_event_failed_audit_event(
    request_id: RequestId,
    exporter_kind: SiemExporterKind,
    error_code: &str,
    buffered: bool,
    batch_size: usize,
) -> Result<AuditEvent, AuditEventError> {
    let source_event_at =
        SourceEventAt::now_utc().map_err(|_| AuditEventError::SourceEventAtUnavailable)?;
    let metadata = SiemEventFailedMetadata::new(
        exporter_kind.as_str(),
        error_code,
        buffered,
        usize_to_u64("batch_size", batch_size)?,
        source_event_at,
    )
    .build()?;

    AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::generate()?,
        request_id,
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::SiemEventFailed,
        target_secret_id: None,
        result: AuditResult::Failure,
        key_version: None,
        metadata_json: metadata,
    })
}

pub fn build_siem_buffer_flushed_audit_event(
    request_id: RequestId,
    flushed_count: usize,
    buffer_remaining_bytes: u64,
) -> Result<AuditEvent, AuditEventError> {
    let source_event_at =
        SourceEventAt::now_utc().map_err(|_| AuditEventError::SourceEventAtUnavailable)?;
    let metadata = SiemBufferFlushedMetadata::new(
        usize_to_u64("flushed_count", flushed_count)?,
        buffer_remaining_bytes,
        source_event_at,
    )
    .build()?;

    AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::generate()?,
        request_id,
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::SiemBufferFlushed,
        target_secret_id: None,
        result: AuditResult::Success,
        key_version: None,
        metadata_json: metadata,
    })
}

fn usize_to_u64(key: &'static str, value: usize) -> Result<u64, AuditEventError> {
    u64::try_from(value).map_err(|_| AuditEventError::InvalidMetadataValue { key })
}

#[cfg(test)]
#[path = "../../tests/unit/siem/forwarder/tests.rs"]
mod tests;

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
    RequestId, SiemForwardFailureMetadata,
};

use super::buffer::LocalSiemFallbackBuffer;
use super::event::SiemEvent;
use super::sink::{SiemSink, SiemSinkError};

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
}

impl<S: SiemSink> SiemForwarder<S> {
    pub fn new(sink: S, buffer: LocalSiemFallbackBuffer) -> Self {
        Self {
            sink: Arc::new(sink),
            buffer,
            status: SiemForwarderStatus::new(),
        }
    }

    pub fn status(&self) -> SiemForwarderStatus {
        self.status.clone()
    }

    pub fn buffer(&self) -> &LocalSiemFallbackBuffer {
        &self.buffer
    }

    /// SIEM へ event を転送する。失敗は呼び出し側に伝播せず、buffer または
    /// ログに退避される。
    pub async fn forward(&self, event: &SiemEvent) -> SiemForwardOutcome {
        match self.sink.send_event(event).await {
            Ok(()) => {
                self.status.clear();
                SiemForwardOutcome::SentDirect
            }
            Err(error) => self.handle_send_failure(event, error).await,
        }
    }

    /// 過去の `pending` event を順に再送する。再送結果のサマリを返す。
    pub async fn resend_pending(&self) -> SiemResendSummary {
        let buffer = self.buffer.clone();
        let pending = tokio::task::spawn_blocking(move || buffer.pending_events()).await;
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
        let mut sent = 0usize;
        let mut failed = 0usize;

        for event in pending {
            match self.sink.send_event(&event).await {
                Ok(()) => {
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
                Err(error) => {
                    tracing::warn!(
                        event_id = event.event_id(),
                        error = %error,
                        "siem forwarder: resend failed; event remains pending"
                    );
                    failed += 1;
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
        event: &SiemEvent,
        error: SiemSinkError,
    ) -> SiemForwardOutcome {
        let code = sink_error_code(&error);
        self.status.record_failure(OffsetDateTime::now_utc());

        tracing::warn!(
            event_id = event.event_id(),
            event_type = event.event_type(),
            error_code = %code,
            "siem forwarder: direct send failed; persisting to local buffer"
        );

        let buffer = self.buffer.clone();
        let buffered_event = event.clone();
        let join_result =
            tokio::task::spawn_blocking(move || buffer.append_pending(&buffered_event)).await;
        match join_result {
            Ok(Ok(())) => SiemForwardOutcome::Buffered {
                sink_error_code: code,
            },
            Ok(Err(error)) => {
                tracing::error!(
                    event_id = event.event_id(),
                    error = %error,
                    "siem forwarder: append_pending failed; event is lost from buffer"
                );
                SiemForwardOutcome::BufferingFailed {
                    sink_error_code: code,
                }
            }
            Err(error) => {
                tracing::error!(
                    event_id = event.event_id(),
                    error = %error,
                    "siem forwarder: spawn_blocking join failed while appending pending"
                );
                SiemForwardOutcome::BufferingFailed {
                    sink_error_code: code,
                }
            }
        }
    }
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

#[cfg(test)]
#[path = "../../tests/unit/siem/forwarder/tests.rs"]
mod tests;

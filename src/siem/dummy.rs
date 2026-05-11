//! テスト用 dummy SIEM sink。
//!
//! `InMemorySiemSink` は `Arc<Mutex<...>>` で複数スレッドから安全に共有でき、
//! 送信した `SiemEvent` を呼び出し順に保持する。`FailingSiemSink` は常に
//! `SiemSinkError::BackendFailed` を返す。
//!
//! **本番用途禁止**: プロセス終了でデータが失われ、外部 SIEM への永続化を
//! 提供しない。

use std::fmt;
use std::sync::{Arc, Mutex};

use super::event::SiemEvent;
use super::sink::{SiemSink, SiemSinkError};

/// メモリ上の SIEM sink（テスト専用）。
///
/// `clone()` すると同じストアを共有する。
#[derive(Clone, Default)]
pub struct InMemorySiemSink {
    events: Arc<Mutex<Vec<SiemEvent>>>,
}

impl InMemorySiemSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// 受信した event の総数を返す。
    pub fn event_count(&self) -> usize {
        self.events.lock().map_or(0, |guard| guard.len())
    }

    /// 受信した event をクローンして返す（順序保持）。
    pub fn events(&self) -> Vec<SiemEvent> {
        self.events
            .lock()
            .ok()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl fmt::Debug for InMemorySiemSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemorySiemSink")
            .field("event_count", &self.event_count())
            .finish()
    }
}

impl SiemSink for InMemorySiemSink {
    async fn send_event(&self, event: &SiemEvent) -> Result<(), SiemSinkError> {
        let mut guard = self
            .events
            .lock()
            .map_err(|_| SiemSinkError::BackendFailed {
                code: "mutex_poisoned".to_owned(),
            })?;
        guard.push(event.clone());
        Ok(())
    }
}

/// 失敗をシミュレートするテスト用 sink。常に `BackendFailed` を返す。
#[derive(Debug, Clone, Default)]
pub struct FailingSiemSink {
    code: String,
}

impl FailingSiemSink {
    pub fn new(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }
}

impl SiemSink for FailingSiemSink {
    async fn send_event(&self, _event: &SiemEvent) -> Result<(), SiemSinkError> {
        Err(SiemSinkError::BackendFailed {
            code: self.code.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditResult, AuthFailureMetadata,
        RequestId,
    };

    fn build_auth_failure_event() -> AuditEvent {
        let metadata = AuthFailureMetadata::new("authorization_header_missing")
            .build()
            .unwrap()
            .with_current_source_event_at()
            .unwrap();
        AuditEvent::new(AuditEventParts {
            audit_event_id: AuditEventId::generate().unwrap(),
            request_id: RequestId::nil(),
            actor_user_id: None,
            actor_device_id: None,
            action: AuditAction::AuthFailure,
            target_secret_id: None,
            result: AuditResult::Failure,
            key_version: None,
            metadata_json: metadata,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn in_memory_sink_stores_events_in_order() {
        let sink = InMemorySiemSink::new();
        let event_a = SiemEvent::from_audit_event(&build_auth_failure_event());
        let event_b = SiemEvent::from_audit_event(&build_auth_failure_event());

        sink.send_event(&event_a).await.unwrap();
        sink.send_event(&event_b).await.unwrap();

        let stored = sink.events();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].event_id(), event_a.event_id());
        assert_eq!(stored[1].event_id(), event_b.event_id());
    }

    #[tokio::test]
    async fn in_memory_sink_is_shared_via_clone() {
        let sink = InMemorySiemSink::new();
        let clone = sink.clone();
        let event = SiemEvent::from_audit_event(&build_auth_failure_event());
        clone.send_event(&event).await.unwrap();
        assert_eq!(sink.event_count(), 1);
    }

    #[tokio::test]
    async fn failing_sink_returns_backend_failed_with_code() {
        let sink = FailingSiemSink::new("simulated_outage");
        let event = SiemEvent::from_audit_event(&build_auth_failure_event());
        let error = sink
            .send_event(&event)
            .await
            .expect_err("must return error");
        match error {
            SiemSinkError::BackendFailed { code } => assert_eq!(code, "simulated_outage"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn in_memory_sink_debug_does_not_expose_event_contents() {
        let sink = InMemorySiemSink::new();
        let debug_string = format!("{sink:?}");
        assert!(debug_string.contains("event_count"));
        assert!(!debug_string.contains("metadata"));
    }
}

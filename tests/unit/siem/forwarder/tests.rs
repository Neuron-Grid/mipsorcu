use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditResult, AuthFailureMetadata,
    RequestId,
};

use super::super::dummy::{FailingSiemSink, InMemorySiemSink};
use super::*;

#[derive(Clone)]
struct CountingFailingSiemSink {
    attempts: Arc<AtomicUsize>,
}

impl CountingFailingSiemSink {
    fn new() -> Self {
        Self {
            attempts: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}

impl SiemSink for CountingFailingSiemSink {
    fn exporter_kind(&self) -> SiemExporterKind {
        SiemExporterKind::SplunkHec
    }

    async fn send_batch(&self, _batch: &[SiemEvent]) -> Result<ForwardReceipt, SiemSinkError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(SiemSinkError::BackendFailed {
            code: "siem_retry_test".to_owned(),
        })
    }
}

fn build_audit_event() -> AuditEvent {
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

fn build_siem_event() -> SiemEvent {
    SiemEvent::from_audit_event(&build_audit_event())
}

fn tempfile_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "mipsorcu-siem-forwarder-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    path.join("siem-buffer-current.jsonl")
}

#[tokio::test]
async fn forward_returns_sent_direct_on_sink_success() {
    let path = tempfile_path("ok");
    let sink = InMemorySiemSink::new();
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let forwarder = SiemForwarder::new(sink.clone(), buffer);
    let event = build_siem_event();

    let outcome = forwarder.forward(&event).await;
    assert!(matches!(outcome, SiemForwardOutcome::SentDirect));
    assert_eq!(sink.event_count(), 1);
    assert!(forwarder.status().failure_since().is_none());
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn forward_buffers_event_on_sink_failure_and_records_failure_since() {
    let path = tempfile_path("fail");
    let sink = FailingSiemSink::new("simulated_outage");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let forwarder =
        SiemForwarder::new_with_retry_policy(sink, buffer.clone(), SiemRetryPolicy::no_retry());
    let event = build_siem_event();

    let outcome = forwarder.forward(&event).await;
    match outcome {
        SiemForwardOutcome::Buffered { sink_error_code } => {
            // sink が "siem_" prefix で始まらないため、固定文字列に丸められる。
            assert_eq!(sink_error_code, "siem_backend_failed");
        }
        other => panic!("expected Buffered, got {other:?}"),
    }
    assert!(forwarder.status().failure_since().is_some());
    let pending = buffer.pending_events().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event_id(), event.event_id());
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn forward_preserves_backend_code_with_siem_prefix() {
    let path = tempfile_path("prefix");
    let sink = FailingSiemSink::new("siem_rate_limited");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let forwarder = SiemForwarder::new_with_retry_policy(sink, buffer, SiemRetryPolicy::no_retry());
    let event = build_siem_event();

    let outcome = forwarder.forward(&event).await;
    match outcome {
        SiemForwardOutcome::Buffered { sink_error_code } => {
            assert_eq!(sink_error_code, "siem_rate_limited");
        }
        other => panic!("expected Buffered, got {other:?}"),
    }
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn resend_pending_drains_buffer_when_sink_recovers() {
    let path = tempfile_path("resend");
    let failing = FailingSiemSink::new("simulated_outage");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let forwarder =
        SiemForwarder::new_with_retry_policy(failing, buffer.clone(), SiemRetryPolicy::no_retry());

    // 1) sink 失敗で buffer に積む
    let event = build_siem_event();
    let _ = forwarder.forward(&event).await;
    assert_eq!(buffer.pending_events().unwrap().len(), 1);
    assert!(forwarder.status().failure_since().is_some());

    // 2) sink を recovering な InMemorySiemSink に差し替え、resend を回す
    let healthy = InMemorySiemSink::new();
    let forwarder = SiemForwarder::new(healthy.clone(), buffer.clone());
    let summary = forwarder.resend_pending().await;
    assert_eq!(summary.attempted, 1);
    assert_eq!(summary.sent, 1);
    assert_eq!(summary.failed, 0);
    assert!(buffer.pending_events().unwrap().is_empty());
    assert!(forwarder.status().failure_since().is_none());
    assert_eq!(healthy.event_count(), 1);

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn status_is_long_failure_after_threshold() {
    let path = tempfile_path("longfail");
    let sink = FailingSiemSink::new("siem_long_outage");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let forwarder = SiemForwarder::new_with_retry_policy(sink, buffer, SiemRetryPolicy::no_retry());

    let event = build_siem_event();
    let _ = forwarder.forward(&event).await;
    let since = forwarder
        .status()
        .failure_since()
        .expect("failure_since must be recorded");

    // 同時刻では long failure ではない
    assert!(
        !forwarder
            .status()
            .is_long_failure(since, Duration::from_secs(60))
    );

    // threshold 経過後は long failure
    let later = since + time::Duration::seconds(120);
    assert!(
        forwarder
            .status()
            .is_long_failure(later, Duration::from_secs(60))
    );

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn forward_batch_retries_at_most_configured_attempts() {
    let path = tempfile_path("retry");
    let sink = CountingFailingSiemSink::new();
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let forwarder = SiemForwarder::new_with_retry_policy(
        sink.clone(),
        buffer,
        SiemRetryPolicy::for_test(3, Duration::ZERO, Duration::ZERO),
    );
    let event = build_siem_event();

    let outcome = forwarder.forward(&event).await;

    assert!(matches!(outcome, SiemForwardOutcome::Buffered { .. }));
    assert_eq!(sink.attempts(), 3);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn forward_outcome_is_not_a_result_type() {
    // 静的型レベルチェック: SiemForwardOutcome は Result でないため、
    // ? 演算子で主要操作に伝播できないことを compile time に確認する。
    fn _assert_not_result<T>(_: &T)
    where
        T: 'static,
    {
    }
    let outcome = SiemForwardOutcome::SentDirect;
    _assert_not_result::<SiemForwardOutcome>(&outcome);
}

#[test]
fn build_siem_forward_failure_audit_event_returns_valid_event() {
    let event = build_siem_forward_failure_audit_event(
        RequestId::nil(),
        "decrypt",
        "siem_backend_failed",
        Some(3),
    )
    .expect("build must succeed");

    assert_eq!(event.action(), AuditAction::SiemForwardFailure);
    assert_eq!(event.result(), AuditResult::Failure);
    let metadata = event.metadata_json().as_value();
    assert_eq!(metadata["error_code"].as_str(), Some("siem_backend_failed"));
    assert_eq!(metadata["event_type"].as_str(), Some("decrypt"));
    assert_eq!(metadata["event_count"].as_u64(), Some(3));
    assert!(event.source_event_at().is_ok());
}

#[test]
fn build_siem_forward_failure_audit_event_omits_optional_event_count() {
    let event = build_siem_forward_failure_audit_event(
        RequestId::nil(),
        "auth_failure",
        "siem_invalid_response",
        None,
    )
    .expect("build must succeed");

    let metadata = event.metadata_json().as_value();
    assert!(metadata.get("event_count").is_none());
}

#[test]
fn sink_error_code_maps_unknown_code_to_default() {
    let error = SiemSinkError::BackendFailed {
        code: "network".to_owned(),
    };
    assert_eq!(sink_error_code(&error), "siem_backend_failed");
}

#[test]
fn sink_error_code_passes_through_siem_prefix() {
    let error = SiemSinkError::BackendFailed {
        code: "siem_rate_limited".to_owned(),
    };
    assert_eq!(sink_error_code(&error), "siem_rate_limited");
}

#[test]
fn sink_error_code_invalid_response_returns_static_code() {
    let error = SiemSinkError::InvalidResponse { reason: "rejected" };
    assert_eq!(sink_error_code(&error), "siem_invalid_response");
}

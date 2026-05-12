use std::sync::Arc;

use crate::audit::{AuditEvent, AuditRecordError, AuditRecordOutcome, AuditRecorder, RequestId};
use crate::ledger::SignedLedgerEntry;
use crate::server::state::ReadinessState;
use crate::server::supabase::SupabaseAuditAppender;
use crate::siem::{
    SiemEvent, SiemForwardOutcome, SiemForwarder, SiemForwarderStatus, SiemResendSummary, SiemSink,
    build_siem_forward_failure_audit_event,
};

/// Server 層の SIEM 転送サービス。
///
/// `src/siem` の基盤は Supabase / readiness に依存しない純粋な sink + buffer として
/// 保ち、このサービスで以下を束ねる。
///
/// - `AuditEvent` / `SignedLedgerEntry` から `SiemEvent` への DTO 化
/// - SIEM forward の実行
/// - SIEM 送信失敗時の `siem_forward_failure` 監査記録
/// - 監査記録も fallback も失敗した場合の readiness 更新
#[derive(Clone)]
pub struct SiemForwardingService<S: SiemSink> {
    forwarder: Arc<SiemForwarder<S>>,
    audit_recorder: Arc<AuditRecorder<SupabaseAuditAppender>>,
    readiness_state: ReadinessState,
}

impl<S: SiemSink> SiemForwardingService<S> {
    pub fn new(
        forwarder: SiemForwarder<S>,
        audit_recorder: Arc<AuditRecorder<SupabaseAuditAppender>>,
        readiness_state: ReadinessState,
    ) -> Self {
        Self {
            forwarder: Arc::new(forwarder),
            audit_recorder,
            readiness_state,
        }
    }

    pub fn status(&self) -> SiemForwarderStatus {
        self.forwarder.status()
    }

    pub async fn resend_pending(&self) -> SiemResendSummary {
        self.forwarder.resend_pending().await
    }

    pub async fn forward_audit_event(&self, event: &AuditEvent) -> SiemForwardOutcome {
        let siem_event = SiemEvent::from_audit_event(event);
        self.forward_siem_event(
            &siem_event,
            event.request_id().clone(),
            event.action().as_str(),
        )
        .await
    }

    pub async fn forward_ledger_entry(&self, entry: &SignedLedgerEntry) -> SiemForwardOutcome {
        let siem_event = SiemEvent::from_signed_ledger_entry(entry);
        self.forward_siem_event(
            &siem_event,
            entry.request_id().clone(),
            entry.entry_type().as_str(),
        )
        .await
    }

    pub async fn forward_siem_event(
        &self,
        event: &SiemEvent,
        request_id: RequestId,
        source_event_type: &str,
    ) -> SiemForwardOutcome {
        let outcome = self.forwarder.forward(event).await;
        match &outcome {
            SiemForwardOutcome::SentDirect => {}
            SiemForwardOutcome::Buffered { sink_error_code }
            | SiemForwardOutcome::BufferingFailed { sink_error_code } => {
                self.record_forward_failure(&request_id, source_event_type, sink_error_code)
                    .await;
            }
        }
        outcome
    }

    async fn record_forward_failure(
        &self,
        request_id: &RequestId,
        source_event_type: &str,
        sink_error_code: &str,
    ) {
        let event = match build_siem_forward_failure_audit_event(
            request_id.clone(),
            source_event_type,
            sink_error_code,
            Some(1),
        ) {
            Ok(event) => event,
            Err(error) => {
                self.readiness_state.mark_failure_audit_both_failed();
                tracing::error!(
                    request_id = %request_id.as_canonical_string(),
                    error = %error,
                    action = "siem_forward_failure",
                    result = "failure",
                    error_code = "audit_event_build_failed",
                    "failed to construct SIEM forward failure audit event"
                );
                return;
            }
        };

        match self.audit_recorder.record(&event).await {
            Ok(AuditRecordOutcome::PrimarySucceeded) => {
                tracing::warn!(
                    request_id = %request_id.as_canonical_string(),
                    action = "siem_forward_failure",
                    result = "failure",
                    error_code = sink_error_code,
                    audit_record_outcome = "primary_succeeded",
                    "SIEM forward failure audit recorded"
                );
            }
            Ok(AuditRecordOutcome::FallbackSucceeded) => {
                tracing::warn!(
                    request_id = %request_id.as_canonical_string(),
                    action = "siem_forward_failure",
                    result = "failure",
                    error_code = sink_error_code,
                    audit_record_outcome = "fallback_succeeded",
                    "SIEM forward failure audit recorded to local fallback"
                );
            }
            Err(error @ AuditRecordError::PrimaryAndFallbackFailed { .. }) => {
                self.readiness_state.mark_failure_audit_both_failed();
                tracing::error!(
                    request_id = %request_id.as_canonical_string(),
                    error = %error,
                    action = "siem_forward_failure",
                    result = "failure",
                    error_code = sink_error_code,
                    audit_record_outcome = "both_failed",
                    "SIEM forward failure audit recording failed"
                );
            }
            Err(error) => {
                tracing::error!(
                    request_id = %request_id.as_canonical_string(),
                    error = %error,
                    action = "siem_forward_failure",
                    result = "failure",
                    error_code = sink_error_code,
                    audit_record_outcome = "unexpected_error",
                    "SIEM forward failure audit recording failed"
                );
            }
        }
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureAuditRecordEffect {
    PrimarySucceeded,
    FallbackSucceeded,
    BothFailed,
    UnexpectedError,
}

impl FailureAuditRecordEffect {
    fn audit_record_outcome(self) -> &'static str {
        match self {
            Self::PrimarySucceeded => "primary_succeeded",
            Self::FallbackSucceeded => "fallback_succeeded",
            Self::BothFailed => "both_failed",
            Self::UnexpectedError => "unexpected_error",
        }
    }

    fn marks_readiness_failure(self) -> bool {
        matches!(self, Self::BothFailed)
    }
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
        if let Some(sink_error_code) = forward_failure_sink_error_code(&outcome) {
            self.record_forward_failure(&request_id, source_event_type, sink_error_code)
                .await;
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

        let record_result = self.audit_recorder.record(&event).await;
        let effect = failure_audit_record_effect(&record_result);
        if effect.marks_readiness_failure() {
            self.readiness_state.mark_failure_audit_both_failed();
        }
        log_failure_audit_record_result(request_id, sink_error_code, &record_result, effect);
    }
}

fn forward_failure_sink_error_code(outcome: &SiemForwardOutcome) -> Option<&str> {
    match outcome {
        SiemForwardOutcome::SentDirect => None,
        SiemForwardOutcome::Buffered { sink_error_code }
        | SiemForwardOutcome::BufferingFailed { sink_error_code } => Some(sink_error_code.as_str()),
    }
}

fn failure_audit_record_effect(
    result: &Result<AuditRecordOutcome, AuditRecordError>,
) -> FailureAuditRecordEffect {
    match result {
        Ok(AuditRecordOutcome::PrimarySucceeded) => FailureAuditRecordEffect::PrimarySucceeded,
        Ok(AuditRecordOutcome::FallbackSucceeded) => FailureAuditRecordEffect::FallbackSucceeded,
        Err(AuditRecordError::PrimaryAndFallbackFailed { .. }) => {
            FailureAuditRecordEffect::BothFailed
        }
        Err(_) => FailureAuditRecordEffect::UnexpectedError,
    }
}

fn log_failure_audit_record_result(
    request_id: &RequestId,
    sink_error_code: &str,
    record_result: &Result<AuditRecordOutcome, AuditRecordError>,
    effect: FailureAuditRecordEffect,
) {
    match effect {
        FailureAuditRecordEffect::PrimarySucceeded => {
            tracing::warn!(
                request_id = %request_id.as_canonical_string(),
                action = "siem_forward_failure",
                result = "failure",
                error_code = sink_error_code,
                audit_record_outcome = effect.audit_record_outcome(),
                "SIEM forward failure audit recorded"
            );
        }
        FailureAuditRecordEffect::FallbackSucceeded => {
            tracing::warn!(
                request_id = %request_id.as_canonical_string(),
                action = "siem_forward_failure",
                result = "failure",
                error_code = sink_error_code,
                audit_record_outcome = effect.audit_record_outcome(),
                "SIEM forward failure audit recorded to local fallback"
            );
        }
        FailureAuditRecordEffect::BothFailed | FailureAuditRecordEffect::UnexpectedError => {
            if let Err(error) = record_result {
                let message = match effect {
                    FailureAuditRecordEffect::BothFailed => {
                        "SIEM forward failure audit recording failed"
                    }
                    FailureAuditRecordEffect::UnexpectedError => {
                        "SIEM forward failure audit recording failed"
                    }
                    FailureAuditRecordEffect::PrimarySucceeded
                    | FailureAuditRecordEffect::FallbackSucceeded => {
                        "SIEM forward failure audit recorded"
                    }
                };
                tracing::error!(
                    request_id = %request_id.as_canonical_string(),
                    error = %error,
                    action = "siem_forward_failure",
                    result = "failure",
                    error_code = sink_error_code,
                    audit_record_outcome = effect.audit_record_outcome(),
                    "{}", message
                );
            } else {
                tracing::error!(
                    request_id = %request_id.as_canonical_string(),
                    action = "siem_forward_failure",
                    result = "failure",
                    error_code = sink_error_code,
                    audit_record_outcome = effect.audit_record_outcome(),
                    classification_error_code = "audit_record_classification_mismatch",
                    "SIEM forward failure audit classification mismatch"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditAppendError, LocalAuditStoreError};

    fn primary_and_fallback_failed_result() -> Result<AuditRecordOutcome, AuditRecordError> {
        Err(AuditRecordError::PrimaryAndFallbackFailed {
            append_error: AuditAppendError::ExternalDependencyFailed { code: "test" },
            store_error: LocalAuditStoreError::LockPoisoned,
        })
    }

    #[test]
    fn forward_failure_sink_error_code_is_none_for_direct_success() {
        assert_eq!(
            forward_failure_sink_error_code(&SiemForwardOutcome::SentDirect),
            None
        );
    }

    #[test]
    fn forward_failure_sink_error_code_extracts_buffered_error() {
        let outcome = SiemForwardOutcome::Buffered {
            sink_error_code: "sink_failed".to_owned(),
        };

        assert_eq!(
            forward_failure_sink_error_code(&outcome),
            Some("sink_failed")
        );
    }

    #[test]
    fn forward_failure_sink_error_code_extracts_buffering_failed_error() {
        let outcome = SiemForwardOutcome::BufferingFailed {
            sink_error_code: "buffer_failed".to_owned(),
        };

        assert_eq!(
            forward_failure_sink_error_code(&outcome),
            Some("buffer_failed")
        );
    }

    #[test]
    fn failure_audit_record_effect_classifies_success_and_error_paths() {
        assert_eq!(
            failure_audit_record_effect(&Ok(AuditRecordOutcome::PrimarySucceeded)),
            FailureAuditRecordEffect::PrimarySucceeded
        );
        assert_eq!(
            failure_audit_record_effect(&Ok(AuditRecordOutcome::FallbackSucceeded)),
            FailureAuditRecordEffect::FallbackSucceeded
        );
        assert_eq!(
            failure_audit_record_effect(&primary_and_fallback_failed_result()),
            FailureAuditRecordEffect::BothFailed
        );
        assert_eq!(
            failure_audit_record_effect(&Err(AuditRecordError::IdempotencyConflict)),
            FailureAuditRecordEffect::UnexpectedError
        );
    }

    #[test]
    fn only_primary_and_fallback_failure_marks_readiness_failure() {
        assert!(
            FailureAuditRecordEffect::BothFailed.marks_readiness_failure(),
            "both_failed must mark readiness degraded"
        );
        assert!(
            !FailureAuditRecordEffect::UnexpectedError.marks_readiness_failure(),
            "unexpected audit errors are logged but do not mean fallback also failed"
        );
    }
}

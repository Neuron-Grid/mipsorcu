use super::error::AuditRecordError;
use super::event::{AuditEvent, AuditEventAppender};
use super::fallback::LocalAuditFallbackStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditRecordOutcome {
    PrimarySucceeded,
    FallbackSucceeded,
}

pub struct AuditRecorder<A> {
    appender: A,
    fallback_store: LocalAuditFallbackStore,
}

impl<A> AuditRecorder<A>
where
    A: AuditEventAppender,
{
    pub fn new(appender: A, fallback_store: LocalAuditFallbackStore) -> Self {
        Self {
            appender,
            fallback_store,
        }
    }

    pub fn record(&self, event: &AuditEvent) -> Result<AuditRecordOutcome, AuditRecordError> {
        match self.appender.append_audit_event(event) {
            Ok(()) => Ok(AuditRecordOutcome::PrimarySucceeded),
            Err(append_error) => self
                .fallback_store
                .append_pending(event)
                .map(|()| AuditRecordOutcome::FallbackSucceeded)
                .map_err(|store_error| AuditRecordError::PrimaryAndFallbackFailed {
                    append_error,
                    store_error,
                }),
        }
    }

    pub fn resend_pending(&self) -> Result<ResendAuditSummary, AuditRecordError> {
        let pending_events = self
            .fallback_store
            .pending_events()
            .map_err(AuditRecordError::ResendReadFailed)?;
        let attempted = pending_events.len();
        let mut sent = 0;
        let mut failed = 0;

        for event in pending_events {
            match self.appender.append_audit_event(&event) {
                Ok(()) => {
                    self.fallback_store
                        .mark_sent(&event)
                        .map_err(AuditRecordError::ResendMarkSentFailed)?;
                    sent += 1;
                }
                Err(_) => {
                    failed += 1;
                }
            }
        }

        Ok(ResendAuditSummary {
            attempted,
            sent,
            failed,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResendAuditSummary {
    pub attempted: usize,
    pub sent: usize,
    pub failed: usize,
}

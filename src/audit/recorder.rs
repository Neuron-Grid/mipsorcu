use super::error::{AuditAppendError, AuditRecordError, LocalAuditStoreError};
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

    pub async fn record(&self, event: &AuditEvent) -> Result<AuditRecordOutcome, AuditRecordError> {
        match self.appender.append_audit_event(event).await {
            Ok(()) => Ok(AuditRecordOutcome::PrimarySucceeded),
            Err(AuditAppendError::ExternalDependencyFailed { code }) => {
                let append_error = AuditAppendError::ExternalDependencyFailed { code };
                let fallback_store = self.fallback_store.clone();
                let event = event.clone();
                let store_result =
                    tokio::task::spawn_blocking(move || fallback_store.append_pending(&event))
                        .await
                        .map_err(|_| AuditRecordError::PrimaryAndFallbackFailed {
                            append_error: append_error.clone(),
                            store_error: join_failed_store_error(),
                        })?;

                store_result
                    .map(|()| AuditRecordOutcome::FallbackSucceeded)
                    .map_err(|store_error| AuditRecordError::PrimaryAndFallbackFailed {
                        append_error,
                        store_error,
                    })
            }
            Err(AuditAppendError::IdempotencyConflict) => {
                Err(AuditRecordError::IdempotencyConflict)
            }
        }
    }

    pub async fn resend_pending(&self) -> Result<ResendAuditSummary, AuditRecordError> {
        let fallback_store = self.fallback_store.clone();
        let pending_events = tokio::task::spawn_blocking(move || fallback_store.pending_events())
            .await
            .map_err(|_| AuditRecordError::ResendReadFailed(join_failed_store_error()))?
            .map_err(AuditRecordError::ResendReadFailed)?;
        let attempted = pending_events.len();
        let mut sent = 0;
        let mut failed = 0;

        for event in pending_events {
            match self.appender.append_audit_event(&event).await {
                Ok(()) => {
                    let fallback_store = self.fallback_store.clone();
                    let sent_event = event.clone();
                    tokio::task::spawn_blocking(move || fallback_store.mark_sent(&sent_event))
                        .await
                        .map_err(|_| {
                            AuditRecordError::ResendMarkSentFailed(join_failed_store_error())
                        })?
                        .map_err(AuditRecordError::ResendMarkSentFailed)?;
                    sent += 1;
                }
                Err(AuditAppendError::ExternalDependencyFailed { .. }) => {
                    failed += 1;
                }
                Err(AuditAppendError::IdempotencyConflict) => {
                    return Err(AuditRecordError::IdempotencyConflict);
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

fn join_failed_store_error() -> LocalAuditStoreError {
    std::io::Error::other("join failed").into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResendAuditSummary {
    pub attempted: usize,
    pub sent: usize,
    pub failed: usize,
}

use super::error::{AuditAppendError, AuditRecordError, LocalAuditStoreError};
use super::event::{AuditEvent, AuditEventAppender};
use super::fallback::{LocalAuditFallbackStore, resend_pending};

pub use super::fallback::ResendAuditSummary;

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
        resend_pending(&self.appender, &self.fallback_store).await
    }
}

fn join_failed_store_error() -> LocalAuditStoreError {
    std::io::Error::other("join failed").into()
}

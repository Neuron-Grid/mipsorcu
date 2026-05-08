use super::super::error::{AuditAppendError, AuditRecordError};
use super::super::event::AuditEventAppender;
use super::error::LocalAuditStoreError;
use super::file_store::LocalAuditFallbackStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResendAuditSummary {
    pub attempted: usize,
    pub sent: usize,
    pub failed: usize,
}

pub(in crate::audit) async fn resend_pending<A>(
    appender: &A,
    fallback_store: &LocalAuditFallbackStore,
) -> Result<ResendAuditSummary, AuditRecordError>
where
    A: AuditEventAppender,
{
    let fallback_store_for_read = fallback_store.clone();
    let pending_events =
        tokio::task::spawn_blocking(move || fallback_store_for_read.pending_events())
            .await
            .map_err(|_| AuditRecordError::ResendReadFailed(join_failed_store_error()))?
            .map_err(AuditRecordError::ResendReadFailed)?;
    let attempted = pending_events.len();
    let mut sent = 0;
    let mut failed = 0;

    for event in pending_events {
        match appender.append_audit_event(&event).await {
            Ok(()) => {
                let fallback_store = fallback_store.clone();
                let sent_event = event.clone();
                tokio::task::spawn_blocking(move || fallback_store.mark_sent(&sent_event))
                    .await
                    .map_err(|_| AuditRecordError::ResendMarkSentFailed(join_failed_store_error()))?
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

fn join_failed_store_error() -> LocalAuditStoreError {
    std::io::Error::other("join failed").into()
}

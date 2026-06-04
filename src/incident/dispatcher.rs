use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::audit::{
    AuditAction, AuditEvent, AuditEventAppender, AuditRecordError, AuditRecorder, AuditResult,
    IncidentNotificationFailedMetadata, IncidentNotificationSentMetadata,
    IncidentNotificationSuppressedMetadata, RequestId,
};
use crate::types::SourceEventAt;

use super::{
    IncidentCategory, IncidentError, IncidentId, IncidentNotification, IncidentNotifier,
    IncidentSeverity, IncidentSummary, NotificationReceipt,
};

const DEFAULT_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(300);
const DEFAULT_MAX_ATTEMPTS: u32 = 3;
const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const DEFAULT_MAX_TOTAL_BACKOFF: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentDispatchOutcome {
    Sent,
    Suppressed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncidentRetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff: Duration,
    pub max_total_backoff: Duration,
}

impl Default for IncidentRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
            max_total_backoff: DEFAULT_MAX_TOTAL_BACKOFF,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RateLimitKey {
    category: IncidentCategory,
    affected_components: Vec<String>,
}

impl RateLimitKey {
    fn from_notification(notification: &IncidentNotification) -> Self {
        Self {
            category: notification.category,
            affected_components: notification
                .affected_components
                .iter()
                .map(|component| component.as_str().to_owned())
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
struct RateLimitWindow {
    started_at: Instant,
    first_notification: IncidentNotification,
    suppressed_count: u64,
}

pub struct IncidentDispatcher<N, A>
where
    N: IncidentNotifier,
    A: AuditEventAppender,
{
    notifier: Arc<N>,
    audit_recorder: Arc<AuditRecorder<A>>,
    rate_limit_window: Duration,
    retry_policy: IncidentRetryPolicy,
    windows: Arc<Mutex<HashMap<RateLimitKey, RateLimitWindow>>>,
}

impl<N, A> IncidentDispatcher<N, A>
where
    N: IncidentNotifier,
    A: AuditEventAppender,
{
    pub fn new(notifier: Arc<N>, audit_recorder: Arc<AuditRecorder<A>>) -> Self {
        Self {
            notifier,
            audit_recorder,
            rate_limit_window: DEFAULT_RATE_LIMIT_WINDOW,
            retry_policy: IncidentRetryPolicy::default(),
            windows: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_rate_limit_window(mut self, rate_limit_window: Duration) -> Self {
        self.rate_limit_window = rate_limit_window;
        self
    }

    pub fn with_retry_policy(mut self, retry_policy: IncidentRetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    pub async fn dispatch(&self, notification: IncidentNotification) -> IncidentDispatchOutcome {
        self.flush_due_aggregates().await;

        if notification.severity != IncidentSeverity::Critical
            && let Some(suppressed_count) = self.suppress_if_rate_limited(&notification)
        {
            self.record_suppressed_audit(&notification, suppressed_count)
                .await;
            return IncidentDispatchOutcome::Suppressed;
        }

        self.remember_rate_limit_window(&notification);
        self.send_and_record(notification).await
    }

    pub async fn flush_due_aggregates(&self) {
        let due = self.take_due_aggregates();
        for aggregate in due {
            let _ = self.send_and_record(aggregate).await;
        }
    }

    fn suppress_if_rate_limited(&self, notification: &IncidentNotification) -> Option<u64> {
        let key = RateLimitKey::from_notification(notification);
        let mut guard = match self.windows.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let window = guard.get_mut(&key)?;
        if window.started_at.elapsed() >= self.rate_limit_window {
            return None;
        }
        window.suppressed_count = window.suppressed_count.saturating_add(1);
        Some(window.suppressed_count)
    }

    fn remember_rate_limit_window(&self, notification: &IncidentNotification) {
        if notification.severity == IncidentSeverity::Critical {
            return;
        }

        let key = RateLimitKey::from_notification(notification);
        let mut guard = match self.windows.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(
            key,
            RateLimitWindow {
                started_at: Instant::now(),
                first_notification: notification.clone(),
                suppressed_count: 0,
            },
        );
    }

    fn take_due_aggregates(&self) -> Vec<IncidentNotification> {
        let mut guard = match self.windows.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let keys = guard
            .iter()
            .filter_map(|(key, window)| {
                if window.started_at.elapsed() >= self.rate_limit_window
                    && window.suppressed_count > 0
                {
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let mut aggregates = Vec::new();
        for key in keys {
            if let Some(window) = guard.remove(&key)
                && let Some(notification) = build_aggregate_notification(&window)
            {
                aggregates.push(notification);
            }
        }
        aggregates
    }

    async fn send_and_record(&self, notification: IncidentNotification) -> IncidentDispatchOutcome {
        match self.notify_with_retry(&notification).await {
            Ok(receipt) => {
                self.record_sent_audit(&notification, &receipt).await;
                IncidentDispatchOutcome::Sent
            }
            Err((error, retry_count)) => {
                self.record_failed_audit(&notification, &error, retry_count)
                    .await;
                IncidentDispatchOutcome::Failed
            }
        }
    }

    async fn notify_with_retry(
        &self,
        notification: &IncidentNotification,
    ) -> Result<NotificationReceipt, (IncidentError, u64)> {
        let mut attempt = 0;
        let mut retry_count = 0;
        let mut total_backoff = Duration::ZERO;
        let mut next_backoff = self.retry_policy.initial_backoff;

        loop {
            attempt += 1;
            match self.notifier.notify(notification).await {
                Ok(receipt) => return Ok(receipt),
                Err(error) => {
                    if attempt >= self.retry_policy.max_attempts {
                        return Err((error, retry_count));
                    }
                    retry_count += 1;
                    if total_backoff.saturating_add(next_backoff)
                        > self.retry_policy.max_total_backoff
                    {
                        return Err((error, retry_count));
                    }
                    tokio::time::sleep(next_backoff).await;
                    total_backoff = total_backoff.saturating_add(next_backoff);
                    next_backoff = next_backoff.saturating_mul(2);
                }
            }
        }
    }

    async fn record_sent_audit(
        &self,
        notification: &IncidentNotification,
        receipt: &NotificationReceipt,
    ) {
        let metadata = match IncidentNotificationSentMetadata::new(
            notification.incident_id.clone(),
            notification.category,
            receipt.notifier_kind,
            receipt.duration_ms,
            receipt.delivered_at.clone(),
        )
        .build()
        {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::error!(error = %error, "failed to build incident notification sent metadata");
                return;
            }
        };
        self.record_notification_audit(
            AuditAction::IncidentNotificationSent,
            AuditResult::Success,
            metadata,
        )
        .await;
    }

    async fn record_failed_audit(
        &self,
        notification: &IncidentNotification,
        error: &IncidentError,
        retry_count: u64,
    ) {
        let source_event_at = match notification_source_event_at(notification) {
            Ok(source_event_at) => source_event_at,
            Err(()) => {
                tracing::error!("failed to build incident notification failed source_event_at");
                return;
            }
        };
        let metadata = match IncidentNotificationFailedMetadata::new(
            notification.incident_id.clone(),
            notification.category,
            self.notifier.notifier_kind(),
            error.code(),
            retry_count,
            source_event_at,
        )
        .build()
        {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::error!(error = %error, "failed to build incident notification failed metadata");
                return;
            }
        };
        self.record_notification_audit(
            AuditAction::IncidentNotificationFailed,
            AuditResult::Failure,
            metadata,
        )
        .await;
    }

    async fn record_suppressed_audit(
        &self,
        notification: &IncidentNotification,
        suppressed_count: u64,
    ) {
        let source_event_at = match notification_source_event_at(notification) {
            Ok(source_event_at) => source_event_at,
            Err(()) => {
                tracing::error!("failed to build incident notification suppressed source_event_at");
                return;
            }
        };
        let metadata = match IncidentNotificationSuppressedMetadata::new(
            notification.incident_id.clone(),
            notification.category,
            suppressed_count,
            self.window_remaining_seconds(notification),
            source_event_at,
        )
        .build()
        {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::error!(error = %error, "failed to build incident notification suppressed metadata");
                return;
            }
        };
        self.record_notification_audit(
            AuditAction::IncidentNotificationSuppressed,
            AuditResult::Success,
            metadata,
        )
        .await;
    }

    async fn record_notification_audit(
        &self,
        action: AuditAction,
        result: AuditResult,
        metadata_json: crate::audit::AuditMetadata,
    ) {
        let request_id = match RequestId::generate() {
            Ok(request_id) => request_id,
            Err(error) => {
                tracing::error!(error = %error, "failed to generate incident notification audit request id");
                return;
            }
        };
        let event = match AuditEvent::build_with_current_source_event_at(
            request_id,
            None,
            None,
            action,
            None,
            result,
            None,
            metadata_json,
        ) {
            Ok(event) => event,
            Err(error) => {
                tracing::error!(error = %error, "failed to build incident notification audit event");
                return;
            }
        };
        if let Err(error) = self.audit_recorder.record(&event).await {
            log_audit_record_failure(error);
        }
    }

    fn window_remaining_seconds(&self, notification: &IncidentNotification) -> u64 {
        let key = RateLimitKey::from_notification(notification);
        let guard = match self.windows.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard
            .get(&key)
            .map(|window| {
                self.rate_limit_window
                    .saturating_sub(window.started_at.elapsed())
                    .as_secs()
            })
            .unwrap_or(0)
    }
}

fn build_aggregate_notification(window: &RateLimitWindow) -> Option<IncidentNotification> {
    let incident_id = IncidentId::generate().ok()?;
    let source_event_at = SourceEventAt::now_utc().ok()?;
    let detected_at = source_event_at.clone();
    let summary = IncidentSummary::new(format!(
        "suppressed {} incident notifications for {}",
        window.suppressed_count,
        window.first_notification.category.as_str()
    ))
    .ok()?;
    IncidentNotification::new(
        incident_id,
        detected_at,
        window.first_notification.category,
        window.first_notification.severity,
        summary,
        window.first_notification.affected_components.clone(),
        source_event_at,
    )
    .ok()
}

fn notification_source_event_at(notification: &IncidentNotification) -> Result<SourceEventAt, ()> {
    SourceEventAt::parse(notification.source_event_at.as_str())
        .or_else(|_| SourceEventAt::now_utc())
        .map_err(|_| ())
}

fn log_audit_record_failure(error: AuditRecordError) {
    tracing::error!(error = %error, "incident notification audit record failed");
}

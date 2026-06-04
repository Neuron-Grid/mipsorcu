use std::fmt;
use std::sync::{Arc, Mutex};

use crate::types::SourceEventAt;

use super::{
    IncidentError, IncidentNotification, IncidentNotificationPayload, IncidentNotifier,
    IncidentNotifierKind, NotificationReceipt, NotificationSink, NotificationSinkError,
};

#[derive(Clone, Default)]
pub struct DummyNotificationSink {
    payloads: Arc<Mutex<Vec<IncidentNotificationPayload>>>,
    notifications: Arc<Mutex<Vec<IncidentNotification>>>,
}

impl DummyNotificationSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn payload_count(&self) -> usize {
        self.payloads.lock().map_or(0, |guard| guard.len())
    }

    pub fn payloads(&self) -> Vec<IncidentNotificationPayload> {
        self.payloads
            .lock()
            .ok()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    pub fn notification_count(&self) -> usize {
        self.notifications.lock().map_or(0, |guard| guard.len())
    }

    pub fn notifications(&self) -> Vec<IncidentNotification> {
        self.notifications
            .lock()
            .ok()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl fmt::Debug for DummyNotificationSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DummyNotificationSink")
            .field("payload_count", &self.payload_count())
            .field("notification_count", &self.notification_count())
            .finish()
    }
}

impl NotificationSink for DummyNotificationSink {
    fn sink_name(&self) -> &'static str {
        "dummy"
    }

    async fn notify(
        &self,
        payload: &IncidentNotificationPayload,
    ) -> Result<(), NotificationSinkError> {
        let mut guard = self
            .payloads
            .lock()
            .map_err(|_| NotificationSinkError::BackendFailed {
                code: "mutex_poisoned".to_owned(),
            })?;
        guard.push(payload.clone());
        Ok(())
    }
}

impl IncidentNotifier for DummyNotificationSink {
    fn notifier_kind(&self) -> IncidentNotifierKind {
        IncidentNotifierKind::Dummy
    }

    async fn notify(
        &self,
        notification: &IncidentNotification,
    ) -> Result<NotificationReceipt, IncidentError> {
        let mut guard = self
            .notifications
            .lock()
            .map_err(|_| IncidentError::BackendFailed {
                code: "mutex_poisoned".to_owned(),
            })?;
        guard.push(notification.clone());
        let delivered_at = SourceEventAt::now_utc().map_err(|_| IncidentError::BackendFailed {
            code: "incident_dummy_timestamp_failed".to_owned(),
        })?;
        Ok(NotificationReceipt::new(
            IncidentNotifierKind::Dummy,
            delivered_at,
            0,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct FailingNotificationSink {
    code: String,
}

impl FailingNotificationSink {
    pub fn new(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }
}

impl NotificationSink for FailingNotificationSink {
    fn sink_name(&self) -> &'static str {
        "dummy"
    }

    async fn notify(
        &self,
        _payload: &IncidentNotificationPayload,
    ) -> Result<(), NotificationSinkError> {
        Err(NotificationSinkError::BackendFailed {
            code: self.code.clone(),
        })
    }
}

impl IncidentNotifier for FailingNotificationSink {
    fn notifier_kind(&self) -> IncidentNotifierKind {
        IncidentNotifierKind::Dummy
    }

    async fn notify(
        &self,
        _notification: &IncidentNotification,
    ) -> Result<NotificationReceipt, IncidentError> {
        Err(IncidentError::BackendFailed {
            code: self.code.clone(),
        })
    }
}

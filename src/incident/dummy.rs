use std::fmt;
use std::sync::{Arc, Mutex};

use super::{IncidentNotificationPayload, NotificationSink, NotificationSinkError};

#[derive(Clone, Default)]
pub struct DummyNotificationSink {
    payloads: Arc<Mutex<Vec<IncidentNotificationPayload>>>,
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
}

impl fmt::Debug for DummyNotificationSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DummyNotificationSink")
            .field("payload_count", &self.payload_count())
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

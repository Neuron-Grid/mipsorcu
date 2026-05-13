use std::fmt;

use super::IncidentNotificationPayload;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationSinkError {
    BackendFailed { code: String },
}

impl fmt::Display for NotificationSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendFailed { code } => {
                write!(formatter, "incident notification backend failed: {code}")
            }
        }
    }
}

impl std::error::Error for NotificationSinkError {}

#[allow(async_fn_in_trait)]
pub trait NotificationSink: Send + Sync + 'static {
    fn sink_name(&self) -> &'static str;

    async fn notify(
        &self,
        payload: &IncidentNotificationPayload,
    ) -> Result<(), NotificationSinkError>;
}

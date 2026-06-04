use std::fmt;

use super::{
    IncidentNotification, IncidentNotificationPayload, IncidentNotifierKind, NotificationReceipt,
};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentError {
    BackendFailed { code: String },
    InvalidPayload { code: String },
}

impl IncidentError {
    pub fn code(&self) -> &str {
        match self {
            Self::BackendFailed { code } | Self::InvalidPayload { code } => code,
        }
    }
}

impl fmt::Display for IncidentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendFailed { code } => {
                write!(formatter, "incident notifier backend failed: {code}")
            }
            Self::InvalidPayload { code } => {
                write!(
                    formatter,
                    "incident notification payload is invalid: {code}"
                )
            }
        }
    }
}

impl std::error::Error for IncidentError {}

impl From<NotificationSinkError> for IncidentError {
    fn from(error: NotificationSinkError) -> Self {
        match error {
            NotificationSinkError::BackendFailed { code } => Self::BackendFailed { code },
        }
    }
}

#[allow(async_fn_in_trait)]
pub trait IncidentNotifier: Send + Sync + 'static {
    fn notifier_kind(&self) -> IncidentNotifierKind;

    async fn notify(
        &self,
        notification: &IncidentNotification,
    ) -> Result<NotificationReceipt, IncidentError>;
}

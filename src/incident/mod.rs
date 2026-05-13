mod dummy;
mod recorder;
mod sink;
mod types;

pub use dummy::{DummyNotificationSink, FailingNotificationSink};
pub use recorder::{
    IncidentRecordError, IncidentRecordResult, IncidentRecorder, dedupe_key,
    monthly_digest_incident_type, scheduler_incident_type, severity_for_incident,
};
pub use sink::{NotificationSink, NotificationSinkError};
pub use types::{
    IncidentNotificationPayload, IncidentRecordInput, IncidentSeverity, IncidentType,
    NotificationResult,
};

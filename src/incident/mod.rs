mod detector;
mod dispatcher;
mod dto;
mod dummy;
mod recorder;
mod sink;
mod text_guard;
mod types;
mod webhook;

pub use detector::{IncidentDetector, IncidentDetectorError};
pub use dispatcher::{IncidentDispatchOutcome, IncidentDispatcher, IncidentRetryPolicy};
pub use dto::{
    ComponentName, IncidentCategory, IncidentDtoError, IncidentId, IncidentNotification,
    IncidentNotifierKind, IncidentSummary, NotificationReceipt, TriageUrl,
};
pub use dummy::{DummyNotificationSink, FailingNotificationSink};
pub use recorder::{
    IncidentRecordError, IncidentRecordResult, IncidentRecorder, archive_incident_input,
    archive_incident_type, audit_ui_forbidden_operation_input, dedupe_key,
    digest_timestamping_incident_input, digest_timestamping_incident_type,
    ledger_payload_contains_forbidden_key, ledger_secret_leak_suspected_input,
    monthly_digest_incident_type, non_auditor_ledger_read_input,
    record_audit_ui_forbidden_operation, record_ledger_secret_leak_suspected,
    record_non_auditor_ledger_read, scheduler_incident_type, severity_for_incident,
};
pub use sink::{IncidentError, IncidentNotifier, NotificationSink, NotificationSinkError};
pub use types::{
    IncidentNotificationPayload, IncidentRecordInput, IncidentSeverity, IncidentType,
    NotificationResult,
};
pub use webhook::{AnyNotificationSink, WebhookIncidentNotifier, WebhookNotificationSink};

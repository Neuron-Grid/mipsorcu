use crate::incident::{
    AnyNotificationSink, IncidentCategory, IncidentDetector, IncidentDispatcher,
    IncidentNotification, IncidentRecordInput, IncidentSeverity, IncidentType,
};
use crate::server::supabase::SupabaseAuditAppender;

use super::state::AppState;

pub(crate) const SIEM_BUFFER_OVERFLOW_ERROR_CODE: &str = "siem_buffer_capacity_exceeded";
const SIEM_BUFFER_OVERFLOW_DEDUPE_KEY: &str = "siem:buffer:overflow";
const SIEM_BUFFER_OVERFLOW_DETECTION_SOURCE: &str = "siem_forwarding";
const SIEM_LONG_FAILURE_DEDUPE_KEY: &str = "siem-long-failure";
const SIEM_LONG_FAILURE_ERROR_CODE: &str = "siem_long_outage";

#[derive(Debug, Clone)]
pub(crate) struct DetectedIncident {
    record_input: IncidentRecordInput,
    notification: IncidentNotification,
}

impl DetectedIncident {
    pub(crate) fn from_notification(
        notification: IncidentNotification,
        detection_source: impl AsRef<str>,
        error_code: impl AsRef<str>,
    ) -> Self {
        let detection_source = detection_source.as_ref();
        let error_code = error_code.as_ref();
        let incident_type = incident_type_for_category(notification.category);
        let record_input = IncidentRecordInput::new(
            incident_type,
            severity_for_category(notification.category),
            detection_source,
            notification_dedupe_key(&notification, detection_source, error_code),
            error_code,
        );
        Self {
            record_input,
            notification,
        }
    }

    pub(crate) fn into_parts(self) -> (IncidentRecordInput, IncidentNotification) {
        (self.record_input, self.notification)
    }

    pub(crate) fn siem_buffer_overflow() -> Result<Self, crate::incident::IncidentDetectorError> {
        let detector = IncidentDetector::new();
        let notification = detector.siem_buffer_overflow()?;
        let record_input = siem_buffer_overflow_incident_input();
        Ok(Self {
            record_input,
            notification,
        })
    }
}

pub(crate) async fn record_and_dispatch_incident(state: &AppState, detected: DetectedIncident) {
    record_and_dispatch_incident_parts(
        state.incident_recorder.as_ref(),
        state.incident_dispatcher.as_deref(),
        detected,
    )
    .await;
}

pub(crate) async fn record_and_dispatch_incident_parts(
    incident_recorder: &crate::incident::IncidentRecorder,
    incident_dispatcher: Option<&IncidentDispatcher<AnyNotificationSink, SupabaseAuditAppender>>,
    detected: DetectedIncident,
) {
    let (record_input, notification) = detected.into_parts();
    match incident_recorder.record(record_input).await {
        Ok(result) => {
            tracing::info!(
                notification_result = result.notification_result.as_str(),
                suppressed = result.suppressed,
                "incident detection recorded"
            );
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                error_code = "incident_detected_record_failed",
                "incident detection recording failed"
            );
        }
    }

    if let Some(dispatcher) = incident_dispatcher {
        let _ = dispatcher.dispatch(notification).await;
    }
}

pub(crate) async fn record_siem_long_failure_incident(state: &AppState, detection_source: &str) {
    let input = siem_long_failure_incident_input(detection_source);
    match state.incident_recorder.record(input).await {
        Ok(result) => {
            tracing::info!(
                notification_result = result.notification_result.as_str(),
                suppressed = result.suppressed,
                "SIEM long failure incident recorded"
            );
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "SIEM long failure incident recording failed"
            );
        }
    }
}

pub(crate) fn siem_buffer_overflow_incident_input() -> IncidentRecordInput {
    let incident_type = IncidentType::SiemBufferOverflow;
    IncidentRecordInput::new(
        incident_type,
        crate::incident::severity_for_incident(incident_type),
        SIEM_BUFFER_OVERFLOW_DETECTION_SOURCE,
        SIEM_BUFFER_OVERFLOW_DEDUPE_KEY,
        SIEM_BUFFER_OVERFLOW_ERROR_CODE,
    )
}

pub(crate) fn siem_long_failure_incident_input(detection_source: &str) -> IncidentRecordInput {
    let incident_type = IncidentType::SiemLongFailure;
    IncidentRecordInput::new(
        incident_type,
        crate::incident::severity_for_incident(incident_type),
        detection_source,
        SIEM_LONG_FAILURE_DEDUPE_KEY,
        SIEM_LONG_FAILURE_ERROR_CODE,
    )
}

fn incident_type_for_category(category: IncidentCategory) -> IncidentType {
    match category {
        IncidentCategory::LedgerAnomaly => IncidentType::LedgerAnomaly,
        IncidentCategory::SchedulerFailure => IncidentType::SchedulerFailure,
        IncidentCategory::ArchiveFailurePersistent => IncidentType::ArchiveFailurePersistent,
        IncidentCategory::TimestampingFailurePersistent => {
            IncidentType::TimestampingFailurePersistent
        }
        IncidentCategory::SiemBufferThreshold => IncidentType::SiemBufferThreshold,
        IncidentCategory::SiemBufferOverflow => IncidentType::SiemBufferOverflow,
        IncidentCategory::EnvelopeMigrationFailureBurst => {
            IncidentType::EnvelopeMigrationFailureBurst
        }
        IncidentCategory::AuthFailureBurst => IncidentType::AuthFailureBurst,
        IncidentCategory::KeyRotationFailure => IncidentType::KeyRotationFailure,
    }
}

fn severity_for_category(category: IncidentCategory) -> IncidentSeverity {
    match category {
        IncidentCategory::LedgerAnomaly | IncidentCategory::KeyRotationFailure => {
            IncidentSeverity::Critical
        }
        IncidentCategory::SchedulerFailure
        | IncidentCategory::ArchiveFailurePersistent
        | IncidentCategory::TimestampingFailurePersistent
        | IncidentCategory::SiemBufferOverflow => IncidentSeverity::High,
        IncidentCategory::SiemBufferThreshold
        | IncidentCategory::EnvelopeMigrationFailureBurst
        | IncidentCategory::AuthFailureBurst => IncidentSeverity::Medium,
    }
}

fn notification_dedupe_key(
    notification: &IncidentNotification,
    detection_source: &str,
    error_code: &str,
) -> String {
    let correlation = notification
        .correlation_id
        .as_deref()
        .map(sanitize_dedupe_component)
        .unwrap_or_else(|| sanitize_dedupe_component(error_code));
    format!(
        "{}:{}:{}",
        notification.category.as_str(),
        sanitize_dedupe_component(detection_source),
        correlation
    )
}

fn sanitize_dedupe_component(value: &str) -> String {
    let mut sanitized = String::new();
    for ch in value.chars().take(48) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-') {
            sanitized.push(ch);
        } else if !sanitized.ends_with('_') {
            sanitized.push('_');
        }
    }
    let sanitized = sanitized.trim_matches('_');
    if sanitized.is_empty() {
        "unknown".to_owned()
    } else {
        sanitized.to_owned()
    }
}

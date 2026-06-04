use crate::incident::{
    IncidentCategory, IncidentNotification, IncidentRecordInput, IncidentSeverity, IncidentType,
};

use super::state::AppState;

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
}

pub(crate) async fn record_and_dispatch_incident(state: &AppState, detected: DetectedIncident) {
    let record_input = detected.record_input;
    let notification = detected.notification;
    match state.incident_recorder.record(record_input).await {
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

    if let Some(dispatcher) = state.incident_dispatcher.as_ref() {
        let _ = dispatcher.dispatch(notification).await;
    }
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
        | IncidentCategory::TimestampingFailurePersistent => IncidentSeverity::High,
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

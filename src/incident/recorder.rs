use std::fmt;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditMetadata, AuditResult, RequestId,
};
use crate::ledger::{
    FORBIDDEN_LEDGER_PAYLOAD_KEYS, LedgerEntryId, LedgerEntryType, LedgerPayload, LedgerResult,
    MonthlyDigestPeriod,
};
use crate::server::ledger_appender::{
    LedgerAppendDraft, LedgerAppendDraftParts, LedgerAppendError, LedgerAppender,
};
use crate::server::supabase::{SupabaseClient, SupabaseRpcError};
use crate::types::SourceEventAt;

use super::{IncidentRecordInput, IncidentSeverity, IncidentType, NotificationResult};

const MAX_RECORD_RETRIES: u8 = 2;

#[derive(Debug)]
pub enum IncidentRecordError {
    IdGenerationFailed,
    SourceEventAtUnavailable,
    InvalidMetadata(crate::audit::AuditEventError),
    InvalidLedgerPayload(crate::ledger::LedgerError),
    InvalidLedgerDraft(crate::ledger::LedgerError),
    LedgerSignFailed(LedgerAppendError),
    Supabase(SupabaseRpcError),
}

impl fmt::Display for IncidentRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdGenerationFailed => formatter.write_str("incident id generation failed"),
            Self::SourceEventAtUnavailable => {
                formatter.write_str("incident source_event_at generation failed")
            }
            Self::InvalidMetadata(error) => write!(formatter, "incident metadata invalid: {error}"),
            Self::InvalidLedgerPayload(error) => {
                write!(formatter, "incident ledger payload invalid: {error}")
            }
            Self::InvalidLedgerDraft(error) => {
                write!(formatter, "incident ledger draft invalid: {error}")
            }
            Self::LedgerSignFailed(error) => {
                write!(formatter, "incident ledger signing failed: {error}")
            }
            Self::Supabase(error) => write!(formatter, "incident Supabase RPC failed: {error}"),
        }
    }
}

impl std::error::Error for IncidentRecordError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentRecordResult {
    pub audit_event_id: Option<AuditEventId>,
    pub notification_result: NotificationResult,
    pub suppressed: bool,
}

pub struct IncidentRecorder {
    supabase_client: Arc<SupabaseClient>,
    ledger_appender: Arc<LedgerAppender>,
    notification_sink_name: String,
}

impl IncidentRecorder {
    pub fn new(
        supabase_client: Arc<SupabaseClient>,
        ledger_appender: Arc<LedgerAppender>,
        notification_sink_name: impl Into<String>,
    ) -> Self {
        Self {
            supabase_client,
            ledger_appender,
            notification_sink_name: notification_sink_name.into(),
        }
    }

    pub fn notification_sink_name(&self) -> &str {
        &self.notification_sink_name
    }

    pub async fn record(
        &self,
        input: IncidentRecordInput,
    ) -> Result<IncidentRecordResult, IncidentRecordError> {
        let source_event_at =
            SourceEventAt::now_utc().map_err(|_| IncidentRecordError::SourceEventAtUnavailable)?;

        if self
            .supabase_client
            .incident_recently_seen(&input, &source_event_at)
            .await
            .map_err(IncidentRecordError::Supabase)?
        {
            return Ok(IncidentRecordResult {
                audit_event_id: None,
                notification_result: NotificationResult::Suppressed,
                suppressed: true,
            });
        }

        let notification_result = NotificationResult::NotConfigured;

        self.record_after_notification(input, source_event_at, notification_result)
            .await
    }

    async fn record_after_notification(
        &self,
        input: IncidentRecordInput,
        source_event_at: SourceEventAt,
        notification_result: NotificationResult,
    ) -> Result<IncidentRecordResult, IncidentRecordError> {
        let request_id =
            RequestId::generate().map_err(|_| IncidentRecordError::IdGenerationFailed)?;
        let audit_event_id =
            AuditEventId::generate().map_err(|_| IncidentRecordError::IdGenerationFailed)?;
        let metadata = build_incident_metadata(
            &input,
            notification_result,
            &self.notification_sink_name,
            &source_event_at,
        )?;
        let event =
            build_incident_audit_event(audit_event_id.clone(), request_id.clone(), metadata)?;

        let draft = build_incident_ledger_draft(
            &input,
            audit_event_id.clone(),
            source_event_at,
            request_id,
            notification_result,
            &self.notification_sink_name,
        )?;

        self.record_incident_with_retry(&input, &event, &draft, notification_result)
            .await
    }

    async fn record_incident_with_retry(
        &self,
        input: &IncidentRecordInput,
        event: &AuditEvent,
        draft: &LedgerAppendDraft,
        notification_result: NotificationResult,
    ) -> Result<IncidentRecordResult, IncidentRecordError> {
        for retry_index in 0..=MAX_RECORD_RETRIES {
            let signed_entries = self
                .ledger_appender
                .sign_entries(std::slice::from_ref(draft))
                .await
                .map_err(IncidentRecordError::LedgerSignFailed)?;
            let Some(signed_entry) = signed_entries.into_iter().next() else {
                return Err(IncidentRecordError::LedgerSignFailed(
                    LedgerAppendError::InvalidEntry {
                        code: "incident_ledger_sign_empty",
                    },
                ));
            };

            match self
                .supabase_client
                .record_incident(input, event, &signed_entry, notification_result)
                .await
            {
                Ok(outcome) => {
                    return Ok(IncidentRecordResult {
                        audit_event_id: Some(outcome.audit_event_id),
                        notification_result,
                        suppressed: outcome.suppressed,
                    });
                }
                Err(error)
                    if self
                        .supabase_client
                        .is_retryable_incident_record_error(&error)
                        && retry_index < MAX_RECORD_RETRIES =>
                {
                    continue;
                }
                Err(error) => return Err(IncidentRecordError::Supabase(error)),
            }
        }

        Err(IncidentRecordError::Supabase(
            SupabaseRpcError::InvalidResponse("incident retry exhausted".to_owned()),
        ))
    }
}

fn build_incident_audit_event(
    audit_event_id: AuditEventId,
    request_id: RequestId,
    metadata: AuditMetadata,
) -> Result<AuditEvent, IncidentRecordError> {
    AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id,
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::IncidentDetected,
        target_secret_id: None,
        result: AuditResult::Failure,
        key_version: None,
        metadata_json: metadata,
    })
    .map_err(IncidentRecordError::InvalidMetadata)
}

fn build_incident_ledger_draft(
    input: &IncidentRecordInput,
    audit_event_id: AuditEventId,
    source_event_at: SourceEventAt,
    request_id: RequestId,
    notification_result: NotificationResult,
    notification_sink: &str,
) -> Result<LedgerAppendDraft, IncidentRecordError> {
    let payload = build_incident_ledger_payload(input, notification_result, notification_sink)?;
    LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::generate()
            .map_err(|_| IncidentRecordError::IdGenerationFailed)?,
        entry_type: LedgerEntryType::IncidentDetected,
        source_event_at,
        request_id,
        source_event_id: Some(audit_event_id),
        target_secret_id: None,
        target_secret_version_id: None,
        actor_user_id: None,
        actor_device_id: None,
        result: LedgerResult::Failure,
        error_code: Some(input.error_code.clone()),
        payload,
    })
    .map_err(IncidentRecordError::InvalidLedgerDraft)
}

#[cfg(test)]
async fn deliver_notification<S: super::NotificationSink>(
    notification_sink: &S,
    input: &IncidentRecordInput,
) -> NotificationResult {
    let notification_payload = super::IncidentNotificationPayload::from_input(input);
    match notification_sink.notify(&notification_payload).await {
        Ok(()) => NotificationResult::Sent,
        Err(error) => {
            tracing::error!(
                error = %error,
                incident_type = input.incident_type.as_str(),
                "incident notification failed"
            );
            NotificationResult::Failed
        }
    }
}

fn build_incident_metadata(
    input: &IncidentRecordInput,
    notification_result: NotificationResult,
    notification_sink: &str,
    source_event_at: &SourceEventAt,
) -> Result<AuditMetadata, IncidentRecordError> {
    let mut object = Map::new();
    object.insert(
        "incident_type".to_owned(),
        Value::String(input.incident_type.as_str().to_owned()),
    );
    object.insert(
        "severity".to_owned(),
        Value::String(input.severity.as_str().to_owned()),
    );
    object.insert(
        "detection_source".to_owned(),
        Value::String(input.detection_source.clone()),
    );
    object.insert(
        "dedupe_key".to_owned(),
        Value::String(input.dedupe_key.clone()),
    );
    object.insert(
        "notification_sink".to_owned(),
        Value::String(notification_sink.to_owned()),
    );
    object.insert(
        "notification_result".to_owned(),
        Value::String(notification_result.as_str().to_owned()),
    );
    object.insert(
        "error_code".to_owned(),
        Value::String(input.error_code.clone()),
    );
    object.insert(
        "source_event_at".to_owned(),
        Value::String(source_event_at.as_str().to_owned()),
    );

    if let Some(source_event_id) = &input.incident_source_event_id {
        object.insert(
            "source_event_id".to_owned(),
            Value::String(source_event_id.as_canonical_string()),
        );
    }
    if let Some(sequence_no) = input.target_sequence_no {
        object.insert(
            "target_sequence_no".to_owned(),
            Value::Number(sequence_no.into()),
        );
    }
    if let Some(period) = &input.target_year_month {
        object.insert(
            "target_year_month".to_owned(),
            Value::String(period.as_str().to_owned()),
        );
    }

    AuditMetadata::from_object(object)
        .and_then(|metadata| {
            metadata.validate_allowlist_for_action(
                AuditAction::IncidentDetected,
                AuditResult::Failure,
            )?;
            Ok(metadata)
        })
        .map_err(IncidentRecordError::InvalidMetadata)
}

fn build_incident_ledger_payload(
    input: &IncidentRecordInput,
    notification_result: NotificationResult,
    notification_sink: &str,
) -> Result<LedgerPayload, IncidentRecordError> {
    let mut object = Map::new();
    object.insert(
        "incident_type".to_owned(),
        Value::String(input.incident_type.as_str().to_owned()),
    );
    object.insert(
        "severity".to_owned(),
        Value::String(input.severity.as_str().to_owned()),
    );
    object.insert(
        "detection_source".to_owned(),
        Value::String(input.detection_source.clone()),
    );
    object.insert(
        "dedupe_key".to_owned(),
        Value::String(input.dedupe_key.clone()),
    );
    object.insert(
        "notification_sink".to_owned(),
        Value::String(notification_sink.to_owned()),
    );
    object.insert(
        "notification_result".to_owned(),
        Value::String(notification_result.as_str().to_owned()),
    );
    if let Some(sequence_no) = input.target_sequence_no {
        object.insert(
            "target_sequence_no".to_owned(),
            Value::Number(sequence_no.into()),
        );
    }
    if let Some(period) = &input.target_year_month {
        object.insert(
            "target_year_month".to_owned(),
            Value::String(period.as_str().to_owned()),
        );
    }

    LedgerPayload::new(LedgerEntryType::IncidentDetected, Value::Object(object))
        .map_err(IncidentRecordError::InvalidLedgerPayload)
}

pub fn scheduler_incident_type(error_code: &str) -> Option<IncidentType> {
    match error_code {
        "ledger_entry_hash_mismatch"
        | "ledger_previous_hash_mismatch"
        | "ledger_chain_head_mismatch" => Some(IncidentType::HashChainMismatch),
        "ledger_sequence_gap" => Some(IncidentType::SequenceGap),
        "ledger_signature_invalid" => Some(IncidentType::SignatureMismatch),
        "ledger_signature_key_missing" => Some(IncidentType::UnknownSignatureKey),
        "ledger_payload_forbidden_key" => Some(IncidentType::LedgerSecretLeakSuspected),
        _ => None,
    }
}

pub fn monthly_digest_incident_type(error_code: &str) -> Option<IncidentType> {
    match error_code {
        "monthly_digest_unknown_signature_key" | "chain_unknown_signature_key" => {
            Some(IncidentType::UnknownSignatureKey)
        }
        "monthly_digest_end_hash_mismatch"
        | "monthly_digest_hash_mismatch"
        | "monthly_digest_signature_invalid"
        | "monthly_digest_range_modified"
        | "monthly_digest_chain_continuity_error"
        | "chain_previous_hash_mismatch"
        | "chain_entry_hash_mismatch"
        | "chain_signature_invalid"
        | "chain_sequence_gap" => Some(IncidentType::MonthlyDigestMismatch),
        _ => None,
    }
}

pub fn digest_timestamping_incident_type(error_code: &str) -> Option<IncidentType> {
    match error_code {
        "digest_timestamping_mismatch"
        | "digest_timestamping_token_mismatch"
        | "digest_timestamping_token_hash_mismatch"
        | "digest_timestamping_verification_failed"
        | "digest_timestamping_invalid_response"
        | "digest_timestamped_append_failed" => Some(IncidentType::DigestTimestampingMismatch),
        _ if error_code.starts_with("digest_timestamping_") => {
            Some(IncidentType::DigestTimestampingMismatch)
        }
        _ => None,
    }
}

pub fn digest_timestamping_incident_input(
    detection_source: &str,
    error_code: &str,
    period: &MonthlyDigestPeriod,
) -> Option<IncidentRecordInput> {
    let incident_type = digest_timestamping_incident_type(error_code)?;
    Some(
        IncidentRecordInput::new(
            incident_type,
            severity_for_incident(incident_type),
            detection_source,
            dedupe_key(incident_type, detection_source, Some(period)),
            error_code,
        )
        .with_target_year_month(period.clone()),
    )
}

pub fn archive_incident_type(error_code: &str) -> Option<IncidentType> {
    match error_code {
        "archive_export_mismatch"
        | "archive_export_content_mismatch"
        | "archive_export_not_found"
        | "archive_export_verify_failed"
        | "archive_export_failed"
        | "archive_exported_append_failed" => Some(IncidentType::ArchiveExportMismatch),
        _ if error_code.starts_with("archive_export_") => Some(IncidentType::ArchiveExportMismatch),
        _ => None,
    }
}

pub fn archive_incident_input(
    detection_source: &str,
    error_code: &str,
    period: &MonthlyDigestPeriod,
) -> Option<IncidentRecordInput> {
    let incident_type = archive_incident_type(error_code)?;
    Some(
        IncidentRecordInput::new(
            incident_type,
            severity_for_incident(incident_type),
            detection_source,
            dedupe_key(incident_type, detection_source, Some(period)),
            error_code,
        )
        .with_target_year_month(period.clone()),
    )
}

pub fn non_auditor_ledger_read_input(detection_source: &str) -> IncidentRecordInput {
    let incident_type = IncidentType::NonAuditorLedgerRead;
    IncidentRecordInput::new(
        incident_type,
        severity_for_incident(incident_type),
        detection_source,
        dedupe_key(incident_type, detection_source, None),
        "non_auditor_ledger_read",
    )
}

pub fn audit_ui_forbidden_operation_input(
    detection_source: &str,
    operation: &str,
) -> IncidentRecordInput {
    let incident_type = IncidentType::AuditUiForbiddenOperation;
    IncidentRecordInput::new(
        incident_type,
        severity_for_incident(incident_type),
        detection_source,
        format!(
            "{}:{detection_source}:{}",
            incident_type.as_str(),
            sanitize_dedupe_component(operation)
        ),
        "audit_ui_forbidden_operation",
    )
}

pub fn ledger_secret_leak_suspected_input(
    detection_source: &str,
    sequence_no: Option<u64>,
) -> IncidentRecordInput {
    let incident_type = IncidentType::LedgerSecretLeakSuspected;
    let mut input = IncidentRecordInput::new(
        incident_type,
        severity_for_incident(incident_type),
        detection_source,
        match sequence_no {
            Some(sequence_no) => format!(
                "{}:{detection_source}:{sequence_no}",
                incident_type.as_str()
            ),
            None => dedupe_key(incident_type, detection_source, None),
        },
        "ledger_payload_forbidden_key",
    );
    if let Some(sequence_no) = sequence_no {
        input = input.with_target_sequence_no(sequence_no);
    }
    input
}

pub fn ledger_payload_contains_forbidden_key(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, nested)| {
            is_forbidden_ledger_payload_key(key) || ledger_payload_contains_forbidden_key(nested)
        }),
        Value::Array(values) => values.iter().any(ledger_payload_contains_forbidden_key),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

pub async fn record_non_auditor_ledger_read(
    recorder: &IncidentRecorder,
    detection_source: &str,
) -> Result<IncidentRecordResult, IncidentRecordError> {
    recorder
        .record(non_auditor_ledger_read_input(detection_source))
        .await
}

pub async fn record_audit_ui_forbidden_operation(
    recorder: &IncidentRecorder,
    detection_source: &str,
    operation: &str,
) -> Result<IncidentRecordResult, IncidentRecordError> {
    recorder
        .record(audit_ui_forbidden_operation_input(
            detection_source,
            operation,
        ))
        .await
}

pub async fn record_ledger_secret_leak_suspected(
    recorder: &IncidentRecorder,
    detection_source: &str,
    sequence_no: Option<u64>,
) -> Result<IncidentRecordResult, IncidentRecordError> {
    recorder
        .record(ledger_secret_leak_suspected_input(
            detection_source,
            sequence_no,
        ))
        .await
}

fn is_forbidden_ledger_payload_key(key: &str) -> bool {
    let normalized = key.trim().to_ascii_lowercase();
    FORBIDDEN_LEDGER_PAYLOAD_KEYS
        .iter()
        .any(|forbidden| normalized == *forbidden)
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

pub fn severity_for_incident(incident_type: IncidentType) -> IncidentSeverity {
    match incident_type {
        IncidentType::HashChainMismatch
        | IncidentType::LedgerSecretLeakSuspected
        | IncidentType::UnknownSignatureKey => IncidentSeverity::Critical,
        IncidentType::SignatureMismatch
        | IncidentType::MonthlyDigestMismatch
        | IncidentType::DigestTimestampingMismatch
        | IncidentType::ArchiveExportMismatch
        | IncidentType::SequenceGap
        | IncidentType::SchedulerFailure
        | IncidentType::ArchiveFailurePersistent
        | IncidentType::TimestampingFailurePersistent => IncidentSeverity::High,
        IncidentType::LedgerAnomaly | IncidentType::KeyRotationFailure => {
            IncidentSeverity::Critical
        }
        IncidentType::NonAuditorLedgerRead
        | IncidentType::SiemLongFailure
        | IncidentType::AuditUiForbiddenOperation
        | IncidentType::SiemBufferThreshold
        | IncidentType::EnvelopeMigrationFailureBurst
        | IncidentType::AuthFailureBurst => IncidentSeverity::Medium,
    }
}

pub fn dedupe_key(
    incident_type: IncidentType,
    detection_source: &str,
    target_year_month: Option<&MonthlyDigestPeriod>,
) -> String {
    match target_year_month {
        Some(period) => format!(
            "{}:{}:{}",
            incident_type.as_str(),
            detection_source,
            period.as_str()
        ),
        None => format!("{}:{detection_source}", incident_type.as_str()),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/incident/recorder/tests.rs"]
mod tests;

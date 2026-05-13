use std::fmt;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditMetadata, AuditResult, RequestId,
};
use crate::ledger::{
    LedgerEntryId, LedgerEntryType, LedgerPayload, LedgerResult, MonthlyDigestPeriod,
};
use crate::server::ledger_appender::{
    LedgerAppendDraft, LedgerAppendDraftParts, LedgerAppendError, LedgerAppender,
};
use crate::server::supabase::{SupabaseClient, SupabaseRpcError};
use crate::types::SourceEventAt;

use super::{
    IncidentNotificationPayload, IncidentRecordInput, IncidentSeverity, IncidentType,
    NotificationResult, NotificationSink,
};

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

pub struct IncidentRecorder<S> {
    supabase_client: Arc<SupabaseClient>,
    ledger_appender: Arc<LedgerAppender>,
    notification_sink: S,
}

impl<S: NotificationSink> IncidentRecorder<S> {
    pub fn new(
        supabase_client: Arc<SupabaseClient>,
        ledger_appender: Arc<LedgerAppender>,
        notification_sink: S,
    ) -> Self {
        Self {
            supabase_client,
            ledger_appender,
            notification_sink,
        }
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

        let notification_result = deliver_notification(&self.notification_sink, &input).await;

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
            self.notification_sink.sink_name(),
            &source_event_at,
        )?;
        let event = AuditEvent::new(AuditEventParts {
            audit_event_id: audit_event_id.clone(),
            request_id: request_id.clone(),
            actor_user_id: None,
            actor_device_id: None,
            action: AuditAction::IncidentDetected,
            target_secret_id: None,
            result: AuditResult::Failure,
            key_version: None,
            metadata_json: metadata,
        })
        .map_err(IncidentRecordError::InvalidMetadata)?;

        let payload = build_incident_ledger_payload(
            &input,
            notification_result,
            self.notification_sink.sink_name(),
        )?;
        let draft = LedgerAppendDraft::new(LedgerAppendDraftParts {
            ledger_entry_id: LedgerEntryId::generate()
                .map_err(|_| IncidentRecordError::IdGenerationFailed)?,
            entry_type: LedgerEntryType::IncidentDetected,
            source_event_at,
            request_id,
            source_event_id: Some(audit_event_id.clone()),
            target_secret_id: None,
            target_secret_version_id: None,
            actor_user_id: None,
            actor_device_id: None,
            result: LedgerResult::Failure,
            error_code: Some(input.error_code.clone()),
            payload,
        })
        .map_err(IncidentRecordError::InvalidLedgerDraft)?;

        for retry_index in 0..=MAX_RECORD_RETRIES {
            let signed_entries = self
                .ledger_appender
                .sign_entries(std::slice::from_ref(&draft))
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
                .record_incident(&input, &event, &signed_entry, notification_result)
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

async fn deliver_notification<S: NotificationSink>(
    notification_sink: &S,
    input: &IncidentRecordInput,
) -> NotificationResult {
    let notification_payload = IncidentNotificationPayload::from_input(input);
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

pub fn severity_for_incident(incident_type: IncidentType) -> IncidentSeverity {
    match incident_type {
        IncidentType::HashChainMismatch
        | IncidentType::LedgerSecretLeakSuspected
        | IncidentType::UnknownSignatureKey => IncidentSeverity::Critical,
        IncidentType::SignatureMismatch
        | IncidentType::MonthlyDigestMismatch
        | IncidentType::DigestTimestampingMismatch
        | IncidentType::ArchiveExportMismatch
        | IncidentType::SequenceGap => IncidentSeverity::High,
        IncidentType::NonAuditorLedgerRead
        | IncidentType::SiemLongFailure
        | IncidentType::AuditUiForbiddenOperation => IncidentSeverity::Medium,
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
mod tests {
    use crate::incident::{
        DummyNotificationSink, FailingNotificationSink, IncidentRecordInput, IncidentSeverity,
        IncidentType, NotificationResult,
    };
    use crate::ledger::MonthlyDigestPeriod;

    use super::{
        dedupe_key, deliver_notification, monthly_digest_incident_type, scheduler_incident_type,
        severity_for_incident,
    };

    #[tokio::test]
    async fn failed_sink_maps_to_failed_notification_result() {
        let sink = FailingNotificationSink::new("backend_down");
        let input = IncidentRecordInput::new(
            IncidentType::HashChainMismatch,
            IncidentSeverity::Critical,
            "ledger_hash_chain_full_verify",
            "hash_chain_mismatch:ledger_hash_chain_full_verify",
            "ledger_entry_hash_mismatch",
        );

        let result = deliver_notification(&sink, &input).await;

        assert_eq!(result, NotificationResult::Failed);
    }

    #[tokio::test]
    async fn dummy_sink_maps_to_sent_notification_result_and_keeps_payload() {
        let sink = DummyNotificationSink::new();
        let input = IncidentRecordInput::new(
            IncidentType::SequenceGap,
            IncidentSeverity::High,
            "ledger_hash_chain_full_verify",
            "sequence_gap:ledger_hash_chain_full_verify",
            "ledger_sequence_gap",
        );

        let result = deliver_notification(&sink, &input).await;

        assert_eq!(result, NotificationResult::Sent);
        assert_eq!(sink.payload_count(), 1);
        assert_eq!(sink.payloads()[0].incident_type, IncidentType::SequenceGap);
    }

    #[test]
    fn scheduler_error_codes_map_to_incident_types() {
        assert_eq!(
            scheduler_incident_type("ledger_entry_hash_mismatch"),
            Some(IncidentType::HashChainMismatch)
        );
        assert_eq!(
            scheduler_incident_type("ledger_previous_hash_mismatch"),
            Some(IncidentType::HashChainMismatch)
        );
        assert_eq!(
            scheduler_incident_type("ledger_chain_head_mismatch"),
            Some(IncidentType::HashChainMismatch)
        );
        assert_eq!(
            scheduler_incident_type("ledger_sequence_gap"),
            Some(IncidentType::SequenceGap)
        );
        assert_eq!(
            scheduler_incident_type("ledger_signature_invalid"),
            Some(IncidentType::SignatureMismatch)
        );
        assert_eq!(
            scheduler_incident_type("ledger_signature_key_missing"),
            Some(IncidentType::UnknownSignatureKey)
        );
        assert_eq!(scheduler_incident_type("other_error"), None);
    }

    #[test]
    fn monthly_digest_error_codes_map_to_incident_types() {
        assert_eq!(
            monthly_digest_incident_type("monthly_digest_hash_mismatch"),
            Some(IncidentType::MonthlyDigestMismatch)
        );
        assert_eq!(
            monthly_digest_incident_type("monthly_digest_unknown_signature_key"),
            Some(IncidentType::UnknownSignatureKey)
        );
        assert_eq!(
            monthly_digest_incident_type("chain_signature_invalid"),
            Some(IncidentType::MonthlyDigestMismatch)
        );
        assert_eq!(monthly_digest_incident_type("network_down"), None);
    }

    #[test]
    fn severity_and_dedupe_key_are_stable() {
        assert_eq!(
            severity_for_incident(IncidentType::HashChainMismatch),
            IncidentSeverity::Critical
        );
        assert_eq!(
            severity_for_incident(IncidentType::SiemLongFailure),
            IncidentSeverity::Medium
        );

        let period = MonthlyDigestPeriod::parse("2026-05").expect("valid test period");
        assert_eq!(
            dedupe_key(
                IncidentType::MonthlyDigestMismatch,
                "monthly_digest_verify",
                Some(&period)
            ),
            "monthly_digest_mismatch:monthly_digest_verify:2026-05"
        );
    }
}

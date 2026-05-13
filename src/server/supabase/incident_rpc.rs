use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::{AuditEvent, AuditEventId};
use crate::incident::{IncidentRecordInput, NotificationResult};
use crate::ledger::SignedLedgerEntry;
use crate::types::SourceEventAt;
use crate::types::supabase::LedgerEntryRpcParams;

use super::response::{ensure_success, response_contains_marker};
use super::{SupabaseClient, SupabaseRpcError};

const LEDGER_SEQUENCE_MISMATCH_MARKER: &str = "ledger_sequence_mismatch";
const LEDGER_PREVIOUS_HASH_MISMATCH_MARKER: &str = "ledger_previous_hash_mismatch";

impl SupabaseClient {
    pub async fn incident_recently_seen(
        &self,
        input: &IncidentRecordInput,
        source_event_at: &SourceEventAt,
    ) -> Result<bool, SupabaseRpcError> {
        let params = IncidentRecentlySeenParams::from_input(input, source_event_at);
        let response = self.post_rpc("rpc_incident_recently_seen", &params).await?;
        ensure_success(response)
            .await?
            .json::<bool>()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))
    }

    pub async fn record_incident(
        &self,
        input: &IncidentRecordInput,
        event: &AuditEvent,
        ledger_entry: &SignedLedgerEntry,
        notification_result: NotificationResult,
    ) -> Result<IncidentRecordOutcome, SupabaseRpcError> {
        let params =
            RecordIncidentParams::from_input(input, event, ledger_entry, notification_result)?;
        let response = self.post_rpc("rpc_record_incident", &params).await?;
        let rows: Vec<RecordIncidentResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(IncidentRecordOutcome::try_from)
    }

    pub fn is_retryable_incident_record_error(&self, error: &SupabaseRpcError) -> bool {
        let SupabaseRpcError::NonSuccessStatus { body, .. } = error else {
            return false;
        };

        response_contains_marker(body, LEDGER_SEQUENCE_MISMATCH_MARKER)
            || response_contains_marker(body, LEDGER_PREVIOUS_HASH_MISMATCH_MARKER)
    }
}

#[derive(Serialize)]
struct IncidentRecentlySeenParams {
    p_incident_type: String,
    p_dedupe_key: String,
    p_source_event_at: String,
    p_dedupe_window_seconds: u32,
}

impl IncidentRecentlySeenParams {
    fn from_input(input: &IncidentRecordInput, source_event_at: &SourceEventAt) -> Self {
        Self {
            p_incident_type: input.incident_type.as_str().to_owned(),
            p_dedupe_key: input.dedupe_key.clone(),
            p_source_event_at: source_event_at.as_str().to_owned(),
            p_dedupe_window_seconds: input.dedupe_window_seconds,
        }
    }
}

#[derive(Serialize)]
struct RecordIncidentParams {
    p_audit_event_id: String,
    p_request_id: String,
    p_incident_type: String,
    p_severity: String,
    p_detection_source: String,
    p_dedupe_key: String,
    p_notification_sink: String,
    p_notification_result: String,
    p_error_code: String,
    p_source_event_at: String,
    p_ledger_entry: Value,
    p_incident_source_event_id: Option<String>,
    p_target_sequence_no: Option<u64>,
    p_target_year_month: Option<String>,
    p_dedupe_window_seconds: u32,
}

impl RecordIncidentParams {
    fn from_input(
        input: &IncidentRecordInput,
        event: &AuditEvent,
        ledger_entry: &SignedLedgerEntry,
        notification_result: NotificationResult,
    ) -> Result<Self, SupabaseRpcError> {
        let ledger_params = LedgerEntryRpcParams::from_signed_entry(ledger_entry);
        let ledger_entry = serde_json::to_value(ledger_params)
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        Ok(Self {
            p_audit_event_id: event.audit_event_id().as_canonical_string(),
            p_request_id: event.request_id().as_canonical_string(),
            p_incident_type: input.incident_type.as_str().to_owned(),
            p_severity: input.severity.as_str().to_owned(),
            p_detection_source: input.detection_source.clone(),
            p_dedupe_key: input.dedupe_key.clone(),
            p_notification_sink: event
                .metadata_json()
                .as_value()
                .get("notification_sink")
                .and_then(Value::as_str)
                .unwrap_or("dummy")
                .to_owned(),
            p_notification_result: notification_result.as_str().to_owned(),
            p_error_code: input.error_code.clone(),
            p_source_event_at: ledger_entry
                .get("p_source_event_at")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SupabaseRpcError::InvalidResponse(
                        "incident ledger entry missing source_event_at".to_owned(),
                    )
                })?
                .to_owned(),
            p_ledger_entry: ledger_entry,
            p_incident_source_event_id: input
                .incident_source_event_id
                .as_ref()
                .map(AuditEventId::as_canonical_string),
            p_target_sequence_no: input.target_sequence_no,
            p_target_year_month: input
                .target_year_month
                .as_ref()
                .map(|period| period.as_str().to_owned()),
            p_dedupe_window_seconds: input.dedupe_window_seconds,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordIncidentResponse {
    audit_event_id: String,
    ledger_entry_id: Option<String>,
    suppressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentRecordOutcome {
    pub audit_event_id: AuditEventId,
    pub suppressed: bool,
}

impl TryFrom<RecordIncidentResponse> for IncidentRecordOutcome {
    type Error = SupabaseRpcError;

    fn try_from(response: RecordIncidentResponse) -> Result<Self, Self::Error> {
        let audit_event_id = AuditEventId::parse(&response.audit_event_id).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "incident RPC returned invalid audit_event_id".to_owned(),
            )
        })?;
        if !response.suppressed && response.ledger_entry_id.is_none() {
            return Err(SupabaseRpcError::InvalidResponse(
                "incident RPC returned null ledger_entry_id for unsuppressed incident".to_owned(),
            ));
        }

        Ok(Self {
            audit_event_id,
            suppressed: response.suppressed,
        })
    }
}

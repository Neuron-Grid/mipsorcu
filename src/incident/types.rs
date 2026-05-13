use std::fmt;

use serde::Serialize;

use crate::audit::AuditEventId;
use crate::ledger::MonthlyDigestPeriod;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentType {
    HashChainMismatch,
    SignatureMismatch,
    MonthlyDigestMismatch,
    DigestTimestampingMismatch,
    ArchiveExportMismatch,
    SequenceGap,
    UnknownSignatureKey,
    NonAuditorLedgerRead,
    LedgerSecretLeakSuspected,
    SiemLongFailure,
    AuditUiForbiddenOperation,
}

impl IncidentType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HashChainMismatch => "hash_chain_mismatch",
            Self::SignatureMismatch => "signature_mismatch",
            Self::MonthlyDigestMismatch => "monthly_digest_mismatch",
            Self::DigestTimestampingMismatch => "digest_timestamping_mismatch",
            Self::ArchiveExportMismatch => "archive_export_mismatch",
            Self::SequenceGap => "sequence_gap",
            Self::UnknownSignatureKey => "unknown_signature_key",
            Self::NonAuditorLedgerRead => "non_auditor_ledger_read",
            Self::LedgerSecretLeakSuspected => "ledger_secret_leak_suspected",
            Self::SiemLongFailure => "siem_long_failure",
            Self::AuditUiForbiddenOperation => "audit_ui_forbidden_operation",
        }
    }
}

impl fmt::Display for IncidentType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl IncidentSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationResult {
    Sent,
    Failed,
    Suppressed,
    NotConfigured,
}

impl NotificationResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Failed => "failed",
            Self::Suppressed => "suppressed",
            Self::NotConfigured => "not_configured",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IncidentNotificationPayload {
    pub incident_type: IncidentType,
    pub severity: IncidentSeverity,
    pub detection_source: String,
    pub dedupe_key: String,
    pub error_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_sequence_no: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_year_month: Option<String>,
}

impl IncidentNotificationPayload {
    pub(crate) fn from_input(input: &IncidentRecordInput) -> Self {
        Self {
            incident_type: input.incident_type,
            severity: input.severity,
            detection_source: input.detection_source.clone(),
            dedupe_key: input.dedupe_key.clone(),
            error_code: input.error_code.clone(),
            source_event_id: input
                .incident_source_event_id
                .as_ref()
                .map(AuditEventId::as_canonical_string),
            target_sequence_no: input.target_sequence_no,
            target_year_month: input
                .target_year_month
                .as_ref()
                .map(|period| period.as_str().to_owned()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IncidentRecordInput {
    pub incident_type: IncidentType,
    pub severity: IncidentSeverity,
    pub detection_source: String,
    pub dedupe_key: String,
    pub error_code: String,
    pub incident_source_event_id: Option<AuditEventId>,
    pub target_sequence_no: Option<u64>,
    pub target_year_month: Option<MonthlyDigestPeriod>,
    pub dedupe_window_seconds: u32,
}

impl IncidentRecordInput {
    pub fn new(
        incident_type: IncidentType,
        severity: IncidentSeverity,
        detection_source: impl Into<String>,
        dedupe_key: impl Into<String>,
        error_code: impl Into<String>,
    ) -> Self {
        Self {
            incident_type,
            severity,
            detection_source: detection_source.into(),
            dedupe_key: dedupe_key.into(),
            error_code: error_code.into(),
            incident_source_event_id: None,
            target_sequence_no: None,
            target_year_month: None,
            dedupe_window_seconds: 3600,
        }
    }

    pub fn with_source_event_id(mut self, source_event_id: AuditEventId) -> Self {
        self.incident_source_event_id = Some(source_event_id);
        self
    }

    pub fn with_target_sequence_no(mut self, sequence_no: u64) -> Self {
        self.target_sequence_no = Some(sequence_no);
        self
    }

    pub fn with_target_year_month(mut self, period: MonthlyDigestPeriod) -> Self {
        self.target_year_month = Some(period);
        self
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::ledger::MonthlyDigestPeriod;

    use super::{IncidentNotificationPayload, IncidentRecordInput, IncidentSeverity, IncidentType};

    #[test]
    fn notification_payload_serializes_only_non_secret_fields() {
        let period = MonthlyDigestPeriod::parse("2026-05").expect("valid test period");
        let input = IncidentRecordInput::new(
            IncidentType::MonthlyDigestMismatch,
            IncidentSeverity::High,
            "monthly_digest_verify",
            "monthly_digest_mismatch:monthly_digest_verify:2026-05",
            "monthly_digest_hash_mismatch",
        )
        .with_target_sequence_no(42)
        .with_target_year_month(period);

        let payload = IncidentNotificationPayload::from_input(&input);
        let value = serde_json::to_value(&payload).expect("payload should serialize");
        let object = value.as_object().expect("payload should be an object");
        let rendered = value.to_string();

        assert_eq!(
            object.get("incident_type").and_then(Value::as_str),
            Some("monthly_digest_mismatch")
        );
        assert_eq!(object.get("severity").and_then(Value::as_str), Some("high"));
        assert_eq!(
            object.get("target_year_month").and_then(Value::as_str),
            Some("2026-05")
        );
        assert_eq!(
            object.get("target_sequence_no").and_then(Value::as_u64),
            Some(42)
        );

        for forbidden_marker in [
            "plaintext",
            "master_key",
            "data_key",
            "jwt",
            "authorization",
            "request_body",
            "response_body",
            "ciphertext",
            "encrypted_data_key",
        ] {
            assert!(!rendered.contains(forbidden_marker));
        }
    }
}

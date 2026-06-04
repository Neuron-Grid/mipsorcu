use std::fmt;

use http::Uri;
use serde::Serialize;

use crate::audit::{AuditEventError, AuditEventId};
use crate::types::SourceEventAt;

use super::IncidentSeverity;

const SUMMARY_MAX_LEN: usize = 240;
const COMPONENT_MAX_LEN: usize = 64;
const CORRELATION_ID_MAX_LEN: usize = 128;
const TRIAGE_URL_MAX_LEN: usize = 512;

const FORBIDDEN_NOTIFICATION_TEXT: &[&str] = &[
    "alias_decryption_key",
    "alias_encryption_key",
    "authorization",
    "bearer_token",
    "ciphertext",
    "data_key",
    "decrypted",
    "encrypted_data_key",
    "jwt",
    "kek_value",
    "master_key",
    "nonce",
    "passphrase",
    "password",
    "plain_text",
    "plaintext",
    "raw_jwt",
    "request_body",
    "response_body",
    "secret_key",
    "secret_value",
    "service_role",
    "signature_private_key",
    "token",
    "wrapped_dek",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentDtoError {
    InvalidIncidentId,
    InvalidSummary,
    InvalidComponent,
    InvalidTriageUrl,
    InvalidCorrelationId,
    MissingAffectedComponent,
    SerializationFailed,
}

impl fmt::Display for IncidentDtoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidIncidentId => "incident id must be a canonical UUID",
            Self::InvalidSummary => "incident summary is invalid",
            Self::InvalidComponent => "incident affected component is invalid",
            Self::InvalidTriageUrl => "incident triage URL is invalid",
            Self::InvalidCorrelationId => "incident correlation id is invalid",
            Self::MissingAffectedComponent => {
                "incident must include at least one affected component"
            }
            Self::SerializationFailed => "incident notification serialization failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for IncidentDtoError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct IncidentId(String);

impl IncidentId {
    pub fn generate() -> Result<Self, AuditEventError> {
        AuditEventId::generate().map(|id| Self(id.as_canonical_string()))
    }

    pub fn parse(value: impl AsRef<str>) -> Result<Self, IncidentDtoError> {
        let value = value.as_ref();
        let parsed =
            uuid::Uuid::parse_str(value).map_err(|_| IncidentDtoError::InvalidIncidentId)?;
        let canonical = parsed.hyphenated().to_string();
        if value != canonical {
            return Err(IncidentDtoError::InvalidIncidentId);
        }
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IncidentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentCategory {
    LedgerAnomaly,
    SchedulerFailure,
    ArchiveFailurePersistent,
    TimestampingFailurePersistent,
    SiemBufferThreshold,
    EnvelopeMigrationFailureBurst,
    AuthFailureBurst,
    KeyRotationFailure,
}

impl IncidentCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LedgerAnomaly => "ledger_anomaly",
            Self::SchedulerFailure => "scheduler_failure",
            Self::ArchiveFailurePersistent => "archive_failure_persistent",
            Self::TimestampingFailurePersistent => "timestamping_failure_persistent",
            Self::SiemBufferThreshold => "siem_buffer_threshold",
            Self::EnvelopeMigrationFailureBurst => "envelope_migration_failure_burst",
            Self::AuthFailureBurst => "auth_failure_burst",
            Self::KeyRotationFailure => "key_rotation_failure",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ledger_anomaly" => Some(Self::LedgerAnomaly),
            "scheduler_failure" => Some(Self::SchedulerFailure),
            "archive_failure_persistent" => Some(Self::ArchiveFailurePersistent),
            "timestamping_failure_persistent" => Some(Self::TimestampingFailurePersistent),
            "siem_buffer_threshold" => Some(Self::SiemBufferThreshold),
            "envelope_migration_failure_burst" => Some(Self::EnvelopeMigrationFailureBurst),
            "auth_failure_burst" => Some(Self::AuthFailureBurst),
            "key_rotation_failure" => Some(Self::KeyRotationFailure),
            _ => None,
        }
    }
}

impl fmt::Display for IncidentCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct IncidentSummary(String);

impl IncidentSummary {
    pub fn new(value: impl Into<String>) -> Result<Self, IncidentDtoError> {
        let value = value.into();
        validate_non_secret_text(&value, SUMMARY_MAX_LEN)
            .map_err(|_| IncidentDtoError::InvalidSummary)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ComponentName(String);

impl ComponentName {
    pub fn new(value: impl Into<String>) -> Result<Self, IncidentDtoError> {
        let value = value.into();
        validate_non_secret_text(&value, COMPONENT_MAX_LEN)
            .map_err(|_| IncidentDtoError::InvalidComponent)?;
        Ok(Self(value))
    }

    pub fn ledger() -> Self {
        Self("ledger".to_owned())
    }

    pub fn scheduler() -> Self {
        Self("scheduler".to_owned())
    }

    pub fn archive() -> Self {
        Self("archive".to_owned())
    }

    pub fn timestamping() -> Self {
        Self("timestamping".to_owned())
    }

    pub fn siem() -> Self {
        Self("siem".to_owned())
    }

    pub fn envelope_migration() -> Self {
        Self("envelope_migration".to_owned())
    }

    pub fn auth() -> Self {
        Self("auth".to_owned())
    }

    pub fn key_rotation() -> Self {
        Self("key_rotation".to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct TriageUrl(String);

impl TriageUrl {
    pub fn parse(value: impl Into<String>) -> Result<Self, IncidentDtoError> {
        let value = value.into();
        validate_non_secret_text(&value, TRIAGE_URL_MAX_LEN)
            .map_err(|_| IncidentDtoError::InvalidTriageUrl)?;
        let uri = value
            .parse::<Uri>()
            .map_err(|_| IncidentDtoError::InvalidTriageUrl)?;
        let scheme = uri.scheme_str().ok_or(IncidentDtoError::InvalidTriageUrl)?;
        if scheme != "https" && scheme != "http" {
            return Err(IncidentDtoError::InvalidTriageUrl);
        }
        if uri.authority().is_none() {
            return Err(IncidentDtoError::InvalidTriageUrl);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentNotifierKind {
    Dummy,
    Webhook,
}

impl IncidentNotifierKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dummy => "dummy",
            Self::Webhook => "webhook",
        }
    }
}

impl fmt::Display for IncidentNotifierKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationReceipt {
    pub notifier_kind: IncidentNotifierKind,
    pub delivered_at: SourceEventAt,
    pub duration_ms: u64,
}

impl NotificationReceipt {
    pub fn new(
        notifier_kind: IncidentNotifierKind,
        delivered_at: SourceEventAt,
        duration_ms: u64,
    ) -> Self {
        Self {
            notifier_kind,
            delivered_at,
            duration_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IncidentNotification {
    pub incident_id: IncidentId,
    pub detected_at: String,
    pub category: IncidentCategory,
    pub severity: IncidentSeverity,
    pub summary: IncidentSummary,
    pub affected_components: Vec<ComponentName>,
    pub source_event_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triage_url: Option<TriageUrl>,
}

impl IncidentNotification {
    pub fn new(
        incident_id: IncidentId,
        detected_at: SourceEventAt,
        category: IncidentCategory,
        severity: IncidentSeverity,
        summary: IncidentSummary,
        affected_components: Vec<ComponentName>,
        source_event_at: SourceEventAt,
    ) -> Result<Self, IncidentDtoError> {
        let affected_components = normalize_components(affected_components)?;
        Ok(Self {
            incident_id,
            detected_at: detected_at.as_str().to_owned(),
            category,
            severity,
            summary,
            affected_components,
            source_event_at: source_event_at.as_str().to_owned(),
            correlation_id: None,
            triage_url: None,
        })
    }

    pub fn with_correlation_id(
        mut self,
        correlation_id: impl Into<String>,
    ) -> Result<Self, IncidentDtoError> {
        let correlation_id = correlation_id.into();
        validate_non_secret_text(&correlation_id, CORRELATION_ID_MAX_LEN)
            .map_err(|_| IncidentDtoError::InvalidCorrelationId)?;
        self.correlation_id = Some(correlation_id);
        Ok(self)
    }

    pub fn with_triage_url(mut self, triage_url: TriageUrl) -> Self {
        self.triage_url = Some(triage_url);
        self
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, IncidentDtoError> {
        serde_json::to_vec(self).map_err(|_| IncidentDtoError::SerializationFailed)
    }
}

fn normalize_components(
    mut components: Vec<ComponentName>,
) -> Result<Vec<ComponentName>, IncidentDtoError> {
    if components.is_empty() {
        return Err(IncidentDtoError::MissingAffectedComponent);
    }
    components.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    components.dedup_by(|left, right| left.as_str() == right.as_str());
    Ok(components)
}

fn validate_non_secret_text(value: &str, max_len: usize) -> Result<(), ()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() != value.len() || value.len() > max_len {
        return Err(());
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_graphic() || character == ' ')
    {
        return Err(());
    }
    let lower = value.to_ascii_lowercase();
    if FORBIDDEN_NOTIFICATION_TEXT
        .iter()
        .any(|forbidden| lower.contains(forbidden))
    {
        return Err(());
    }
    Ok(())
}

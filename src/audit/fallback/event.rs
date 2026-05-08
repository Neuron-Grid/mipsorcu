use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::types::{DeviceId, KeyVersion, OwnerUserId, SecretId};

use super::super::error::AuditEventError;
use super::super::event::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditMetadata, AuditResult, RequestId,
};
use super::error::LocalAuditStoreError;

const DELIVERY_STATUS_PENDING: &str = "pending";
const DELIVERY_STATUS_SENT: &str = "sent";

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DeliveryStatus {
    Pending,
    Sent,
}

impl DeliveryStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => DELIVERY_STATUS_PENDING,
            Self::Sent => DELIVERY_STATUS_SENT,
        }
    }
}

pub(super) fn fallback_json(
    event: &AuditEvent,
    delivery_status: DeliveryStatus,
) -> Result<Value, LocalAuditStoreError> {
    Ok(json!({
        "audit_event_id": event.audit_event_id().as_canonical_string(),
        "request_id": event.request_id().as_canonical_string(),
        "actor_user_id": event
            .actor_user_id()
            .map(OwnerUserId::as_canonical_string),
        "actor_device_id": event.actor_device_id().map(DeviceId::as_str),
        "action": event.action().as_str(),
        "target_secret_id": event
            .target_secret_id()
            .map(SecretId::as_canonical_string),
        "result": event.result().as_str(),
        "key_version": event.key_version().map(KeyVersion::get),
        "metadata_json": event.metadata_json().as_value(),
        "occurred_at": current_occurred_at()?,
        "delivery_status": delivery_status.as_str(),
    }))
}

#[derive(Deserialize)]
pub(super) struct LocalAuditFallbackRecord {
    audit_event_id: String,
    request_id: String,
    actor_user_id: Option<String>,
    actor_device_id: Option<String>,
    action: String,
    target_secret_id: Option<String>,
    result: String,
    key_version: Option<u32>,
    metadata_json: Value,
    occurred_at: Option<String>,
    delivery_status: DeliveryStatus,
}

impl LocalAuditFallbackRecord {
    pub(super) fn delivery_status(&self) -> DeliveryStatus {
        self.delivery_status
    }

    pub(super) fn non_empty_occurred_at(&self) -> Option<&str> {
        self.occurred_at
            .as_deref()
            .filter(|value| !value.trim().is_empty())
    }

    pub(super) fn to_event(&self, line_number: usize) -> Result<AuditEvent, LocalAuditStoreError> {
        let actor_user_id = self
            .actor_user_id
            .as_deref()
            .map(OwnerUserId::parse)
            .transpose()
            .map_err(|_| LocalAuditStoreError::InvalidLine {
                line_number,
                reason: "actor_user_id is invalid",
            })?;
        let actor_device_id = self
            .actor_device_id
            .as_deref()
            .map(DeviceId::new)
            .transpose()
            .map_err(|_| LocalAuditStoreError::InvalidLine {
                line_number,
                reason: "actor_device_id is invalid",
            })?;
        let target_secret_id = self
            .target_secret_id
            .as_deref()
            .map(SecretId::parse)
            .transpose()
            .map_err(|_| LocalAuditStoreError::InvalidLine {
                line_number,
                reason: "target_secret_id is invalid",
            })?;
        let key_version = self
            .key_version
            .map(KeyVersion::new)
            .transpose()
            .map_err(|_| LocalAuditStoreError::InvalidLine {
                line_number,
                reason: "key_version is invalid",
            })?;

        let metadata_json = match AuditMetadata::new(self.metadata_json.clone()) {
            Ok(metadata_json) => metadata_json,
            Err(AuditEventError::InvalidSourceEventAt) => {
                return Err(LocalAuditStoreError::InvalidLine {
                    line_number,
                    reason: "metadata_json.source_event_at is invalid",
                });
            }
            Err(error) => return Err(LocalAuditStoreError::from(error)),
        };

        AuditEvent::new(AuditEventParts {
            audit_event_id: AuditEventId::parse(&self.audit_event_id)?,
            request_id: RequestId::parse(&self.request_id)?,
            actor_user_id,
            actor_device_id,
            action: AuditAction::parse(&self.action)?,
            target_secret_id,
            result: AuditResult::parse(&self.result)?,
            key_version,
            metadata_json,
        })
        .map_err(|error| match error {
            AuditEventError::MissingSourceEventAt => LocalAuditStoreError::InvalidLine {
                line_number,
                reason: "metadata_json.source_event_at is missing",
            },
            AuditEventError::InvalidSourceEventAt => LocalAuditStoreError::InvalidLine {
                line_number,
                reason: "metadata_json.source_event_at is invalid",
            },
            error => LocalAuditStoreError::from(error),
        })
    }
}

fn current_occurred_at() -> Result<String, LocalAuditStoreError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(LocalAuditStoreError::TimestampFormat)
}

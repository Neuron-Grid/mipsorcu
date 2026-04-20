use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::types::{DeviceId, KeyVersion, OwnerUserId, SecretId};

use super::error::LocalAuditStoreError;
use super::event::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditMetadata, AuditResult, RequestId,
};

const DELIVERY_STATUS_PENDING: &str = "pending";
const DELIVERY_STATUS_SENT: &str = "sent";

#[derive(Debug, Clone)]
pub struct LocalAuditFallbackStore {
    path: PathBuf,
}

impl LocalAuditFallbackStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append_pending(&self, event: &AuditEvent) -> Result<(), LocalAuditStoreError> {
        self.append_line(&event.to_fallback_json(DeliveryStatus::Pending)?)
    }

    pub fn mark_sent(&self, event: &AuditEvent) -> Result<(), LocalAuditStoreError> {
        self.append_line(&event.to_fallback_json(DeliveryStatus::Sent)?)
    }

    pub fn pending_events(&self) -> Result<Vec<AuditEvent>, LocalAuditStoreError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut states = BTreeMap::<String, LocalAuditEventState>::new();

        for (index, line) in reader.lines().enumerate() {
            let line_number = index + 1;
            let line = line?;

            if line.trim().is_empty() {
                continue;
            }

            let record: LocalAuditFallbackRecord = serde_json::from_str(&line)?;
            let event = record.to_event(line_number)?;
            let event_id = event.audit_event_id().as_canonical_string();
            states.insert(
                event_id,
                LocalAuditEventState {
                    event,
                    delivery_status: record.delivery_status,
                },
            );
        }

        Ok(states
            .into_values()
            .filter_map(|state| {
                if state.delivery_status == DeliveryStatus::Pending {
                    Some(state.event)
                } else {
                    None
                }
            })
            .collect())
    }

    fn append_line(&self, value: &Value) -> Result<(), LocalAuditStoreError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_data()?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DeliveryStatus {
    Pending,
    Sent,
}

impl DeliveryStatus {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => DELIVERY_STATUS_PENDING,
            Self::Sent => DELIVERY_STATUS_SENT,
        }
    }
}

#[derive(Debug)]
struct LocalAuditEventState {
    event: AuditEvent,
    delivery_status: DeliveryStatus,
}

#[derive(Debug, Deserialize)]
struct LocalAuditFallbackRecord {
    audit_event_id: String,
    request_id: String,
    actor_user_id: Option<String>,
    actor_device_id: Option<String>,
    action: String,
    target_secret_id: Option<String>,
    result: String,
    key_version: Option<u32>,
    metadata_json: Value,
    delivery_status: DeliveryStatus,
}

impl LocalAuditFallbackRecord {
    fn to_event(&self, line_number: usize) -> Result<AuditEvent, LocalAuditStoreError> {
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

        AuditEvent::new(AuditEventParts {
            audit_event_id: AuditEventId::parse(&self.audit_event_id)?,
            request_id: RequestId::parse(&self.request_id)?,
            actor_user_id,
            actor_device_id,
            action: AuditAction::parse(&self.action)?,
            target_secret_id,
            result: AuditResult::parse(&self.result)?,
            key_version,
            metadata_json: AuditMetadata::new(self.metadata_json.clone())?,
        })
        .map_err(LocalAuditStoreError::from)
    }
}

pub(super) fn current_occurred_at() -> Result<String, LocalAuditStoreError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(LocalAuditStoreError::TimestampFormat)
}

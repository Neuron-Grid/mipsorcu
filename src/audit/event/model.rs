use std::fmt;
use std::future::Future;

use crate::types::{DeviceId, KeyVersion, OwnerUserId, SecretId, SourceEventAt};

use super::super::error::{AuditAppendError, AuditEventError};
use super::action::{AuditAction, AuditResult};
use super::id::{AuditEventId, RequestId};
use super::metadata::AuditMetadata;
use super::validation::validate_event_parts;

#[derive(Clone, PartialEq, Eq)]
pub struct AuditEvent {
    audit_event_id: AuditEventId,
    request_id: RequestId,
    actor_user_id: Option<OwnerUserId>,
    actor_device_id: Option<DeviceId>,
    action: AuditAction,
    target_secret_id: Option<SecretId>,
    result: AuditResult,
    key_version: Option<KeyVersion>,
    metadata_json: AuditMetadata,
}

impl AuditEvent {
    pub fn new(parts: AuditEventParts) -> Result<Self, AuditEventError> {
        validate_event_parts(&parts)?;
        let metadata_json = parts.metadata_json;

        Ok(Self {
            audit_event_id: parts.audit_event_id,
            request_id: parts.request_id,
            actor_user_id: parts.actor_user_id,
            actor_device_id: parts.actor_device_id,
            action: parts.action,
            target_secret_id: parts.target_secret_id,
            result: parts.result,
            key_version: parts.key_version,
            metadata_json,
        })
    }

    pub fn audit_event_id(&self) -> &AuditEventId {
        &self.audit_event_id
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn actor_user_id(&self) -> Option<&OwnerUserId> {
        self.actor_user_id.as_ref()
    }

    pub fn actor_device_id(&self) -> Option<&DeviceId> {
        self.actor_device_id.as_ref()
    }

    pub fn action(&self) -> AuditAction {
        self.action
    }

    pub fn target_secret_id(&self) -> Option<&SecretId> {
        self.target_secret_id.as_ref()
    }

    pub fn result(&self) -> AuditResult {
        self.result
    }

    pub fn key_version(&self) -> Option<KeyVersion> {
        self.key_version
    }

    pub fn metadata_json(&self) -> &AuditMetadata {
        &self.metadata_json
    }

    pub fn source_event_at(&self) -> Result<SourceEventAt, AuditEventError> {
        self.metadata_json.require_source_event_at()
    }
}

impl fmt::Debug for AuditEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditEvent")
            .field("audit_event_id", &self.audit_event_id)
            .field("request_id", &self.request_id)
            .field("actor_user_id", &self.actor_user_id)
            .field("actor_device_id", &self.actor_device_id)
            .field("action", &self.action)
            .field("target_secret_id", &self.target_secret_id)
            .field("result", &self.result)
            .field("key_version", &self.key_version)
            .field("metadata_json", &self.metadata_json)
            .finish()
    }
}

pub struct AuditEventParts {
    pub audit_event_id: AuditEventId,
    pub request_id: RequestId,
    pub actor_user_id: Option<OwnerUserId>,
    pub actor_device_id: Option<DeviceId>,
    pub action: AuditAction,
    pub target_secret_id: Option<SecretId>,
    pub result: AuditResult,
    pub key_version: Option<KeyVersion>,
    pub metadata_json: AuditMetadata,
}

/// Appends an audit event to the authoritative `audit_events` store.
pub trait AuditEventAppender: Send + Sync + 'static {
    fn append_audit_event<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> impl Future<Output = Result<(), AuditAppendError>> + Send + 'a;
}

use serde_json::{Map, Value};

use crate::types::{SecretId, SecretVersion, SecretVersionId, SourceEventAt};

use super::super::{AuditEventError, AuditMetadata, SOURCE_EVENT_AT_KEY};

/// `encrypt_create` action metadata builder.
#[derive(Debug, Clone)]
pub struct EncryptCreateMetadata {
    version: SecretVersion,
    secret_version_id: SecretVersionId,
    source_event_at: Option<SourceEventAt>,
}

impl EncryptCreateMetadata {
    pub fn new(version: SecretVersion, secret_version_id: SecretVersionId) -> Self {
        Self {
            version,
            secret_version_id,
            source_event_at: None,
        }
    }

    pub fn with_source_event_at(mut self, source_event_at: SourceEventAt) -> Self {
        self.source_event_at = Some(source_event_at);
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "version".to_owned(),
            Value::Number(self.version.get().into()),
        );
        object.insert(
            "secret_version_id".to_owned(),
            Value::String(self.secret_version_id.as_canonical_string()),
        );
        if let Some(source_event_at) = self.source_event_at {
            object.insert(
                SOURCE_EVENT_AT_KEY.to_owned(),
                Value::String(source_event_at.as_str().to_owned()),
            );
        }
        AuditMetadata::new(Value::Object(object))
    }
}

/// `encrypt_rotate` action metadata builder.
#[derive(Debug, Clone)]
pub struct EncryptRotateMetadata {
    version: SecretVersion,
    secret_version_id: SecretVersionId,
    source_event_at: Option<SourceEventAt>,
}

impl EncryptRotateMetadata {
    pub fn new(version: SecretVersion, secret_version_id: SecretVersionId) -> Self {
        Self {
            version,
            secret_version_id,
            source_event_at: None,
        }
    }

    pub fn with_source_event_at(mut self, source_event_at: SourceEventAt) -> Self {
        self.source_event_at = Some(source_event_at);
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "version".to_owned(),
            Value::Number(self.version.get().into()),
        );
        object.insert(
            "secret_version_id".to_owned(),
            Value::String(self.secret_version_id.as_canonical_string()),
        );
        if let Some(source_event_at) = self.source_event_at {
            object.insert(
                SOURCE_EVENT_AT_KEY.to_owned(),
                Value::String(source_event_at.as_str().to_owned()),
            );
        }
        AuditMetadata::new(Value::Object(object))
    }
}

/// `version_purge` action metadata builder.
#[derive(Debug, Clone)]
pub struct VersionPurgeMetadata {
    version: SecretVersion,
    secret_version_id: SecretVersionId,
    source_event_at: Option<SourceEventAt>,
}

impl VersionPurgeMetadata {
    pub fn new(version: SecretVersion, secret_version_id: SecretVersionId) -> Self {
        Self {
            version,
            secret_version_id,
            source_event_at: None,
        }
    }

    pub fn with_source_event_at(mut self, source_event_at: SourceEventAt) -> Self {
        self.source_event_at = Some(source_event_at);
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "version".to_owned(),
            Value::Number(self.version.get().into()),
        );
        object.insert(
            "secret_version_id".to_owned(),
            Value::String(self.secret_version_id.as_canonical_string()),
        );
        if let Some(source_event_at) = self.source_event_at {
            object.insert(
                SOURCE_EVENT_AT_KEY.to_owned(),
                Value::String(source_event_at.as_str().to_owned()),
            );
        }
        AuditMetadata::new(Value::Object(object))
    }
}

/// `decrypt` action metadata builder.
#[derive(Debug, Clone)]
pub struct DecryptMetadata {
    attempted_secret_id: Option<SecretId>,
    source_event_at: Option<SourceEventAt>,
}

impl DecryptMetadata {
    pub fn success() -> Self {
        Self {
            attempted_secret_id: None,
            source_event_at: None,
        }
    }

    pub fn failure() -> Self {
        Self {
            attempted_secret_id: None,
            source_event_at: None,
        }
    }

    pub fn with_attempted_secret_id(mut self, secret_id: SecretId) -> Self {
        self.attempted_secret_id = Some(secret_id);
        self
    }

    pub fn with_source_event_at(mut self, source_event_at: SourceEventAt) -> Self {
        self.source_event_at = Some(source_event_at);
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        if let Some(secret_id) = self.attempted_secret_id {
            object.insert(
                "attempted_secret_id".to_owned(),
                Value::String(secret_id.as_canonical_string()),
            );
        }
        if let Some(source_event_at) = self.source_event_at {
            object.insert(
                SOURCE_EVENT_AT_KEY.to_owned(),
                Value::String(source_event_at.as_str().to_owned()),
            );
        }
        AuditMetadata::new(Value::Object(object))
    }
}

/// `auth_failure` action metadata builder.
#[derive(Debug, Clone)]
pub struct AuthFailureMetadata {
    error_code: &'static str,
    source_event_at: Option<SourceEventAt>,
}

impl AuthFailureMetadata {
    pub fn new(error_code: &'static str) -> Self {
        Self {
            error_code,
            source_event_at: None,
        }
    }

    pub fn with_source_event_at(mut self, source_event_at: SourceEventAt) -> Self {
        self.source_event_at = Some(source_event_at);
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "error_code".to_owned(),
            Value::String(self.error_code.to_owned()),
        );
        if let Some(source_event_at) = self.source_event_at {
            object.insert(
                SOURCE_EVENT_AT_KEY.to_owned(),
                Value::String(source_event_at.as_str().to_owned()),
            );
        }
        AuditMetadata::new(Value::Object(object))
    }
}

#[cfg(test)]
#[path = "../../../../../tests/unit/audit/event/metadata/builders/secret_ops/tests.rs"]
mod tests;

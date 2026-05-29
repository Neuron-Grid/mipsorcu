use serde_json::{Map, Value};

use crate::types::{KeyVersion, SecretVersion, SecretVersionId, SourceEventAt};

use super::super::{AuditEventError, AuditMetadata, SOURCE_EVENT_AT_KEY};

/// `key_rotation_start` action metadata builder.
#[derive(Debug, Clone)]
pub struct KeyRotationStartMetadata {
    old_key_version: KeyVersion,
    new_key_version: KeyVersion,
    source_event_at: Option<SourceEventAt>,
}

impl KeyRotationStartMetadata {
    pub fn new(old_key_version: KeyVersion, new_key_version: KeyVersion) -> Self {
        Self {
            old_key_version,
            new_key_version,
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
            "old_key_version".to_owned(),
            Value::Number(self.old_key_version.get().into()),
        );
        object.insert(
            "new_key_version".to_owned(),
            Value::Number(self.new_key_version.get().into()),
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

/// `key_rotation_reencrypt` action metadata builder.
#[derive(Debug, Clone)]
pub struct KeyRotationReencryptMetadata {
    old_key_version: KeyVersion,
    new_key_version: KeyVersion,
    batch_size: u64,
    processed_count: u64,
    remaining_count: u64,
    source_event_at: Option<SourceEventAt>,
}

impl KeyRotationReencryptMetadata {
    pub fn new(
        old_key_version: KeyVersion,
        new_key_version: KeyVersion,
        batch_size: u64,
        processed_count: u64,
        remaining_count: u64,
    ) -> Self {
        Self {
            old_key_version,
            new_key_version,
            batch_size,
            processed_count,
            remaining_count,
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
            "old_key_version".to_owned(),
            Value::Number(self.old_key_version.get().into()),
        );
        object.insert(
            "new_key_version".to_owned(),
            Value::Number(self.new_key_version.get().into()),
        );
        object.insert(
            "batch_size".to_owned(),
            Value::Number(self.batch_size.into()),
        );
        object.insert(
            "processed_count".to_owned(),
            Value::Number(self.processed_count.into()),
        );
        object.insert(
            "remaining_count".to_owned(),
            Value::Number(self.remaining_count.into()),
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

/// `key_rotation_complete` action metadata builder.
#[derive(Debug, Clone)]
pub struct KeyRotationCompleteMetadata {
    old_key_version: KeyVersion,
    new_key_version: KeyVersion,
    remaining_count: u64,
    source_event_at: Option<SourceEventAt>,
}

impl KeyRotationCompleteMetadata {
    pub fn new(
        old_key_version: KeyVersion,
        new_key_version: KeyVersion,
        remaining_count: u64,
    ) -> Self {
        Self {
            old_key_version,
            new_key_version,
            remaining_count,
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
            "old_key_version".to_owned(),
            Value::Number(self.old_key_version.get().into()),
        );
        object.insert(
            "new_key_version".to_owned(),
            Value::Number(self.new_key_version.get().into()),
        );
        object.insert(
            "remaining_count".to_owned(),
            Value::Number(self.remaining_count.into()),
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

/// `key_rotation_envelope_migrated` action metadata builder.
#[derive(Debug, Clone)]
pub struct KeyRotationEnvelopeMigratedMetadata {
    batch_size: u64,
    success_count: u64,
    failure_count: u64,
    source_event_at: Option<SourceEventAt>,
}

impl KeyRotationEnvelopeMigratedMetadata {
    pub fn new(batch_size: u64, success_count: u64, failure_count: u64) -> Self {
        Self {
            batch_size,
            success_count,
            failure_count,
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
            "batch_size".to_owned(),
            Value::Number(self.batch_size.into()),
        );
        object.insert(
            "success_count".to_owned(),
            Value::Number(self.success_count.into()),
        );
        object.insert(
            "failure_count".to_owned(),
            Value::Number(self.failure_count.into()),
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

/// `key_rotation_envelope_failed` action metadata builder.
#[derive(Debug, Clone)]
pub struct KeyRotationEnvelopeFailedMetadata {
    secret_version_id: SecretVersionId,
    version: SecretVersion,
    error_code: &'static str,
    source_event_at: Option<SourceEventAt>,
}

impl KeyRotationEnvelopeFailedMetadata {
    pub fn new(
        secret_version_id: SecretVersionId,
        version: SecretVersion,
        error_code: &'static str,
    ) -> Self {
        Self {
            secret_version_id,
            version,
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
            "secret_version_id".to_owned(),
            Value::String(self.secret_version_id.as_canonical_string()),
        );
        object.insert(
            "version".to_owned(),
            Value::Number(self.version.get().into()),
        );
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
mod tests {
    use super::*;

    #[test]
    fn key_rotation_start_metadata_builds_expected_keys() {
        let old_kv = KeyVersion::new(1).unwrap();
        let new_kv = KeyVersion::new(2).unwrap();
        let metadata = KeyRotationStartMetadata::new(old_kv, new_kv)
            .build()
            .unwrap();
        let value = metadata.as_value();
        assert_eq!(value["old_key_version"], 1);
        assert_eq!(value["new_key_version"], 2);
    }

    #[test]
    fn key_rotation_reencrypt_metadata_builds_expected_keys() {
        let old_kv = KeyVersion::new(1).unwrap();
        let new_kv = KeyVersion::new(2).unwrap();
        let metadata = KeyRotationReencryptMetadata::new(old_kv, new_kv, 100, 50, 50)
            .build()
            .unwrap();
        let value = metadata.as_value();
        assert_eq!(value["batch_size"], 100);
        assert_eq!(value["processed_count"], 50);
        assert_eq!(value["remaining_count"], 50);
    }

    #[test]
    fn key_rotation_complete_metadata_builds_expected_keys() {
        let old_kv = KeyVersion::new(1).unwrap();
        let new_kv = KeyVersion::new(2).unwrap();
        let metadata = KeyRotationCompleteMetadata::new(old_kv, new_kv, 0)
            .build()
            .unwrap();
        let value = metadata.as_value();
        assert_eq!(value["old_key_version"], 1);
        assert_eq!(value["new_key_version"], 2);
        assert_eq!(value["remaining_count"], 0);
    }
}

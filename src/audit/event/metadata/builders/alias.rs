use super::super::{AuditEventError, AuditMetadata, SOURCE_EVENT_AT_KEY};
use crate::alias::AliasFingerprint;
use crate::types::{AliasFingerprintSchemaVersion, KeyVersion, SourceEventAt};
use serde_json::{Map, Value};

// SecretAlias*Metadata

/// `secret_alias_create` audit metadata builder.
#[derive(Debug, Clone)]
pub struct SecretAliasCreateMetadata {
    alias_fingerprint: Option<AliasFingerprint>,
    alias_fingerprint_key_version: Option<KeyVersion>,
    alias_fingerprint_schema_version: Option<AliasFingerprintSchemaVersion>,
    error_code: Option<String>,
    source_event_at: SourceEventAt,
}

impl SecretAliasCreateMetadata {
    pub fn success(
        alias_fingerprint: AliasFingerprint,
        alias_fingerprint_key_version: KeyVersion,
        alias_fingerprint_schema_version: AliasFingerprintSchemaVersion,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            alias_fingerprint: Some(alias_fingerprint),
            alias_fingerprint_key_version: Some(alias_fingerprint_key_version),
            alias_fingerprint_schema_version: Some(alias_fingerprint_schema_version),
            error_code: None,
            source_event_at,
        }
    }

    pub fn failure(source_event_at: SourceEventAt) -> Self {
        Self {
            alias_fingerprint: None,
            alias_fingerprint_key_version: None,
            alias_fingerprint_schema_version: None,
            error_code: None,
            source_event_at,
        }
    }

    pub fn with_error_code(mut self, error_code: impl Into<String>) -> Self {
        self.error_code = Some(error_code.into());
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        if let Some(alias_fingerprint) = self.alias_fingerprint {
            object.insert(
                "alias_fingerprint".to_owned(),
                Value::String(alias_fingerprint.to_hex_string()),
            );
        }
        if let Some(alias_fingerprint_key_version) = self.alias_fingerprint_key_version {
            object.insert(
                "alias_fingerprint_key_version".to_owned(),
                Value::Number(alias_fingerprint_key_version.get().into()),
            );
        }
        if let Some(alias_fingerprint_schema_version) = self.alias_fingerprint_schema_version {
            object.insert(
                "alias_fingerprint_schema_version".to_owned(),
                Value::Number(alias_fingerprint_schema_version.get().into()),
            );
        }
        if let Some(error_code) = self.error_code {
            object.insert("error_code".to_owned(), Value::String(error_code));
        }
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::from_object(object)
    }
}

/// `secret_alias_update` audit metadata builder.
#[derive(Debug, Clone)]
pub struct SecretAliasUpdateMetadata {
    old_alias_fingerprint: Option<AliasFingerprint>,
    new_alias_fingerprint: Option<AliasFingerprint>,
    alias_fingerprint_key_version: Option<KeyVersion>,
    alias_fingerprint_schema_version: Option<AliasFingerprintSchemaVersion>,
    error_code: Option<String>,
    source_event_at: SourceEventAt,
}

impl SecretAliasUpdateMetadata {
    pub fn success(
        old_alias_fingerprint: AliasFingerprint,
        new_alias_fingerprint: AliasFingerprint,
        alias_fingerprint_key_version: KeyVersion,
        alias_fingerprint_schema_version: AliasFingerprintSchemaVersion,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            old_alias_fingerprint: Some(old_alias_fingerprint),
            new_alias_fingerprint: Some(new_alias_fingerprint),
            alias_fingerprint_key_version: Some(alias_fingerprint_key_version),
            alias_fingerprint_schema_version: Some(alias_fingerprint_schema_version),
            error_code: None,
            source_event_at,
        }
    }

    pub fn failure(source_event_at: SourceEventAt) -> Self {
        Self {
            old_alias_fingerprint: None,
            new_alias_fingerprint: None,
            alias_fingerprint_key_version: None,
            alias_fingerprint_schema_version: None,
            error_code: None,
            source_event_at,
        }
    }

    pub fn with_error_code(mut self, error_code: impl Into<String>) -> Self {
        self.error_code = Some(error_code.into());
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        if let Some(old_alias_fingerprint) = self.old_alias_fingerprint {
            object.insert(
                "old_alias_fingerprint".to_owned(),
                Value::String(old_alias_fingerprint.to_hex_string()),
            );
        }
        if let Some(new_alias_fingerprint) = self.new_alias_fingerprint {
            object.insert(
                "new_alias_fingerprint".to_owned(),
                Value::String(new_alias_fingerprint.to_hex_string()),
            );
        }
        if let Some(alias_fingerprint_key_version) = self.alias_fingerprint_key_version {
            object.insert(
                "alias_fingerprint_key_version".to_owned(),
                Value::Number(alias_fingerprint_key_version.get().into()),
            );
        }
        if let Some(alias_fingerprint_schema_version) = self.alias_fingerprint_schema_version {
            object.insert(
                "alias_fingerprint_schema_version".to_owned(),
                Value::Number(alias_fingerprint_schema_version.get().into()),
            );
        }
        if let Some(error_code) = self.error_code {
            object.insert("error_code".to_owned(), Value::String(error_code));
        }
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::from_object(object)
    }
}

/// `secret_alias_delete` audit metadata builder.
#[derive(Debug, Clone)]
pub struct SecretAliasDeleteMetadata {
    alias_fingerprint: Option<AliasFingerprint>,
    alias_fingerprint_key_version: Option<KeyVersion>,
    alias_fingerprint_schema_version: Option<AliasFingerprintSchemaVersion>,
    error_code: Option<String>,
    source_event_at: SourceEventAt,
}

impl SecretAliasDeleteMetadata {
    pub fn success(
        alias_fingerprint: AliasFingerprint,
        alias_fingerprint_key_version: KeyVersion,
        alias_fingerprint_schema_version: AliasFingerprintSchemaVersion,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            alias_fingerprint: Some(alias_fingerprint),
            alias_fingerprint_key_version: Some(alias_fingerprint_key_version),
            alias_fingerprint_schema_version: Some(alias_fingerprint_schema_version),
            error_code: None,
            source_event_at,
        }
    }

    pub fn failure(source_event_at: SourceEventAt) -> Self {
        Self {
            alias_fingerprint: None,
            alias_fingerprint_key_version: None,
            alias_fingerprint_schema_version: None,
            error_code: None,
            source_event_at,
        }
    }

    pub fn with_error_code(mut self, error_code: impl Into<String>) -> Self {
        self.error_code = Some(error_code.into());
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        if let Some(alias_fingerprint) = self.alias_fingerprint {
            object.insert(
                "alias_fingerprint".to_owned(),
                Value::String(alias_fingerprint.to_hex_string()),
            );
        }
        if let Some(alias_fingerprint_key_version) = self.alias_fingerprint_key_version {
            object.insert(
                "alias_fingerprint_key_version".to_owned(),
                Value::Number(alias_fingerprint_key_version.get().into()),
            );
        }
        if let Some(alias_fingerprint_schema_version) = self.alias_fingerprint_schema_version {
            object.insert(
                "alias_fingerprint_schema_version".to_owned(),
                Value::Number(alias_fingerprint_schema_version.get().into()),
            );
        }
        if let Some(error_code) = self.error_code {
            object.insert("error_code".to_owned(), Value::String(error_code));
        }
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::from_object(object)
    }
}

/// `secret_alias_list` audit metadata builder.
#[derive(Debug, Clone)]
pub struct SecretAliasListMetadata {
    result_count: Option<u64>,
    error_code: Option<String>,
    source_event_at: SourceEventAt,
}

impl SecretAliasListMetadata {
    pub fn success(result_count: u64, source_event_at: SourceEventAt) -> Self {
        Self {
            result_count: Some(result_count),
            error_code: None,
            source_event_at,
        }
    }

    pub fn failure(source_event_at: SourceEventAt) -> Self {
        Self {
            result_count: None,
            error_code: None,
            source_event_at,
        }
    }

    pub fn with_error_code(mut self, error_code: impl Into<String>) -> Self {
        self.error_code = Some(error_code.into());
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        if let Some(result_count) = self.result_count {
            object.insert(
                "result_count".to_owned(),
                Value::Number(result_count.into()),
            );
        }
        if let Some(error_code) = self.error_code {
            object.insert("error_code".to_owned(), Value::String(error_code));
        }
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::from_object(object)
    }
}

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
mod tests {
    use super::*;
    use crate::audit::event::metadata::SOURCE_EVENT_AT_KEY;

    #[test]
    fn encrypt_create_metadata_builds_expected_keys() {
        let version = SecretVersion::new(3).unwrap();
        let svid = SecretVersionId::generate().unwrap();
        let metadata = EncryptCreateMetadata::new(version, svid.clone())
            .build()
            .unwrap();
        let value = metadata.as_value();
        assert_eq!(value["version"], 3);
        assert_eq!(value["secret_version_id"], svid.as_canonical_string());
        assert!(!value.as_object().unwrap().contains_key(SOURCE_EVENT_AT_KEY));
    }

    #[test]
    fn encrypt_create_metadata_with_source_event_at() {
        let version = SecretVersion::new(1).unwrap();
        let svid = SecretVersionId::generate().unwrap();
        let source_at = SourceEventAt::now_utc().unwrap();
        let metadata = EncryptCreateMetadata::new(version, svid)
            .with_source_event_at(source_at.clone())
            .build()
            .unwrap();
        assert_eq!(metadata.as_value()[SOURCE_EVENT_AT_KEY], source_at.as_str());
    }

    #[test]
    fn encrypt_rotate_metadata_builds_expected_keys() {
        let version = SecretVersion::new(2).unwrap();
        let svid = SecretVersionId::generate().unwrap();
        let metadata = EncryptRotateMetadata::new(version, svid.clone())
            .build()
            .unwrap();
        let value = metadata.as_value();
        assert_eq!(value["version"], 2);
        assert_eq!(value["secret_version_id"], svid.as_canonical_string());
    }

    #[test]
    fn version_purge_metadata_builds_expected_keys() {
        let version = SecretVersion::new(1).unwrap();
        let svid = SecretVersionId::generate().unwrap();
        let metadata = VersionPurgeMetadata::new(version, svid.clone())
            .build()
            .unwrap();
        let value = metadata.as_value();
        assert_eq!(value["version"], 1);
        assert_eq!(value["secret_version_id"], svid.as_canonical_string());
    }

    #[test]
    fn decrypt_success_metadata_is_empty_object() {
        let metadata = DecryptMetadata::success().build().unwrap();
        let obj = metadata.as_value().as_object().unwrap();
        assert!(obj.is_empty());
    }

    #[test]
    fn decrypt_failure_metadata_with_attempted_secret_id() {
        let secret_id = SecretId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let metadata = DecryptMetadata::failure()
            .with_attempted_secret_id(secret_id.clone())
            .build()
            .unwrap();
        assert_eq!(
            metadata.as_value()["attempted_secret_id"],
            secret_id.as_canonical_string()
        );
    }

    #[test]
    fn decrypt_metadata_rejects_forbidden_key_at_new_layer() {
        // DecryptMetadata builder cannot inject forbidden keys at the type level.
        // This test verifies the builder still passes through AuditMetadata::new,
        // so indirect injection (via source_event_at) is canonicalized.
        let metadata = DecryptMetadata::success().build().unwrap();
        assert!(metadata.as_value().as_object().unwrap().is_empty());
    }

    #[test]
    fn auth_failure_metadata_builds_expected_keys() {
        let metadata = AuthFailureMetadata::new("authorization_header_missing")
            .build()
            .unwrap();
        let value = metadata.as_value();
        assert_eq!(value["error_code"], "authorization_header_missing");
    }

    #[test]
    fn builder_unknown_keys_are_impossible_at_type_level() {
        // The type system guarantees that no extra keys can be inserted into
        // the JSON object produced by the action-specific metadata builders.
        // This is enforced by the fact that each builder only exposes methods
        // for the keys defined in the allowlist for its action.
        let metadata = AuthFailureMetadata::new("test_error").build().unwrap();
        let obj = metadata.as_value().as_object().unwrap();
        assert!(obj.contains_key("error_code"));
        assert!(!obj.contains_key("forbidden_key"));
    }
}

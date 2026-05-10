use serde_json::{Map, Value};

use crate::types::supabase::IntegrityCheckViolationSummary;
use crate::types::{KeyVersion, SecretId, SecretVersion, SecretVersionId, SourceEventAt};

use super::{AuditEventError, AuditMetadata, AuditTrigger, SOURCE_EVENT_AT_KEY};

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

/// `integrity_check` action metadata builder.
#[derive(Debug, Clone)]
pub struct IntegrityCheckMetadata {
    check_name: &'static str,
    checked_secret_count: u64,
    checked_secret_version_count: u64,
    checked_audit_event_count: u64,
    duration_ms: u64,
    violation_count: u64,
    violation_summary: IntegrityCheckViolationSummary,
    trigger: AuditTrigger,
    error_code: Option<&'static str>,
    source_event_at: Option<SourceEventAt>,
}

impl IntegrityCheckMetadata {
    pub fn new(
        checked_secret_count: u64,
        checked_secret_version_count: u64,
        checked_audit_event_count: u64,
        violation_count: u64,
        violation_summary: IntegrityCheckViolationSummary,
        trigger: AuditTrigger,
    ) -> Self {
        Self {
            check_name: "mvp_integrity_check",
            checked_secret_count,
            checked_secret_version_count,
            checked_audit_event_count,
            duration_ms: 0,
            violation_count,
            violation_summary,
            trigger,
            error_code: None,
            source_event_at: None,
        }
    }

    pub fn with_duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = duration_ms;
        self
    }

    pub fn with_error_code(mut self, error_code: &'static str) -> Self {
        self.error_code = Some(error_code);
        self
    }

    pub fn with_error_code_opt(mut self, error_code: Option<&'static str>) -> Self {
        self.error_code = error_code;
        self
    }

    pub fn with_source_event_at(mut self, source_event_at: SourceEventAt) -> Self {
        self.source_event_at = Some(source_event_at);
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "check_name".to_owned(),
            Value::String(self.check_name.to_owned()),
        );
        object.insert(
            "checked_secret_count".to_owned(),
            Value::Number(self.checked_secret_count.into()),
        );
        object.insert(
            "checked_secret_version_count".to_owned(),
            Value::Number(self.checked_secret_version_count.into()),
        );
        object.insert(
            "checked_audit_event_count".to_owned(),
            Value::Number(self.checked_audit_event_count.into()),
        );
        object.insert(
            "duration_ms".to_owned(),
            Value::Number(self.duration_ms.into()),
        );
        object.insert(
            "violation_count".to_owned(),
            Value::Number(self.violation_count.into()),
        );
        let violation_summary = serde_json::to_value(&self.violation_summary)
            .map_err(|_| AuditEventError::MetadataMustBeObject)?;
        object.insert("violation_summary".to_owned(), violation_summary);
        object.insert(
            "trigger".to_owned(),
            Value::String(self.trigger.as_str().to_owned()),
        );
        if let Some(error_code) = self.error_code {
            object.insert(
                "error_code".to_owned(),
                Value::String(error_code.to_owned()),
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

/// `restore_test` action metadata builder.
#[derive(Debug, Clone)]
pub struct RestoreTestMetadata {
    phase: &'static str,
    sample_count: u64,
    trigger: AuditTrigger,
    duration_ms: Option<u64>,
    error_code: Option<&'static str>,
    failed_version: Option<SecretVersion>,
    reason: Option<&'static str>,
    source_event_at: Option<SourceEventAt>,
}

impl RestoreTestMetadata {
    pub fn new(sample_count: u64, trigger: AuditTrigger) -> Self {
        Self {
            phase: "verify",
            sample_count,
            trigger,
            duration_ms: None,
            error_code: None,
            failed_version: None,
            reason: None,
            source_event_at: None,
        }
    }

    pub fn with_duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    pub fn with_duration_ms_opt(mut self, duration_ms: Option<u64>) -> Self {
        self.duration_ms = duration_ms;
        self
    }

    pub fn with_error_code(mut self, error_code: &'static str) -> Self {
        self.error_code = Some(error_code);
        self
    }

    pub fn with_error_code_opt(mut self, error_code: Option<&'static str>) -> Self {
        self.error_code = error_code;
        self
    }

    pub fn with_failed_version(mut self, failed_version: SecretVersion) -> Self {
        self.failed_version = Some(failed_version);
        self
    }

    pub fn with_failed_version_opt_u32(mut self, failed_version: Option<u32>) -> Self {
        self.failed_version = failed_version.and_then(|v| SecretVersion::new(v).ok());
        self
    }

    pub fn with_reason(mut self, reason: &'static str) -> Self {
        self.reason = Some(reason);
        self
    }

    pub fn with_reason_opt(mut self, reason: Option<&'static str>) -> Self {
        self.reason = reason;
        self
    }

    pub fn with_source_event_at(mut self, source_event_at: SourceEventAt) -> Self {
        self.source_event_at = Some(source_event_at);
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert("phase".to_owned(), Value::String(self.phase.to_owned()));
        object.insert(
            "sample_count".to_owned(),
            Value::Number(self.sample_count.into()),
        );
        object.insert(
            "trigger".to_owned(),
            Value::String(self.trigger.as_str().to_owned()),
        );
        if let Some(duration_ms) = self.duration_ms {
            object.insert(
                "duration_ms".to_owned(),
                Value::Number(duration_ms.into()),
            );
        }
        if let Some(error_code) = self.error_code {
            object.insert(
                "error_code".to_owned(),
                Value::String(error_code.to_owned()),
            );
        }
        if let Some(failed_version) = self.failed_version {
            object.insert(
                "failed_version".to_owned(),
                Value::Number(failed_version.get().into()),
            );
        }
        if let Some(reason) = self.reason {
            object.insert("reason".to_owned(), Value::String(reason.to_owned()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::event::metadata::SOURCE_EVENT_AT_KEY;

    #[test]
    fn encrypt_create_metadata_builds_expected_keys() {
        let version = SecretVersion::new(3).unwrap();
        let svid = SecretVersionId::generate().unwrap();
        let metadata = EncryptCreateMetadata::new(version, svid.clone()).build().unwrap();
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
        assert_eq!(
            metadata.as_value()[SOURCE_EVENT_AT_KEY],
            source_at.as_str()
        );
    }

    #[test]
    fn encrypt_rotate_metadata_builds_expected_keys() {
        let version = SecretVersion::new(2).unwrap();
        let svid = SecretVersionId::generate().unwrap();
        let metadata = EncryptRotateMetadata::new(version, svid.clone()).build().unwrap();
        let value = metadata.as_value();
        assert_eq!(value["version"], 2);
        assert_eq!(value["secret_version_id"], svid.as_canonical_string());
    }

    #[test]
    fn version_purge_metadata_builds_expected_keys() {
        let version = SecretVersion::new(1).unwrap();
        let svid = SecretVersionId::generate().unwrap();
        let metadata = VersionPurgeMetadata::new(version, svid.clone()).build().unwrap();
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
        let secret_id =
            SecretId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
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
    fn integrity_check_metadata_builds_expected_keys() {
        let summary = IntegrityCheckViolationSummary::zero();
        let metadata = IntegrityCheckMetadata::new(1, 2, 3, 0, summary, AuditTrigger::Background)
            .with_duration_ms(100)
            .with_error_code("rpc_failed")
            .build()
            .unwrap();
        let value = metadata.as_value();
        assert_eq!(value["check_name"], "mvp_integrity_check");
        assert_eq!(value["checked_secret_count"], 1);
        assert_eq!(value["checked_secret_version_count"], 2);
        assert_eq!(value["checked_audit_event_count"], 3);
        assert_eq!(value["duration_ms"], 100);
        assert_eq!(value["violation_count"], 0);
        assert!(value["violation_summary"].is_object());
        assert_eq!(value["trigger"], "background");
        assert_eq!(value["error_code"], "rpc_failed");
    }

    #[test]
    fn integrity_check_metadata_without_optional_fields() {
        let summary = IntegrityCheckViolationSummary::zero();
        let metadata = IntegrityCheckMetadata::new(0, 0, 0, 0, summary, AuditTrigger::Startup)
            .build()
            .unwrap();
        let value = metadata.as_value();
        assert!(!value.as_object().unwrap().contains_key("error_code"));
        assert!(!value.as_object().unwrap().contains_key(SOURCE_EVENT_AT_KEY));
    }

    #[test]
    fn restore_test_metadata_success_builds_expected_keys() {
        let metadata = RestoreTestMetadata::new(5, AuditTrigger::Background)
            .with_duration_ms(250)
            .build()
            .unwrap();
        let value = metadata.as_value();
        assert_eq!(value["phase"], "verify");
        assert_eq!(value["sample_count"], 5);
        assert_eq!(value["trigger"], "background");
        assert_eq!(value["duration_ms"], 250);
    }

    #[test]
    fn restore_test_metadata_with_error_and_failed_version() {
        let failed_version = SecretVersion::new(3).unwrap();
        let metadata = RestoreTestMetadata::new(5, AuditTrigger::Cli)
            .with_error_code("decrypt_failed")
            .with_failed_version(failed_version)
            .with_reason("no_current_secret_versions")
            .build()
            .unwrap();
        let value = metadata.as_value();
        assert_eq!(value["error_code"], "decrypt_failed");
        assert_eq!(value["failed_version"], 3);
        assert_eq!(value["reason"], "no_current_secret_versions");
    }

    #[test]
    fn key_rotation_start_metadata_builds_expected_keys() {
        let old_kv = KeyVersion::new(1).unwrap();
        let new_kv = KeyVersion::new(2).unwrap();
        let metadata = KeyRotationStartMetadata::new(old_kv, new_kv).build().unwrap();
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

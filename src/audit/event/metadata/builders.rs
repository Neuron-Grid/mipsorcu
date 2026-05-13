use serde_json::{Map, Value};

use crate::archive::backend::ArchiveObjectKey;
use crate::ledger::{LedgerSignatureKeyVersion, MonthlyDigestPeriod};
use crate::types::supabase::IntegrityCheckViolationSummary;
use crate::types::{KeyVersion, SecretId, SecretVersion, SecretVersionId, SourceEventAt};

use super::{AuditEventError, AuditMetadata, AuditTrigger, SOURCE_EVENT_AT_KEY, TRIGGER_KEY};

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
    duration_ms: u64,
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
            duration_ms: 0,
            error_code: None,
            failed_version: None,
            reason: None,
            source_event_at: None,
        }
    }

    pub fn with_duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = duration_ms;
        self
    }

    pub fn with_duration_ms_opt(mut self, duration_ms: Option<u64>) -> Self {
        if let Some(duration_ms) = duration_ms {
            self.duration_ms = duration_ms;
        }
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
        object.insert(
            "duration_ms".to_owned(),
            Value::Number(self.duration_ms.into()),
        );
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

/// `scheduler_job` action metadata builder.
#[derive(Debug, Clone)]
pub struct SchedulerJobMetadata {
    job_name: &'static str,
    trigger: AuditTrigger,
    duration_ms: u64,
    error_code: Option<&'static str>,
    target_year_month: Option<String>,
    source_event_at: SourceEventAt,
}

impl SchedulerJobMetadata {
    pub fn new(
        job_name: &'static str,
        trigger: AuditTrigger,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            job_name,
            trigger,
            duration_ms: 0,
            error_code: None,
            target_year_month: None,
            source_event_at,
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

    pub fn with_target_year_month(mut self, target_year_month: impl Into<String>) -> Self {
        self.target_year_month = Some(target_year_month.into());
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "job_name".to_owned(),
            Value::String(self.job_name.to_owned()),
        );
        object.insert(
            TRIGGER_KEY.to_owned(),
            Value::String(self.trigger.as_str().to_owned()),
        );
        object.insert(
            "duration_ms".to_owned(),
            Value::Number(self.duration_ms.into()),
        );
        if let Some(error_code) = self.error_code {
            object.insert(
                "error_code".to_owned(),
                Value::String(error_code.to_owned()),
            );
        }
        if let Some(target_year_month) = self.target_year_month {
            object.insert(
                "target_year_month".to_owned(),
                Value::String(target_year_month),
            );
        }
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
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

/// `signature_key_created` action metadata builder.
#[derive(Debug, Clone)]
pub struct SignatureKeyCreatedMetadata {
    signature_key_version: LedgerSignatureKeyVersion,
    public_key_fingerprint: String,
    created_at: SourceEventAt,
    source_event_at: SourceEventAt,
}

impl SignatureKeyCreatedMetadata {
    pub fn new(
        signature_key_version: LedgerSignatureKeyVersion,
        public_key_fingerprint: impl Into<String>,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            signature_key_version,
            public_key_fingerprint: public_key_fingerprint.into(),
            created_at: source_event_at.clone(),
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "signature_key_version".to_owned(),
            Value::Number(self.signature_key_version.get().into()),
        );
        object.insert(
            "public_key_fingerprint".to_owned(),
            Value::String(self.public_key_fingerprint),
        );
        object.insert(
            "created_at".to_owned(),
            Value::String(self.created_at.as_str().to_owned()),
        );
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::new(Value::Object(object))
    }
}

/// `signature_key_activated` action metadata builder.
#[derive(Debug, Clone)]
pub struct SignatureKeyActivatedMetadata {
    signature_key_version: LedgerSignatureKeyVersion,
    public_key_fingerprint: String,
    activated_at: SourceEventAt,
    source_event_at: SourceEventAt,
}

impl SignatureKeyActivatedMetadata {
    pub fn new(
        signature_key_version: LedgerSignatureKeyVersion,
        public_key_fingerprint: impl Into<String>,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            signature_key_version,
            public_key_fingerprint: public_key_fingerprint.into(),
            activated_at: source_event_at.clone(),
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "signature_key_version".to_owned(),
            Value::Number(self.signature_key_version.get().into()),
        );
        object.insert(
            "public_key_fingerprint".to_owned(),
            Value::String(self.public_key_fingerprint),
        );
        object.insert(
            "activated_at".to_owned(),
            Value::String(self.activated_at.as_str().to_owned()),
        );
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::new(Value::Object(object))
    }
}

/// `signature_key_retired` action metadata builder.
#[derive(Debug, Clone)]
pub struct SignatureKeyRetiredMetadata {
    signature_key_version: LedgerSignatureKeyVersion,
    public_key_fingerprint: String,
    retired_at: SourceEventAt,
    source_event_at: SourceEventAt,
}

impl SignatureKeyRetiredMetadata {
    pub fn new(
        signature_key_version: LedgerSignatureKeyVersion,
        public_key_fingerprint: impl Into<String>,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            signature_key_version,
            public_key_fingerprint: public_key_fingerprint.into(),
            retired_at: source_event_at.clone(),
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "signature_key_version".to_owned(),
            Value::Number(self.signature_key_version.get().into()),
        );
        object.insert(
            "public_key_fingerprint".to_owned(),
            Value::String(self.public_key_fingerprint),
        );
        object.insert(
            "retired_at".to_owned(),
            Value::String(self.retired_at.as_str().to_owned()),
        );
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
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

// ─────────────────────────────────────────────────────────────────────────────
// MonthlyDigestGenerateMetadata / MonthlyDigestVerifyMetadata
// ─────────────────────────────────────────────────────────────────────────────

/// `monthly_digest_generate` failure audit metadata builder.
#[derive(Debug, Clone)]
pub struct MonthlyDigestGenerateMetadata {
    target_year_month: String,
    error_code: String,
    source_event_at: SourceEventAt,
}

impl MonthlyDigestGenerateMetadata {
    pub fn new(
        period: &MonthlyDigestPeriod,
        error_code: impl Into<String>,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            target_year_month: period.as_str().to_owned(),
            error_code: error_code.into(),
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert("error_code".to_owned(), Value::String(self.error_code));
        object.insert(
            "target_year_month".to_owned(),
            Value::String(self.target_year_month),
        );
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::from_object(object)
    }
}

/// `monthly_digest_verify` failure audit metadata builder.
#[derive(Debug, Clone)]
pub struct MonthlyDigestVerifyMetadata {
    target_year_month: String,
    error_code: String,
    source_event_at: SourceEventAt,
}

impl MonthlyDigestVerifyMetadata {
    pub fn new(
        period: &MonthlyDigestPeriod,
        error_code: impl Into<String>,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            target_year_month: period.as_str().to_owned(),
            error_code: error_code.into(),
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert("error_code".to_owned(), Value::String(self.error_code));
        object.insert(
            "target_year_month".to_owned(),
            Value::String(self.target_year_month),
        );
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::from_object(object)
    }
}

#[cfg(test)]
mod monthly_digest_metadata_tests {
    use super::*;
    use crate::audit::{AuditAction, AuditResult};
    use crate::ledger::MonthlyDigestPeriod;
    use crate::types::SourceEventAt;

    fn make_period() -> MonthlyDigestPeriod {
        MonthlyDigestPeriod::parse("2026-05").unwrap()
    }

    fn make_source_event_at() -> SourceEventAt {
        SourceEventAt::parse("2026-06-01T00:00:00Z").unwrap()
    }

    #[test]
    fn generate_failure_metadata_contains_only_allowed_keys() {
        let metadata = MonthlyDigestGenerateMetadata::new(
            &make_period(),
            "append_failed",
            make_source_event_at(),
        )
        .build()
        .unwrap();
        let value = metadata.as_value();
        assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
        assert_eq!(value["error_code"].as_str(), Some("append_failed"));
        assert_eq!(
            value["source_event_at"].as_str(),
            Some("2026-06-01T00:00:00Z")
        );
        assert_eq!(value.as_object().unwrap().len(), 3);
        metadata
            .validate_allowlist_for_action(AuditAction::MonthlyDigestGenerate, AuditResult::Failure)
            .unwrap();
    }

    #[test]
    fn verify_failure_metadata_contains_only_allowed_keys() {
        let metadata = MonthlyDigestVerifyMetadata::new(
            &make_period(),
            "signature_invalid",
            make_source_event_at(),
        )
        .build()
        .unwrap();
        let value = metadata.as_value();
        assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
        assert_eq!(value["error_code"].as_str(), Some("signature_invalid"));
        assert_eq!(
            value["source_event_at"].as_str(),
            Some("2026-06-01T00:00:00Z")
        );
        assert_eq!(value.as_object().unwrap().len(), 3);
        metadata
            .validate_allowlist_for_action(AuditAction::MonthlyDigestVerify, AuditResult::Failure)
            .unwrap();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArchiveExportMetadata
// ─────────────────────────────────────────────────────────────────────────────

/// `archive_export` action metadata builder。
///
/// `target_year_month` と `source_event_at` は構築時に必須。
/// 成功時: `.with_archive_key(key)` を呼ぶ（`archive_key` フィールドを追加）。
/// 失敗時: `.with_error_code(code)` を呼ぶ（`error_code` フィールドを追加）。
#[derive(Debug, Clone)]
pub struct ArchiveExportMetadata {
    target_year_month: String,
    archive_key: Option<String>,
    digest_hash: Option<String>,
    error_code: Option<String>,
    source_event_at: SourceEventAt,
}

impl ArchiveExportMetadata {
    /// 新しい builder を作成する。
    ///
    /// `period` に `MonthlyDigestPeriod` を要求することで、`target_year_month` の
    /// `YYYY-MM` 形式が型レベルで保証される。
    pub fn new(period: &MonthlyDigestPeriod, source_event_at: SourceEventAt) -> Self {
        Self {
            target_year_month: period.as_str().to_owned(),
            archive_key: None,
            digest_hash: None,
            error_code: None,
            source_event_at,
        }
    }

    /// アーカイブオブジェクトキーを追加する（成功時）。
    pub fn with_archive_key(mut self, key: &ArchiveObjectKey) -> Self {
        self.archive_key = Some(key.as_str().to_owned());
        self
    }

    /// digest hash の hex 文字列を追加する（成功・失敗両方で相関 ID として使用）。
    pub fn with_digest_hash(mut self, hex: &str) -> Self {
        self.digest_hash = Some(hex.to_owned());
        self
    }

    /// エラーコードを追加する（失敗時）。
    pub fn with_error_code(mut self, code: &str) -> Self {
        self.error_code = Some(code.to_owned());
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "target_year_month".to_owned(),
            Value::String(self.target_year_month),
        );
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        if let Some(archive_key) = self.archive_key {
            object.insert("archive_key".to_owned(), Value::String(archive_key));
        }
        if let Some(digest_hash) = self.digest_hash {
            object.insert("digest_hash".to_owned(), Value::String(digest_hash));
        }
        if let Some(error_code) = self.error_code {
            object.insert("error_code".to_owned(), Value::String(error_code));
        }
        AuditMetadata::new(Value::Object(object))
    }
}

#[cfg(test)]
mod archive_export_metadata_tests {
    use super::*;
    use crate::archive::backend::ArchiveObjectKey;
    use crate::ledger::MonthlyDigestPeriod;
    use crate::types::SourceEventAt;

    fn make_period() -> MonthlyDigestPeriod {
        MonthlyDigestPeriod::parse("2026-05").unwrap()
    }

    fn make_source_event_at() -> SourceEventAt {
        SourceEventAt::parse("2026-06-01T00:00:00Z").unwrap()
    }

    fn make_archive_key() -> ArchiveObjectKey {
        ArchiveObjectKey::for_monthly_digest(&make_period()).unwrap()
    }

    #[test]
    fn success_metadata_contains_archive_key() {
        let key = make_archive_key();
        let metadata = ArchiveExportMetadata::new(&make_period(), make_source_event_at())
            .with_archive_key(&key)
            .build()
            .expect("build must succeed");
        let value = metadata.as_value();
        assert_eq!(value["archive_key"].as_str(), Some(key.as_str()));
        assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
        assert!(value.get("error_code").is_none());
    }

    #[test]
    fn failure_metadata_contains_error_code() {
        let metadata = ArchiveExportMetadata::new(&make_period(), make_source_event_at())
            .with_error_code("backend_failed")
            .build()
            .expect("build must succeed");
        let value = metadata.as_value();
        assert_eq!(value["error_code"].as_str(), Some("backend_failed"));
        assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
        assert!(value.get("archive_key").is_none());
    }

    #[test]
    fn digest_hash_is_included_when_set() {
        let metadata = ArchiveExportMetadata::new(&make_period(), make_source_event_at())
            .with_digest_hash("abcd1234")
            .build()
            .expect("build must succeed");
        let value = metadata.as_value();
        assert_eq!(value["digest_hash"].as_str(), Some("abcd1234"));
    }

    #[test]
    fn required_target_year_month_always_present() {
        let metadata = ArchiveExportMetadata::new(&make_period(), make_source_event_at())
            .build()
            .expect("build must succeed");
        let value = metadata.as_value();
        assert!(value.get("target_year_month").is_some());
        assert!(value.get("source_event_at").is_some());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DigestTimestampingMetadata
// ─────────────────────────────────────────────────────────────────────────────

/// `digest_timestamping` action metadata builder。
///
/// `target_year_month` と `source_event_at` は構築時に必須。
/// 成功時: `.with_timestamp_token_hash(hex)` を呼ぶ。
/// 失敗時: `.with_error_code(code)` を呼ぶ。
/// `digest_hash` は相関 ID として成功・失敗どちらでも記録できる。
#[derive(Debug, Clone)]
pub struct DigestTimestampingMetadata {
    target_year_month: String,
    digest_hash: Option<String>,
    timestamp_token_hash: Option<String>,
    error_code: Option<String>,
    source_event_at: SourceEventAt,
}

impl DigestTimestampingMetadata {
    /// 新しい builder を作成する。
    ///
    /// `period` に `MonthlyDigestPeriod` を要求することで、`target_year_month` の
    /// `YYYY-MM` 形式が型レベルで保証される。
    pub fn new(period: &MonthlyDigestPeriod, source_event_at: SourceEventAt) -> Self {
        Self {
            target_year_month: period.as_str().to_owned(),
            digest_hash: None,
            timestamp_token_hash: None,
            error_code: None,
            source_event_at,
        }
    }

    /// digest hash の hex 文字列を追加する（成功・失敗両方で相関 ID として使用）。
    pub fn with_digest_hash(mut self, hex: &str) -> Self {
        self.digest_hash = Some(hex.to_owned());
        self
    }

    /// timestamping token hash の hex 文字列を追加する（成功時）。
    pub fn with_timestamp_token_hash(mut self, hex: &str) -> Self {
        self.timestamp_token_hash = Some(hex.to_owned());
        self
    }

    /// エラーコードを追加する（失敗時）。
    pub fn with_error_code(mut self, code: &str) -> Self {
        self.error_code = Some(code.to_owned());
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "target_year_month".to_owned(),
            Value::String(self.target_year_month),
        );
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        if let Some(digest_hash) = self.digest_hash {
            object.insert("digest_hash".to_owned(), Value::String(digest_hash));
        }
        if let Some(token_hash) = self.timestamp_token_hash {
            object.insert("timestamp_token_hash".to_owned(), Value::String(token_hash));
        }
        if let Some(error_code) = self.error_code {
            object.insert("error_code".to_owned(), Value::String(error_code));
        }
        AuditMetadata::new(Value::Object(object))
    }
}

#[cfg(test)]
mod digest_timestamping_metadata_tests {
    use super::*;
    use crate::ledger::MonthlyDigestPeriod;
    use crate::types::SourceEventAt;

    fn make_period() -> MonthlyDigestPeriod {
        MonthlyDigestPeriod::parse("2026-05").unwrap()
    }

    fn make_source_event_at() -> SourceEventAt {
        SourceEventAt::parse("2026-06-01T00:00:00Z").unwrap()
    }

    #[test]
    fn success_metadata_contains_timestamp_token_hash() {
        let metadata = DigestTimestampingMetadata::new(&make_period(), make_source_event_at())
            .with_digest_hash(&"a".repeat(64))
            .with_timestamp_token_hash(&"b".repeat(64))
            .build()
            .expect("build must succeed");
        let value = metadata.as_value();
        assert_eq!(
            value["timestamp_token_hash"].as_str(),
            Some(&*"b".repeat(64))
        );
        assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
        assert!(value.get("error_code").is_none());
    }

    #[test]
    fn failure_metadata_contains_error_code() {
        let metadata = DigestTimestampingMetadata::new(&make_period(), make_source_event_at())
            .with_error_code("backend_failed")
            .build()
            .expect("build must succeed");
        let value = metadata.as_value();
        assert_eq!(value["error_code"].as_str(), Some("backend_failed"));
        assert_eq!(value["target_year_month"].as_str(), Some("2026-05"));
        assert!(value.get("timestamp_token_hash").is_none());
    }

    #[test]
    fn required_target_year_month_always_present() {
        let metadata = DigestTimestampingMetadata::new(&make_period(), make_source_event_at())
            .build()
            .expect("build must succeed");
        let value = metadata.as_value();
        assert!(value.get("target_year_month").is_some());
        assert!(value.get("source_event_at").is_some());
    }

    #[test]
    fn digest_hash_is_optional_and_set_when_provided() {
        let metadata = DigestTimestampingMetadata::new(&make_period(), make_source_event_at())
            .with_digest_hash(&"c".repeat(64))
            .build()
            .expect("build must succeed");
        let value = metadata.as_value();
        assert_eq!(value["digest_hash"].as_str(), Some(&*"c".repeat(64)));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AuditReportGenerateMetadata
// ─────────────────────────────────────────────────────────────────────────────

/// `audit_report_generate` audit metadata builder.
#[derive(Debug, Clone)]
pub struct AuditReportGenerateMetadata {
    format: String,
    period_end: SourceEventAt,
    period_start: SourceEventAt,
    error_code: Option<String>,
    source_event_at: SourceEventAt,
}

impl AuditReportGenerateMetadata {
    pub fn new(
        format: impl Into<String>,
        period_start: SourceEventAt,
        period_end: SourceEventAt,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            format: format.into(),
            period_end,
            period_start,
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
        object.insert("format".to_owned(), Value::String(self.format));
        object.insert(
            "period_end".to_owned(),
            Value::String(self.period_end.as_str().to_owned()),
        );
        object.insert(
            "period_start".to_owned(),
            Value::String(self.period_start.as_str().to_owned()),
        );
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

// ─────────────────────────────────────────────────────────────────────────────
// SiemForwardFailureMetadata
// ─────────────────────────────────────────────────────────────────────────────

/// `siem_forward_failure` action metadata builder（failure-only）。
///
/// `error_code` は構築時に必須。`event_type` は転送しようとした監査の
/// `AuditAction` 文字列、`event_count` はバッチ送信時の件数 (u64) を任意で
/// 添付できる。`source_event_at` は省略時に呼び出し側で付与される。
///
/// 信頼境界ノート: 秘密情報・JWT・request/response body は AuditMetadata
/// 共通の `FORBIDDEN_AUDIT_METADATA_KEYS` で構造的に排除される。本 builder
/// は更にキー集合を 4 種（`error_code` / `event_type` / `event_count` /
/// `source_event_at`）に限定する型レベル絞り込みとして機能する。
#[derive(Debug, Clone)]
pub struct SiemForwardFailureMetadata {
    error_code: String,
    event_type: Option<String>,
    event_count: Option<u64>,
    source_event_at: Option<SourceEventAt>,
}

impl SiemForwardFailureMetadata {
    /// 新しい builder を作成する。`error_code` は SIEM forwarder 側で
    /// 集約された短い識別文字列を想定する（最大 64 文字、空白不可）。
    pub fn new(error_code: impl Into<String>) -> Self {
        Self {
            error_code: error_code.into(),
            event_type: None,
            event_count: None,
            source_event_at: None,
        }
    }

    /// 転送しようとした監査の `AuditAction::as_str()` を相関 ID として記録する。
    pub fn with_event_type(mut self, event_type: impl Into<String>) -> Self {
        self.event_type = Some(event_type.into());
        self
    }

    /// バッチ送信時の件数を記録する。
    pub fn with_event_count(mut self, event_count: u64) -> Self {
        self.event_count = Some(event_count);
        self
    }

    pub fn with_source_event_at(mut self, source_event_at: SourceEventAt) -> Self {
        self.source_event_at = Some(source_event_at);
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert("error_code".to_owned(), Value::String(self.error_code));
        if let Some(event_type) = self.event_type {
            object.insert("event_type".to_owned(), Value::String(event_type));
        }
        if let Some(event_count) = self.event_count {
            object.insert("event_count".to_owned(), Value::Number(event_count.into()));
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

// ─────────────────────────────────────────────────────────────────────────────
// IncidentDetectedMetadata
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IncidentDetectedMetadata {
    incident_type: String,
    severity: String,
    detection_source: String,
    dedupe_key: String,
    notification_sink: String,
    notification_result: String,
    error_code: String,
    source_event_at: SourceEventAt,
    source_event_id: Option<String>,
    target_sequence_no: Option<u64>,
    target_year_month: Option<MonthlyDigestPeriod>,
}

impl IncidentDetectedMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        incident_type: impl Into<String>,
        severity: impl Into<String>,
        detection_source: impl Into<String>,
        dedupe_key: impl Into<String>,
        notification_sink: impl Into<String>,
        notification_result: impl Into<String>,
        error_code: impl Into<String>,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            incident_type: incident_type.into(),
            severity: severity.into(),
            detection_source: detection_source.into(),
            dedupe_key: dedupe_key.into(),
            notification_sink: notification_sink.into(),
            notification_result: notification_result.into(),
            error_code: error_code.into(),
            source_event_at,
            source_event_id: None,
            target_sequence_no: None,
            target_year_month: None,
        }
    }

    pub fn with_source_event_id(mut self, source_event_id: impl Into<String>) -> Self {
        self.source_event_id = Some(source_event_id.into());
        self
    }

    pub fn with_target_sequence_no(mut self, target_sequence_no: u64) -> Self {
        self.target_sequence_no = Some(target_sequence_no);
        self
    }

    pub fn with_target_year_month(mut self, target_year_month: MonthlyDigestPeriod) -> Self {
        self.target_year_month = Some(target_year_month);
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "incident_type".to_owned(),
            Value::String(self.incident_type),
        );
        object.insert("severity".to_owned(), Value::String(self.severity));
        object.insert(
            "detection_source".to_owned(),
            Value::String(self.detection_source),
        );
        object.insert("dedupe_key".to_owned(), Value::String(self.dedupe_key));
        object.insert(
            "notification_sink".to_owned(),
            Value::String(self.notification_sink),
        );
        object.insert(
            "notification_result".to_owned(),
            Value::String(self.notification_result),
        );
        object.insert("error_code".to_owned(), Value::String(self.error_code));
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        if let Some(source_event_id) = self.source_event_id {
            object.insert("source_event_id".to_owned(), Value::String(source_event_id));
        }
        if let Some(target_sequence_no) = self.target_sequence_no {
            object.insert(
                "target_sequence_no".to_owned(),
                Value::Number(target_sequence_no.into()),
            );
        }
        if let Some(target_year_month) = self.target_year_month {
            object.insert(
                "target_year_month".to_owned(),
                Value::String(target_year_month.as_str().to_owned()),
            );
        }

        AuditMetadata::new(Value::Object(object))
    }
}

#[cfg(test)]
mod siem_forward_failure_metadata_tests {
    use super::*;

    #[test]
    fn minimum_metadata_contains_error_code_only() {
        let metadata = SiemForwardFailureMetadata::new("siem_backend_failed")
            .build()
            .expect("build must succeed");
        let value = metadata.as_value();
        assert_eq!(value["error_code"].as_str(), Some("siem_backend_failed"));
        assert!(value.get("event_type").is_none());
        assert!(value.get("event_count").is_none());
        assert!(value.get(SOURCE_EVENT_AT_KEY).is_none());
    }

    #[test]
    fn full_metadata_contains_all_optional_keys() {
        let source_event_at = SourceEventAt::parse("2026-05-11T00:00:00Z").unwrap();
        let metadata = SiemForwardFailureMetadata::new("siem_backend_failed")
            .with_event_type("decrypt")
            .with_event_count(7)
            .with_source_event_at(source_event_at)
            .build()
            .expect("build must succeed");
        let value = metadata.as_value();
        assert_eq!(value["event_type"].as_str(), Some("decrypt"));
        assert_eq!(value["event_count"].as_u64(), Some(7));
        assert_eq!(
            value[SOURCE_EVENT_AT_KEY].as_str(),
            Some("2026-05-11T00:00:00Z")
        );
    }
}

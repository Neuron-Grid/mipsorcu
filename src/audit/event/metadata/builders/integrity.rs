use serde_json::{Map, Value};

use crate::types::supabase::IntegrityCheckViolationSummary;
use crate::types::{SecretVersion, SourceEventAt};

use super::super::{
    AuditEventError, AuditMetadata, AuditTrigger, SOURCE_EVENT_AT_KEY, TRIGGER_KEY,
};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::event::metadata::SOURCE_EVENT_AT_KEY;

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
}

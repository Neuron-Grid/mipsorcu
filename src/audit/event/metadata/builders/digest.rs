use serde_json::{Map, Value};

use crate::archive::backend::ArchiveObjectKey;
use crate::ledger::{DigestHash, LedgerSequenceNo, LedgerSignatureKeyVersion, MonthlyDigestPeriod};
use crate::types::SourceEventAt;

use super::super::{AuditEventError, AuditMetadata, SOURCE_EVENT_AT_KEY};

// MonthlyDigestGenerateMetadata / MonthlyDigestVerifyMetadata

/// `monthly_digest_generate` audit metadata builder.
#[derive(Debug, Clone)]
pub struct MonthlyDigestGenerateMetadata {
    target_year_month: String,
    start_sequence_no: Option<LedgerSequenceNo>,
    end_sequence_no: Option<LedgerSequenceNo>,
    entry_count: Option<u64>,
    signature_key_version: Option<LedgerSignatureKeyVersion>,
    digest_hash: Option<String>,
    error_code: Option<String>,
    source_event_at: SourceEventAt,
}

impl MonthlyDigestGenerateMetadata {
    /// 失敗監査用 metadata を構築する。
    pub fn new(
        period: &MonthlyDigestPeriod,
        error_code: impl Into<String>,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            target_year_month: period.as_str().to_owned(),
            start_sequence_no: None,
            end_sequence_no: None,
            entry_count: None,
            signature_key_version: None,
            digest_hash: None,
            error_code: Some(error_code.into()),
            source_event_at,
        }
    }

    /// 成功監査用 metadata を構築する。
    pub fn success(
        period: &MonthlyDigestPeriod,
        start_sequence_no: LedgerSequenceNo,
        end_sequence_no: LedgerSequenceNo,
        entry_count: u64,
        signature_key_version: LedgerSignatureKeyVersion,
        digest_hash: DigestHash,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            target_year_month: period.as_str().to_owned(),
            start_sequence_no: Some(start_sequence_no),
            end_sequence_no: Some(end_sequence_no),
            entry_count: Some(entry_count),
            signature_key_version: Some(signature_key_version),
            digest_hash: Some(digest_hash.to_hex()),
            error_code: None,
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        if let Some(error_code) = self.error_code {
            object.insert("error_code".to_owned(), Value::String(error_code));
        }
        if let Some(start_sequence_no) = self.start_sequence_no {
            object.insert(
                "start_sequence_no".to_owned(),
                Value::Number(start_sequence_no.get().into()),
            );
        }
        if let Some(end_sequence_no) = self.end_sequence_no {
            object.insert(
                "end_sequence_no".to_owned(),
                Value::Number(end_sequence_no.get().into()),
            );
        }
        if let Some(entry_count) = self.entry_count {
            object.insert("entry_count".to_owned(), Value::Number(entry_count.into()));
        }
        if let Some(signature_key_version) = self.signature_key_version {
            object.insert(
                "signature_key_version".to_owned(),
                Value::Number(signature_key_version.get().into()),
            );
        }
        if let Some(digest_hash) = self.digest_hash {
            object.insert("digest_hash".to_owned(), Value::String(digest_hash));
        }
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

/// `monthly_digest_verify` audit metadata builder.
#[derive(Debug, Clone)]
pub struct MonthlyDigestVerifyMetadata {
    target_year_month: String,
    verify_result: &'static str,
    error_code: Option<String>,
    source_event_at: SourceEventAt,
}

impl MonthlyDigestVerifyMetadata {
    /// 失敗監査用 metadata を構築する。
    pub fn new(
        period: &MonthlyDigestPeriod,
        error_code: impl Into<String>,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            target_year_month: period.as_str().to_owned(),
            verify_result: "invalid",
            error_code: Some(error_code.into()),
            source_event_at,
        }
    }

    /// 成功監査用 metadata を構築する。
    pub fn success(period: &MonthlyDigestPeriod, source_event_at: SourceEventAt) -> Self {
        Self {
            target_year_month: period.as_str().to_owned(),
            verify_result: "valid",
            error_code: None,
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        if let Some(error_code) = self.error_code {
            object.insert("error_code".to_owned(), Value::String(error_code));
        }
        object.insert(
            "target_year_month".to_owned(),
            Value::String(self.target_year_month),
        );
        object.insert(
            "verify_result".to_owned(),
            Value::String(self.verify_result.to_owned()),
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
        assert_eq!(value["verify_result"].as_str(), Some("invalid"));
        assert_eq!(value.as_object().unwrap().len(), 4);
        metadata
            .validate_allowlist_for_action(AuditAction::MonthlyDigestVerify, AuditResult::Failure)
            .unwrap();
    }
}

// ArchiveExportMetadata

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

// DigestTimestampingMetadata

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

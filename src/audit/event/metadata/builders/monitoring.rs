use serde_json::{Map, Value};

use crate::incident::{IncidentCategory, IncidentId, IncidentNotifierKind};
use crate::ledger::MonthlyDigestPeriod;
use crate::types::SourceEventAt;

use super::super::{AuditEventError, AuditMetadata, SOURCE_EVENT_AT_KEY};

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
// Task 13 SIEM production operational audit metadata
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SiemEventForwardedMetadata {
    exporter_kind: String,
    batch_size: u64,
    source_event_at: SourceEventAt,
}

impl SiemEventForwardedMetadata {
    pub fn new(
        exporter_kind: impl Into<String>,
        batch_size: u64,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            exporter_kind: exporter_kind.into(),
            batch_size,
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "exporter_kind".to_owned(),
            Value::String(self.exporter_kind),
        );
        object.insert(
            "batch_size".to_owned(),
            Value::Number(self.batch_size.into()),
        );
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::new(Value::Object(object))
    }
}

#[derive(Debug, Clone)]
pub struct SiemEventFailedMetadata {
    exporter_kind: String,
    error_code: String,
    buffered: bool,
    batch_size: u64,
    source_event_at: SourceEventAt,
}

impl SiemEventFailedMetadata {
    pub fn new(
        exporter_kind: impl Into<String>,
        error_code: impl Into<String>,
        buffered: bool,
        batch_size: u64,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            exporter_kind: exporter_kind.into(),
            error_code: error_code.into(),
            buffered,
            batch_size,
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "exporter_kind".to_owned(),
            Value::String(self.exporter_kind),
        );
        object.insert("error_code".to_owned(), Value::String(self.error_code));
        object.insert("buffered".to_owned(), Value::Bool(self.buffered));
        object.insert(
            "batch_size".to_owned(),
            Value::Number(self.batch_size.into()),
        );
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::new(Value::Object(object))
    }
}

#[derive(Debug, Clone)]
pub struct SiemBufferFlushedMetadata {
    flushed_count: u64,
    buffer_remaining_bytes: u64,
    source_event_at: SourceEventAt,
}

impl SiemBufferFlushedMetadata {
    pub fn new(
        flushed_count: u64,
        buffer_remaining_bytes: u64,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            flushed_count,
            buffer_remaining_bytes,
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "flushed_count".to_owned(),
            Value::Number(self.flushed_count.into()),
        );
        object.insert(
            "buffer_remaining_bytes".to_owned(),
            Value::Number(self.buffer_remaining_bytes.into()),
        );
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::new(Value::Object(object))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Task 14 incident notification operational audit metadata
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IncidentNotificationSentMetadata {
    incident_id: IncidentId,
    category: IncidentCategory,
    notifier_kind: IncidentNotifierKind,
    duration_ms: u64,
    source_event_at: SourceEventAt,
}

impl IncidentNotificationSentMetadata {
    pub fn new(
        incident_id: IncidentId,
        category: IncidentCategory,
        notifier_kind: IncidentNotifierKind,
        duration_ms: u64,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            incident_id,
            category,
            notifier_kind,
            duration_ms,
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = incident_notification_base_object(
            &self.incident_id,
            self.category,
            self.source_event_at,
        );
        object.insert(
            "notifier_kind".to_owned(),
            Value::String(self.notifier_kind.as_str().to_owned()),
        );
        object.insert(
            "duration_ms".to_owned(),
            Value::Number(self.duration_ms.into()),
        );
        AuditMetadata::new(Value::Object(object))
    }
}

#[derive(Debug, Clone)]
pub struct IncidentNotificationFailedMetadata {
    incident_id: IncidentId,
    category: IncidentCategory,
    notifier_kind: IncidentNotifierKind,
    error_code: String,
    retry_count: u64,
    source_event_at: SourceEventAt,
}

impl IncidentNotificationFailedMetadata {
    pub fn new(
        incident_id: IncidentId,
        category: IncidentCategory,
        notifier_kind: IncidentNotifierKind,
        error_code: impl Into<String>,
        retry_count: u64,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            incident_id,
            category,
            notifier_kind,
            error_code: error_code.into(),
            retry_count,
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = incident_notification_base_object(
            &self.incident_id,
            self.category,
            self.source_event_at,
        );
        object.insert(
            "notifier_kind".to_owned(),
            Value::String(self.notifier_kind.as_str().to_owned()),
        );
        object.insert("error_code".to_owned(), Value::String(self.error_code));
        object.insert(
            "retry_count".to_owned(),
            Value::Number(self.retry_count.into()),
        );
        AuditMetadata::new(Value::Object(object))
    }
}

#[derive(Debug, Clone)]
pub struct IncidentNotificationSuppressedMetadata {
    incident_id: IncidentId,
    category: IncidentCategory,
    suppressed_count: u64,
    window_remaining_sec: u64,
    source_event_at: SourceEventAt,
}

impl IncidentNotificationSuppressedMetadata {
    pub fn new(
        incident_id: IncidentId,
        category: IncidentCategory,
        suppressed_count: u64,
        window_remaining_sec: u64,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            incident_id,
            category,
            suppressed_count,
            window_remaining_sec,
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = incident_notification_base_object(
            &self.incident_id,
            self.category,
            self.source_event_at,
        );
        object.insert(
            "reason".to_owned(),
            Value::String("rate_limited".to_owned()),
        );
        object.insert(
            "suppressed_count".to_owned(),
            Value::Number(self.suppressed_count.into()),
        );
        object.insert(
            "window_remaining_sec".to_owned(),
            Value::Number(self.window_remaining_sec.into()),
        );
        AuditMetadata::new(Value::Object(object))
    }
}

fn incident_notification_base_object(
    incident_id: &IncidentId,
    category: IncidentCategory,
    source_event_at: SourceEventAt,
) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert(
        "incident_id".to_owned(),
        Value::String(incident_id.as_str().to_owned()),
    );
    object.insert(
        "category".to_owned(),
        Value::String(category.as_str().to_owned()),
    );
    object.insert(
        SOURCE_EVENT_AT_KEY.to_owned(),
        Value::String(source_event_at.as_str().to_owned()),
    );
    object
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
#[path = "../../../../../tests/unit/audit/event/metadata/builders/monitoring/siem_forward_failure_metadata_tests.rs"]
mod siem_forward_failure_metadata_tests;

use serde_json::{Map, Value};

use crate::ledger::MonthlyDigestPeriod;
use crate::types::SourceEventAt;

use super::super::{AuditEventError, AuditMetadata, SOURCE_EVENT_AT_KEY};

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
// AuditUiReadMetadata
// ─────────────────────────────────────────────────────────────────────────────

/// `audit_ui_read` audit metadata builder.
#[derive(Debug, Clone)]
pub struct AuditUiReadMetadata {
    endpoint: String,
    resource: String,
    result_count: Option<u64>,
    period_start: Option<SourceEventAt>,
    period_end: Option<SourceEventAt>,
    start_sequence_no: Option<u64>,
    end_sequence_no: Option<u64>,
    target_year_month: Option<MonthlyDigestPeriod>,
    error_code: Option<String>,
    source_event_at: SourceEventAt,
}

impl AuditUiReadMetadata {
    pub fn new(
        endpoint: impl Into<String>,
        resource: impl Into<String>,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            resource: resource.into(),
            result_count: None,
            period_start: None,
            period_end: None,
            start_sequence_no: None,
            end_sequence_no: None,
            target_year_month: None,
            error_code: None,
            source_event_at,
        }
    }

    pub fn with_result_count(mut self, result_count: u64) -> Self {
        self.result_count = Some(result_count);
        self
    }

    pub fn with_period(mut self, period_start: SourceEventAt, period_end: SourceEventAt) -> Self {
        self.period_start = Some(period_start);
        self.period_end = Some(period_end);
        self
    }

    pub fn with_sequence_range(mut self, start_sequence_no: u64, end_sequence_no: u64) -> Self {
        self.start_sequence_no = Some(start_sequence_no);
        self.end_sequence_no = Some(end_sequence_no);
        self
    }

    pub fn with_target_year_month(mut self, target_year_month: MonthlyDigestPeriod) -> Self {
        self.target_year_month = Some(target_year_month);
        self
    }

    pub fn with_error_code(mut self, error_code: impl Into<String>) -> Self {
        self.error_code = Some(error_code.into());
        self
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert("endpoint".to_owned(), Value::String(self.endpoint));
        object.insert("method".to_owned(), Value::String("GET".to_owned()));
        object.insert("resource".to_owned(), Value::String(self.resource));
        if let Some(result_count) = self.result_count {
            object.insert(
                "result_count".to_owned(),
                Value::Number(result_count.into()),
            );
        }
        if let Some(period_start) = self.period_start {
            object.insert(
                "period_start".to_owned(),
                Value::String(period_start.as_str().to_owned()),
            );
        }
        if let Some(period_end) = self.period_end {
            object.insert(
                "period_end".to_owned(),
                Value::String(period_end.as_str().to_owned()),
            );
        }
        if let Some(start_sequence_no) = self.start_sequence_no {
            object.insert(
                "start_sequence_no".to_owned(),
                Value::Number(start_sequence_no.into()),
            );
        }
        if let Some(end_sequence_no) = self.end_sequence_no {
            object.insert(
                "end_sequence_no".to_owned(),
                Value::Number(end_sequence_no.into()),
            );
        }
        if let Some(target_year_month) = self.target_year_month {
            object.insert(
                "target_year_month".to_owned(),
                Value::String(target_year_month.as_str().to_owned()),
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

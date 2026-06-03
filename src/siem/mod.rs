//! SIEM 連携基盤。
//!
//! `SiemSink` trait と送信専用 DTO `SiemEvent`、テスト用 dummy sink、
//! 失敗時のローカル buffer（`LocalSiemFallbackBuffer`）、それらを束ねる
//! `SiemForwarder` を提供する。具体的な SIEM 製品連携（Splunk / Elastic /
//! Datadog 等）の本番設定は後続タスクで実装する。
//!
//! 信頼境界ノート: `SiemSink::send_event` の引数型は `&SiemEvent` に限定さ
//! れる。`SiemEvent` は `AuditEvent` 等の SBC 内正本オブジェクトから非秘密
//! フィールドのみを抽出して構築されるため、Master Key・Data Key・JWT 全文・
//! 平文・request/response body 全文を SIEM へ送信することが型レベルで不可能。

pub mod buffer;
pub mod dummy;
pub mod event;
pub mod forwarder;
pub mod otlp;
pub mod sink;
pub mod splunk_hec;

pub use buffer::{DEFAULT_SIEM_BUFFER_MAX_BYTES, LocalSiemBufferError, LocalSiemFallbackBuffer};
pub use dummy::{FailingSiemSink, InMemorySiemSink};
pub use event::{SIEM_EVENT_SCHEMA_VERSION, SIEM_EVENT_TOP_LEVEL_KEYS, SiemEvent};
pub use forwarder::{
    SiemForwardOutcome, SiemForwarder, SiemForwarderStatus, SiemResendSummary, SiemRetryPolicy,
    build_siem_buffer_flushed_audit_event, build_siem_event_failed_audit_event,
    build_siem_event_forwarded_audit_event, build_siem_forward_failure_audit_event,
};
pub use otlp::OtlpSiemSink;
pub use sink::{
    AnySiemSink, ForwardReceipt, SIEM_MAX_BATCH_SIZE, SiemExporterKind, SiemSink, SiemSinkError,
};
pub use splunk_hec::SplunkHecSiemSink;

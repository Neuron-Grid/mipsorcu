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
pub mod sink;

pub use buffer::{LocalSiemBufferError, LocalSiemFallbackBuffer};
pub use dummy::{FailingSiemSink, InMemorySiemSink};
pub use event::{SIEM_EVENT_SCHEMA_VERSION, SIEM_EVENT_TOP_LEVEL_KEYS, SiemEvent};
pub use forwarder::{
    SiemForwardOutcome, SiemForwarder, SiemForwarderStatus, SiemResendSummary,
    build_siem_forward_failure_audit_event,
};
pub use sink::{SiemSink, SiemSinkError};

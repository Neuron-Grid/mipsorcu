//! `SiemSink` trait と関連エラー型。
//!
//! 信頼境界ノート: `send_event` の引数型は `&SiemEvent` に限定される。
//! `SiemEvent` 自体が SBC 内正本オブジェクト（`AuditEvent` 等）から
//! 非秘密フィールドのみを抽出して構築される DTO であるため、本 trait の実装は
//! 平文・Master Key・Data Key・JWT 全文・request/response body 全文を
//! バックエンドへ送信することが型レベルで不可能。

use std::fmt;

use super::event::SiemEvent;

/// SIEM バックエンドのエラー型。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiemSinkError {
    /// バックエンドの I/O・ネットワーク・プロトコル操作が失敗した。
    BackendFailed { code: String },
    /// バックエンドから返ってきた応答が不正（HTTP 4xx/5xx 等、再送可能性は呼び出し側判断）。
    InvalidResponse { reason: &'static str },
}

impl fmt::Display for SiemSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendFailed { code } => write!(formatter, "siem backend failed: {code}"),
            Self::InvalidResponse { reason } => {
                write!(formatter, "siem invalid response: {reason}")
            }
        }
    }
}

impl std::error::Error for SiemSinkError {}

/// 外部 SIEM への送信抽象化 trait。
///
/// # 型安全保証
///
/// `send_event` の引数型は `&SiemEvent` であり、秘密型（`Plaintext` /
/// `MasterKey` / `DataKey` / `EncryptedDataKey` / `RawJwt` 等）を
/// フィールドに持たない DTO のみを受け入れる。実装者は引数を `Debug` /
/// `Display` 形式で外部送信する場合でも、SBC 信頼境界外に秘密情報を漏らす
/// ことが構造的に不可能。
#[allow(async_fn_in_trait)]
pub trait SiemSink: Send + Sync + 'static {
    async fn send_event(&self, event: &SiemEvent) -> Result<(), SiemSinkError>;
}

/// runtime で選択される SIEM exporter を 1 つの enum に閉じ込め、
/// `SiemForwarder<S: SiemSink>` のジェネリック境界を維持したまま動的選択を
/// 可能にする dispatcher。`Box<dyn SiemSink>` を避けることで async fn in trait の
/// dyn-incompatibility を回避する。
pub enum AnySiemSink {
    InMemory(super::dummy::InMemorySiemSink),
    Otlp(super::otlp::OtlpSiemSink),
    SplunkHec(super::splunk_hec::SplunkHecSiemSink),
}

impl AnySiemSink {
    /// runtime での経路名（log / audit metadata に使用）。
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::InMemory(_) => "in_memory",
            Self::Otlp(_) => "otlp",
            Self::SplunkHec(_) => "splunk_hec",
        }
    }
}

impl SiemSink for AnySiemSink {
    async fn send_event(&self, event: &SiemEvent) -> Result<(), SiemSinkError> {
        match self {
            Self::InMemory(sink) => sink.send_event(event).await,
            Self::Otlp(sink) => sink.send_event(event).await,
            Self::SplunkHec(sink) => sink.send_event(event).await,
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/siem/sink/tests.rs"]
mod tests;

//! `SiemSink` trait と関連エラー型。
//!
//! 信頼境界ノート: `send_event` の引数型は `&SiemEvent` に限定される。
//! `SiemEvent` 自体が SBC 内正本オブジェクト（`AuditEvent` 等）から
//! 非秘密フィールドのみを抽出して構築される DTO であるため、本 trait の実装は
//! 平文・Master Key・Data Key・JWT 全文・request/response body 全文を
//! バックエンドへ送信することが型レベルで不可能。

use std::fmt;

use super::event::SiemEvent;

/// 1 回の SIEM 送信で扱う最大イベント数。
pub const SIEM_MAX_BATCH_SIZE: usize = 100;

/// runtime で選択される SIEM exporter の種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SiemExporterKind {
    InMemory,
    Otlp,
    SplunkHec,
}

impl SiemExporterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InMemory => "in_memory",
            Self::Otlp => "otlp",
            Self::SplunkHec => "splunk_hec",
        }
    }
}

/// SIEM backend へ batch を渡せたことを示す非秘密 receipt。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardReceipt {
    exporter_kind: SiemExporterKind,
    batch_size: usize,
}

impl ForwardReceipt {
    pub fn new(exporter_kind: SiemExporterKind, batch_size: usize) -> Self {
        Self {
            exporter_kind,
            batch_size,
        }
    }

    pub fn exporter_kind(self) -> SiemExporterKind {
        self.exporter_kind
    }

    pub fn batch_size(self) -> usize {
        self.batch_size
    }
}

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
    fn exporter_kind(&self) -> SiemExporterKind;

    async fn send_batch(&self, batch: &[SiemEvent]) -> Result<ForwardReceipt, SiemSinkError>;

    async fn send_event(&self, event: &SiemEvent) -> Result<(), SiemSinkError> {
        self.send_batch(std::slice::from_ref(event))
            .await
            .map(|_| ())
    }
}

pub(crate) fn validate_batch_size(batch_size: usize) -> Result<(), SiemSinkError> {
    if batch_size <= SIEM_MAX_BATCH_SIZE {
        return Ok(());
    }

    Err(SiemSinkError::InvalidResponse {
        reason: "siem_batch_size_exceeded",
    })
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
        self.exporter_kind().as_str()
    }
}

impl SiemSink for AnySiemSink {
    fn exporter_kind(&self) -> SiemExporterKind {
        match self {
            Self::InMemory(sink) => sink.exporter_kind(),
            Self::Otlp(sink) => sink.exporter_kind(),
            Self::SplunkHec(sink) => sink.exporter_kind(),
        }
    }

    async fn send_batch(&self, batch: &[SiemEvent]) -> Result<ForwardReceipt, SiemSinkError> {
        match self {
            Self::InMemory(sink) => sink.send_batch(batch).await,
            Self::Otlp(sink) => sink.send_batch(batch).await,
            Self::SplunkHec(sink) => sink.send_batch(batch).await,
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/siem/sink/tests.rs"]
mod tests;

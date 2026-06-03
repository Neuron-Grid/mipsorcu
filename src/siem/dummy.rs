//! テスト用 dummy SIEM sink。
//!
//! `InMemorySiemSink` は `Arc<Mutex<...>>` で複数スレッドから安全に共有でき、
//! 送信した `SiemEvent` を呼び出し順に保持する。`FailingSiemSink` は常に
//! `SiemSinkError::BackendFailed` を返す。
//!
//! **本番用途禁止**: プロセス終了でデータが失われ、外部 SIEM への永続化を
//! 提供しない。

use std::fmt;
use std::sync::{Arc, Mutex};

use super::event::SiemEvent;
use super::sink::{ForwardReceipt, SiemExporterKind, SiemSink, SiemSinkError, validate_batch_size};

/// メモリ上の SIEM sink（テスト専用）。
///
/// `clone()` すると同じストアを共有する。
#[derive(Clone, Default)]
pub struct InMemorySiemSink {
    events: Arc<Mutex<Vec<SiemEvent>>>,
}

impl InMemorySiemSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// 受信した event の総数を返す。
    pub fn event_count(&self) -> usize {
        self.events.lock().map_or(0, |guard| guard.len())
    }

    /// 受信した event をクローンして返す（順序保持）。
    pub fn events(&self) -> Vec<SiemEvent> {
        self.events
            .lock()
            .ok()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl fmt::Debug for InMemorySiemSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemorySiemSink")
            .field("event_count", &self.event_count())
            .finish()
    }
}

impl SiemSink for InMemorySiemSink {
    fn exporter_kind(&self) -> SiemExporterKind {
        SiemExporterKind::InMemory
    }

    async fn send_batch(&self, batch: &[SiemEvent]) -> Result<ForwardReceipt, SiemSinkError> {
        validate_batch_size(batch.len())?;
        let mut guard = self
            .events
            .lock()
            .map_err(|_| SiemSinkError::BackendFailed {
                code: "mutex_poisoned".to_owned(),
            })?;
        guard.extend(batch.iter().cloned());
        Ok(ForwardReceipt::new(self.exporter_kind(), batch.len()))
    }
}

/// 失敗をシミュレートするテスト用 sink。常に `BackendFailed` を返す。
#[derive(Debug, Clone, Default)]
pub struct FailingSiemSink {
    code: String,
}

impl FailingSiemSink {
    pub fn new(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }
}

impl SiemSink for FailingSiemSink {
    fn exporter_kind(&self) -> SiemExporterKind {
        SiemExporterKind::InMemory
    }

    async fn send_batch(&self, _batch: &[SiemEvent]) -> Result<ForwardReceipt, SiemSinkError> {
        Err(SiemSinkError::BackendFailed {
            code: self.code.clone(),
        })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/siem/dummy/tests.rs"]
mod tests;

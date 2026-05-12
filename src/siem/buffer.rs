//! SIEM 送信失敗時のローカル append-only buffer。
//!
//! 設計: `LocalAuditFallbackStore`
//! （`src/audit/fallback/file_store.rs`）と同形の append-only JSONL を採用
//! するが、保管対象は `SiemEvent` の serialized 形のみで、`AuditEvent` 全体は
//! 保持しない（信頼境界とディスクサイズの両面で利点がある）。
//!
//! 各レコードは `{ "event_id": ..., "status": "pending|sent", "event": {...} }`
//! の 1 行 JSON で、同 `event_id` の最新ステータスを再生する。冪等性は
//! `event_id` 単位で保証される（`pending` 後に `sent` を append すると
//! `pending_events` から除外される）。
//!
//! MVP 範囲ではアーカイブ rollover や gzip 化を提供しない（YAGNI）。長期運用
//! 時に必要になった段階で `LocalAuditFallbackStore` と同じパターンで拡張する。

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::event::SiemEvent;

/// `SiemEvent` の serialized 形に統一して buffer に書き出すための内部表現。
///
/// `event` フィールドは `SiemEvent::serialize` の出力をそのまま保持する。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalSiemFallbackRecord {
    event_id: String,
    status: DeliveryStatus,
    event: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DeliveryStatus {
    Pending,
    Sent,
}

#[derive(Debug)]
pub enum LocalSiemBufferError {
    Io(std::io::Error),
    Serialization(serde_json::Error),
    LockPoisoned,
}

impl std::fmt::Display for LocalSiemBufferError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "siem buffer I/O error: {error}"),
            Self::Serialization(error) => {
                write!(formatter, "siem buffer serialization error: {error}")
            }
            Self::LockPoisoned => write!(formatter, "siem buffer lock poisoned"),
        }
    }
}

impl std::error::Error for LocalSiemBufferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::LockPoisoned => None,
        }
    }
}

impl From<std::io::Error> for LocalSiemBufferError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for LocalSiemBufferError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

/// SIEM 送信失敗時のローカル buffer。
#[derive(Debug, Clone)]
pub struct LocalSiemFallbackBuffer {
    path: PathBuf,
    operation_lock: Arc<Mutex<()>>,
}

impl LocalSiemFallbackBuffer {
    /// 指定パスに buffer を構築する。同パスの既存ファイルがあれば追記モード。
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            operation_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `pending` 状態で event を append する（送信失敗を記録）。
    pub fn append_pending(&self, event: &SiemEvent) -> Result<(), LocalSiemBufferError> {
        let value = serde_json::to_value(event)?;
        let record = LocalSiemFallbackRecord {
            event_id: event.event_id().to_owned(),
            status: DeliveryStatus::Pending,
            event: value,
        };
        self.append_record(&record)
    }

    /// `sent` 状態で event の completion を append する（再送成功時）。
    pub fn mark_sent(&self, event: &SiemEvent) -> Result<(), LocalSiemBufferError> {
        let value = serde_json::to_value(event)?;
        let record = LocalSiemFallbackRecord {
            event_id: event.event_id().to_owned(),
            status: DeliveryStatus::Sent,
            event: value,
        };
        self.append_record(&record)
    }

    /// 未送信の `pending` レコードを `event_id` 順に返す。同 `event_id` の
    /// 最新ステータスが `pending` の場合のみ含める（`sent` で打ち消されたものは除外）。
    pub fn pending_events(&self) -> Result<Vec<SiemEvent>, LocalSiemBufferError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| LocalSiemBufferError::LockPoisoned)?;

        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut states = BTreeMap::<String, LatestState>::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: LocalSiemFallbackRecord = serde_json::from_str(&line)?;
            states.insert(
                record.event_id.clone(),
                LatestState {
                    status: record.status,
                    event: record.event,
                },
            );
        }

        let mut pending = Vec::new();
        for (_, state) in states {
            if state.status == DeliveryStatus::Pending {
                let event: SiemEvent = serde_json::from_value(state.event)?;
                pending.push(event);
            }
        }
        Ok(pending)
    }

    fn append_record(&self, record: &LocalSiemFallbackRecord) -> Result<(), LocalSiemBufferError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| LocalSiemBufferError::LockPoisoned)?;

        let mut file = open_append_private(&self.path)?;
        serde_json::to_writer(&mut file, record)?;
        file.write_all(b"\n")?;
        file.sync_data()?;
        Ok(())
    }
}

struct LatestState {
    status: DeliveryStatus,
    event: Value,
}

fn open_append_private(path: &Path) -> Result<File, std::io::Error> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let mut options = OpenOptions::new();
    options.append(true).create(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options.open(path)
}

// SiemEvent must be deserializable for resend / mark_sent round-trips.
// We rely on serde's default derive — but SiemEvent currently does not derive
// Deserialize. Add the bound here as a const compile-time check.
const _: fn() = || {
    fn assert_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
    assert_deserialize::<SiemEvent>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditResult, AuthFailureMetadata,
        RequestId,
    };

    fn build_event() -> SiemEvent {
        let metadata = AuthFailureMetadata::new("authorization_header_missing")
            .build()
            .unwrap()
            .with_current_source_event_at()
            .unwrap();
        let audit_event = AuditEvent::new(AuditEventParts {
            audit_event_id: AuditEventId::generate().unwrap(),
            request_id: RequestId::nil(),
            actor_user_id: None,
            actor_device_id: None,
            action: AuditAction::AuthFailure,
            target_secret_id: None,
            result: AuditResult::Failure,
            key_version: None,
            metadata_json: metadata,
        })
        .unwrap();
        SiemEvent::from_audit_event(&audit_event)
    }

    fn tempfile_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "mipsorcu-siem-buffer-{}-{}.jsonl",
            name,
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn pending_events_empty_when_file_missing() {
        let path = tempfile_path("missing");
        let buffer = LocalSiemFallbackBuffer::new(&path);
        let events = buffer.pending_events().unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn append_pending_then_pending_events_returns_event() {
        let path = tempfile_path("append");
        let buffer = LocalSiemFallbackBuffer::new(&path);
        let event = build_event();
        buffer.append_pending(&event).unwrap();
        let pending = buffer.pending_events().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event_id(), event.event_id());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn mark_sent_removes_event_from_pending() {
        let path = tempfile_path("sent");
        let buffer = LocalSiemFallbackBuffer::new(&path);
        let event = build_event();
        buffer.append_pending(&event).unwrap();
        buffer.mark_sent(&event).unwrap();
        let pending = buffer.pending_events().unwrap();
        assert!(pending.is_empty(), "mark_sent should clear pending");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn duplicate_append_pending_is_idempotent_at_pending_count() {
        let path = tempfile_path("dup");
        let buffer = LocalSiemFallbackBuffer::new(&path);
        let event = build_event();
        buffer.append_pending(&event).unwrap();
        buffer.append_pending(&event).unwrap();
        let pending = buffer.pending_events().unwrap();
        assert_eq!(
            pending.len(),
            1,
            "same event_id must collapse to one pending"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn clone_shares_underlying_file() {
        let path = tempfile_path("clone");
        let buffer = LocalSiemFallbackBuffer::new(&path);
        let clone = buffer.clone();
        let event = build_event();
        clone.append_pending(&event).unwrap();
        let pending = buffer.pending_events().unwrap();
        assert_eq!(pending.len(), 1);
        let _ = fs::remove_file(&path);
    }
}

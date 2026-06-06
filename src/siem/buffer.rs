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
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use super::event::SiemEvent;

pub const DEFAULT_SIEM_BUFFER_MAX_BYTES: u64 = 100 * 1024 * 1024;
pub const DEFAULT_SIEM_BUFFER_TOTAL_MAX_BYTES: u64 = DEFAULT_SIEM_BUFFER_MAX_BYTES;
const ROTATED_BUFFER_PREFIX: &str = "siem-buffer-";
const ROTATED_BUFFER_SUFFIX: &str = ".jsonl";
const CURRENT_BUFFER_FILE_NAME: &str = "siem-buffer-current.jsonl";

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
    CapacityExceeded {
        total_size_bytes: u64,
        total_max_bytes: u64,
    },
    LockPoisoned,
}

impl std::fmt::Display for LocalSiemBufferError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "siem buffer I/O error: {error}"),
            Self::Serialization(error) => {
                write!(formatter, "siem buffer serialization error: {error}")
            }
            Self::CapacityExceeded {
                total_size_bytes,
                total_max_bytes,
            } => write!(
                formatter,
                "siem buffer capacity exceeded: total_size_bytes={total_size_bytes}, total_max_bytes={total_max_bytes}"
            ),
            Self::LockPoisoned => write!(formatter, "siem buffer lock poisoned"),
        }
    }
}

impl std::error::Error for LocalSiemBufferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::CapacityExceeded { .. } => None,
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
    max_bytes: u64,
    total_max_bytes: u64,
    operation_lock: Arc<Mutex<()>>,
}

impl LocalSiemFallbackBuffer {
    /// 指定パスに buffer を構築する。同パスの既存ファイルがあれば追記モード。
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_limits(
            path,
            DEFAULT_SIEM_BUFFER_MAX_BYTES,
            DEFAULT_SIEM_BUFFER_TOTAL_MAX_BYTES,
        )
    }

    pub fn with_config(path: impl Into<PathBuf>, max_bytes: u64) -> Self {
        Self::with_limits(path, max_bytes, max_bytes)
    }

    pub fn with_limits(path: impl Into<PathBuf>, max_bytes: u64, total_max_bytes: u64) -> Self {
        Self {
            path: path.into(),
            max_bytes,
            total_max_bytes,
            operation_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    pub fn total_max_bytes(&self) -> u64 {
        self.total_max_bytes
    }

    /// `pending` 状態で event を append する（送信失敗を記録）。
    pub fn append_pending(&self, event: &SiemEvent) -> Result<(), LocalSiemBufferError> {
        let value = serde_json::to_value(event)?;
        let record = LocalSiemFallbackRecord {
            event_id: event.event_id().to_owned(),
            status: DeliveryStatus::Pending,
            event: value,
        };
        self.append_record(&record, CapacityPolicy::Enforce)
    }

    /// `sent` 状態で event の completion を append する（再送成功時）。
    pub fn mark_sent(&self, event: &SiemEvent) -> Result<(), LocalSiemBufferError> {
        let value = serde_json::to_value(event)?;
        let record = LocalSiemFallbackRecord {
            event_id: event.event_id().to_owned(),
            status: DeliveryStatus::Sent,
            event: value,
        };
        self.append_record(&record, CapacityPolicy::AllowOverflow)
    }

    /// 未送信の `pending` レコードをファイル replay 順に返す。同 `event_id` の
    /// 最新ステータスが `pending` の場合のみ含める（`sent` で打ち消されたものは除外）。
    pub fn pending_events(&self) -> Result<Vec<SiemEvent>, LocalSiemBufferError> {
        self.pending_batch(usize::MAX)
    }

    /// 未送信 event を最大 `limit` 件返す。
    pub fn pending_batch(&self, limit: usize) -> Result<Vec<SiemEvent>, LocalSiemBufferError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| LocalSiemBufferError::LockPoisoned)?;

        let states = self.latest_states_unlocked()?;
        let mut pending = Vec::new();
        for state in states {
            if state.status == DeliveryStatus::Pending {
                let event: SiemEvent = serde_json::from_value(state.event)?;
                pending.push(event);
                if pending.len() >= limit {
                    break;
                }
            }
        }
        Ok(pending)
    }

    pub fn remaining_bytes(&self) -> Result<u64, LocalSiemBufferError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| LocalSiemBufferError::LockPoisoned)?;

        let size = self.total_size_bytes_unlocked()?;
        Ok(self.total_max_bytes.saturating_sub(size))
    }

    pub fn total_size_bytes(&self) -> Result<u64, LocalSiemBufferError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| LocalSiemBufferError::LockPoisoned)?;

        self.total_size_bytes_unlocked()
    }

    pub fn current_size_bytes(&self) -> Result<u64, LocalSiemBufferError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| LocalSiemBufferError::LockPoisoned)?;

        match fs::metadata(&self.path) {
            Ok(metadata) if metadata.is_file() => Ok(metadata.len()),
            Ok(_) => Ok(0),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(error.into()),
        }
    }

    pub fn compact(&self) -> Result<(), LocalSiemBufferError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| LocalSiemBufferError::LockPoisoned)?;

        self.compact_unlocked()
    }

    fn append_record(
        &self,
        record: &LocalSiemFallbackRecord,
        capacity_policy: CapacityPolicy,
    ) -> Result<(), LocalSiemBufferError> {
        let bytes = encode_record(record)?;
        let additional_bytes =
            u64::try_from(bytes.len()).map_err(|_| std::io::Error::other("record too large"))?;
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| LocalSiemBufferError::LockPoisoned)?;

        if capacity_policy == CapacityPolicy::Enforce {
            self.ensure_capacity_unlocked(additional_bytes)?;
        }
        self.rotate_if_needed_unlocked()?;
        let mut file = open_append_private(&self.path)?;
        file.write_all(&bytes)?;
        file.sync_data()?;
        Ok(())
    }

    fn buffer_files_unlocked(&self) -> Result<Vec<PathBuf>, LocalSiemBufferError> {
        let mut paths = rotated_buffer_paths(&self.path)?;
        if self.path.exists() {
            paths.push(self.path.clone());
        }
        Ok(paths)
    }

    fn ensure_capacity_unlocked(&self, additional_bytes: u64) -> Result<(), LocalSiemBufferError> {
        if self.has_capacity_unlocked(additional_bytes)? {
            return Ok(());
        }

        self.compact_unlocked()?;
        if self.has_capacity_unlocked(additional_bytes)? {
            return Ok(());
        }

        Err(LocalSiemBufferError::CapacityExceeded {
            total_size_bytes: self.total_size_bytes_unlocked()?,
            total_max_bytes: self.total_max_bytes,
        })
    }

    fn has_capacity_unlocked(&self, additional_bytes: u64) -> Result<bool, LocalSiemBufferError> {
        let total_size = self.total_size_bytes_unlocked()?;
        let projected = total_size.saturating_add(additional_bytes);
        Ok(projected <= self.total_max_bytes)
    }

    fn total_size_bytes_unlocked(&self) -> Result<u64, LocalSiemBufferError> {
        let mut total = 0u64;
        for path in self.buffer_files_unlocked()? {
            let metadata = fs::metadata(&path)?;
            if !metadata.is_file() {
                continue;
            }
            total = total
                .checked_add(metadata.len())
                .ok_or_else(|| std::io::Error::other("siem buffer total size overflow"))?;
        }
        Ok(total)
    }

    fn latest_states_unlocked(&self) -> Result<Vec<LatestState>, LocalSiemBufferError> {
        let paths = self.buffer_files_unlocked()?;
        if paths.is_empty() {
            return Ok(Vec::new());
        }

        let mut states = HashMap::<String, LatestState>::new();
        let mut next_order = 0usize;

        for path in paths {
            parse_records(&path, |record| {
                let order = states
                    .get(&record.event_id)
                    .map(|state| state.order)
                    .unwrap_or_else(|| {
                        let order = next_order;
                        next_order = next_order.saturating_add(1);
                        order
                    });
                let event_id = record.event_id;
                states.insert(
                    event_id.clone(),
                    LatestState {
                        event_id,
                        status: record.status,
                        event: record.event,
                        order,
                    },
                );
                Ok(())
            })?;
        }

        let mut states = states.into_values().collect::<Vec<_>>();
        states.sort_by_key(|state| state.order);
        Ok(states)
    }

    fn compact_unlocked(&self) -> Result<(), LocalSiemBufferError> {
        let paths = self.buffer_files_unlocked()?;
        if paths.is_empty() {
            return Ok(());
        }
        let rotated_paths = paths
            .iter()
            .filter(|path| path.as_path() != self.path.as_path())
            .cloned()
            .collect::<Vec<_>>();
        let states = self.latest_states_unlocked()?;
        let temp_path = compaction_temp_path(&self.path);
        let mut file = create_private_file(&temp_path)?;

        for state in states {
            if state.status != DeliveryStatus::Pending {
                continue;
            }
            let record = LocalSiemFallbackRecord {
                event_id: state.event_id,
                status: DeliveryStatus::Pending,
                event: state.event,
            };
            let bytes = encode_record(&record)?;
            file.write_all(&bytes)?;
        }
        file.sync_data()?;
        drop(file);

        fs::rename(&temp_path, &self.path)?;
        for path in rotated_paths {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    fn rotate_if_needed_unlocked(&self) -> Result<(), LocalSiemBufferError> {
        let metadata = match fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() || metadata.len() < self.max_bytes {
            return Ok(());
        }

        let archive_path = next_rotated_buffer_path(&self.path)?;
        if let Some(parent) = archive_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&self.path, &archive_path)?;
        let file = create_private_file(&self.path)?;
        file.sync_data()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapacityPolicy {
    Enforce,
    AllowOverflow,
}

struct LatestState {
    event_id: String,
    status: DeliveryStatus,
    event: Value,
    order: usize,
}

fn encode_record(record: &LocalSiemFallbackRecord) -> Result<Vec<u8>, LocalSiemBufferError> {
    let mut bytes = serde_json::to_vec(record)?;
    bytes.push(b'\n');
    Ok(bytes)
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

fn create_private_file(path: &Path) -> Result<File, std::io::Error> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options.open(path)
}

fn compaction_temp_path(current_path: &Path) -> PathBuf {
    let temp_name = current_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.compact.tmp"))
        .unwrap_or_else(|| format!("{CURRENT_BUFFER_FILE_NAME}.compact.tmp"));
    current_path.with_file_name(temp_name)
}

fn parse_records(
    path: &Path,
    mut handle: impl FnMut(LocalSiemFallbackRecord) -> Result<(), LocalSiemBufferError>,
) -> Result<(), LocalSiemBufferError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: LocalSiemFallbackRecord = serde_json::from_str(&line)?;
        handle(record)?;
    }

    Ok(())
}

fn rotated_buffer_paths(current_path: &Path) -> Result<Vec<PathBuf>, LocalSiemBufferError> {
    let parent = current_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.exists() {
        return Ok(Vec::new());
    }

    let mut paths = Vec::new();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if !metadata.is_file() || !is_rotated_buffer_file(&path) {
            continue;
        }
        paths.push(path);
    }
    paths.sort();
    Ok(paths)
}

fn is_rotated_buffer_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.starts_with(ROTATED_BUFFER_PREFIX)
        && name.ends_with(ROTATED_BUFFER_SUFFIX)
        && name != CURRENT_BUFFER_FILE_NAME
}

fn next_rotated_buffer_path(current_path: &Path) -> Result<PathBuf, LocalSiemBufferError> {
    let parent = current_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let date = utc_yyyymmdd();
    let sequence = next_rotated_sequence(parent, &date)?;
    Ok(parent.join(format!(
        "{ROTATED_BUFFER_PREFIX}{date}-{sequence:04}{ROTATED_BUFFER_SUFFIX}"
    )))
}

fn next_rotated_sequence(parent: &Path, date: &str) -> Result<u32, LocalSiemBufferError> {
    if !parent.exists() {
        return Ok(1);
    }

    let mut max_sequence = 0u32;
    let prefix = format!("{ROTATED_BUFFER_PREFIX}{date}-");
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with(&prefix) || !name.ends_with(ROTATED_BUFFER_SUFFIX) {
            continue;
        }
        let suffix_start = prefix.len();
        let suffix_end = name.len().saturating_sub(ROTATED_BUFFER_SUFFIX.len());
        let Some(sequence_text) = name.get(suffix_start..suffix_end) else {
            continue;
        };
        if let Ok(sequence) = sequence_text.parse::<u32>() {
            max_sequence = max_sequence.max(sequence);
        }
    }

    Ok(max_sequence.saturating_add(1))
}

fn utc_yyyymmdd() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    )
}

// SiemEvent must be deserializable for resend / mark_sent round-trips.
// We rely on serde's default derive — but SiemEvent currently does not derive
// Deserialize. Add the bound here as a const compile-time check.
const _: fn() = || {
    fn assert_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
    assert_deserialize::<SiemEvent>();
};

#[cfg(test)]
#[path = "../../tests/unit/siem/buffer/tests.rs"]
mod tests;

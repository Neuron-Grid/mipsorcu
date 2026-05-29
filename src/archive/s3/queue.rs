//! Persistent local queue for S3 archive exports.
//!
//! The queue stores only `ArchiveExportPackage` JSON bytes plus object keys and
//! hashes. `ArchiveExportPackage` is non-secret by construction, so plaintext,
//! keys and full JWTs cannot enter this queue through this API.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::archive::backend::{ArchiveBackendError, ArchiveObjectKey};
use crate::archive::export::ArchiveExportPackage;

#[derive(Debug, Clone)]
pub struct LocalArchiveQueue {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedArchiveObject {
    pub queue_id: String,
    pub key: ArchiveObjectKey,
    pub payload_sha256_hex: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResendArchiveSummary {
    pub attempted: usize,
    pub sent: usize,
    pub failed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchivePutOrQueueOutcome {
    PutSucceeded,
    Queued,
}

#[derive(Debug)]
pub enum ArchiveQueueError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidKey,
    InvalidPayloadHex,
    InvalidPayloadHash,
    TimeUnavailable,
}

impl LocalArchiveQueue {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append_pending(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
    ) -> Result<(), ArchiveQueueError> {
        let payload = package
            .to_json_bytes()
            .map_err(|_| ArchiveQueueError::InvalidPayloadHash)?;
        self.append_pending_bytes(key, payload)
    }

    pub fn append_pending_bytes(
        &self,
        key: &ArchiveObjectKey,
        payload: Vec<u8>,
    ) -> Result<(), ArchiveQueueError> {
        let _guard = self.lock.lock().map_err(|_| {
            ArchiveQueueError::Io(std::io::Error::other("archive queue lock poisoned"))
        })?;
        let record = QueueRecord::pending(key, payload)?;
        append_record(&self.path, &record)
    }

    pub fn pending_objects(&self) -> Result<Vec<QueuedArchiveObject>, ArchiveQueueError> {
        let _guard = self.lock.lock().map_err(|_| {
            ArchiveQueueError::Io(std::io::Error::other("archive queue lock poisoned"))
        })?;
        self.pending_objects_unlocked()
    }

    pub fn mark_sent(&self, queued: &QueuedArchiveObject) -> Result<(), ArchiveQueueError> {
        let _guard = self.lock.lock().map_err(|_| {
            ArchiveQueueError::Io(std::io::Error::other("archive queue lock poisoned"))
        })?;
        append_record(&self.path, &QueueRecord::sent(queued))
    }

    fn pending_objects_unlocked(&self) -> Result<Vec<QueuedArchiveObject>, ArchiveQueueError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = OpenOptions::new().read(true).open(&self.path)?;
        let reader = BufReader::new(file);
        let mut states = BTreeMap::<String, QueueRecord>::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: QueueRecord = serde_json::from_str(&line)?;
            states.insert(record.queue_id.clone(), record);
        }

        states
            .into_values()
            .filter(|record| record.delivery_status == DeliveryStatus::Pending)
            .map(QueuedArchiveObject::try_from)
            .collect()
    }
}

impl std::fmt::Display for ArchiveQueueError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "archive queue I/O error: {error}"),
            Self::Json(error) => write!(formatter, "archive queue JSON error: {error}"),
            Self::InvalidKey => formatter.write_str("archive queue key is invalid"),
            Self::InvalidPayloadHex => formatter.write_str("archive queue payload hex is invalid"),
            Self::InvalidPayloadHash => formatter.write_str("archive queue payload hash mismatch"),
            Self::TimeUnavailable => formatter.write_str("archive queue time unavailable"),
        }
    }
}

impl std::error::Error for ArchiveQueueError {}

impl From<std::io::Error> for ArchiveQueueError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for ArchiveQueueError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<ArchiveQueueError> for ArchiveBackendError {
    fn from(error: ArchiveQueueError) -> Self {
        Self::BackendFailed {
            code: match error {
                ArchiveQueueError::Io(_) => "archive_export_queue_io_failed",
                ArchiveQueueError::Json(_) => "archive_export_queue_json_failed",
                ArchiveQueueError::InvalidKey => "archive_export_queue_invalid_key",
                ArchiveQueueError::InvalidPayloadHex => "archive_export_queue_invalid_payload_hex",
                ArchiveQueueError::InvalidPayloadHash => {
                    "archive_export_queue_payload_hash_mismatch"
                }
                ArchiveQueueError::TimeUnavailable => "archive_export_queue_time_unavailable",
            }
            .to_owned(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DeliveryStatus {
    Pending,
    Sent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QueueRecord {
    queue_id: String,
    delivery_status: DeliveryStatus,
    key: String,
    payload_sha256_hex: String,
    payload_hex: String,
    queued_at: String,
}

impl QueueRecord {
    fn pending(key: &ArchiveObjectKey, payload: Vec<u8>) -> Result<Self, ArchiveQueueError> {
        let payload_sha256_hex = hex::encode(Sha256::digest(&payload));
        let queued_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| ArchiveQueueError::TimeUnavailable)?;
        Ok(Self {
            queue_id: format!("{}:{payload_sha256_hex}", key.as_str()),
            delivery_status: DeliveryStatus::Pending,
            key: key.as_str().to_owned(),
            payload_sha256_hex,
            payload_hex: hex::encode(payload),
            queued_at,
        })
    }

    fn sent(queued: &QueuedArchiveObject) -> Self {
        Self {
            queue_id: queued.queue_id.clone(),
            delivery_status: DeliveryStatus::Sent,
            key: queued.key.as_str().to_owned(),
            payload_sha256_hex: queued.payload_sha256_hex.clone(),
            payload_hex: hex::encode(&queued.payload),
            queued_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned()),
        }
    }
}

impl TryFrom<QueueRecord> for QueuedArchiveObject {
    type Error = ArchiveQueueError;

    fn try_from(record: QueueRecord) -> Result<Self, Self::Error> {
        let key = ArchiveObjectKey::new(record.key).map_err(|_| ArchiveQueueError::InvalidKey)?;
        let payload =
            hex::decode(record.payload_hex).map_err(|_| ArchiveQueueError::InvalidPayloadHex)?;
        let actual_hash = hex::encode(Sha256::digest(&payload));
        if actual_hash != record.payload_sha256_hex {
            return Err(ArchiveQueueError::InvalidPayloadHash);
        }
        Ok(Self {
            queue_id: record.queue_id,
            key,
            payload_sha256_hex: record.payload_sha256_hex,
            payload,
        })
    }
}

fn append_record(path: &Path, record: &QueueRecord) -> Result<(), ArchiveQueueError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, record)?;
    file.write_all(b"\n")?;
    file.sync_data()?;
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/archive/s3/queue/tests.rs"]
mod tests;

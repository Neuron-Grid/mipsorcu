use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::local_jsonl::{create_new_private, for_each_nonempty_line, open_append_private};

use super::super::event::AuditEvent;
use super::error::LocalAuditStoreError;
use super::event::{DeliveryStatus, LocalAuditFallbackRecord, fallback_json};
use super::store::{ArchiveSweepOutcome, RolloverArchive, RolloverOutcome, SweptArchive};

const DEFAULT_ROLLOVER_SIZE_BYTES: u64 = 64 * 1024 * 1024;
const ARCHIVE_FILE_PREFIX: &str = "audit-fallback-";
const ARCHIVE_FILE_SUFFIX: &str = ".jsonl.sealed.gz";

#[derive(Debug, Clone)]
pub struct LocalAuditFallbackStore {
    path: PathBuf,
    archive_dir: PathBuf,
    rotate_size_bytes: u64,
    operation_lock: Arc<Mutex<()>>,
}

impl LocalAuditFallbackStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let archive_dir = default_archive_dir_for(&path);

        Self::with_rollover_config(path, archive_dir, DEFAULT_ROLLOVER_SIZE_BYTES)
    }

    pub fn with_rollover_config(
        path: impl Into<PathBuf>,
        archive_dir: impl Into<PathBuf>,
        rotate_size_bytes: u64,
    ) -> Self {
        Self {
            path: path.into(),
            archive_dir: archive_dir.into(),
            rotate_size_bytes,
            operation_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn archive_dir(&self) -> &Path {
        &self.archive_dir
    }

    pub fn rotate_size_bytes(&self) -> u64 {
        self.rotate_size_bytes
    }

    pub fn append_pending(&self, event: &AuditEvent) -> Result<(), LocalAuditStoreError> {
        self.append_line(&fallback_json(event, DeliveryStatus::Pending)?)
    }

    pub fn mark_sent(&self, event: &AuditEvent) -> Result<(), LocalAuditStoreError> {
        self.append_line(&fallback_json(event, DeliveryStatus::Sent)?)
    }

    pub fn pending_events(&self) -> Result<Vec<AuditEvent>, LocalAuditStoreError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| LocalAuditStoreError::LockPoisoned)?;

        self.pending_events_unlocked()
    }

    pub fn should_rollover(&self) -> Result<bool, LocalAuditStoreError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| LocalAuditStoreError::LockPoisoned)?;

        self.should_rollover_unlocked()
    }

    pub fn rollover(&self) -> Result<RolloverOutcome, LocalAuditStoreError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| LocalAuditStoreError::LockPoisoned)?;

        let Some(snapshot) = self.current_file_snapshot_unlocked()? else {
            return Ok(RolloverOutcome::Skipped);
        };

        if !snapshot.is_rollover_eligible(self.rotate_size_bytes) {
            return Ok(RolloverOutcome::Skipped);
        }

        fs::create_dir_all(&self.archive_dir)?;
        let archive_path = self.next_archive_path()?;
        self.write_gzip_archive(&archive_path)?;
        let sha256_hex =
            sha256_file(&archive_path).map_err(|source| LocalAuditStoreError::HashReadFailed {
                path: archive_path.clone(),
                source,
            })?;

        fs::remove_file(&self.path).map_err(|source| {
            LocalAuditStoreError::CurrentFileRemoveFailed {
                path: self.path.clone(),
                source,
            }
        })?;
        let file = create_new_private(&self.path)?;
        file.sync_data()?;

        Ok(RolloverOutcome::Sealed(RolloverArchive {
            archive_path,
            sha256_hex,
            line_count: snapshot.line_count,
            first_occurred_at: snapshot.first_occurred_at,
            last_occurred_at: snapshot.last_occurred_at,
            size_bytes: snapshot.size_bytes,
        }))
    }

    pub fn sweep_archive(
        &self,
        max_age: Duration,
    ) -> Result<ArchiveSweepOutcome, LocalAuditStoreError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| LocalAuditStoreError::LockPoisoned)?;

        if !self.archive_dir.exists() {
            return Ok(ArchiveSweepOutcome {
                deleted_archives: Vec::new(),
            });
        }

        let now = SystemTime::now();
        let mut deleted_archives = Vec::new();

        for entry in fs::read_dir(&self.archive_dir)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = entry.metadata()?;

            if !metadata.is_file() || !is_archive_file(&path) {
                continue;
            }

            let modified = metadata.modified()?;
            let age = now.duration_since(modified).unwrap_or(Duration::ZERO);

            if age < max_age {
                continue;
            }

            let sha256_hex = sha256_file(&path).ok();
            let line_count = gzip_line_count(&path).ok();
            let size_bytes = metadata.len();

            fs::remove_file(&path).map_err(|source| LocalAuditStoreError::ArchiveDeleteFailed {
                path: path.clone(),
                source,
            })?;
            deleted_archives.push(SweptArchive {
                archive_path: path,
                sha256_hex,
                line_count,
                size_bytes,
            });
        }

        Ok(ArchiveSweepOutcome { deleted_archives })
    }

    fn append_line(&self, value: &Value) -> Result<(), LocalAuditStoreError> {
        let _guard = self
            .operation_lock
            .lock()
            .map_err(|_| LocalAuditStoreError::LockPoisoned)?;

        let mut file = open_append_private(&self.path)?;
        serde_json::to_writer(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_data()?;

        Ok(())
    }

    fn pending_events_unlocked(&self) -> Result<Vec<AuditEvent>, LocalAuditStoreError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let mut states = BTreeMap::<String, LocalAuditEventState>::new();
        self.parse_existing_fallback_records_unlocked(|record| {
            states.insert(
                record.event_id,
                LocalAuditEventState {
                    event: record.event,
                    delivery_status: record.delivery_status,
                },
            );
            Ok(())
        })?;

        Ok(states
            .into_values()
            .filter_map(|state| {
                if state.delivery_status == DeliveryStatus::Pending {
                    Some(state.event)
                } else {
                    None
                }
            })
            .collect())
    }

    fn should_rollover_unlocked(&self) -> Result<bool, LocalAuditStoreError> {
        let Some(snapshot) = self.current_file_snapshot_unlocked()? else {
            return Ok(false);
        };

        Ok(snapshot.is_rollover_eligible(self.rotate_size_bytes))
    }

    fn current_file_snapshot_unlocked(
        &self,
    ) -> Result<Option<FallbackFileSnapshot>, LocalAuditStoreError> {
        let metadata = match fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };

        if !metadata.is_file() {
            return Ok(None);
        }

        let mut final_status_by_event_id = BTreeMap::<String, DeliveryStatus>::new();
        let mut line_count = 0usize;
        let mut first_occurred_at = None;
        let mut last_occurred_at = None;

        self.parse_existing_fallback_records_unlocked(|record| {
            final_status_by_event_id.insert(record.event_id, record.delivery_status);
            line_count += 1;

            if let Some(occurred_at) = record.occurred_at {
                if first_occurred_at.is_none() {
                    first_occurred_at = Some(occurred_at.to_owned());
                }
                last_occurred_at = Some(occurred_at.to_owned());
            }
            Ok(())
        })?;

        Ok(Some(FallbackFileSnapshot {
            size_bytes: metadata.len(),
            line_count,
            final_status_by_event_id,
            first_occurred_at,
            last_occurred_at,
        }))
    }

    fn parse_existing_fallback_records_unlocked<F>(
        &self,
        mut handle_record: F,
    ) -> Result<(), LocalAuditStoreError>
    where
        F: for<'a> FnMut(ParsedFallbackRecord<'a>) -> Result<(), LocalAuditStoreError>,
    {
        for_each_nonempty_line(&self.path, |line_number, line| {
            let record: LocalAuditFallbackRecord = serde_json::from_str(line)?;
            let event = record.to_event(line_number)?;
            let event_id = event.audit_event_id().as_canonical_string();
            handle_record(ParsedFallbackRecord {
                event,
                event_id,
                delivery_status: record.delivery_status(),
                occurred_at: record.non_empty_occurred_at(),
            })?;
            Ok::<(), LocalAuditStoreError>(())
        })
    }

    fn next_archive_path(&self) -> Result<PathBuf, LocalAuditStoreError> {
        let archive_path = self.archive_dir.join(format!(
            "{ARCHIVE_FILE_PREFIX}{}{ARCHIVE_FILE_SUFFIX}",
            archive_timestamp()
        ));

        if archive_path.exists() {
            return Err(LocalAuditStoreError::ArchivePathUnavailable { path: archive_path });
        }

        Ok(archive_path)
    }

    fn write_gzip_archive(&self, archive_path: &Path) -> Result<(), LocalAuditStoreError> {
        let mut input =
            File::open(&self.path).map_err(|source| LocalAuditStoreError::GzipWriteFailed {
                path: archive_path.to_path_buf(),
                source,
            })?;
        let archive_file = create_new_private(archive_path).map_err(|source| {
            LocalAuditStoreError::GzipWriteFailed {
                path: archive_path.to_path_buf(),
                source,
            }
        })?;
        let mut encoder = GzEncoder::new(archive_file, Compression::default());

        std::io::copy(&mut input, &mut encoder).map_err(|source| {
            LocalAuditStoreError::GzipWriteFailed {
                path: archive_path.to_path_buf(),
                source,
            }
        })?;
        let archive_file =
            encoder
                .finish()
                .map_err(|source| LocalAuditStoreError::GzipWriteFailed {
                    path: archive_path.to_path_buf(),
                    source,
                })?;
        archive_file
            .sync_data()
            .map_err(|source| LocalAuditStoreError::GzipWriteFailed {
                path: archive_path.to_path_buf(),
                source,
            })?;

        Ok(())
    }
}

struct LocalAuditEventState {
    event: AuditEvent,
    delivery_status: DeliveryStatus,
}

struct ParsedFallbackRecord<'a> {
    event: AuditEvent,
    event_id: String,
    delivery_status: DeliveryStatus,
    occurred_at: Option<&'a str>,
}

struct FallbackFileSnapshot {
    size_bytes: u64,
    line_count: usize,
    final_status_by_event_id: BTreeMap<String, DeliveryStatus>,
    first_occurred_at: Option<String>,
    last_occurred_at: Option<String>,
}

impl FallbackFileSnapshot {
    fn is_rollover_eligible(&self, rotate_size_bytes: u64) -> bool {
        self.size_bytes >= rotate_size_bytes
            && self.line_count > 0
            && !self.final_status_by_event_id.is_empty()
            && self
                .final_status_by_event_id
                .values()
                .all(|status| *status == DeliveryStatus::Sent)
    }
}

fn default_archive_dir_for(path: &Path) -> PathBuf {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("archive")
}

fn archive_timestamp() -> String {
    let now = OffsetDateTime::now_utc();

    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn is_archive_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.starts_with(ARCHIVE_FILE_PREFIX) && name.ends_with(ARCHIVE_FILE_SUFFIX)
        })
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

fn gzip_line_count(path: &Path) -> Result<usize, std::io::Error> {
    let file = File::open(path)?;
    let decoder = GzDecoder::new(file);
    let reader = BufReader::new(decoder);
    let mut line_count = 0usize;

    for line in reader.lines() {
        line?;
        line_count += 1;
    }

    Ok(line_count)
}

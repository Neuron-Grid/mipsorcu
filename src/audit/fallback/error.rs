use std::fmt;
use std::path::PathBuf;

use super::super::error::AuditEventError;

#[derive(Debug)]
pub enum LocalAuditStoreError {
    Io(std::io::Error),
    Json(serde_json::Error),
    TimestampFormat(time::error::Format),
    ArchivePathUnavailable {
        path: PathBuf,
    },
    GzipWriteFailed {
        path: PathBuf,
        source: std::io::Error,
    },
    HashReadFailed {
        path: PathBuf,
        source: std::io::Error,
    },
    CurrentFileRemoveFailed {
        path: PathBuf,
        source: std::io::Error,
    },
    ArchiveDeleteFailed {
        path: PathBuf,
        source: std::io::Error,
    },
    LockPoisoned,
    InvalidLine {
        line_number: usize,
        reason: &'static str,
    },
    Event(AuditEventError),
}

impl fmt::Display for LocalAuditStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "local audit store I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "local audit store JSON failed: {error}"),
            Self::TimestampFormat(error) => {
                write!(
                    formatter,
                    "local audit store timestamp format failed: {error}"
                )
            }
            Self::ArchivePathUnavailable { path } => {
                write!(
                    formatter,
                    "local audit archive path is unavailable: {}",
                    path.display()
                )
            }
            Self::GzipWriteFailed { path, source } => {
                write!(
                    formatter,
                    "local audit archive gzip write failed for {}: {source}",
                    path.display()
                )
            }
            Self::HashReadFailed { path, source } => {
                write!(
                    formatter,
                    "local audit archive hash read failed for {}: {source}",
                    path.display()
                )
            }
            Self::CurrentFileRemoveFailed { path, source } => {
                write!(
                    formatter,
                    "local audit current file removal failed for {}: {source}",
                    path.display()
                )
            }
            Self::ArchiveDeleteFailed { path, source } => {
                write!(
                    formatter,
                    "local audit archive deletion failed for {}: {source}",
                    path.display()
                )
            }
            Self::LockPoisoned => {
                write!(formatter, "local audit store lock is poisoned")
            }
            Self::InvalidLine {
                line_number,
                reason,
            } => {
                write!(
                    formatter,
                    "local audit store line {line_number} is invalid: {reason}"
                )
            }
            Self::Event(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for LocalAuditStoreError {}

impl From<std::io::Error> for LocalAuditStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for LocalAuditStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<AuditEventError> for LocalAuditStoreError {
    fn from(error: AuditEventError) -> Self {
        Self::Event(error)
    }
}

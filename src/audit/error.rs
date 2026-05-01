use std::fmt;
use std::path::PathBuf;

use super::event::AuditAction;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEventError {
    InvalidUuid { field: &'static str },
    UnknownAction { value: String },
    UnknownResult { value: String },
    WriteSuccessActionNotAllowed { action: AuditAction },
    FailureOnlyActionSuccessNotAllowed { action: AuditAction },
    MetadataMustBeObject,
    ForbiddenMetadataKey { key: String },
    InvalidSourceEventAt,
    MissingSourceEventAt,
    SourceEventAtUnavailable,
}

impl fmt::Display for AuditEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUuid { field } => {
                write!(formatter, "{field} must be a valid UUID")
            }
            Self::UnknownAction { value } => {
                write!(formatter, "unknown audit action: {value}")
            }
            Self::UnknownResult { value } => {
                write!(formatter, "unknown audit result: {value}")
            }
            Self::WriteSuccessActionNotAllowed { action } => {
                write!(
                    formatter,
                    "success audit for {} must be recorded by the write RPC",
                    action.as_str()
                )
            }
            Self::FailureOnlyActionSuccessNotAllowed { action } => {
                write!(
                    formatter,
                    "success audit for {} is not allowed",
                    action.as_str()
                )
            }
            Self::MetadataMustBeObject => {
                write!(formatter, "audit metadata must be a JSON object")
            }
            Self::ForbiddenMetadataKey { key } => {
                write!(formatter, "audit metadata contains forbidden key: {key}")
            }
            Self::InvalidSourceEventAt => {
                write!(
                    formatter,
                    "audit metadata source_event_at must be a canonical UTC RFC3339 timestamp string"
                )
            }
            Self::MissingSourceEventAt => {
                write!(formatter, "audit metadata source_event_at is required")
            }
            Self::SourceEventAtUnavailable => {
                write!(formatter, "failed to generate audit source_event_at")
            }
        }
    }
}

impl std::error::Error for AuditEventError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditAppendError {
    ExternalDependencyFailed { code: &'static str },
    IdempotencyConflict,
}

impl fmt::Display for AuditAppendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExternalDependencyFailed { code } => {
                write!(formatter, "audit append external dependency failed: {code}")
            }
            Self::IdempotencyConflict => {
                write!(formatter, "audit append idempotency conflict")
            }
        }
    }
}

impl std::error::Error for AuditAppendError {}

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

#[derive(Debug)]
pub enum AuditRecordError {
    EventConstructionFailed(AuditEventError),
    PrimaryAndFallbackFailed {
        append_error: AuditAppendError,
        store_error: LocalAuditStoreError,
    },
    IdempotencyConflict,
    ResendReadFailed(LocalAuditStoreError),
    ResendMarkSentFailed(LocalAuditStoreError),
}

impl fmt::Display for AuditRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventConstructionFailed(error) => {
                write!(formatter, "audit event construction failed: {error}")
            }
            Self::PrimaryAndFallbackFailed {
                append_error,
                store_error,
            } => {
                write!(
                    formatter,
                    "audit append failed ({append_error}) and fallback write failed: {store_error}"
                )
            }
            Self::IdempotencyConflict => {
                write!(
                    formatter,
                    "audit append failed permanently: audit append idempotency conflict"
                )
            }
            Self::ResendReadFailed(error) => {
                write!(
                    formatter,
                    "failed to read pending audit fallback events: {error}"
                )
            }
            Self::ResendMarkSentFailed(error) => {
                write!(
                    formatter,
                    "failed to mark audit fallback event as sent: {error}"
                )
            }
        }
    }
}

impl std::error::Error for AuditRecordError {}

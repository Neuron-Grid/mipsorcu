use std::fmt;

use super::event::AuditAction;
pub use super::fallback::LocalAuditStoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEventError {
    InvalidUuid { field: &'static str },
    UnknownAction { value: String },
    UnknownResult { value: String },
    WriteSuccessActionNotAllowed { action: AuditAction },
    FailureOnlyActionSuccessNotAllowed { action: AuditAction },
    SuccessOnlyActionFailureNotAllowed { action: AuditAction },
    AuthFailureFieldMustBeNull { field: &'static str },
    MetadataMustBeObject,
    ForbiddenMetadataKey { key: String },
    UnknownMetadataKey { key: String },
    MissingMetadataKey { key: &'static str },
    InvalidMetadataValue { key: &'static str },
    ViolationSummaryMustBeObject,
    InvalidTrigger { value: String },
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
            Self::SuccessOnlyActionFailureNotAllowed { action } => {
                write!(
                    formatter,
                    "failure audit for {} is not allowed",
                    action.as_str()
                )
            }
            Self::AuthFailureFieldMustBeNull { field } => {
                write!(formatter, "auth_failure audit field must be null: {field}")
            }
            Self::MetadataMustBeObject => {
                write!(formatter, "audit metadata must be a JSON object")
            }
            Self::ForbiddenMetadataKey { key } => {
                write!(formatter, "audit metadata contains forbidden key: {key}")
            }
            Self::UnknownMetadataKey { key } => {
                write!(
                    formatter,
                    "audit metadata contains unknown key for action: {key}"
                )
            }
            Self::MissingMetadataKey { key } => {
                write!(formatter, "audit metadata is missing required key: {key}")
            }
            Self::InvalidMetadataValue { key } => {
                write!(
                    formatter,
                    "audit metadata contains invalid value for key: {key}"
                )
            }
            Self::ViolationSummaryMustBeObject => {
                write!(
                    formatter,
                    "integrity_check violation_summary must be a JSON object"
                )
            }
            Self::InvalidTrigger { value } => {
                write!(
                    formatter,
                    "audit metadata trigger must be startup, background, or cli: {value}"
                )
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
pub enum AuditRecordError {
    EventConstructionFailed(AuditEventError),
    LedgerAppendFailed,
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
            Self::LedgerAppendFailed => {
                write!(formatter, "audit and ledger append failed")
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

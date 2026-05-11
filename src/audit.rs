mod error;
mod event;
mod fallback;
mod recorder;

pub use error::{AuditAppendError, AuditEventError, AuditRecordError, LocalAuditStoreError};
pub use event::{
    ArchiveExportMetadata, AuditAction, AuditEvent, AuditEventAppender, AuditEventId,
    AuditEventParts, AuditMetadata, AuditResult, AuditTrigger, AuthFailureMetadata, DecryptMetadata,
    EncryptCreateMetadata, EncryptRotateMetadata, FORBIDDEN_AUDIT_METADATA_KEYS,
    INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST, IntegrityCheckMetadata,
    KeyRotationCompleteMetadata, KeyRotationReencryptMetadata, KeyRotationStartMetadata, RequestId,
    RestoreTestMetadata, VersionPurgeMetadata,
};
pub use fallback::{
    ArchiveSweepOutcome, LocalAuditFallbackStore, RolloverArchive, RolloverOutcome, SweptArchive,
};
pub use recorder::{AuditRecordOutcome, AuditRecorder, ResendAuditSummary};

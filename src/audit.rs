mod error;
mod event;
mod fallback;
mod recorder;

pub use error::{AuditAppendError, AuditEventError, AuditRecordError, LocalAuditStoreError};
pub use event::{
    ArchiveExportMetadata, AuditAction, AuditEvent, AuditEventAppender, AuditEventId,
    AuditEventParts, AuditMetadata, AuditReportGenerateMetadata, AuditResult, AuditTrigger,
    AuditUiReadMetadata, AuthFailureMetadata, DecryptMetadata, DigestTimestampingMetadata,
    EncryptCreateMetadata, EncryptRotateMetadata, FORBIDDEN_AUDIT_METADATA_KEYS,
    INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST, IncidentDetectedMetadata, IntegrityCheckMetadata,
    KeyRotationCompleteMetadata, KeyRotationEnvelopeFailedMetadata,
    KeyRotationEnvelopeMigratedMetadata, KeyRotationReencryptMetadata, KeyRotationStartMetadata,
    MonthlyDigestGenerateMetadata, MonthlyDigestVerifyMetadata, RequestId, RestoreTestMetadata,
    SchedulerJobMetadata, SecretAliasCreateMetadata, SecretAliasDeleteMetadata,
    SecretAliasListMetadata, SecretAliasUpdateMetadata, SiemForwardFailureMetadata,
    SignatureKeyActivatedMetadata, SignatureKeyCreatedMetadata, SignatureKeyRetiredMetadata,
    VersionPurgeMetadata,
};
pub use fallback::{
    ArchiveSweepOutcome, LocalAuditFallbackStore, RolloverArchive, RolloverOutcome, SweptArchive,
};
pub use recorder::{AuditRecordOutcome, AuditRecorder, ResendAuditSummary};

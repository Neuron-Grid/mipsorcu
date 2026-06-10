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
    INCIDENT_NOTIFICATION_CATEGORY_ALLOWLIST, INCIDENT_SEVERITY_ALLOWLIST, INCIDENT_TYPE_ALLOWLIST,
    INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST, IncidentDetectedMetadata,
    IncidentNotificationFailedMetadata, IncidentNotificationSentMetadata,
    IncidentNotificationSuppressedMetadata, IntegrityCheckMetadata, KeyRotationCompleteMetadata,
    KeyRotationEnvelopeFailedMetadata, KeyRotationEnvelopeMigratedMetadata,
    KeyRotationReencryptMetadata, KeyRotationStartMetadata, MonthlyDigestGenerateMetadata,
    MonthlyDigestVerifyMetadata, NOTIFICATION_RESULT_ALLOWLIST, NOTIFIER_KIND_ALLOWLIST, RequestId,
    RestoreTestMetadata, SchedulerJobMetadata, SecretAliasCreateMetadata,
    SecretAliasDeleteMetadata, SecretAliasListMetadata, SecretAliasUpdateMetadata,
    SiemBufferFlushedMetadata, SiemEventFailedMetadata, SiemEventForwardedMetadata,
    SiemForwardFailureMetadata, SignatureKeyActivatedMetadata, SignatureKeyCreatedMetadata,
    SignatureKeyRetiredMetadata, VersionPurgeMetadata, required_metadata_keys,
};
pub use fallback::{
    ArchiveSweepOutcome, LocalAuditFallbackStore, RolloverArchive, RolloverOutcome, SweptArchive,
};
pub use recorder::{AuditRecordOutcome, AuditRecorder, ResendAuditSummary};

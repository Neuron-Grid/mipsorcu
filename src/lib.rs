#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod aad;
pub mod archive;
pub mod audit;
pub mod auth;
pub mod authorization;
pub mod crypto;
pub mod error;
pub mod incident;
pub mod ledger;
pub mod read;
pub mod server;
pub mod siem;
pub mod timestamping;
pub mod types;
pub mod write;

pub use aad::AadV1;
pub use archive::{
    ARCHIVE_SCHEMA_VERSION, ArchiveBackend, ArchiveBackendError, ArchiveExportPackage,
    ArchiveObjectKey, ArchiveVerifyOutcome, InMemoryArchiveBackend, LocalFileArchiveBackend,
    S3ArchiveBackendConfig, S3ArchiveBackendConfigError, S3ImmutableArchiveBackend,
    S3ObjectLockMode,
};
pub use audit::{
    ArchiveExportMetadata, ArchiveSweepOutcome, AuditAction, AuditAppendError, AuditEvent,
    AuditEventAppender, AuditEventError, AuditEventId, AuditEventParts, AuditMetadata,
    AuditRecordError, AuditRecordOutcome, AuditRecorder, AuditReportGenerateMetadata, AuditResult,
    AuditTrigger, AuthFailureMetadata, DecryptMetadata, DigestTimestampingMetadata,
    EncryptCreateMetadata, EncryptRotateMetadata, FORBIDDEN_AUDIT_METADATA_KEYS,
    INTEGRITY_CHECK_VIOLATION_SUMMARY_ALLOWLIST, IncidentDetectedMetadata, IntegrityCheckMetadata,
    KeyRotationCompleteMetadata, KeyRotationReencryptMetadata, KeyRotationStartMetadata,
    LocalAuditFallbackStore, LocalAuditStoreError, MonthlyDigestGenerateMetadata,
    MonthlyDigestVerifyMetadata, RequestId, ResendAuditSummary, RestoreTestMetadata,
    RolloverArchive, RolloverOutcome, SchedulerJobMetadata, SiemForwardFailureMetadata,
    SweptArchive, VersionPurgeMetadata,
};
pub use auth::{
    Jwk, Jwks, JwksCache, JwksFetchError, JwtVerifier, JwtVerifierConfig, RawJwt,
    VerifiedJwtClaims, fetch_jwks,
};
pub use authorization::{
    authorize_current_version_decrypt, authorize_existing_secret_version_write,
    authorize_new_secret_create,
};
pub use crypto::{
    ALGORITHM_XCHACHA20_POLY1305, EncryptedPayload, KeyWrapContext, MasterKeyRing, decrypt_secret,
    encrypt_secret, unwrap_data_key, wrap_data_key,
};
pub use error::{
    AadError, AuthorizationError, CryptoError, DecryptIntegrityError, InputError,
    JwtVerificationError, KeyringError, SecretDecryptError, SecretWriteError,
};
pub use incident::{
    DummyNotificationSink, FailingNotificationSink, IncidentNotificationPayload,
    IncidentRecordError, IncidentRecordInput, IncidentRecordResult, IncidentRecorder,
    IncidentSeverity, IncidentType, NotificationResult, NotificationSink, NotificationSinkError,
};
pub use ledger::{
    DIGEST_GENERATED_BY, DIGEST_SCHEMA_VERSION_V1, DigestCanonicalBytes, DigestHash,
    FORBIDDEN_LEDGER_PAYLOAD_KEYS, LEDGER_CANONICAL_SCHEMA_V1, LEDGER_CANONICALIZATION_VERSION_V1,
    LEDGER_ED25519_PUBLIC_KEY_LENGTH, LEDGER_ED25519_SECRET_KEY_LENGTH,
    LEDGER_HASH_ALGORITHM_SHA256, LEDGER_HASH_LENGTH, LEDGER_PAYLOAD_MAX_CANONICAL_BYTES,
    LEDGER_SIGNATURE_ALGORITHM_ED25519, LEDGER_SIGNATURE_LENGTH, LedgerCanonicalPayload,
    LedgerChainHead, LedgerEntryDraft, LedgerEntryDraftParts, LedgerEntryId, LedgerEntryType,
    LedgerError, LedgerHash, LedgerPayload, LedgerResult, LedgerSequenceNo, LedgerSignature,
    LedgerSignatureKeyVersion, LedgerSigningKey, LedgerTargetSecretVersionId,
    LedgerVerificationKey, LedgerVerifyingKey, MonthlyDigestPeriod, SignedLedgerEntry,
    SignedLedgerEntryParts, SignedMonthlyDigest, build_monthly_digest_canonical_form,
    verify_ledger_chain,
};
pub use read::{
    DecryptCurrentSecretVersionInput, DecryptCurrentSecretVersionInputParts,
    decrypt_current_secret_version, decrypt_current_secret_version_with_keyring,
};
pub use server::use_cases::export_digest_to_archive::{
    ExportDigestToArchiveError, export_digest_to_archive, record_archive_export_failure_audit,
};
pub use server::use_cases::request_timestamping_for_digest::{
    RequestTimestampingError, record_digest_timestamping_failure_audit,
    request_timestamping_for_digest,
};
pub use siem::{
    FailingSiemSink, InMemorySiemSink, LocalSiemBufferError, LocalSiemFallbackBuffer,
    SIEM_EVENT_SCHEMA_VERSION, SIEM_EVENT_TOP_LEVEL_KEYS, SiemEvent, SiemForwardOutcome,
    SiemForwarder, SiemForwarderStatus, SiemResendSummary, SiemSink, SiemSinkError,
    build_siem_forward_failure_audit_event,
};
pub use timestamping::{
    FailingTimestampingService, InMemoryTimestampingService, TimestampingService,
    TimestampingServiceError, TimestampingToken, TimestampingTokenHash,
};
pub use types::{
    Ciphertext, Classification, CreatedAt, DATA_KEY_LENGTH, DataKey, DeviceId,
    ENCRYPTED_DATA_KEY_CIPHERTEXT_LENGTH, ENCRYPTED_DATA_KEY_LENGTH, ENCRYPTED_DATA_KEY_TAG_LENGTH,
    ENCRYPTED_DATA_KEY_VERSION, EncryptedDataKey, KeyVersion, MASTER_KEY_LENGTH, MasterKey,
    NONCE_LENGTH, Nonce, OwnerUserId, Plaintext, SecretId, SecretVersion, SecretVersionId,
    SourceEventAt,
};
pub use write::{
    CurrentSecretVersionState, ExistingSecretVersionInput, NewSecretVersionInput,
    PreparedSecretVersion, SecretWriteAction, prepare_existing_secret_version,
    prepare_existing_secret_version_with_keyring, prepare_new_secret_version,
    prepare_new_secret_version_with_keyring,
};

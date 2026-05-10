pub mod aad;
pub mod audit;
pub mod auth;
pub mod authorization;
pub mod crypto;
pub mod error;
pub mod ledger;
pub mod read;
pub mod server;
pub mod types;
pub mod write;

pub use aad::AadV1;
pub use audit::{
    ArchiveSweepOutcome, AuditAction, AuditAppendError, AuditEvent, AuditEventAppender,
    AuditEventError, AuditEventId, AuditEventParts, AuditMetadata, AuditRecordError,
    AuditRecordOutcome, AuditRecorder, AuditResult, AuditTrigger, FORBIDDEN_AUDIT_METADATA_KEYS,
    LocalAuditFallbackStore, LocalAuditStoreError, RequestId, ResendAuditSummary, RolloverArchive,
    RolloverOutcome, SweptArchive,
    AuthFailureMetadata, DecryptMetadata, EncryptCreateMetadata, EncryptRotateMetadata,
    IntegrityCheckMetadata, KeyRotationCompleteMetadata, KeyRotationReencryptMetadata,
    KeyRotationStartMetadata, RestoreTestMetadata, VersionPurgeMetadata,
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
pub use ledger::{
    FORBIDDEN_LEDGER_PAYLOAD_KEYS, LEDGER_CANONICAL_SCHEMA_V1, LEDGER_CANONICALIZATION_VERSION_V1,
    LEDGER_ED25519_PUBLIC_KEY_LENGTH, LEDGER_ED25519_SECRET_KEY_LENGTH,
    LEDGER_HASH_ALGORITHM_SHA256, LEDGER_HASH_LENGTH, LEDGER_PAYLOAD_MAX_CANONICAL_BYTES,
    LEDGER_SIGNATURE_ALGORITHM_ED25519, LEDGER_SIGNATURE_LENGTH, LedgerCanonicalPayload,
    LedgerChainHead, LedgerEntryDraft, LedgerEntryDraftParts, LedgerEntryId, LedgerEntryType,
    LedgerError, LedgerHash, LedgerPayload, LedgerResult, LedgerSequenceNo, LedgerSignature,
    LedgerSignatureKeyVersion, LedgerSigningKey, LedgerTargetSecretVersionId,
    LedgerVerificationKey, LedgerVerifyingKey, SignedLedgerEntry, SignedLedgerEntryParts,
    verify_ledger_chain,
};
pub use read::{
    DecryptCurrentSecretVersionInput, DecryptCurrentSecretVersionInputParts,
    decrypt_current_secret_version, decrypt_current_secret_version_with_keyring,
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

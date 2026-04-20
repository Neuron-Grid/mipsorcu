pub mod aad;
pub mod audit;
pub mod auth;
pub mod authorization;
pub mod crypto;
pub mod error;
pub mod read;
pub mod server;
pub mod types;
pub mod write;

pub use aad::AadV1;
pub use audit::{
    ArchiveSweepOutcome, AuditAction, AuditAppendError, AuditEvent, AuditEventAppender,
    AuditEventError, AuditEventId, AuditEventParts, AuditMetadata, AuditRecordError,
    AuditRecordOutcome, AuditRecorder, AuditResult, LocalAuditFallbackStore, LocalAuditStoreError,
    RequestId, ResendAuditSummary, RolloverArchive, RolloverOutcome, SweptArchive,
};
pub use auth::{
    Jwk, Jwks, JwksCache, JwksFetchError, JwtVerifier, JwtVerifierConfig, RawJwt,
    VerifiedJwtClaims, fetch_jwks,
};
pub use authorization::{
    authorize_current_version_decrypt, authorize_existing_secret_version_write,
};
pub use crypto::{
    ALGORITHM_XCHACHA20_POLY1305, EncryptedPayload, KeyWrapContext, decrypt_secret, encrypt_secret,
    unwrap_data_key, wrap_data_key,
};
pub use error::{
    AadError, AuthorizationError, CryptoError, DecryptIntegrityError, InputError,
    JwtVerificationError, SecretDecryptError, SecretWriteError,
};
pub use read::{
    DecryptCurrentSecretVersionInput, DecryptCurrentSecretVersionInputParts,
    decrypt_current_secret_version,
};
pub use types::{
    Ciphertext, Classification, CreatedAt, DATA_KEY_LENGTH, DataKey, DeviceId,
    ENCRYPTED_DATA_KEY_CIPHERTEXT_LENGTH, ENCRYPTED_DATA_KEY_LENGTH, ENCRYPTED_DATA_KEY_TAG_LENGTH,
    ENCRYPTED_DATA_KEY_VERSION, EncryptedDataKey, KeyVersion, MASTER_KEY_LENGTH, MasterKey,
    NONCE_LENGTH, Nonce, OwnerUserId, Plaintext, SecretId, SecretVersion,
};
pub use write::{
    CurrentSecretVersionState, ExistingSecretVersionInput, NewSecretVersionInput,
    PreparedSecretVersion, SecretWriteAction, prepare_existing_secret_version,
    prepare_new_secret_version,
};

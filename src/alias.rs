mod aad;
mod crypto;
mod error;
mod fingerprint;
mod input;

pub use aad::{ALIAS_AAD_VERSION_V1, AliasAadV1};
pub use crypto::{EncryptedAlias, decrypt_alias, encrypt_alias};
pub use error::AliasInputError;
pub use fingerprint::{
    ALIAS_FINGERPRINT_LENGTH, ALIAS_FINGERPRINT_SCHEMA_VERSION_V1, AliasFingerprint,
    compute_alias_fingerprint,
};
pub use input::{ALIAS_MAX_LENGTH, AliasInput, NormalizedAlias};

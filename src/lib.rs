pub mod aad;
pub mod crypto;
pub mod error;
pub mod types;
pub mod write;

pub use aad::AadV1;
pub use crypto::{
    ALGORITHM_XCHACHA20_POLY1305, EncryptedPayload, KeyWrapContext, decrypt_secret, encrypt_secret,
    unwrap_data_key, wrap_data_key,
};
pub use error::{AadError, CryptoError, InputError, SecretWriteError};
pub use types::{
    Ciphertext, Classification, CreatedAt, DATA_KEY_LENGTH, DataKey, DeviceId,
    ENCRYPTED_DATA_KEY_CIPHERTEXT_LENGTH, ENCRYPTED_DATA_KEY_LENGTH, ENCRYPTED_DATA_KEY_TAG_LENGTH,
    ENCRYPTED_DATA_KEY_VERSION, EncryptedDataKey, KeyVersion, MASTER_KEY_LENGTH, MasterKey,
    NONCE_LENGTH, Nonce, OwnerUserId, Plaintext, SecretId, SecretVersion,
};
pub use write::{NewSecretVersionInput, PreparedSecretVersion, prepare_new_secret_version};

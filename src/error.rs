use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AadError {
    ExpectedJsonObject,
    MissingField {
        field: &'static str,
    },
    UnexpectedField {
        field: String,
    },
    InvalidFieldType {
        field: &'static str,
        expected: &'static str,
    },
    UnsupportedAadVersion {
        value: String,
    },
    InvalidUuid {
        field: &'static str,
        value: String,
    },
    InvalidUuidVersion {
        field: &'static str,
        value: String,
        expected: &'static str,
    },
    InvalidPositiveInteger {
        field: &'static str,
        value: String,
    },
    InvalidClassification,
    InvalidTimestamp {
        field: &'static str,
        value: String,
    },
    SerializationFailed(String),
}

impl fmt::Display for AadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpectedJsonObject => {
                write!(formatter, "aad_context must be a JSON object")
            }
            Self::MissingField { field } => {
                write!(formatter, "required field is missing: {field}")
            }
            Self::UnexpectedField { field } => {
                write!(formatter, "unexpected field in aad_context: {field}")
            }
            Self::InvalidFieldType { field, expected } => {
                write!(formatter, "field {field} must be {expected}")
            }
            Self::UnsupportedAadVersion { value } => {
                write!(formatter, "unsupported aad_version: {value}")
            }
            Self::InvalidUuid { field, value } => {
                write!(
                    formatter,
                    "field {field} must be a canonicalizable UUID: {value}"
                )
            }
            Self::InvalidUuidVersion {
                field,
                value,
                expected,
            } => {
                write!(
                    formatter,
                    "field {field} must be a {expected} UUID: {value}"
                )
            }
            Self::InvalidPositiveInteger { field, value } => {
                write!(
                    formatter,
                    "field {field} must be a positive integer: {value}"
                )
            }
            Self::InvalidClassification => {
                write!(
                    formatter,
                    "classification must not be empty or whitespace only"
                )
            }
            Self::InvalidTimestamp { field, value } => {
                write!(
                    formatter,
                    "field {field} must be a UTC RFC3339 timestamp: {value}"
                )
            }
            Self::SerializationFailed(message) => {
                write!(formatter, "failed to serialize canonical AAD: {message}")
            }
        }
    }
}

impl std::error::Error for AadError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    InvalidDeviceId,
    InvalidSecretAlias,
    SecretAliasTooLong { max: usize },
    SecretAliasLooksLikeUuid,
    SecretVersionOverflow,
}

impl fmt::Display for InputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDeviceId => {
                write!(formatter, "device_id must not be empty or whitespace only")
            }
            Self::InvalidSecretAlias => {
                write!(
                    formatter,
                    "secret alias must use only ASCII letters, digits, '.', '_', or '-'"
                )
            }
            Self::SecretAliasTooLong { max } => {
                write!(formatter, "secret alias must be at most {max} characters")
            }
            Self::SecretAliasLooksLikeUuid => {
                write!(formatter, "secret alias must not be a UUID v4")
            }
            Self::SecretVersionOverflow => {
                write!(formatter, "secret version cannot be incremented")
            }
        }
    }
}

impl std::error::Error for InputError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtVerificationError {
    EmptyToken,
    InvalidToken,
    MissingKeyId,
    UnsupportedAlgorithm,
    KeyNotFound,
    InvalidSignature,
    Expired,
    InvalidIssuer,
    InvalidAudience,
    InvalidSubject,
    InvalidJwks,
    MalformedClaims,
}

impl fmt::Display for JwtVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyToken => {
                write!(formatter, "jwt must not be empty or whitespace only")
            }
            Self::InvalidToken => {
                write!(formatter, "jwt is invalid")
            }
            Self::MissingKeyId => {
                write!(formatter, "jwt header is missing kid")
            }
            Self::UnsupportedAlgorithm => {
                write!(formatter, "jwt algorithm is not supported")
            }
            Self::KeyNotFound => {
                write!(formatter, "matching jwks key was not found")
            }
            Self::InvalidSignature => {
                write!(formatter, "jwt signature is invalid")
            }
            Self::Expired => {
                write!(formatter, "jwt is expired")
            }
            Self::InvalidIssuer => {
                write!(formatter, "jwt issuer is invalid")
            }
            Self::InvalidAudience => {
                write!(formatter, "jwt audience is invalid")
            }
            Self::InvalidSubject => {
                write!(formatter, "jwt subject is invalid")
            }
            Self::InvalidJwks => {
                write!(formatter, "jwks is invalid")
            }
            Self::MalformedClaims => {
                write!(formatter, "jwt claims are malformed")
            }
        }
    }
}

impl std::error::Error for JwtVerificationError {}

#[derive(Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidDataKeyLength { actual: usize },
    InvalidMasterKeyLength { actual: usize },
    InvalidNonceLength { actual: usize },
    InvalidKeyVersion { value: u32 },
    UnsupportedAliasFingerprintSchemaVersion { value: u32 },
    InvalidEncryptedDataKeyLength { actual: usize },
    UnsupportedEncryptedDataKeyVersion { version: u8 },
    EmptyCiphertext,
    RandomnessUnavailable,
    AadFailed,
    EncryptionFailed,
    DecryptionFailed,
    KeyWrapFailed,
    KeyUnwrapFailed,
}

impl fmt::Debug for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDataKeyLength { actual } => formatter
                .debug_struct("InvalidDataKeyLength")
                .field("actual", actual)
                .finish(),
            Self::InvalidMasterKeyLength { actual } => formatter
                .debug_struct("InvalidMasterKeyLength")
                .field("actual", actual)
                .finish(),
            Self::InvalidNonceLength { actual } => formatter
                .debug_struct("InvalidNonceLength")
                .field("actual", actual)
                .finish(),
            Self::InvalidKeyVersion { value } => formatter
                .debug_struct("InvalidKeyVersion")
                .field("value", value)
                .finish(),
            Self::UnsupportedAliasFingerprintSchemaVersion { value } => formatter
                .debug_struct("UnsupportedAliasFingerprintSchemaVersion")
                .field("value", value)
                .finish(),
            Self::InvalidEncryptedDataKeyLength { actual } => formatter
                .debug_struct("InvalidEncryptedDataKeyLength")
                .field("actual", actual)
                .finish(),
            Self::UnsupportedEncryptedDataKeyVersion { version } => formatter
                .debug_struct("UnsupportedEncryptedDataKeyVersion")
                .field("version", version)
                .finish(),
            Self::EmptyCiphertext => formatter.write_str("EmptyCiphertext"),
            Self::RandomnessUnavailable => formatter.write_str("RandomnessUnavailable"),
            Self::AadFailed => formatter.write_str("AadFailed"),
            Self::EncryptionFailed => formatter.write_str("EncryptionFailed"),
            Self::DecryptionFailed => formatter.write_str("DecryptionFailed"),
            Self::KeyWrapFailed => formatter.write_str("KeyWrapFailed"),
            Self::KeyUnwrapFailed => formatter.write_str("KeyUnwrapFailed"),
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDataKeyLength { actual } => {
                write!(
                    formatter,
                    "data key must be 32 bytes: actual length {actual}"
                )
            }
            Self::InvalidMasterKeyLength { actual } => {
                write!(
                    formatter,
                    "master key must be 32 bytes: actual length {actual}"
                )
            }
            Self::InvalidNonceLength { actual } => {
                write!(formatter, "nonce must be 24 bytes: actual length {actual}")
            }
            Self::InvalidKeyVersion { value } => {
                write!(
                    formatter,
                    "key version must be positive: actual value {value}"
                )
            }
            Self::UnsupportedAliasFingerprintSchemaVersion { value } => {
                write!(
                    formatter,
                    "unsupported alias fingerprint schema version: {value}"
                )
            }
            Self::InvalidEncryptedDataKeyLength { actual } => {
                write!(
                    formatter,
                    "encrypted data key envelope has invalid length: actual length {actual}"
                )
            }
            Self::UnsupportedEncryptedDataKeyVersion { version } => {
                write!(
                    formatter,
                    "unsupported encrypted data key envelope version: {version}"
                )
            }
            Self::EmptyCiphertext => {
                write!(formatter, "ciphertext must not be empty")
            }
            Self::RandomnessUnavailable => {
                write!(formatter, "cryptographic randomness is unavailable")
            }
            Self::AadFailed => {
                write!(formatter, "failed to build canonical AAD")
            }
            Self::EncryptionFailed => {
                write!(formatter, "encryption failed")
            }
            Self::DecryptionFailed => {
                write!(formatter, "decryption failed")
            }
            Self::KeyWrapFailed => {
                write!(formatter, "data key wrapping failed")
            }
            Self::KeyUnwrapFailed => {
                write!(formatter, "data key unwrapping failed")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<AadError> for CryptoError {
    fn from(_: AadError) -> Self {
        Self::AadFailed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyringError {
    Empty,
    DuplicateKeyVersion { key_version: u32 },
    ActiveKeyMissing { key_version: u32 },
    KeyUnavailable { key_version: u32 },
}

impl fmt::Display for KeyringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(formatter, "master keyring must not be empty"),
            Self::DuplicateKeyVersion { key_version } => {
                write!(formatter, "duplicate master key version: {key_version}")
            }
            Self::ActiveKeyMissing { key_version } => {
                write!(
                    formatter,
                    "active master key version is not present: {key_version}"
                )
            }
            Self::KeyUnavailable { key_version } => {
                write!(
                    formatter,
                    "master key version is unavailable: {key_version}"
                )
            }
        }
    }
}

impl std::error::Error for KeyringError {}

#[derive(Clone, PartialEq, Eq)]
pub enum SecretWriteError {
    Input(InputError),
    Aad(AadError),
    Crypto(CryptoError),
    Keyring(KeyringError),
}

impl fmt::Debug for SecretWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => formatter.debug_tuple("Input").field(error).finish(),
            Self::Aad(error) => formatter.debug_tuple("Aad").field(error).finish(),
            Self::Crypto(error) => formatter.debug_tuple("Crypto").field(error).finish(),
            Self::Keyring(error) => formatter.debug_tuple("Keyring").field(error).finish(),
        }
    }
}

impl fmt::Display for SecretWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => write!(formatter, "{error}"),
            Self::Aad(error) => write!(formatter, "{error}"),
            Self::Crypto(error) => write!(formatter, "{error}"),
            Self::Keyring(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for SecretWriteError {}

impl From<InputError> for SecretWriteError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl From<AadError> for SecretWriteError {
    fn from(error: AadError) -> Self {
        Self::Aad(error)
    }
}

impl From<CryptoError> for SecretWriteError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<KeyringError> for SecretWriteError {
    fn from(error: KeyringError) -> Self {
        Self::Keyring(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationError {
    OwnerMismatch,
    NotCurrentVersion,
    MissingAuditorRole,
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnerMismatch => {
                write!(formatter, "actor is not allowed to decrypt this secret")
            }
            Self::NotCurrentVersion => {
                write!(formatter, "requested secret version is not current")
            }
            Self::MissingAuditorRole => {
                write!(formatter, "actor is not allowed to read audit ui data")
            }
        }
    }
}

impl std::error::Error for AuthorizationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptIntegrityError {
    AadContextMismatch,
}

impl fmt::Display for DecryptIntegrityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AadContextMismatch => {
                write!(formatter, "aad_context does not match row metadata")
            }
        }
    }
}

impl std::error::Error for DecryptIntegrityError {}

#[derive(Clone, PartialEq, Eq)]
pub enum SecretDecryptError {
    Authorization(AuthorizationError),
    Aad(AadError),
    Crypto(CryptoError),
    Integrity(DecryptIntegrityError),
    Keyring(KeyringError),
}

impl fmt::Debug for SecretDecryptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(error) => {
                formatter.debug_tuple("Authorization").field(error).finish()
            }
            Self::Aad(error) => formatter.debug_tuple("Aad").field(error).finish(),
            Self::Crypto(error) => formatter.debug_tuple("Crypto").field(error).finish(),
            Self::Integrity(error) => formatter.debug_tuple("Integrity").field(error).finish(),
            Self::Keyring(error) => formatter.debug_tuple("Keyring").field(error).finish(),
        }
    }
}

impl fmt::Display for SecretDecryptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(error) => write!(formatter, "{error}"),
            Self::Aad(error) => write!(formatter, "{error}"),
            Self::Crypto(error) => write!(formatter, "{error}"),
            Self::Integrity(error) => write!(formatter, "{error}"),
            Self::Keyring(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for SecretDecryptError {}

impl From<AuthorizationError> for SecretDecryptError {
    fn from(error: AuthorizationError) -> Self {
        Self::Authorization(error)
    }
}

impl From<AadError> for SecretDecryptError {
    fn from(error: AadError) -> Self {
        Self::Aad(error)
    }
}

impl From<CryptoError> for SecretDecryptError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<DecryptIntegrityError> for SecretDecryptError {
    fn from(error: DecryptIntegrityError) -> Self {
        Self::Integrity(error)
    }
}

impl From<KeyringError> for SecretDecryptError {
    fn from(error: KeyringError) -> Self {
        Self::Keyring(error)
    }
}

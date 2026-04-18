use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AadError {
    ExpectedJsonObject,
    MissingField {
        field: &'static str,
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
}

impl fmt::Display for InputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDeviceId => {
                write!(formatter, "device_id must not be empty or whitespace only")
            }
        }
    }
}

impl std::error::Error for InputError {}

#[derive(Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidDataKeyLength { actual: usize },
    InvalidMasterKeyLength { actual: usize },
    InvalidNonceLength { actual: usize },
    InvalidKeyVersion { value: u32 },
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

#[derive(Clone, PartialEq, Eq)]
pub enum SecretWriteError {
    Input(InputError),
    Aad(AadError),
    Crypto(CryptoError),
}

impl fmt::Debug for SecretWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => formatter.debug_tuple("Input").field(error).finish(),
            Self::Aad(error) => formatter.debug_tuple("Aad").field(error).finish(),
            Self::Crypto(error) => formatter.debug_tuple("Crypto").field(error).finish(),
        }
    }
}

impl fmt::Display for SecretWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => write!(formatter, "{error}"),
            Self::Aad(error) => write!(formatter, "{error}"),
            Self::Crypto(error) => write!(formatter, "{error}"),
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

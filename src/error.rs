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

#[derive(Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidDataKeyLength { actual: usize },
    InvalidNonceLength { actual: usize },
    EmptyCiphertext,
    RandomnessUnavailable,
    AadFailed,
    EncryptionFailed,
    DecryptionFailed,
}

impl fmt::Debug for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDataKeyLength { actual } => formatter
                .debug_struct("InvalidDataKeyLength")
                .field("actual", actual)
                .finish(),
            Self::InvalidNonceLength { actual } => formatter
                .debug_struct("InvalidNonceLength")
                .field("actual", actual)
                .finish(),
            Self::EmptyCiphertext => formatter.write_str("EmptyCiphertext"),
            Self::RandomnessUnavailable => formatter.write_str("RandomnessUnavailable"),
            Self::AadFailed => formatter.write_str("AadFailed"),
            Self::EncryptionFailed => formatter.write_str("EncryptionFailed"),
            Self::DecryptionFailed => formatter.write_str("DecryptionFailed"),
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
            Self::InvalidNonceLength { actual } => {
                write!(formatter, "nonce must be 24 bytes: actual length {actual}")
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
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<AadError> for CryptoError {
    fn from(_: AadError) -> Self {
        Self::AadFailed
    }
}

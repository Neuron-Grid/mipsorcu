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

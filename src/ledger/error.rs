use std::fmt;

use super::entry_type::LedgerEntryType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    InvalidUuid {
        field: &'static str,
    },
    InvalidUuidVersion {
        field: &'static str,
        expected: &'static str,
    },
    InvalidPositiveInteger {
        field: &'static str,
    },
    InvalidNonNegativeInteger {
        field: &'static str,
    },
    SequenceOverflow,
    UnknownEntryType {
        value: String,
    },
    UnknownResult {
        value: String,
    },
    PayloadMustBeObject,
    ForbiddenPayloadKey {
        key: String,
    },
    UnknownPayloadKey {
        key: String,
        entry_type: LedgerEntryType,
    },
    PayloadValueMustBeScalar {
        key: String,
    },
    InvalidPayloadField {
        key: String,
        expected: &'static str,
    },
    PayloadTooLarge {
        max_bytes: usize,
    },
    InvalidErrorCode {
        field: &'static str,
    },
    InvalidActorDeviceId,
    InvalidHashLength {
        actual: usize,
    },
    InvalidHashEncoding,
    InvalidSignatureLength {
        actual: usize,
    },
    InvalidSignatureEncoding,
    InvalidSigningKeyLength {
        actual: usize,
    },
    InvalidVerificationKeyLength {
        actual: usize,
    },
    InvalidVerificationKey,
    SignatureKeyVersionMismatch {
        expected: u32,
        actual: u32,
    },
    UnknownSignatureKey {
        key_version: u32,
        sequence_no: u64,
    },
    SignatureInvalid {
        sequence_no: u64,
    },
    HashMismatch {
        sequence_no: u64,
    },
    PreviousHashMismatch {
        sequence_no: u64,
    },
    SequenceGap {
        expected: u64,
        actual: u64,
    },
    SerializationFailed(String),
    RandomnessUnavailable,
    InvalidMonthlyDigestPeriod,
}

impl fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUuid { field } => write!(formatter, "ledger {field} must be a UUID"),
            Self::InvalidUuidVersion { field, expected } => {
                write!(formatter, "ledger {field} must be a {expected} UUID")
            }
            Self::InvalidPositiveInteger { field } => {
                write!(formatter, "ledger {field} must be a positive integer")
            }
            Self::InvalidNonNegativeInteger { field } => {
                write!(formatter, "ledger {field} must be a non-negative integer")
            }
            Self::SequenceOverflow => write!(formatter, "ledger sequence number overflow"),
            Self::UnknownEntryType { value } => {
                write!(formatter, "unknown ledger entry_type: {value}")
            }
            Self::UnknownResult { value } => write!(formatter, "unknown ledger result: {value}"),
            Self::PayloadMustBeObject => write!(formatter, "ledger payload must be a JSON object"),
            Self::ForbiddenPayloadKey { key } => {
                write!(formatter, "ledger payload contains a forbidden key: {key}")
            }
            Self::UnknownPayloadKey { key, entry_type } => write!(
                formatter,
                "ledger payload key {key} is not allowed for entry_type {}",
                entry_type.as_str()
            ),
            Self::PayloadValueMustBeScalar { key } => {
                write!(formatter, "ledger payload field {key} must be scalar")
            }
            Self::InvalidPayloadField { key, expected } => {
                write!(formatter, "ledger payload field {key} must be {expected}")
            }
            Self::PayloadTooLarge { max_bytes } => {
                write!(
                    formatter,
                    "ledger payload canonical JSON exceeds {max_bytes} bytes"
                )
            }
            Self::InvalidErrorCode { field } => {
                write!(
                    formatter,
                    "ledger {field} must be non-blank and at most 128 bytes"
                )
            }
            Self::InvalidActorDeviceId => {
                write!(
                    formatter,
                    "ledger actor_device_id must be at most 128 bytes"
                )
            }
            Self::InvalidHashLength { actual } => {
                write!(
                    formatter,
                    "ledger hash must be 32 bytes: actual length {actual}"
                )
            }
            Self::InvalidHashEncoding => write!(formatter, "ledger hash bytea encoding is invalid"),
            Self::InvalidSignatureLength { actual } => {
                write!(
                    formatter,
                    "ledger signature must be 64 bytes: actual length {actual}"
                )
            }
            Self::InvalidSignatureEncoding => {
                write!(formatter, "ledger signature bytea encoding is invalid")
            }
            Self::InvalidSigningKeyLength { actual } => {
                write!(
                    formatter,
                    "ledger signing key must be 32 bytes: actual length {actual}"
                )
            }
            Self::InvalidVerificationKeyLength { actual } => write!(
                formatter,
                "ledger verification key must be 32 bytes: actual length {actual}"
            ),
            Self::InvalidVerificationKey => write!(formatter, "ledger verification key is invalid"),
            Self::SignatureKeyVersionMismatch { expected, actual } => write!(
                formatter,
                "ledger signature key version mismatch: expected {expected}, actual {actual}"
            ),
            Self::UnknownSignatureKey {
                key_version,
                sequence_no,
            } => {
                write!(
                    formatter,
                    "unknown ledger signature key version: {key_version} at sequence {sequence_no}"
                )
            }
            Self::SignatureInvalid { sequence_no } => {
                write!(
                    formatter,
                    "ledger signature is invalid at sequence {sequence_no}"
                )
            }
            Self::HashMismatch { sequence_no } => {
                write!(
                    formatter,
                    "ledger entry hash mismatch at sequence {sequence_no}"
                )
            }
            Self::PreviousHashMismatch { sequence_no } => write!(
                formatter,
                "ledger previous hash mismatch at sequence {sequence_no}"
            ),
            Self::SequenceGap { expected, actual } => write!(
                formatter,
                "ledger sequence gap: expected {expected}, actual {actual}"
            ),
            Self::SerializationFailed(message) => {
                write!(
                    formatter,
                    "failed to serialize canonical ledger payload: {message}"
                )
            }
            Self::RandomnessUnavailable => write!(formatter, "ledger randomness unavailable"),
            Self::InvalidMonthlyDigestPeriod => write!(
                formatter,
                "monthly digest period must be in YYYY-MM format with a valid month (01-12)"
            ),
        }
    }
}

impl std::error::Error for LedgerError {}

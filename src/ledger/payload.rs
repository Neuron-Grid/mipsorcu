use std::fmt;

use serde_json::{Map, Value};

use crate::types::SourceEventAt;

use super::canonical::CanonicalPayloadObject;
use super::constants::{
    FORBIDDEN_LEDGER_PAYLOAD_KEYS, LEDGER_I64_MAX_U64, LEDGER_PAYLOAD_MAX_CANONICAL_BYTES,
};
use super::entry_type::LedgerEntryType;
use super::error::LedgerError;

#[derive(Clone, PartialEq, Eq)]
pub struct LedgerPayload {
    entry_type: LedgerEntryType,
    object: Map<String, Value>,
}

impl LedgerPayload {
    pub fn new(entry_type: LedgerEntryType, value: Value) -> Result<Self, LedgerError> {
        let object = value
            .as_object()
            .cloned()
            .ok_or(LedgerError::PayloadMustBeObject)?;

        reject_forbidden_payload_keys(&Value::Object(object.clone()))?;
        validate_payload_object(entry_type, &object)?;
        ensure_payload_size(entry_type, &object)?;

        Ok(Self { entry_type, object })
    }

    pub fn empty(entry_type: LedgerEntryType) -> Result<Self, LedgerError> {
        Self::new(entry_type, Value::Object(Map::new()))
    }

    pub fn entry_type(&self) -> LedgerEntryType {
        self.entry_type
    }

    pub fn as_value(&self) -> Value {
        Value::Object(self.object.clone())
    }

    pub(super) fn canonical_serializer(&self) -> CanonicalPayloadObject<'_> {
        CanonicalPayloadObject {
            entry_type: self.entry_type,
            object: &self.object,
        }
    }

    fn key_count(&self) -> usize {
        self.object.len()
    }
}

impl fmt::Debug for LedgerPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerPayload")
            .field("entry_type", &self.entry_type)
            .field("key_count", &self.key_count())
            .field("contents", &"<redacted>")
            .finish()
    }
}

fn reject_forbidden_payload_keys(value: &Value) -> Result<(), LedgerError> {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                if is_forbidden_payload_key(key) {
                    return Err(LedgerError::ForbiddenPayloadKey {
                        key: key.to_owned(),
                    });
                }

                reject_forbidden_payload_keys(nested)?;
            }

            Ok(())
        }
        Value::Array(values) => {
            for nested in values {
                reject_forbidden_payload_keys(nested)?;
            }

            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
    }
}

fn is_forbidden_payload_key(key: &str) -> bool {
    let normalized = key.trim().to_ascii_lowercase();
    FORBIDDEN_LEDGER_PAYLOAD_KEYS
        .iter()
        .any(|forbidden| normalized == *forbidden)
}

fn validate_payload_object(
    entry_type: LedgerEntryType,
    object: &Map<String, Value>,
) -> Result<(), LedgerError> {
    for (key, value) in object {
        if !entry_type.allowed_payload_keys().contains(&key.as_str()) {
            return Err(LedgerError::UnknownPayloadKey {
                key: key.to_owned(),
                entry_type,
            });
        }

        if matches!(value, Value::Object(_) | Value::Array(_)) {
            return Err(LedgerError::PayloadValueMustBeScalar {
                key: key.to_owned(),
            });
        }

        validate_payload_field(key, value)?;
    }

    validate_required_payload_keys(entry_type, object)?;
    validate_old_new_key_versions(object)
}

fn validate_payload_field(key: &str, value: &Value) -> Result<(), LedgerError> {
    match key {
        "version"
        | "key_version"
        | "old_key_version"
        | "new_key_version"
        | "signature_key_version"
        | "retention_limit"
        | "start_sequence_no"
        | "end_sequence_no"
        | "entry_count"
        | "target_sequence_no" => {
            let parsed = require_positive_json_u64(key, value)?;
            if key == "retention_limit" && parsed != 4 {
                return Err(LedgerError::InvalidPayloadField {
                    key: key.to_owned(),
                    expected: "the integer 4",
                });
            }
            Ok(())
        }
        "batch_size"
        | "checked_audit_event_count"
        | "checked_count"
        | "checked_secret_count"
        | "checked_secret_version_count"
        | "duration_ms"
        | "failed_count"
        | "failure_count"
        | "processed_count"
        | "remaining_count"
        | "resent_count"
        | "sample_count"
        | "success_count"
        | "violation_count" => require_non_negative_json_u64(key, value).map(|_| ()),
        "algorithm" => require_string_value(key, value, "xchacha20-poly1305"),
        "classification" => validate_classification_value(key, value),
        "trigger" => validate_trigger_value(key, value),
        "error_code" | "reason_code" | "archive_key" | "job_name" | "detection_source"
        | "dedupe_key" | "notification_sink" => validate_non_blank_short_string(key, value),
        "incident_type" => validate_incident_type_value(key, value),
        "severity" => {
            validate_string_enum_value(key, value, &["critical", "high", "medium", "low"])
        }
        "notification_result" => validate_string_enum_value(
            key,
            value,
            &["sent", "failed", "suppressed", "not_configured"],
        ),
        // monthly_digest 専用フィールド
        "target_year_month" => validate_year_month_value(key, value),
        "digest_hash" | "timestamp_token_hash" | "public_key_fingerprint" => {
            validate_digest_hash_value(key, value)
        }
        "created_at" | "activated_at" | "retired_at" => validate_source_event_at_value(key, value),
        _ => Err(LedgerError::UnknownPayloadKey {
            key: key.to_owned(),
            entry_type: LedgerEntryType::SecretCreated,
        }),
    }
}

fn validate_required_payload_keys(
    entry_type: LedgerEntryType,
    object: &Map<String, Value>,
) -> Result<(), LedgerError> {
    if entry_type != LedgerEntryType::IncidentDetected {
        return Ok(());
    }

    for key in [
        "incident_type",
        "severity",
        "detection_source",
        "dedupe_key",
        "notification_sink",
        "notification_result",
    ] {
        if !object.contains_key(key) {
            return Err(LedgerError::InvalidPayloadField {
                key: key.to_owned(),
                expected: "a required incident_detected payload key",
            });
        }
    }

    Ok(())
}

/// `YYYY-MM` 形式の文字列値を検証する。
fn validate_year_month_value(key: &str, value: &Value) -> Result<(), LedgerError> {
    let Some(text) = value.as_str() else {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a string in YYYY-MM format",
        });
    };

    let bytes = text.as_bytes();
    let is_valid = bytes.len() == 7
        && bytes[4] == b'-'
        && bytes[..4].iter().all(|b| b.is_ascii_digit())
        && bytes[5..].iter().all(|b| b.is_ascii_digit())
        && {
            let month: u8 = text[5..].parse().unwrap_or(0);
            (1u8..=12).contains(&month)
        };

    if !is_valid {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a string in YYYY-MM format",
        });
    }

    Ok(())
}

fn validate_source_event_at_value(key: &str, value: &Value) -> Result<(), LedgerError> {
    let Some(text) = value.as_str() else {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "an RFC3339 UTC timestamp ending with Z",
        });
    };

    SourceEventAt::parse(text).map_err(|_| LedgerError::InvalidPayloadField {
        key: key.to_owned(),
        expected: "an RFC3339 UTC timestamp ending with Z",
    })?;

    Ok(())
}

/// 64文字の小文字 hex 文字列を検証する（digest_hash フィールド用）。
fn validate_digest_hash_value(key: &str, value: &Value) -> Result<(), LedgerError> {
    let Some(text) = value.as_str() else {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a 64-character lowercase hex string",
        });
    };

    if text.len() != 64
        || !text
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
    {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a 64-character lowercase hex string",
        });
    }

    Ok(())
}

fn require_positive_json_u64(key: &str, value: &Value) -> Result<u64, LedgerError> {
    let parsed = require_json_u64(key, value, "a positive integer")?;
    if parsed == 0 {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a positive integer",
        });
    }

    Ok(parsed)
}

fn require_non_negative_json_u64(key: &str, value: &Value) -> Result<u64, LedgerError> {
    require_json_u64(key, value, "a non-negative integer")
}

fn require_json_u64(key: &str, value: &Value, expected: &'static str) -> Result<u64, LedgerError> {
    let parsed = value
        .as_u64()
        .ok_or_else(|| LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected,
        })?;

    if parsed > LEDGER_I64_MAX_U64 {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected,
        });
    }

    Ok(parsed)
}

fn require_string_value(
    key: &str,
    value: &Value,
    expected_value: &'static str,
) -> Result<(), LedgerError> {
    if value.as_str() == Some(expected_value) {
        return Ok(());
    }

    Err(LedgerError::InvalidPayloadField {
        key: key.to_owned(),
        expected: expected_value,
    })
}

fn validate_classification_value(key: &str, value: &Value) -> Result<(), LedgerError> {
    let Some(text) = value.as_str() else {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a non-blank string at most 128 bytes",
        });
    };

    if text.trim().is_empty() || text.len() > 128 {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a non-blank string at most 128 bytes",
        });
    }

    Ok(())
}

fn validate_trigger_value(key: &str, value: &Value) -> Result<(), LedgerError> {
    match value.as_str() {
        Some("background" | "cli" | "scheduled" | "startup") => Ok(()),
        _ => Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "one of background, cli, scheduled, startup",
        }),
    }
}

fn validate_non_blank_short_string(key: &str, value: &Value) -> Result<(), LedgerError> {
    let Some(text) = value.as_str() else {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a non-blank string at most 128 bytes",
        });
    };

    if text.trim().is_empty() || text.len() > 128 {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "a non-blank string at most 128 bytes",
        });
    }

    Ok(())
}

fn validate_string_enum_value(
    key: &str,
    value: &Value,
    allowed: &[&str],
) -> Result<(), LedgerError> {
    let Some(text) = value.as_str() else {
        return Err(LedgerError::InvalidPayloadField {
            key: key.to_owned(),
            expected: "an allowed string value",
        });
    };

    if allowed.contains(&text) {
        return Ok(());
    }

    Err(LedgerError::InvalidPayloadField {
        key: key.to_owned(),
        expected: "an allowed string value",
    })
}

fn validate_incident_type_value(key: &str, value: &Value) -> Result<(), LedgerError> {
    validate_string_enum_value(
        key,
        value,
        &[
            "hash_chain_mismatch",
            "signature_mismatch",
            "monthly_digest_mismatch",
            "digest_timestamping_mismatch",
            "archive_export_mismatch",
            "sequence_gap",
            "unknown_signature_key",
            "non_auditor_ledger_read",
            "ledger_secret_leak_suspected",
            "siem_long_failure",
            "audit_ui_forbidden_operation",
        ],
    )
}

fn validate_old_new_key_versions(object: &Map<String, Value>) -> Result<(), LedgerError> {
    let Some(old_value) = object.get("old_key_version") else {
        return Ok(());
    };
    let Some(new_value) = object.get("new_key_version") else {
        return Ok(());
    };

    let old_key_version = require_positive_json_u64("old_key_version", old_value)?;
    let new_key_version = require_positive_json_u64("new_key_version", new_value)?;

    if old_key_version == new_key_version {
        return Err(LedgerError::InvalidPayloadField {
            key: "new_key_version".to_owned(),
            expected: "a different value from old_key_version",
        });
    }

    Ok(())
}

fn ensure_payload_size(
    entry_type: LedgerEntryType,
    object: &Map<String, Value>,
) -> Result<(), LedgerError> {
    let bytes = serde_json::to_vec(&CanonicalPayloadObject { entry_type, object })
        .map_err(|error| LedgerError::SerializationFailed(error.to_string()))?;

    if bytes.len() > LEDGER_PAYLOAD_MAX_CANONICAL_BYTES {
        return Err(LedgerError::PayloadTooLarge {
            max_bytes: LEDGER_PAYLOAD_MAX_CANONICAL_BYTES,
        });
    }

    Ok(())
}

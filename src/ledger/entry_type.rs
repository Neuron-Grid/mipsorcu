use super::error::LedgerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LedgerEntryType {
    SecretCreated,
    SecretVersionCreated,
    SecretDecrypted,
    SecretVersionPurged,
    IntegrityCheckCompleted,
    RestoreTestCompleted,
    KeyRotationStarted,
    KeyRotationReencrypted,
    KeyRotationCompleted,
    KeyRotationAborted,
    LedgerVerified,
    LedgerVerificationFailed,
    AuditFallbackResent,
}

impl LedgerEntryType {
    pub fn parse(value: &str) -> Result<Self, LedgerError> {
        match value {
            "secret_created" => Ok(Self::SecretCreated),
            "secret_version_created" => Ok(Self::SecretVersionCreated),
            "secret_decrypted" => Ok(Self::SecretDecrypted),
            "secret_version_purged" => Ok(Self::SecretVersionPurged),
            "integrity_check_completed" => Ok(Self::IntegrityCheckCompleted),
            "restore_test_completed" => Ok(Self::RestoreTestCompleted),
            "key_rotation_started" => Ok(Self::KeyRotationStarted),
            "key_rotation_reencrypted" => Ok(Self::KeyRotationReencrypted),
            "key_rotation_completed" => Ok(Self::KeyRotationCompleted),
            "key_rotation_aborted" => Ok(Self::KeyRotationAborted),
            "ledger_verified" => Ok(Self::LedgerVerified),
            "ledger_verification_failed" => Ok(Self::LedgerVerificationFailed),
            "audit_fallback_resent" => Ok(Self::AuditFallbackResent),
            _ => Err(LedgerError::UnknownEntryType {
                value: value.to_owned(),
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecretCreated => "secret_created",
            Self::SecretVersionCreated => "secret_version_created",
            Self::SecretDecrypted => "secret_decrypted",
            Self::SecretVersionPurged => "secret_version_purged",
            Self::IntegrityCheckCompleted => "integrity_check_completed",
            Self::RestoreTestCompleted => "restore_test_completed",
            Self::KeyRotationStarted => "key_rotation_started",
            Self::KeyRotationReencrypted => "key_rotation_reencrypted",
            Self::KeyRotationCompleted => "key_rotation_completed",
            Self::KeyRotationAborted => "key_rotation_aborted",
            Self::LedgerVerified => "ledger_verified",
            Self::LedgerVerificationFailed => "ledger_verification_failed",
            Self::AuditFallbackResent => "audit_fallback_resent",
        }
    }

    pub(super) fn allowed_payload_keys(self) -> &'static [&'static str] {
        match self {
            Self::SecretCreated | Self::SecretVersionCreated => {
                &["algorithm", "classification", "key_version", "version"]
            }
            Self::SecretDecrypted => &["algorithm", "key_version", "version"],
            Self::SecretVersionPurged => &["key_version", "retention_limit", "version"],
            Self::IntegrityCheckCompleted => &[
                "checked_audit_event_count",
                "checked_secret_count",
                "checked_secret_version_count",
                "duration_ms",
                "violation_count",
            ],
            Self::RestoreTestCompleted => &[
                "duration_ms",
                "failure_count",
                "sample_count",
                "success_count",
                "trigger",
            ],
            Self::KeyRotationStarted => &["new_key_version", "old_key_version"],
            Self::KeyRotationReencrypted => &[
                "batch_size",
                "new_key_version",
                "old_key_version",
                "processed_count",
                "remaining_count",
            ],
            Self::KeyRotationCompleted => {
                &["new_key_version", "old_key_version", "remaining_count"]
            }
            Self::KeyRotationAborted => &["new_key_version", "old_key_version", "reason_code"],
            Self::LedgerVerified => &[
                "checked_count",
                "duration_ms",
                "end_sequence_no",
                "start_sequence_no",
            ],
            Self::LedgerVerificationFailed => &[
                "end_sequence_no",
                "error_code",
                "failed_count",
                "start_sequence_no",
            ],
            Self::AuditFallbackResent => &["duration_ms", "failed_count", "resent_count"],
        }
    }
}

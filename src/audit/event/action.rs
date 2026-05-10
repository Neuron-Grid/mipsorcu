use super::super::error::AuditEventError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditAction {
    EncryptCreate,
    EncryptRotate,
    Decrypt,
    VersionPurge,
    IntegrityCheck,
    RestoreTest,
    AuthFailure,
    KeyRotationStart,
    KeyRotationReencrypt,
    KeyRotationComplete,
    /// 月次 digest 生成操作（失敗時の監査記録用、Ledger Phase 2 §7.3）。
    MonthlyDigestGenerate,
    /// 月次 digest 検証操作（失敗時の監査記録用、Ledger Phase 2 §7.4）。
    MonthlyDigestVerify,
}

impl AuditAction {
    pub fn parse(value: &str) -> Result<Self, AuditEventError> {
        match value {
            "encrypt_create" => Ok(Self::EncryptCreate),
            "encrypt_rotate" => Ok(Self::EncryptRotate),
            "decrypt" => Ok(Self::Decrypt),
            "version_purge" => Ok(Self::VersionPurge),
            "integrity_check" => Ok(Self::IntegrityCheck),
            "restore_test" => Ok(Self::RestoreTest),
            "auth_failure" => Ok(Self::AuthFailure),
            "key_rotation_start" => Ok(Self::KeyRotationStart),
            "key_rotation_reencrypt" => Ok(Self::KeyRotationReencrypt),
            "key_rotation_complete" => Ok(Self::KeyRotationComplete),
            "monthly_digest_generate" => Ok(Self::MonthlyDigestGenerate),
            "monthly_digest_verify" => Ok(Self::MonthlyDigestVerify),
            _ => Err(AuditEventError::UnknownAction {
                value: value.to_owned(),
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EncryptCreate => "encrypt_create",
            Self::EncryptRotate => "encrypt_rotate",
            Self::Decrypt => "decrypt",
            Self::VersionPurge => "version_purge",
            Self::IntegrityCheck => "integrity_check",
            Self::RestoreTest => "restore_test",
            Self::AuthFailure => "auth_failure",
            Self::KeyRotationStart => "key_rotation_start",
            Self::KeyRotationReencrypt => "key_rotation_reencrypt",
            Self::KeyRotationComplete => "key_rotation_complete",
            Self::MonthlyDigestGenerate => "monthly_digest_generate",
            Self::MonthlyDigestVerify => "monthly_digest_verify",
        }
    }

    pub fn is_write_success_only(self) -> bool {
        matches!(
            self,
            Self::EncryptCreate | Self::EncryptRotate | Self::VersionPurge
        )
    }

    pub fn is_failure_only(self) -> bool {
        matches!(self, Self::AuthFailure)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditResult {
    Success,
    Failure,
}

impl AuditResult {
    pub fn parse(value: &str) -> Result<Self, AuditEventError> {
        match value {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            _ => Err(AuditEventError::UnknownResult {
                value: value.to_owned(),
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

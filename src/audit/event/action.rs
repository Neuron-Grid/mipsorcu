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
    /// Ledger 署名公開鍵の registry 作成。
    SignatureKeyCreated,
    /// Ledger 署名鍵の新規署名用有効化。
    SignatureKeyActivated,
    /// Ledger 署名鍵の新規署名用失効。過去署名検証には保持する。
    SignatureKeyRetired,
    /// 月次 digest 生成操作（失敗時の監査記録用）。
    MonthlyDigestGenerate,
    /// 月次 digest 検証操作（失敗時の監査記録用）。
    MonthlyDigestVerify,
    /// 外部アーカイブ export 操作（成功・失敗両方の監査記録用）。
    ArchiveExport,
    /// 月次 digest 外部 timestamping 操作（成功・失敗両方の監査記録用）。
    DigestTimestamping,
    /// SIEM への監査イベント転送に失敗した（failure-only の監査）。
    SiemForwardFailure,
    /// 監査レポート生成操作（成功・失敗両方の監査記録用）。
    AuditReportGenerate,
    /// 監査担当者向け UI backend read-only API の閲覧操作。
    AuditUiRead,
    /// 定期実行スケジューラ job の実行結果（成功・失敗両方の監査記録用）。
    SchedulerJob,
    /// インシデント検知（failure-only の監査）。
    IncidentDetected,
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
            "signature_key_created" => Ok(Self::SignatureKeyCreated),
            "signature_key_activated" => Ok(Self::SignatureKeyActivated),
            "signature_key_retired" => Ok(Self::SignatureKeyRetired),
            "monthly_digest_generate" => Ok(Self::MonthlyDigestGenerate),
            "monthly_digest_verify" => Ok(Self::MonthlyDigestVerify),
            "archive_export" => Ok(Self::ArchiveExport),
            "digest_timestamping" => Ok(Self::DigestTimestamping),
            "siem_forward_failure" => Ok(Self::SiemForwardFailure),
            "audit_report_generate" => Ok(Self::AuditReportGenerate),
            "audit_ui_read" => Ok(Self::AuditUiRead),
            "scheduler_job" => Ok(Self::SchedulerJob),
            "incident_detected" => Ok(Self::IncidentDetected),
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
            Self::SignatureKeyCreated => "signature_key_created",
            Self::SignatureKeyActivated => "signature_key_activated",
            Self::SignatureKeyRetired => "signature_key_retired",
            Self::MonthlyDigestGenerate => "monthly_digest_generate",
            Self::MonthlyDigestVerify => "monthly_digest_verify",
            Self::ArchiveExport => "archive_export",
            Self::DigestTimestamping => "digest_timestamping",
            Self::SiemForwardFailure => "siem_forward_failure",
            Self::AuditReportGenerate => "audit_report_generate",
            Self::AuditUiRead => "audit_ui_read",
            Self::SchedulerJob => "scheduler_job",
            Self::IncidentDetected => "incident_detected",
        }
    }

    pub fn is_write_success_only(self) -> bool {
        matches!(
            self,
            Self::EncryptCreate | Self::EncryptRotate | Self::VersionPurge
        )
    }

    pub fn is_failure_only(self) -> bool {
        matches!(
            self,
            Self::AuthFailure | Self::SiemForwardFailure | Self::IncidentDetected
        )
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

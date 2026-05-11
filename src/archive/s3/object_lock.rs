//! S3 Object Lock 関連（mode 判別、retain_until_date 計算）。

use std::fmt;
use std::time::Duration;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::error::S3BackendError;

const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

/// S3 Object Lock の保持モード。
///
/// - `Governance`: 特権ロールは `s3:BypassGovernanceRetention` で削除可能
/// - `Compliance`: retain_until_date 前は root でも削除不可
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3ObjectLockMode {
    Governance,
    Compliance,
}

impl S3ObjectLockMode {
    /// env 文字列をパースする。大文字小文字を区別しない。
    pub fn parse(value: &str) -> Result<Self, S3BackendError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "governance" => Ok(Self::Governance),
            "compliance" => Ok(Self::Compliance),
            _ => Err(S3BackendError::InvalidConfig(
                "object_lock_mode must be 'governance' or 'compliance'",
            )),
        }
    }

    /// PUT 時に付与する `x-amz-object-lock-mode` ヘッダ値。
    pub fn as_header_value(self) -> &'static str {
        match self {
            Self::Governance => "GOVERNANCE",
            Self::Compliance => "COMPLIANCE",
        }
    }
}

impl fmt::Display for S3ObjectLockMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_header_value())
    }
}

/// `now + retention_days` を RFC3339 UTC（末尾 `Z`）で返す。
///
/// 失敗時は `S3BackendError::InvalidConfig` を返す（時刻フォーマット失敗は
/// 内部不変条件違反だが、回復不能 panic は機微処理規約に違反するため
/// 明示的エラーとして扱う）。
pub fn retain_until_date(
    now: OffsetDateTime,
    retention_days: u32,
) -> Result<String, S3BackendError> {
    let days_secs = u64::from(retention_days)
        .checked_mul(SECONDS_PER_DAY)
        .ok_or(S3BackendError::InvalidConfig("retention_days too large"))?;
    let offset = time::Duration::try_from(Duration::from_secs(days_secs))
        .map_err(|_| S3BackendError::InvalidConfig("retention_days overflows time::Duration"))?;
    let target = now
        .checked_add(offset)
        .ok_or(S3BackendError::InvalidConfig(
            "retain_until_date overflowed",
        ))?;
    target
        .format(&Rfc3339)
        .map_err(|_| S3BackendError::InvalidConfig("failed to format retain_until_date"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_governance() {
        assert_eq!(
            S3ObjectLockMode::parse("governance").unwrap(),
            S3ObjectLockMode::Governance
        );
        assert_eq!(
            S3ObjectLockMode::parse("GOVERNANCE").unwrap(),
            S3ObjectLockMode::Governance
        );
        assert_eq!(
            S3ObjectLockMode::parse("  Governance  ").unwrap(),
            S3ObjectLockMode::Governance
        );
    }

    #[test]
    fn parse_compliance() {
        assert_eq!(
            S3ObjectLockMode::parse("compliance").unwrap(),
            S3ObjectLockMode::Compliance
        );
    }

    #[test]
    fn parse_rejects_unknown() {
        assert!(S3ObjectLockMode::parse("none").is_err());
        assert!(S3ObjectLockMode::parse("").is_err());
    }

    #[test]
    fn header_value_is_uppercase() {
        assert_eq!(S3ObjectLockMode::Governance.as_header_value(), "GOVERNANCE");
        assert_eq!(S3ObjectLockMode::Compliance.as_header_value(), "COMPLIANCE");
    }

    #[test]
    fn retain_until_date_adds_days() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let formatted = retain_until_date(now, 7).unwrap();
        assert!(formatted.ends_with('Z'), "got: {formatted}");
        // 7 days = 604800 seconds; the rendered timestamp must parse and be
        // exactly 7*86400 seconds after `now`.
        let parsed = OffsetDateTime::parse(&formatted, &Rfc3339).unwrap();
        assert_eq!((parsed - now).whole_seconds(), 7 * 86_400);
    }

    #[test]
    fn retain_until_date_rejects_zero_overflow() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        // u32::MAX days overflows time::Duration
        let result = retain_until_date(now, u32::MAX);
        assert!(result.is_err());
    }
}

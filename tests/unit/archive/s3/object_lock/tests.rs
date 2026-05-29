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

use std::path::PathBuf;
use std::time::Duration;

use mipsorcu::server::config::{
    AppConfig, ConfigError, parse_audit_fallback_alert_threshold, parse_audit_resend_interval,
    parse_jwks_refresh_interval, parse_restore_test_interval,
};
use mipsorcu::{KeyVersion, MASTER_KEY_LENGTH, MasterKey};

#[test]
fn audit_resend_interval_defaults_to_sixty_seconds() {
    let interval = parse_audit_resend_interval(None).expect("default interval should be valid");

    assert_eq!(interval, Duration::from_secs(60));
}

#[test]
fn audit_resend_interval_accepts_positive_seconds() {
    let interval = parse_audit_resend_interval(Some("30".to_owned()))
        .expect("positive interval should be valid");

    assert_eq!(interval, Duration::from_secs(30));
}

#[test]
fn audit_resend_interval_rejects_zero_empty_and_non_numeric_values() {
    assert!(matches!(
        parse_audit_resend_interval(Some("0".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_audit_resend_interval(Some(String::new())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_audit_resend_interval(Some("not-a-number".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
}

#[test]
fn audit_fallback_alert_threshold_defaults_to_ten_mib() {
    let threshold =
        parse_audit_fallback_alert_threshold(None).expect("default threshold should be valid");

    assert_eq!(threshold, 10 * 1024 * 1024);
}

#[test]
fn audit_fallback_alert_threshold_accepts_positive_bytes() {
    let threshold = parse_audit_fallback_alert_threshold(Some("4096".to_owned()))
        .expect("positive threshold should be valid");

    assert_eq!(threshold, 4096);
}

#[test]
fn audit_fallback_alert_threshold_rejects_zero_empty_and_non_numeric_values() {
    assert!(matches!(
        parse_audit_fallback_alert_threshold(Some("0".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_audit_fallback_alert_threshold(Some(String::new())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_audit_fallback_alert_threshold(Some("not-a-number".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
}

#[test]
fn restore_test_interval_defaults_to_twenty_four_hours() {
    let interval = parse_restore_test_interval(None).expect("default interval should be valid");

    assert_eq!(interval, Duration::from_secs(24 * 60 * 60));
}

#[test]
fn restore_test_interval_accepts_positive_seconds() {
    let interval = parse_restore_test_interval(Some("3600".to_owned()))
        .expect("positive interval should be valid");

    assert_eq!(interval, Duration::from_secs(3600));
}

#[test]
fn restore_test_interval_rejects_zero_empty_and_non_numeric_values() {
    assert!(matches!(
        parse_restore_test_interval(Some("0".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_restore_test_interval(Some(String::new())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_restore_test_interval(Some("not-a-number".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
}

#[test]
fn jwks_refresh_interval_defaults_to_sixty_minutes() {
    let interval = parse_jwks_refresh_interval(None).expect("default interval should be valid");

    assert_eq!(interval, Duration::from_secs(60 * 60));
}

#[test]
fn jwks_refresh_interval_accepts_positive_seconds() {
    let interval = parse_jwks_refresh_interval(Some("300".to_owned()))
        .expect("positive interval should be valid");

    assert_eq!(interval, Duration::from_secs(300));
}

#[test]
fn jwks_refresh_interval_rejects_zero_empty_and_non_numeric_values() {
    assert!(matches!(
        parse_jwks_refresh_interval(Some("0".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_jwks_refresh_interval(Some(String::new())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_jwks_refresh_interval(Some("not-a-number".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
}

#[test]
fn app_config_debug_redacts_secrets_and_shows_audit_threshold() {
    let master_key_bytes = vec![7; MASTER_KEY_LENGTH];
    let config = AppConfig {
        listen_addr: "127.0.0.1:3000"
            .parse()
            .expect("listen address should parse"),
        master_key: MasterKey::parse(&master_key_bytes).expect("master key should parse"),
        key_version: KeyVersion::new(1).expect("key version should be valid"),
        supabase_url: "https://example.supabase.co".to_owned(),
        supabase_service_role_key: "service-role-secret".to_owned(),
        supabase_publishable_key: "publishable-secret".to_owned(),
        jwt_issuer: "issuer".to_owned(),
        jwt_audience: "audience".to_owned(),
        jwks_url: "https://example.supabase.co/auth/v1/.well-known/jwks.json".to_owned(),
        jwks_refresh_interval: Duration::from_secs(300),
        audit_fallback_path: PathBuf::from("/tmp/mipsorcu-audit.jsonl"),
        audit_resend_interval: Duration::from_secs(60),
        audit_fallback_alert_threshold_bytes: 4096,
        restore_test_interval: Duration::from_secs(24 * 60 * 60),
    };

    let output = format!("{config:?}");

    assert!(output.contains("audit_fallback_alert_threshold_bytes"));
    assert!(output.contains("4096"));
    assert!(output.contains("restore_test_interval_seconds"));
    assert!(output.contains("jwks_url"));
    assert!(output.contains("jwks_refresh_interval_seconds"));
    assert!(output.contains("300"));
    assert!(!output.contains("service-role-secret"));
    assert!(!output.contains("publishable-secret"));
}

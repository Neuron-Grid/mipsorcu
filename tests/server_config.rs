use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mipsorcu::server::config::{
    AppConfig, ConfigError, load_config_from_sources, parse_audit_fallback_alert_threshold,
    parse_audit_fallback_archive_auto_delete_enabled, parse_audit_fallback_archive_retention_days,
    parse_audit_fallback_rotate_size, parse_audit_resend_interval, parse_dotenv_contents,
    parse_health_readiness_poll_interval, parse_http_handler_timeout,
    parse_http_rate_limit_requests, parse_http_rate_limit_window, parse_integrity_check_interval,
    parse_integrity_check_startup_delay, parse_jwks_refresh_interval,
    parse_outbound_http_connect_timeout, parse_outbound_http_request_timeout,
    parse_restore_test_interval, parse_restore_test_sample_limit, parse_restore_test_startup_delay,
};
use mipsorcu::{
    KeyVersion, LEDGER_ED25519_SECRET_KEY_LENGTH, LedgerSignatureKeyVersion, LedgerSigningKey,
    MASTER_KEY_LENGTH, MasterKey, MasterKeyRing,
};

fn base_dotenv() -> HashMap<String, String> {
    HashMap::from([
        (
            "MIPSORCU_MASTER_KEY".to_owned(),
            hex::encode([7u8; MASTER_KEY_LENGTH]),
        ),
        ("MIPSORCU_KEY_VERSION".to_owned(), "1".to_owned()),
        (
            "MIPSORCU_SUPABASE_URL".to_owned(),
            "https://from-dotenv.supabase.co".to_owned(),
        ),
        (
            "MIPSORCU_SUPABASE_SERVICE_ROLE_KEY".to_owned(),
            "service-role-secret".to_owned(),
        ),
        (
            "MIPSORCU_SUPABASE_PUBLISHABLE_KEY".to_owned(),
            "publishable-secret".to_owned(),
        ),
        (
            "MIPSORCU_LEDGER_SIGNING_KEY".to_owned(),
            hex::encode([9u8; LEDGER_ED25519_SECRET_KEY_LENGTH]),
        ),
        (
            "MIPSORCU_LEDGER_SIGNATURE_KEY_VERSION".to_owned(),
            "1".to_owned(),
        ),
        (
            "MIPSORCU_JWT_ISSUER".to_owned(),
            "https://example.supabase.co/auth/v1".to_owned(),
        ),
        (
            "MIPSORCU_JWT_AUDIENCE".to_owned(),
            "authenticated".to_owned(),
        ),
        (
            "MIPSORCU_JWKS_URL".to_owned(),
            "https://example.supabase.co/auth/v1/.well-known/jwks.json".to_owned(),
        ),
    ])
}

fn temp_dir(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    std::env::temp_dir().join(format!("mipsorcu-config-{test_name}-{unique}"))
}

#[test]
fn parse_dotenv_contents_supports_unquoted_and_quoted_values() {
    let contents = r#"
MIPSORCU_SUPABASE_URL=https://from-dotenv.supabase.co
MIPSORCU_SUPABASE_SERVICE_ROLE_KEY="service role"
export MIPSORCU_SUPABASE_PUBLISHABLE_KEY='publishable key'
"#;

    let dotenv = parse_dotenv_contents(contents, Path::new(".env")).expect("dotenv should parse");

    assert_eq!(
        dotenv.get("MIPSORCU_SUPABASE_URL"),
        Some(&"https://from-dotenv.supabase.co".to_owned())
    );
    assert_eq!(
        dotenv.get("MIPSORCU_SUPABASE_SERVICE_ROLE_KEY"),
        Some(&"service role".to_owned())
    );
    assert_eq!(
        dotenv.get("MIPSORCU_SUPABASE_PUBLISHABLE_KEY"),
        Some(&"publishable key".to_owned())
    );
}

#[test]
fn load_config_from_sources_uses_dotenv_for_missing_process_vars() {
    let process_env = HashMap::<String, String>::new();
    let get_process_var = |name: &str| process_env.get(name).cloned();

    let config =
        load_config_from_sources(&get_process_var, &base_dotenv()).expect("config should load");

    assert_eq!(config.listen_addr, "127.0.0.1:3000".parse().unwrap());
    assert_eq!(config.supabase_url, "https://from-dotenv.supabase.co");
}

#[test]
fn load_config_from_sources_prefers_process_env_over_dotenv() {
    let process_env = HashMap::from([
        (
            "MIPSORCU_SUPABASE_URL".to_owned(),
            "https://from-process.supabase.co".to_owned(),
        ),
        (
            "MIPSORCU_LISTEN_ADDR".to_owned(),
            "127.0.0.1:4000".to_owned(),
        ),
    ]);
    let get_process_var = |name: &str| process_env.get(name).cloned();

    let config =
        load_config_from_sources(&get_process_var, &base_dotenv()).expect("config should load");

    assert_eq!(config.listen_addr, "127.0.0.1:4000".parse().unwrap());
    assert_eq!(config.supabase_url, "https://from-process.supabase.co");
}

#[test]
fn load_config_from_sources_loads_master_keyring_from_directory() {
    let key_dir = temp_dir("keyring");
    fs::create_dir(&key_dir).expect("key directory should be created");
    fs::write(key_dir.join("1.key"), hex::encode([7u8; MASTER_KEY_LENGTH]))
        .expect("old key should be written");
    fs::write(
        key_dir.join("2.key"),
        format!("{}\n", hex::encode([8u8; MASTER_KEY_LENGTH])),
    )
    .expect("new key should be written");

    let mut dotenv = base_dotenv();
    dotenv.remove("MIPSORCU_MASTER_KEY");
    dotenv.remove("MIPSORCU_KEY_VERSION");
    dotenv.insert(
        "MIPSORCU_MASTER_KEY_DIR".to_owned(),
        key_dir.to_string_lossy().into_owned(),
    );
    dotenv.insert("MIPSORCU_ACTIVE_KEY_VERSION".to_owned(), "2".to_owned());
    let process_env = HashMap::<String, String>::new();
    let get_process_var = |name: &str| process_env.get(name).cloned();

    let config =
        load_config_from_sources(&get_process_var, &dotenv).expect("keyring config should load");

    assert!(config.master_key_ring.contains(KeyVersion::new(1).unwrap()));
    assert!(config.master_key_ring.contains(KeyVersion::new(2).unwrap()));
    assert_eq!(config.master_key_ring.active_key_version().get(), 2);

    fs::remove_dir_all(key_dir).expect("key directory should be removed");
}

#[test]
fn load_config_from_sources_rejects_duplicate_key_versions_in_directory() {
    let key_dir = temp_dir("duplicate-keyring");
    fs::create_dir(&key_dir).expect("key directory should be created");
    fs::write(key_dir.join("1.key"), hex::encode([7u8; MASTER_KEY_LENGTH]))
        .expect("key should be written");
    fs::write(
        key_dir.join("01.key"),
        hex::encode([8u8; MASTER_KEY_LENGTH]),
    )
    .expect("duplicate key should be written");

    let mut dotenv = base_dotenv();
    dotenv.insert(
        "MIPSORCU_MASTER_KEY_DIR".to_owned(),
        key_dir.to_string_lossy().into_owned(),
    );
    dotenv.insert("MIPSORCU_ACTIVE_KEY_VERSION".to_owned(), "1".to_owned());
    let process_env = HashMap::<String, String>::new();
    let get_process_var = |name: &str| process_env.get(name).cloned();

    let result = load_config_from_sources(&get_process_var, &dotenv);

    assert!(matches!(result, Err(ConfigError::InvalidValue { .. })));

    fs::remove_dir_all(key_dir).expect("key directory should be removed");
}

#[test]
fn load_config_from_sources_rejects_missing_active_key_in_directory() {
    let key_dir = temp_dir("missing-active-keyring");
    fs::create_dir(&key_dir).expect("key directory should be created");
    fs::write(key_dir.join("1.key"), hex::encode([7u8; MASTER_KEY_LENGTH]))
        .expect("key should be written");

    let mut dotenv = base_dotenv();
    dotenv.insert(
        "MIPSORCU_MASTER_KEY_DIR".to_owned(),
        key_dir.to_string_lossy().into_owned(),
    );
    dotenv.insert("MIPSORCU_ACTIVE_KEY_VERSION".to_owned(), "2".to_owned());
    let process_env = HashMap::<String, String>::new();
    let get_process_var = |name: &str| process_env.get(name).cloned();

    let result = load_config_from_sources(&get_process_var, &dotenv);

    assert!(matches!(result, Err(ConfigError::InvalidValue { .. })));

    fs::remove_dir_all(key_dir).expect("key directory should be removed");
}

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
fn audit_fallback_rotate_size_defaults_to_sixty_four_mib() {
    let threshold =
        parse_audit_fallback_rotate_size(None).expect("default rotate size should be valid");

    assert_eq!(threshold, 64 * 1024 * 1024);
}

#[test]
fn audit_fallback_rotate_size_accepts_positive_bytes() {
    let threshold = parse_audit_fallback_rotate_size(Some("8192".to_owned()))
        .expect("positive rotate size should be valid");

    assert_eq!(threshold, 8192);
}

#[test]
fn audit_fallback_rotate_size_rejects_zero_empty_and_non_numeric_values() {
    assert!(matches!(
        parse_audit_fallback_rotate_size(Some("0".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_audit_fallback_rotate_size(Some(String::new())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_audit_fallback_rotate_size(Some("not-a-number".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
}

#[test]
fn audit_fallback_archive_auto_delete_defaults_to_false() {
    let enabled = parse_audit_fallback_archive_auto_delete_enabled(None)
        .expect("default auto delete flag should be valid");

    assert!(!enabled);
}

#[test]
fn audit_fallback_archive_auto_delete_accepts_true_and_false() {
    assert!(
        parse_audit_fallback_archive_auto_delete_enabled(Some("true".to_owned()))
            .expect("true should be valid")
    );
    assert!(
        !parse_audit_fallback_archive_auto_delete_enabled(Some("false".to_owned()))
            .expect("false should be valid")
    );
    assert!(
        parse_audit_fallback_archive_auto_delete_enabled(Some("TRUE".to_owned()))
            .expect("uppercase true should be valid")
    );
}

#[test]
fn audit_fallback_archive_auto_delete_rejects_empty_and_invalid_bool_values() {
    assert!(matches!(
        parse_audit_fallback_archive_auto_delete_enabled(Some(String::new())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_audit_fallback_archive_auto_delete_enabled(Some("yes".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
}

#[test]
fn audit_fallback_archive_retention_defaults_to_ninety_days() {
    let retention = parse_audit_fallback_archive_retention_days(None)
        .expect("default archive retention should be valid");

    assert_eq!(retention, Duration::from_secs(90 * 24 * 60 * 60));
}

#[test]
fn audit_fallback_archive_retention_accepts_positive_days() {
    let retention = parse_audit_fallback_archive_retention_days(Some("30".to_owned()))
        .expect("positive archive retention should be valid");

    assert_eq!(retention, Duration::from_secs(30 * 24 * 60 * 60));
}

#[test]
fn audit_fallback_archive_retention_rejects_zero_empty_and_non_numeric_values() {
    assert!(matches!(
        parse_audit_fallback_archive_retention_days(Some("0".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_audit_fallback_archive_retention_days(Some(String::new())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_audit_fallback_archive_retention_days(Some("not-a-number".to_owned())),
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
fn restore_test_startup_delay_defaults_to_five_minutes() {
    let delay =
        parse_restore_test_startup_delay(None).expect("default startup delay should be valid");

    assert_eq!(delay, Duration::from_secs(300));
}

#[test]
fn restore_test_startup_delay_accepts_zero_and_positive_seconds() {
    let zero = parse_restore_test_startup_delay(Some("0".to_owned()))
        .expect("zero startup delay should be valid");
    let positive = parse_restore_test_startup_delay(Some("30".to_owned()))
        .expect("positive startup delay should be valid");

    assert_eq!(zero, Duration::from_secs(0));
    assert_eq!(positive, Duration::from_secs(30));
}

#[test]
fn restore_test_startup_delay_rejects_empty_and_non_numeric_values() {
    assert!(matches!(
        parse_restore_test_startup_delay(Some(String::new())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_restore_test_startup_delay(Some("not-a-number".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
}

#[test]
fn restore_test_sample_limit_defaults_to_three() {
    let limit =
        parse_restore_test_sample_limit(None).expect("default sample limit should be valid");

    assert_eq!(limit, 3);
}

#[test]
fn restore_test_sample_limit_accepts_positive_values() {
    let limit = parse_restore_test_sample_limit(Some("5".to_owned()))
        .expect("positive sample limit should be valid");

    assert_eq!(limit, 5);
}

#[test]
fn restore_test_sample_limit_rejects_zero_empty_and_non_numeric_values() {
    assert!(matches!(
        parse_restore_test_sample_limit(Some("0".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_restore_test_sample_limit(Some(String::new())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_restore_test_sample_limit(Some("not-a-number".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
}

#[test]
fn integrity_check_interval_defaults_to_twenty_four_hours() {
    let interval = parse_integrity_check_interval(None).expect("default interval should be valid");

    assert_eq!(interval, Duration::from_secs(24 * 60 * 60));
}

#[test]
fn integrity_check_interval_accepts_positive_seconds() {
    let interval = parse_integrity_check_interval(Some("3600".to_owned()))
        .expect("positive interval should be valid");

    assert_eq!(interval, Duration::from_secs(3600));
}

#[test]
fn integrity_check_interval_rejects_zero_empty_and_non_numeric_values() {
    assert!(matches!(
        parse_integrity_check_interval(Some("0".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_integrity_check_interval(Some(String::new())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_integrity_check_interval(Some("not-a-number".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
}

#[test]
fn integrity_check_startup_delay_defaults_to_sixty_five_minutes() {
    let delay =
        parse_integrity_check_startup_delay(None).expect("default startup delay should be valid");

    assert_eq!(delay, Duration::from_secs(3900));
}

#[test]
fn integrity_check_startup_delay_accepts_zero_and_positive_seconds() {
    let zero = parse_integrity_check_startup_delay(Some("0".to_owned()))
        .expect("zero startup delay should be valid");
    let positive = parse_integrity_check_startup_delay(Some("3900".to_owned()))
        .expect("positive startup delay should be valid");

    assert_eq!(zero, Duration::from_secs(0));
    assert_eq!(positive, Duration::from_secs(3900));
}

#[test]
fn integrity_check_startup_delay_rejects_empty_and_non_numeric_values() {
    assert!(matches!(
        parse_integrity_check_startup_delay(Some(String::new())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_integrity_check_startup_delay(Some("not-a-number".to_owned())),
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
fn health_readiness_poll_interval_defaults_to_thirty_seconds() {
    let interval =
        parse_health_readiness_poll_interval(None).expect("default poll interval should be valid");

    assert_eq!(interval, Duration::from_secs(30));
}

#[test]
fn health_readiness_poll_interval_accepts_positive_seconds() {
    let interval = parse_health_readiness_poll_interval(Some("45".to_owned()))
        .expect("positive poll interval should be valid");

    assert_eq!(interval, Duration::from_secs(45));
}

#[test]
fn health_readiness_poll_interval_rejects_zero_empty_and_non_numeric_values() {
    assert!(matches!(
        parse_health_readiness_poll_interval(Some("0".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_health_readiness_poll_interval(Some(String::new())),
        Err(ConfigError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse_health_readiness_poll_interval(Some("not-a-number".to_owned())),
        Err(ConfigError::InvalidValue { .. })
    ));
}

#[test]
fn outbound_http_connect_timeout_defaults_to_five_seconds() {
    let timeout =
        parse_outbound_http_connect_timeout(None).expect("default timeout should be valid");

    assert_eq!(timeout, Duration::from_secs(5));
}

#[test]
fn outbound_http_request_timeout_defaults_to_twenty_seconds() {
    let timeout =
        parse_outbound_http_request_timeout(None).expect("default timeout should be valid");

    assert_eq!(timeout, Duration::from_secs(20));
}

#[test]
fn outbound_http_timeouts_accept_positive_seconds() {
    assert_eq!(
        parse_outbound_http_connect_timeout(Some("3".to_owned()))
            .expect("positive connect timeout should be valid"),
        Duration::from_secs(3)
    );
    assert_eq!(
        parse_outbound_http_request_timeout(Some("9".to_owned()))
            .expect("positive request timeout should be valid"),
        Duration::from_secs(9)
    );
}

#[test]
fn outbound_http_timeouts_reject_zero_empty_and_non_numeric_values() {
    for value in ["0", "", "not-a-number"] {
        assert!(matches!(
            parse_outbound_http_connect_timeout(Some(value.to_owned())),
            Err(ConfigError::InvalidValue { .. })
        ));
        assert!(matches!(
            parse_outbound_http_request_timeout(Some(value.to_owned())),
            Err(ConfigError::InvalidValue { .. })
        ));
    }
}

#[test]
fn http_handler_timeout_defaults_to_seventy_five_seconds() {
    let timeout = parse_http_handler_timeout(None, Duration::from_secs(20))
        .expect("default handler timeout should be valid");

    assert_eq!(timeout, Duration::from_secs(75));
}

#[test]
fn http_handler_timeout_accepts_value_at_outbound_lower_bound() {
    let timeout = parse_http_handler_timeout(Some("45".to_owned()), Duration::from_secs(10))
        .expect("handler timeout at lower bound should be valid");

    assert_eq!(timeout, Duration::from_secs(45));
}

#[test]
fn http_handler_timeout_rejects_value_below_outbound_lower_bound() {
    let result = parse_http_handler_timeout(Some("44".to_owned()), Duration::from_secs(10));

    assert!(matches!(result, Err(ConfigError::InvalidValue { .. })));
}

#[test]
fn http_handler_timeout_rejects_zero_empty_and_non_numeric_values() {
    for value in ["0", "", "not-a-number"] {
        assert!(matches!(
            parse_http_handler_timeout(Some(value.to_owned()), Duration::from_secs(1)),
            Err(ConfigError::InvalidValue { .. })
        ));
    }
}

#[test]
fn http_rate_limit_defaults_to_three_hundred_requests_per_minute() {
    let requests =
        parse_http_rate_limit_requests(None).expect("default request limit should be valid");
    let window = parse_http_rate_limit_window(None).expect("default rate window should be valid");

    assert_eq!(requests, 300);
    assert_eq!(window, Duration::from_secs(60));
}

#[test]
fn http_rate_limit_accepts_positive_values() {
    let requests = parse_http_rate_limit_requests(Some("7".to_owned()))
        .expect("positive request limit should be valid");
    let window = parse_http_rate_limit_window(Some("11".to_owned()))
        .expect("positive rate window should be valid");

    assert_eq!(requests, 7);
    assert_eq!(window, Duration::from_secs(11));
}

#[test]
fn http_rate_limit_rejects_zero_empty_and_non_numeric_values() {
    for value in ["0", "", "not-a-number"] {
        assert!(matches!(
            parse_http_rate_limit_requests(Some(value.to_owned())),
            Err(ConfigError::InvalidValue { .. })
        ));
        assert!(matches!(
            parse_http_rate_limit_window(Some(value.to_owned())),
            Err(ConfigError::InvalidValue { .. })
        ));
    }
}

#[test]
fn load_config_from_sources_loads_runtime_resilience_env_values() {
    let mut dotenv = base_dotenv();
    dotenv.insert(
        "MIPSORCU_OUTBOUND_HTTP_CONNECT_TIMEOUT_SECONDS".to_owned(),
        "4".to_owned(),
    );
    dotenv.insert(
        "MIPSORCU_OUTBOUND_HTTP_REQUEST_TIMEOUT_SECONDS".to_owned(),
        "8".to_owned(),
    );
    dotenv.insert(
        "MIPSORCU_HTTP_HANDLER_TIMEOUT_SECONDS".to_owned(),
        "39".to_owned(),
    );
    dotenv.insert(
        "MIPSORCU_HTTP_RATE_LIMIT_REQUESTS".to_owned(),
        "9".to_owned(),
    );
    dotenv.insert(
        "MIPSORCU_HTTP_RATE_LIMIT_WINDOW_SECONDS".to_owned(),
        "10".to_owned(),
    );
    dotenv.insert(
        "MIPSORCU_RESTORE_TEST_STARTUP_DELAY_SECONDS".to_owned(),
        "5".to_owned(),
    );
    dotenv.insert(
        "MIPSORCU_INTEGRITY_CHECK_INTERVAL_SECONDS".to_owned(),
        "86401".to_owned(),
    );
    dotenv.insert(
        "MIPSORCU_INTEGRITY_CHECK_STARTUP_DELAY_SECONDS".to_owned(),
        "65".to_owned(),
    );
    let process_env = HashMap::<String, String>::new();
    let get_process_var = |name: &str| process_env.get(name).cloned();

    let config = load_config_from_sources(&get_process_var, &dotenv).expect("config should load");

    assert_eq!(config.outbound_http_connect_timeout, Duration::from_secs(4));
    assert_eq!(config.outbound_http_request_timeout, Duration::from_secs(8));
    assert_eq!(config.http_handler_timeout, Duration::from_secs(39));
    assert_eq!(config.http_rate_limit_requests, 9);
    assert_eq!(config.http_rate_limit_window, Duration::from_secs(10));
    assert_eq!(config.restore_test_startup_delay, Duration::from_secs(5));
    assert_eq!(config.integrity_check_interval, Duration::from_secs(86401));
    assert_eq!(
        config.integrity_check_startup_delay,
        Duration::from_secs(65)
    );
}

#[test]
fn app_config_debug_redacts_secrets_and_shows_audit_threshold() {
    let master_key_bytes = vec![7; MASTER_KEY_LENGTH];
    let key_version = KeyVersion::new(1).expect("key version should be valid");
    let config = AppConfig {
        listen_addr: "127.0.0.1:3000"
            .parse()
            .expect("listen address should parse"),
        master_key_ring: MasterKeyRing::single(
            key_version,
            MasterKey::parse(&master_key_bytes).expect("master key should parse"),
        )
        .expect("master keyring should be valid"),
        supabase_url: "https://example.supabase.co".to_owned(),
        supabase_service_role_key: "service-role-secret".to_owned(),
        supabase_publishable_key: "publishable-secret".to_owned(),
        ledger_signing_key: LedgerSigningKey::from_secret_key_bytes(
            LedgerSignatureKeyVersion::new(1).expect("ledger key version should be valid"),
            &[9u8; LEDGER_ED25519_SECRET_KEY_LENGTH],
        )
        .expect("ledger signing key should be valid"),
        jwt_issuer: "issuer".to_owned(),
        jwt_audience: "audience".to_owned(),
        jwks_url: "https://example.supabase.co/auth/v1/.well-known/jwks.json".to_owned(),
        jwks_refresh_interval: Duration::from_secs(300),
        health_readiness_poll_interval: Duration::from_secs(45),
        outbound_http_connect_timeout: Duration::from_secs(4),
        outbound_http_request_timeout: Duration::from_secs(8),
        http_handler_timeout: Duration::from_secs(39),
        http_rate_limit_requests: 9,
        http_rate_limit_window: Duration::from_secs(10),
        audit_fallback_path: PathBuf::from("/tmp/mipsorcu-audit.jsonl"),
        siem_buffer_path: PathBuf::from("/tmp/mipsorcu-siem.jsonl"),
        audit_resend_interval: Duration::from_secs(60),
        siem_resend_interval: Duration::from_secs(61),
        siem_long_failure_threshold: Duration::from_secs(900),
        audit_fallback_alert_threshold_bytes: 4096,
        audit_fallback_rotate_size_bytes: 8192,
        audit_fallback_archive_dir: PathBuf::from("/tmp/mipsorcu-audit-archive"),
        audit_fallback_archive_auto_delete_enabled: false,
        audit_fallback_archive_retention: Duration::from_secs(90 * 24 * 60 * 60),
        restore_test_interval: Duration::from_secs(24 * 60 * 60),
        restore_test_startup_delay: Duration::from_secs(300),
        restore_test_sample_limit: 3,
        integrity_check_interval: Duration::from_secs(24 * 60 * 60),
        integrity_check_startup_delay: Duration::from_secs(3900),
    };

    let output = format!("{config:?}");

    assert!(output.contains("audit_fallback_alert_threshold_bytes"));
    assert!(output.contains("4096"));
    assert!(output.contains("siem_buffer_path"));
    assert!(output.contains("siem_resend_interval_seconds"));
    assert!(output.contains("61"));
    assert!(output.contains("siem_long_failure_threshold_seconds"));
    assert!(output.contains("900"));
    assert!(output.contains("audit_fallback_rotate_size_bytes"));
    assert!(output.contains("8192"));
    assert!(output.contains("audit_fallback_archive_dir"));
    assert!(output.contains("audit_fallback_archive_auto_delete_enabled"));
    assert!(output.contains("audit_fallback_archive_retention_days"));
    assert!(output.contains("90"));
    assert!(output.contains("restore_test_interval_seconds"));
    assert!(output.contains("restore_test_startup_delay_seconds"));
    assert!(output.contains("300"));
    assert!(output.contains("restore_test_sample_limit"));
    assert!(output.contains("3"));
    assert!(output.contains("integrity_check_interval_seconds"));
    assert!(output.contains("86400"));
    assert!(output.contains("integrity_check_startup_delay_seconds"));
    assert!(output.contains("3900"));
    assert!(output.contains("jwks_url"));
    assert!(output.contains("jwks_refresh_interval_seconds"));
    assert!(output.contains("300"));
    assert!(output.contains("health_readiness_poll_interval_seconds"));
    assert!(output.contains("45"));
    assert!(output.contains("outbound_http_connect_timeout_seconds"));
    assert!(output.contains("4"));
    assert!(output.contains("outbound_http_request_timeout_seconds"));
    assert!(output.contains("8"));
    assert!(output.contains("http_handler_timeout_seconds"));
    assert!(output.contains("39"));
    assert!(output.contains("http_rate_limit_requests"));
    assert!(output.contains("9"));
    assert!(output.contains("http_rate_limit_window_seconds"));
    assert!(output.contains("10"));
    assert!(!output.contains("service-role-secret"));
    assert!(!output.contains("publishable-secret"));
}

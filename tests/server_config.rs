use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mipsorcu::server::config::{
    AppConfig, ConfigError, load_config_from_sources, parse_audit_fallback_alert_threshold,
    parse_audit_fallback_archive_auto_delete_enabled, parse_audit_fallback_archive_retention_days,
    parse_audit_fallback_rotate_size, parse_audit_resend_interval, parse_dotenv_contents,
    parse_health_readiness_poll_interval, parse_jwks_refresh_interval, parse_restore_test_interval,
    parse_restore_test_sample_limit,
};
use mipsorcu::{KeyVersion, MASTER_KEY_LENGTH, MasterKey, MasterKeyRing};

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
        jwt_issuer: "issuer".to_owned(),
        jwt_audience: "audience".to_owned(),
        jwks_url: "https://example.supabase.co/auth/v1/.well-known/jwks.json".to_owned(),
        jwks_refresh_interval: Duration::from_secs(300),
        health_readiness_poll_interval: Duration::from_secs(45),
        audit_fallback_path: PathBuf::from("/tmp/mipsorcu-audit.jsonl"),
        audit_resend_interval: Duration::from_secs(60),
        audit_fallback_alert_threshold_bytes: 4096,
        audit_fallback_rotate_size_bytes: 8192,
        audit_fallback_archive_dir: PathBuf::from("/tmp/mipsorcu-audit-archive"),
        audit_fallback_archive_auto_delete_enabled: false,
        audit_fallback_archive_retention: Duration::from_secs(90 * 24 * 60 * 60),
        restore_test_interval: Duration::from_secs(24 * 60 * 60),
        restore_test_sample_limit: 3,
    };

    let output = format!("{config:?}");

    assert!(output.contains("audit_fallback_alert_threshold_bytes"));
    assert!(output.contains("4096"));
    assert!(output.contains("audit_fallback_rotate_size_bytes"));
    assert!(output.contains("8192"));
    assert!(output.contains("audit_fallback_archive_dir"));
    assert!(output.contains("audit_fallback_archive_auto_delete_enabled"));
    assert!(output.contains("audit_fallback_archive_retention_days"));
    assert!(output.contains("90"));
    assert!(output.contains("restore_test_interval_seconds"));
    assert!(output.contains("restore_test_sample_limit"));
    assert!(output.contains("3"));
    assert!(output.contains("jwks_url"));
    assert!(output.contains("jwks_refresh_interval_seconds"));
    assert!(output.contains("300"));
    assert!(output.contains("health_readiness_poll_interval_seconds"));
    assert!(output.contains("45"));
    assert!(!output.contains("service-role-secret"));
    assert!(!output.contains("publishable-secret"));
}

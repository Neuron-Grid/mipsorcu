use super::*;
use std::collections::HashMap;

fn base_env() -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert(
        ENV_S3_ENDPOINT_URL.to_owned(),
        "https://s3.example".to_owned(),
    );
    env.insert(ENV_S3_REGION.to_owned(), "us-east-1".to_owned());
    env.insert(ENV_S3_BUCKET.to_owned(), "mipsorcu-archive".to_owned());
    env.insert(ENV_S3_ACCESS_KEY_ID.to_owned(), "AKIA".to_owned());
    env.insert(
        ENV_S3_SECRET_ACCESS_KEY.to_owned(),
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
    );
    env.insert(ENV_S3_OBJECT_LOCK_MODE.to_owned(), "compliance".to_owned());
    env.insert(ENV_S3_RETENTION_DAYS.to_owned(), "30".to_owned());
    env
}

fn get_var(env: &HashMap<String, String>) -> impl Fn(&str) -> Option<String> + '_ {
    move |name: &str| env.get(name).cloned()
}

#[test]
fn from_env_loads_required_vars() {
    let env = base_env();
    let config = S3ArchiveBackendConfig::from_env(get_var(&env)).expect("config must load");
    assert_eq!(config.endpoint_url(), "https://s3.example");
    assert_eq!(config.region(), "us-east-1");
    assert_eq!(config.bucket(), "mipsorcu-archive");
    assert_eq!(config.access_key_id(), "AKIA");
    assert_eq!(config.object_lock_mode(), S3ObjectLockMode::Compliance);
    assert_eq!(config.retention_days(), 30);
    assert!(config.path_style());
    assert!(config.forbid_overwrite());
}

#[test]
fn from_env_rejects_missing_required() {
    let mut env = base_env();
    env.remove(ENV_S3_BUCKET);
    let result = S3ArchiveBackendConfig::from_env(get_var(&env));
    assert!(matches!(
        result,
        Err(S3ArchiveBackendConfigError::MissingVar { name }) if name == ENV_S3_BUCKET
    ));
}

#[test]
fn from_env_rejects_blank_required() {
    let mut env = base_env();
    env.insert(ENV_S3_REGION.to_owned(), "   ".to_owned());
    let result = S3ArchiveBackendConfig::from_env(get_var(&env));
    assert!(matches!(
        result,
        Err(S3ArchiveBackendConfigError::InvalidValue { name, .. }) if name == ENV_S3_REGION
    ));
}

#[test]
fn from_env_rejects_zero_retention() {
    let mut env = base_env();
    env.insert(ENV_S3_RETENTION_DAYS.to_owned(), "0".to_owned());
    let result = S3ArchiveBackendConfig::from_env(get_var(&env));
    assert!(matches!(
        result,
        Err(S3ArchiveBackendConfigError::InvalidValue { name, .. }) if name == ENV_S3_RETENTION_DAYS
    ));
}

#[test]
fn from_env_rejects_invalid_object_lock_mode() {
    let mut env = base_env();
    env.insert(ENV_S3_OBJECT_LOCK_MODE.to_owned(), "none".to_owned());
    let result = S3ArchiveBackendConfig::from_env(get_var(&env));
    assert!(matches!(
        result,
        Err(S3ArchiveBackendConfigError::InvalidValue { name, .. }) if name == ENV_S3_OBJECT_LOCK_MODE
    ));
}

#[test]
fn debug_redacts_credentials() {
    let env = base_env();
    let config = S3ArchiveBackendConfig::from_env(get_var(&env)).unwrap();
    let formatted = format!("{config:?}");
    assert!(formatted.contains("<redacted>"));
    assert!(
        !formatted.contains("wJalrXUtnFEMI"),
        "secret_access_key must not appear in Debug: {formatted}"
    );
    assert!(
        !formatted.contains("AKIA"),
        "access_key_id must not appear in Debug: {formatted}"
    );
}

#[test]
fn secret_string_debug_is_redacted() {
    let secret = SecretString::new("sensitive".to_owned());
    let formatted = format!("{secret:?}");
    assert_eq!(formatted, "<redacted>");
    assert_eq!(secret.expose(), "sensitive");
}

#[test]
fn path_style_defaults_to_true() {
    let env = base_env();
    let config = S3ArchiveBackendConfig::from_env(get_var(&env)).unwrap();
    assert!(config.path_style());
}

#[test]
fn path_style_override_to_false() {
    let mut env = base_env();
    env.insert(ENV_S3_PATH_STYLE.to_owned(), "false".to_owned());
    let config = S3ArchiveBackendConfig::from_env(get_var(&env)).unwrap();
    assert!(!config.path_style());
}

#[test]
fn forbid_overwrite_override() {
    let mut env = base_env();
    env.insert(ENV_S3_FORBID_OVERWRITE.to_owned(), "no".to_owned());
    let config = S3ArchiveBackendConfig::from_env(get_var(&env)).unwrap();
    assert!(!config.forbid_overwrite());
}

#[test]
fn from_env_rejects_invalid_endpoint_values() {
    for endpoint in [
        "ftp://s3.example",
        "https://user:pass@s3.example",
        "https://s3.example/archive",
        "https://s3.example?debug=true",
        "https://s3.example#fragment",
    ] {
        let mut env = base_env();
        env.insert(ENV_S3_ENDPOINT_URL.to_owned(), endpoint.to_owned());
        let result = S3ArchiveBackendConfig::from_env(get_var(&env));
        assert!(
            matches!(
                result,
                Err(S3ArchiveBackendConfigError::InvalidValue { name, .. })
                    if name == ENV_S3_ENDPOINT_URL
            ),
            "endpoint must be rejected: {endpoint}"
        );
    }
}

#[test]
fn from_env_rejects_invalid_bucket_names() {
    for bucket in [
        "ab",
        "MipsorcuArchive",
        "mipsorcu_archive",
        "-mipsorcu",
        "mipsorcu-",
        "mipsorcu..archive",
        "mipsorcu.-archive",
        "mipsorcu-.archive",
        "192.168.0.1",
    ] {
        let mut env = base_env();
        env.insert(ENV_S3_BUCKET.to_owned(), bucket.to_owned());
        let result = S3ArchiveBackendConfig::from_env(get_var(&env));
        assert!(
            matches!(
                result,
                Err(S3ArchiveBackendConfigError::InvalidValue { name, .. })
                    if name == ENV_S3_BUCKET
            ),
            "bucket must be rejected: {bucket}"
        );
    }
}

#[test]
fn new_applies_endpoint_and_bucket_validation() {
    let invalid_endpoint = S3ArchiveBackendConfig::new(
        "ftp://s3.example".to_owned(),
        "us-east-1".to_owned(),
        "mipsorcu-archive".to_owned(),
        "AKIA".to_owned(),
        "secret".to_owned(),
        None,
        S3ObjectLockMode::Compliance,
        30,
    );
    assert!(invalid_endpoint.is_err());

    let invalid_bucket = S3ArchiveBackendConfig::new(
        "https://s3.example".to_owned(),
        "us-east-1".to_owned(),
        "MipsorcuArchive".to_owned(),
        "AKIA".to_owned(),
        "secret".to_owned(),
        None,
        S3ObjectLockMode::Compliance,
        30,
    );
    assert!(invalid_bucket.is_err());

    let valid = S3ArchiveBackendConfig::new(
        "http://localhost:9000/".to_owned(),
        "us-east-1".to_owned(),
        "mipsorcu-archive".to_owned(),
        "AKIA".to_owned(),
        "secret".to_owned(),
        None,
        S3ObjectLockMode::Compliance,
        30,
    );
    assert!(valid.is_ok());
}

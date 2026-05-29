//! `S3ArchiveBackendConfig` の env 読み出しとバリデーション。
//!
//! credentials は `Debug` で必ず `<redacted>` 化される。ログに `Authorization`
//! ヘッダ・`secret_access_key` を出さないため、本構造体を直接 `tracing` へ
//! 流す経路があっても秘密情報が漏れない。

use std::fmt;

use super::error::S3BackendError;
use super::object_lock::S3ObjectLockMode;

// Env keys（独自スコープ）

pub const ENV_S3_ENDPOINT_URL: &str = "MIPSORCU_ARCHIVE_S3_ENDPOINT_URL";
pub const ENV_S3_REGION: &str = "MIPSORCU_ARCHIVE_S3_REGION";
pub const ENV_S3_BUCKET: &str = "MIPSORCU_ARCHIVE_S3_BUCKET";
pub const ENV_S3_ACCESS_KEY_ID: &str = "MIPSORCU_ARCHIVE_S3_ACCESS_KEY_ID";
pub const ENV_S3_SECRET_ACCESS_KEY: &str = "MIPSORCU_ARCHIVE_S3_SECRET_ACCESS_KEY";
pub const ENV_S3_SESSION_TOKEN: &str = "MIPSORCU_ARCHIVE_S3_SESSION_TOKEN";
pub const ENV_S3_OBJECT_LOCK_MODE: &str = "MIPSORCU_ARCHIVE_S3_OBJECT_LOCK_MODE";
pub const ENV_S3_RETENTION_DAYS: &str = "MIPSORCU_ARCHIVE_S3_RETENTION_DAYS";
pub const ENV_S3_PATH_STYLE: &str = "MIPSORCU_ARCHIVE_S3_PATH_STYLE";
pub const ENV_S3_FORBID_OVERWRITE: &str = "MIPSORCU_ARCHIVE_S3_FORBID_OVERWRITE";
pub const ENV_S3_MAX_RETRIES: &str = "MIPSORCU_ARCHIVE_S3_MAX_RETRIES";
pub const ENV_S3_RETRY_BASE_MILLIS: &str = "MIPSORCU_ARCHIVE_S3_RETRY_BASE_MILLIS";

const DEFAULT_PATH_STYLE: bool = true;
const DEFAULT_FORBID_OVERWRITE: bool = true;
const DEFAULT_MAX_RETRIES: u32 = 4;
const DEFAULT_RETRY_BASE_MILLIS: u64 = 250;

// SecretString — `Debug` で `<redacted>` 化される簡易ラッパ

#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

// S3ArchiveBackendConfigError — env load 失敗の分類

#[derive(Debug)]
pub enum S3ArchiveBackendConfigError {
    MissingVar { name: &'static str },
    InvalidValue { name: &'static str, reason: String },
}

impl fmt::Display for S3ArchiveBackendConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVar { name } => {
                write!(formatter, "missing required env var: {name}")
            }
            Self::InvalidValue { name, reason } => {
                write!(formatter, "invalid env var {name}: {reason}")
            }
        }
    }
}

impl std::error::Error for S3ArchiveBackendConfigError {}

// S3ArchiveBackendConfig

#[derive(Clone)]
pub struct S3ArchiveBackendConfig {
    endpoint_url: String,
    region: String,
    bucket: String,
    access_key_id: String,
    secret_access_key: SecretString,
    session_token: Option<SecretString>,
    object_lock_mode: S3ObjectLockMode,
    retention_days: u32,
    path_style: bool,
    forbid_overwrite: bool,
    max_retries: u32,
    retry_base_millis: u64,
}

impl S3ArchiveBackendConfig {
    /// テスト・統合テスト用の直接コンストラクタ。env 読み出し本体は
    /// `from_env` を使用する。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint_url: String,
        region: String,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
        object_lock_mode: S3ObjectLockMode,
        retention_days: u32,
    ) -> Result<Self, S3BackendError> {
        let endpoint_url = endpoint_url.trim().to_owned();
        let region = region.trim().to_owned();
        let bucket = bucket.trim().to_owned();
        let access_key_id = access_key_id.trim().to_owned();
        let secret_access_key = secret_access_key.trim().to_owned();
        let session_token = session_token
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());

        if endpoint_url.is_empty() {
            return Err(S3BackendError::InvalidConfig("endpoint_url is empty"));
        }
        validate_endpoint_url(&endpoint_url).map_err(S3BackendError::InvalidConfig)?;
        if region.is_empty() {
            return Err(S3BackendError::InvalidConfig("region is empty"));
        }
        if bucket.is_empty() {
            return Err(S3BackendError::InvalidConfig("bucket is empty"));
        }
        validate_bucket_name(&bucket).map_err(S3BackendError::InvalidConfig)?;
        if access_key_id.is_empty() {
            return Err(S3BackendError::InvalidConfig("access_key_id is empty"));
        }
        if secret_access_key.is_empty() {
            return Err(S3BackendError::InvalidConfig("secret_access_key is empty"));
        }
        if retention_days == 0 {
            return Err(S3BackendError::InvalidConfig("retention_days must be > 0"));
        }
        Ok(Self {
            endpoint_url,
            region,
            bucket,
            access_key_id,
            secret_access_key: SecretString::new(secret_access_key),
            session_token: session_token.map(SecretString::new),
            object_lock_mode,
            retention_days,
            path_style: DEFAULT_PATH_STYLE,
            forbid_overwrite: DEFAULT_FORBID_OVERWRITE,
            max_retries: DEFAULT_MAX_RETRIES,
            retry_base_millis: DEFAULT_RETRY_BASE_MILLIS,
        })
    }

    pub fn with_path_style(mut self, path_style: bool) -> Self {
        self.path_style = path_style;
        self
    }

    pub fn with_forbid_overwrite(mut self, forbid_overwrite: bool) -> Self {
        self.forbid_overwrite = forbid_overwrite;
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_retry_base_millis(mut self, retry_base_millis: u64) -> Self {
        self.retry_base_millis = retry_base_millis;
        self
    }

    pub fn endpoint_url(&self) -> &str {
        &self.endpoint_url
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    pub fn secret_access_key(&self) -> &SecretString {
        &self.secret_access_key
    }

    pub fn session_token(&self) -> Option<&SecretString> {
        self.session_token.as_ref()
    }

    pub fn object_lock_mode(&self) -> S3ObjectLockMode {
        self.object_lock_mode
    }

    pub fn retention_days(&self) -> u32 {
        self.retention_days
    }

    pub fn path_style(&self) -> bool {
        self.path_style
    }

    pub fn forbid_overwrite(&self) -> bool {
        self.forbid_overwrite
    }

    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }

    pub fn retry_base_millis(&self) -> u64 {
        self.retry_base_millis
    }

    /// env から構成を読む。`get_var(name) -> Option<String>` を受けることで
    /// テスト時に `HashMap` 由来の値を注入できる。
    pub fn from_env<F>(get_var: F) -> Result<Self, S3ArchiveBackendConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let endpoint_url = required(&get_var, ENV_S3_ENDPOINT_URL)?;
        validate_endpoint_url(&endpoint_url).map_err(|reason| {
            S3ArchiveBackendConfigError::InvalidValue {
                name: ENV_S3_ENDPOINT_URL,
                reason: reason.to_owned(),
            }
        })?;
        let region = required(&get_var, ENV_S3_REGION)?;
        let bucket = required(&get_var, ENV_S3_BUCKET)?;
        validate_bucket_name(&bucket).map_err(|reason| {
            S3ArchiveBackendConfigError::InvalidValue {
                name: ENV_S3_BUCKET,
                reason: reason.to_owned(),
            }
        })?;
        let access_key_id = required(&get_var, ENV_S3_ACCESS_KEY_ID)?;
        let secret_access_key = required(&get_var, ENV_S3_SECRET_ACCESS_KEY)?;
        let session_token = optional(&get_var, ENV_S3_SESSION_TOKEN);

        let object_lock_mode_raw = required(&get_var, ENV_S3_OBJECT_LOCK_MODE)?;
        let object_lock_mode = S3ObjectLockMode::parse(&object_lock_mode_raw).map_err(|error| {
            S3ArchiveBackendConfigError::InvalidValue {
                name: ENV_S3_OBJECT_LOCK_MODE,
                reason: error.to_string(),
            }
        })?;

        let retention_days_raw = required(&get_var, ENV_S3_RETENTION_DAYS)?;
        let retention_days: u32 = retention_days_raw.trim().parse().map_err(|_| {
            S3ArchiveBackendConfigError::InvalidValue {
                name: ENV_S3_RETENTION_DAYS,
                reason: "must be a non-negative integer".to_owned(),
            }
        })?;
        if retention_days == 0 {
            return Err(S3ArchiveBackendConfigError::InvalidValue {
                name: ENV_S3_RETENTION_DAYS,
                reason: "must be greater than 0".to_owned(),
            });
        }

        let path_style =
            parse_bool_optional(&get_var, ENV_S3_PATH_STYLE)?.unwrap_or(DEFAULT_PATH_STYLE);
        let forbid_overwrite = parse_bool_optional(&get_var, ENV_S3_FORBID_OVERWRITE)?
            .unwrap_or(DEFAULT_FORBID_OVERWRITE);
        let max_retries =
            parse_u32_optional(&get_var, ENV_S3_MAX_RETRIES)?.unwrap_or(DEFAULT_MAX_RETRIES);
        let retry_base_millis = parse_u64_optional(&get_var, ENV_S3_RETRY_BASE_MILLIS)?
            .unwrap_or(DEFAULT_RETRY_BASE_MILLIS);

        Ok(Self {
            endpoint_url,
            region,
            bucket,
            access_key_id,
            secret_access_key: SecretString::new(secret_access_key),
            session_token: session_token.map(SecretString::new),
            object_lock_mode,
            retention_days,
            path_style,
            forbid_overwrite,
            max_retries,
            retry_base_millis,
        })
    }
}

impl fmt::Debug for S3ArchiveBackendConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3ArchiveBackendConfig")
            .field("endpoint_url", &self.endpoint_url)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .field("object_lock_mode", &self.object_lock_mode)
            .field("retention_days", &self.retention_days)
            .field("path_style", &self.path_style)
            .field("forbid_overwrite", &self.forbid_overwrite)
            .field("max_retries", &self.max_retries)
            .field("retry_base_millis", &self.retry_base_millis)
            .finish()
    }
}

// helpers

fn required<F>(get_var: &F, name: &'static str) -> Result<String, S3ArchiveBackendConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let value = get_var(name).ok_or(S3ArchiveBackendConfigError::MissingVar { name })?;
    if value.trim().is_empty() {
        return Err(S3ArchiveBackendConfigError::InvalidValue {
            name,
            reason: "value must not be empty".to_owned(),
        });
    }
    Ok(value.trim().to_owned())
}

fn optional<F>(get_var: &F, name: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    get_var(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse_bool_optional<F>(
    get_var: &F,
    name: &'static str,
) -> Result<Option<bool>, S3ArchiveBackendConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(raw) = optional(get_var, name) else {
        return Ok(None);
    };
    match raw.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(Some(true)),
        "false" | "0" | "no" => Ok(Some(false)),
        _ => Err(S3ArchiveBackendConfigError::InvalidValue {
            name,
            reason: "must be 'true' or 'false'".to_owned(),
        }),
    }
}

fn parse_u32_optional<F>(
    get_var: &F,
    name: &'static str,
) -> Result<Option<u32>, S3ArchiveBackendConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(raw) = optional(get_var, name) else {
        return Ok(None);
    };
    raw.parse::<u32>()
        .map(Some)
        .map_err(|_| S3ArchiveBackendConfigError::InvalidValue {
            name,
            reason: "must be a u32".to_owned(),
        })
}

fn parse_u64_optional<F>(
    get_var: &F,
    name: &'static str,
) -> Result<Option<u64>, S3ArchiveBackendConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let Some(raw) = optional(get_var, name) else {
        return Ok(None);
    };
    raw.parse::<u64>()
        .map(Some)
        .map_err(|_| S3ArchiveBackendConfigError::InvalidValue {
            name,
            reason: "must be a u64".to_owned(),
        })
}

fn validate_endpoint_url(endpoint_url: &str) -> Result<(), &'static str> {
    let (scheme, rest) = endpoint_url
        .split_once("://")
        .ok_or("endpoint_url must include scheme (http:// or https://)")?;
    if !matches!(scheme, "http" | "https") {
        return Err("endpoint_url scheme must be http or https");
    }
    if rest.contains('?') {
        return Err("endpoint_url must not include query");
    }
    if rest.contains('#') {
        return Err("endpoint_url must not include fragment");
    }

    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, Some(path)),
        None => (rest, None),
    };
    if authority.is_empty() {
        return Err("endpoint_url host is empty");
    }
    if authority.contains('@') {
        return Err("endpoint_url must not include userinfo");
    }
    if path.is_some_and(|path| !path.is_empty()) {
        return Err("endpoint_url path must be empty or /");
    }
    Ok(())
}

fn validate_bucket_name(bucket: &str) -> Result<(), &'static str> {
    if !(3..=63).contains(&bucket.len()) {
        return Err("bucket must be 3 to 63 characters");
    }
    if !bucket.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
    }) {
        return Err("bucket contains invalid characters");
    }
    if !bucket
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err("bucket must start with a lowercase letter or digit");
    }
    if !bucket
        .bytes()
        .last()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err("bucket must end with a lowercase letter or digit");
    }
    if bucket.contains("..") || bucket.contains(".-") || bucket.contains("-.") {
        return Err("bucket contains invalid dot or hyphen sequence");
    }
    if is_ipv4_address_like(bucket) {
        return Err("bucket must not be formatted as an IPv4 address");
    }
    Ok(())
}

fn is_ipv4_address_like(bucket: &str) -> bool {
    let mut parts = bucket.split('.');
    let mut count = 0usize;
    for part in &mut parts {
        count += 1;
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        if part.parse::<u8>().is_err() {
            return false;
        }
    }
    count == 4
}

#[cfg(test)]
#[path = "../../../tests/unit/archive/s3/config/tests.rs"]
mod tests;

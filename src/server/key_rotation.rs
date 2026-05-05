use std::fmt;
use std::sync::Arc;

use serde_json::json;

use crate::audit::{
    AuditAction, AuditEvent, AuditEventAppender, AuditEventId, AuditEventParts, AuditMetadata,
    AuditRecordError, AuditRecordOutcome, AuditRecorder, AuditResult, LocalAuditFallbackStore,
    RequestId,
};
use crate::crypto::{KeyWrapContext, unwrap_data_key, wrap_data_key};
use crate::server::config::AppConfig;
use crate::server::supabase::{
    KeyRotationApplyRow, KeyRotationBatchRow, SupabaseAuditAppender, SupabaseClient,
    SupabaseRpcError,
};
use crate::types::{EncryptedDataKey, KeyVersion, SecretId, SecretVersion};

#[derive(Debug)]
pub enum KeyRotationCliError {
    Usage(String),
    Config(String),
    Audit(String),
    Crypto(String),
    Supabase(SupabaseRpcError),
}

impl fmt::Display for KeyRotationCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::Config(message) => {
                write!(formatter, "key rotation configuration error: {message}")
            }
            Self::Audit(message) => write!(formatter, "key rotation audit error: {message}"),
            Self::Crypto(message) => write!(formatter, "key rotation crypto error: {message}"),
            Self::Supabase(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for KeyRotationCliError {}

impl From<SupabaseRpcError> for KeyRotationCliError {
    fn from(error: SupabaseRpcError) -> Self {
        Self::Supabase(error)
    }
}

pub async fn run_cli(config: AppConfig, args: &[String]) -> Result<(), KeyRotationCliError> {
    let Some((command, command_args)) = args.split_first() else {
        return Err(KeyRotationCliError::Usage(usage()));
    };

    let http_client = crate::server::config::build_outbound_http_client(&config)
        .map_err(|error| KeyRotationCliError::Config(error.to_string()))?;
    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url.clone(),
        config.supabase_service_role_key.clone(),
        config.supabase_publishable_key.clone(),
    ));

    match command.as_str() {
        "status" => status(supabase_client, command_args).await,
        "start" => {
            let audit_recorder = key_rotation_start_audit_recorder(supabase_client, &config);
            start(&audit_recorder, &config, command_args).await
        }
        "rewrap" => rewrap(supabase_client, &config, command_args).await,
        "complete" => complete(supabase_client, command_args).await,
        _ => Err(KeyRotationCliError::Usage(usage())),
    }
}

fn key_rotation_start_audit_recorder(
    supabase_client: Arc<SupabaseClient>,
    config: &AppConfig,
) -> AuditRecorder<SupabaseAuditAppender> {
    let audit_appender = SupabaseAuditAppender::new(supabase_client);
    let audit_fallback_store = LocalAuditFallbackStore::with_rollover_config(
        config.audit_fallback_path.clone(),
        config.audit_fallback_archive_dir.clone(),
        config.audit_fallback_rotate_size_bytes,
    );

    AuditRecorder::new(audit_appender, audit_fallback_store)
}

async fn status(
    supabase_client: Arc<SupabaseClient>,
    args: &[String],
) -> Result<(), KeyRotationCliError> {
    let key_version = parse_key_version_flag(args, "--key-version")?;
    let status = supabase_client
        .call_key_rotation_status(key_version)
        .await?;

    println!(
        "key_version={} remaining_count={}",
        status.key_version, status.remaining_count
    );
    Ok(())
}

async fn start<A>(
    audit_recorder: &AuditRecorder<A>,
    config: &AppConfig,
    args: &[String],
) -> Result<(), KeyRotationCliError>
where
    A: AuditEventAppender,
{
    let old_key_version = parse_key_version_flag(args, "--old-key-version")?;
    let new_key_version = parse_key_version_flag(args, "--new-key-version")?;
    ensure_keyring_contains(config, old_key_version)?;
    ensure_keyring_contains(config, new_key_version)?;

    let request_id =
        RequestId::generate().map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;
    let event = match build_key_rotation_start_event(&request_id, old_key_version, new_key_version)
    {
        Ok(event) => event,
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                old_key_version = old_key_version.get(),
                new_key_version = new_key_version.get(),
                action = AuditAction::KeyRotationStart.as_str(),
                result = AuditResult::Success.as_str(),
                audit_record_outcome = "event_construction_failed",
                "key_rotation_start audit event construction failed"
            );
            return Err(error);
        }
    };
    record_key_rotation_start_audit(
        audit_recorder,
        &event,
        &request_id,
        old_key_version,
        new_key_version,
    )
    .await?;

    println!(
        "key_rotation_start request_id={} old_key_version={} new_key_version={}",
        request_id.as_canonical_string(),
        old_key_version.get(),
        new_key_version.get()
    );
    Ok(())
}

async fn record_key_rotation_start_audit<A>(
    audit_recorder: &AuditRecorder<A>,
    event: &AuditEvent,
    request_id: &RequestId,
    old_key_version: KeyVersion,
    new_key_version: KeyVersion,
) -> Result<AuditRecordOutcome, KeyRotationCliError>
where
    A: AuditEventAppender,
{
    match audit_recorder.record(event).await {
        Ok(AuditRecordOutcome::PrimarySucceeded) => {
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                old_key_version = old_key_version.get(),
                new_key_version = new_key_version.get(),
                action = AuditAction::KeyRotationStart.as_str(),
                result = AuditResult::Success.as_str(),
                audit_record_outcome = "primary_succeeded",
                "key_rotation_start audit recorded"
            );
            Ok(AuditRecordOutcome::PrimarySucceeded)
        }
        Ok(AuditRecordOutcome::FallbackSucceeded) => {
            tracing::warn!(
                request_id = %request_id.as_canonical_string(),
                old_key_version = old_key_version.get(),
                new_key_version = new_key_version.get(),
                action = AuditAction::KeyRotationStart.as_str(),
                result = AuditResult::Success.as_str(),
                audit_record_outcome = "fallback_succeeded",
                "key_rotation_start audit recorded to local fallback"
            );
            Ok(AuditRecordOutcome::FallbackSucceeded)
        }
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                old_key_version = old_key_version.get(),
                new_key_version = new_key_version.get(),
                action = AuditAction::KeyRotationStart.as_str(),
                result = AuditResult::Success.as_str(),
                audit_record_outcome = audit_record_error_label(&error),
                "key_rotation_start audit recording failed"
            );
            Err(KeyRotationCliError::Audit(error.to_string()))
        }
    }
}

fn audit_record_error_label(error: &AuditRecordError) -> &'static str {
    match error {
        AuditRecordError::EventConstructionFailed(_) => "event_construction_failed",
        AuditRecordError::PrimaryAndFallbackFailed { .. } => "both_failed",
        AuditRecordError::IdempotencyConflict => "idempotency_conflict",
        AuditRecordError::ResendReadFailed(_) | AuditRecordError::ResendMarkSentFailed(_) => {
            "unexpected_resend_error"
        }
    }
}

async fn rewrap(
    supabase_client: Arc<SupabaseClient>,
    config: &AppConfig,
    args: &[String],
) -> Result<(), KeyRotationCliError> {
    let old_key_version = parse_key_version_flag(args, "--old-key-version")?;
    let new_key_version = parse_key_version_flag(args, "--new-key-version")?;
    let batch_limit = parse_positive_u32_flag(args, "--batch-limit")?;
    let old_master_key = config
        .master_key_ring
        .get(old_key_version)
        .map_err(|error| KeyRotationCliError::Config(error.to_string()))?;
    let new_master_key = config
        .master_key_ring
        .get(new_key_version)
        .map_err(|error| KeyRotationCliError::Config(error.to_string()))?;
    let batch_rows = supabase_client
        .call_list_key_rotation_batch(old_key_version, batch_limit)
        .await?;

    if batch_rows.is_empty() {
        println!(
            "key_rotation_rewrap processed_count=0 remaining_count=0 old_key_version={} new_key_version={}",
            old_key_version.get(),
            new_key_version.get()
        );
        return Ok(());
    }

    let mut apply_rows = Vec::with_capacity(batch_rows.len());
    for row in batch_rows {
        let parsed = parse_rotation_batch_row(row, old_key_version)?;
        let old_context = KeyWrapContext::new(parsed.secret_id.clone(), old_key_version);
        let data_key = unwrap_data_key(old_master_key, &old_context, &parsed.encrypted_data_key)
            .map_err(|error| KeyRotationCliError::Crypto(error.to_string()))?;
        let new_context = KeyWrapContext::new(parsed.secret_id, new_key_version);
        let rewrapped = wrap_data_key(new_master_key, &new_context, &data_key)
            .map_err(|error| KeyRotationCliError::Crypto(error.to_string()))?;

        apply_rows.push(KeyRotationApplyRow {
            id: parsed.id,
            encrypted_data_key: encode_bytea(rewrapped.as_bytes()),
        });
    }

    let request_id =
        RequestId::generate().map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;
    let outcome = supabase_client
        .call_apply_key_rotation_batch(&request_id, old_key_version, new_key_version, apply_rows)
        .await?;

    println!(
        "key_rotation_rewrap request_id={} processed_count={} remaining_count={} old_key_version={} new_key_version={}",
        request_id.as_canonical_string(),
        outcome.processed_count,
        outcome.remaining_count,
        old_key_version.get(),
        new_key_version.get()
    );
    Ok(())
}

async fn complete(
    supabase_client: Arc<SupabaseClient>,
    args: &[String],
) -> Result<(), KeyRotationCliError> {
    let old_key_version = parse_key_version_flag(args, "--old-key-version")?;
    let new_key_version = parse_key_version_flag(args, "--new-key-version")?;
    let request_id =
        RequestId::generate().map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;
    let outcome = supabase_client
        .call_complete_key_rotation(&request_id, old_key_version, new_key_version)
        .await?;

    println!(
        "key_rotation_complete request_id={} remaining_count={} old_key_version={} new_key_version={}",
        request_id.as_canonical_string(),
        outcome.remaining_count,
        old_key_version.get(),
        new_key_version.get()
    );
    Ok(())
}

fn build_key_rotation_start_event(
    request_id: &RequestId,
    old_key_version: KeyVersion,
    new_key_version: KeyVersion,
) -> Result<AuditEvent, KeyRotationCliError> {
    let metadata = AuditMetadata::new(json!({
        "old_key_version": old_key_version.get(),
        "new_key_version": new_key_version.get(),
    }))
    .and_then(AuditMetadata::with_current_source_event_at)
    .map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;
    let audit_event_id =
        AuditEventId::generate().map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;

    AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::KeyRotationStart,
        target_secret_id: None,
        result: AuditResult::Success,
        key_version: Some(new_key_version),
        metadata_json: metadata,
    })
    .map_err(|error| KeyRotationCliError::Audit(error.to_string()))
}

fn ensure_keyring_contains(
    config: &AppConfig,
    key_version: KeyVersion,
) -> Result<(), KeyRotationCliError> {
    config
        .master_key_ring
        .get(key_version)
        .map(|_| ())
        .map_err(|error| KeyRotationCliError::Config(error.to_string()))
}

struct ParsedRotationBatchRow {
    id: String,
    secret_id: SecretId,
    encrypted_data_key: EncryptedDataKey,
}

fn parse_rotation_batch_row(
    row: KeyRotationBatchRow,
    expected_key_version: KeyVersion,
) -> Result<ParsedRotationBatchRow, KeyRotationCliError> {
    let key_version = u32::try_from(row.key_version)
        .ok()
        .and_then(|value| KeyVersion::new(value).ok())
        .ok_or_else(|| {
            KeyRotationCliError::Config("rotation row key_version is invalid".to_owned())
        })?;
    if key_version != expected_key_version {
        return Err(KeyRotationCliError::Config(
            "rotation row key_version does not match requested old key version".to_owned(),
        ));
    }

    let _version = u32::try_from(row.version)
        .ok()
        .and_then(|value| SecretVersion::new(value).ok())
        .ok_or_else(|| KeyRotationCliError::Config("rotation row version is invalid".to_owned()))?;
    let secret_id = SecretId::parse(&row.secret_id)
        .map_err(|_| KeyRotationCliError::Config("rotation row secret_id is invalid".to_owned()))?;
    let encrypted_data_key_bytes = decode_bytea(&row.encrypted_data_key)?;
    let encrypted_data_key = EncryptedDataKey::parse(&encrypted_data_key_bytes).map_err(|_| {
        KeyRotationCliError::Config("rotation row encrypted_data_key is invalid".to_owned())
    })?;

    Ok(ParsedRotationBatchRow {
        id: row.id,
        secret_id,
        encrypted_data_key,
    })
}

fn parse_key_version_flag(
    args: &[String],
    flag: &'static str,
) -> Result<KeyVersion, KeyRotationCliError> {
    let value = parse_required_flag(args, flag)?;
    let parsed = value
        .parse::<u32>()
        .map_err(|_| KeyRotationCliError::Usage(format!("{flag} must be a positive integer")))?;

    KeyVersion::new(parsed)
        .map_err(|_| KeyRotationCliError::Usage(format!("{flag} must be a positive integer")))
}

fn parse_positive_u32_flag(
    args: &[String],
    flag: &'static str,
) -> Result<u32, KeyRotationCliError> {
    let value = parse_required_flag(args, flag)?;
    let parsed = value
        .parse::<u32>()
        .map_err(|_| KeyRotationCliError::Usage(format!("{flag} must be a positive integer")))?;

    if parsed == 0 {
        return Err(KeyRotationCliError::Usage(format!(
            "{flag} must be a positive integer"
        )));
    }

    Ok(parsed)
}

fn parse_required_flag<'a>(
    args: &'a [String],
    flag: &'static str,
) -> Result<&'a str, KeyRotationCliError> {
    let mut index = 0;
    let mut found = None;

    while index < args.len() {
        let current = args[index].as_str();
        if !current.starts_with("--") {
            return Err(KeyRotationCliError::Usage(usage()));
        }

        let value = args
            .get(index + 1)
            .ok_or_else(|| KeyRotationCliError::Usage(format!("{current} requires a value")))?;
        if value.starts_with("--") {
            return Err(KeyRotationCliError::Usage(format!(
                "{current} requires a value"
            )));
        }

        if current == flag {
            if found.is_some() {
                return Err(KeyRotationCliError::Usage(format!(
                    "{flag} must be provided once"
                )));
            }
            found = Some(value.as_str());
        }

        index += 2;
    }

    found.ok_or_else(|| KeyRotationCliError::Usage(format!("missing required flag {flag}")))
}

fn decode_bytea(value: &str) -> Result<Vec<u8>, KeyRotationCliError> {
    let hex_value = value.strip_prefix("\\x").ok_or_else(|| {
        KeyRotationCliError::Config("rotation row bytea is not hex encoded".to_owned())
    })?;

    hex::decode(hex_value)
        .map_err(|_| KeyRotationCliError::Config("rotation row bytea is invalid".to_owned()))
}

fn encode_bytea(bytes: &[u8]) -> String {
    format!("\\x{}", hex::encode(bytes))
}

pub fn usage() -> String {
    [
        "usage:",
        "  mipsorcu",
        "  mipsorcu key-rotation status --key-version <n>",
        "  mipsorcu key-rotation start --old-key-version <old> --new-key-version <new>",
        "  mipsorcu key-rotation rewrap --old-key-version <old> --new-key-version <new> --batch-limit <n>",
        "  mipsorcu key-rotation complete --old-key-version <old> --new-key-version <new>",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::future::{Future, ready};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use serde_json::Value;

    use super::*;
    use crate::audit::AuditAppendError;
    use crate::crypto::MasterKeyRing;
    use crate::types::{MASTER_KEY_LENGTH, MasterKey, SourceEventAt};

    #[derive(Debug, Clone)]
    struct FakeAppender {
        result: Result<(), AuditAppendError>,
        appended_actions: Arc<Mutex<Vec<String>>>,
    }

    impl FakeAppender {
        fn new(result: Result<(), AuditAppendError>) -> Self {
            Self {
                result,
                appended_actions: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn appended_actions(&self) -> Vec<String> {
            self.appended_actions
                .lock()
                .map(|actions| actions.clone())
                .unwrap_or_default()
        }

        fn append_audit_event_sync(&self, event: &AuditEvent) -> Result<(), AuditAppendError> {
            self.appended_actions
                .lock()
                .map_err(|_| AuditAppendError::ExternalDependencyFailed {
                    code: "test_lock_poisoned",
                })?
                .push(event.action().as_str().to_owned());

            self.result.clone()
        }
    }

    impl AuditEventAppender for FakeAppender {
        fn append_audit_event<'a>(
            &'a self,
            event: &'a AuditEvent,
        ) -> impl Future<Output = Result<(), AuditAppendError>> + Send + 'a {
            ready(self.append_audit_event_sync(event))
        }
    }

    fn temp_path(test_name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);

        std::env::temp_dir().join(format!("mipsorcu-key-rotation-{test_name}-{unique}"))
    }

    fn start_args() -> Vec<String> {
        ["--old-key-version", "1", "--new-key-version", "2"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    fn test_config(audit_fallback_path: PathBuf) -> AppConfig {
        let old_key_version = KeyVersion::new(1).expect("old key version should be valid");
        let new_key_version = KeyVersion::new(2).expect("new key version should be valid");
        let master_key_ring = MasterKeyRing::from_key_entries(
            new_key_version,
            [
                (
                    old_key_version,
                    MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH]),
                ),
                (
                    new_key_version,
                    MasterKey::from_bytes([12u8; MASTER_KEY_LENGTH]),
                ),
            ],
        )
        .expect("master keyring should be valid");

        AppConfig {
            listen_addr: "127.0.0.1:3000"
                .parse()
                .expect("listen address should parse"),
            master_key_ring,
            supabase_url: "http://127.0.0.1:1".to_owned(),
            supabase_service_role_key: "service-role-key".to_owned(),
            supabase_publishable_key: "publishable-key".to_owned(),
            jwt_issuer: "issuer".to_owned(),
            jwt_audience: "audience".to_owned(),
            jwks_url: "http://127.0.0.1:1/jwks".to_owned(),
            jwks_refresh_interval: Duration::from_secs(300),
            health_readiness_poll_interval: Duration::from_secs(30),
            outbound_http_connect_timeout: Duration::from_secs(5),
            outbound_http_request_timeout: Duration::from_secs(20),
            http_handler_timeout: Duration::from_secs(75),
            http_rate_limit_requests: 300,
            http_rate_limit_window: Duration::from_secs(60),
            audit_fallback_path,
            audit_resend_interval: Duration::from_secs(60),
            audit_fallback_alert_threshold_bytes: 4096,
            audit_fallback_rotate_size_bytes: 8192,
            audit_fallback_archive_dir: temp_path("archive"),
            audit_fallback_archive_auto_delete_enabled: false,
            audit_fallback_archive_retention: Duration::from_secs(90 * 24 * 60 * 60),
            restore_test_interval: Duration::from_secs(24 * 60 * 60),
            restore_test_startup_delay: Duration::from_secs(300),
            restore_test_sample_limit: 3,
            integrity_check_interval: Duration::from_secs(24 * 60 * 60),
            integrity_check_startup_delay: Duration::from_secs(3900),
        }
    }

    fn read_single_json_line(path: &Path) -> Value {
        let contents = fs::read_to_string(path).expect("fallback JSON Lines file should exist");
        let mut lines = contents.lines();
        let line = lines.next().expect("fallback should contain one line");
        assert!(
            lines.next().is_none(),
            "fallback should contain exactly one line"
        );

        serde_json::from_str(line).expect("fallback line should be valid JSON")
    }

    #[tokio::test]
    async fn key_rotation_start_succeeds_when_primary_audit_append_succeeds() {
        let fallback_path = temp_path("primary-success.jsonl");
        let config = test_config(fallback_path.clone());
        let appender = FakeAppender::new(Ok(()));
        let recorder = AuditRecorder::new(
            appender.clone(),
            LocalAuditFallbackStore::new(fallback_path.clone()),
        );

        start(&recorder, &config, &start_args())
            .await
            .expect("key_rotation_start should succeed");

        assert_eq!(
            appender.appended_actions(),
            vec!["key_rotation_start".to_owned()]
        );
        assert!(!fallback_path.exists());
    }

    #[tokio::test]
    async fn key_rotation_start_succeeds_when_primary_fails_and_fallback_succeeds() {
        let fallback_path = temp_path("fallback-success.jsonl");
        let config = test_config(fallback_path.clone());
        let appender = FakeAppender::new(Err(AuditAppendError::ExternalDependencyFailed {
            code: "supabase_rpc_failed",
        }));
        let recorder = AuditRecorder::new(
            appender.clone(),
            LocalAuditFallbackStore::new(fallback_path.clone()),
        );

        start(&recorder, &config, &start_args())
            .await
            .expect("key_rotation_start should succeed via fallback");

        assert_eq!(
            appender.appended_actions(),
            vec!["key_rotation_start".to_owned()]
        );

        let record = read_single_json_line(&fallback_path);
        assert_eq!(record["action"], "key_rotation_start");
        assert_eq!(record["result"], "success");
        assert_eq!(record["key_version"], 2);
        assert_eq!(record["delivery_status"], "pending");
        assert_eq!(record["metadata_json"]["old_key_version"], 1);
        assert_eq!(record["metadata_json"]["new_key_version"], 2);
        let source_event_at = record["metadata_json"]["source_event_at"]
            .as_str()
            .expect("fallback metadata should include source_event_at");
        assert!(SourceEventAt::parse(source_event_at).is_ok());

        let fallback_contents =
            fs::read_to_string(&fallback_path).expect("fallback JSON Lines file should exist");
        let metadata_contents = record["metadata_json"].to_string();
        for forbidden in [
            "master_key",
            "data_key",
            "encrypted_data_key",
            "ciphertext",
            "jwt",
            "service_role_key",
            "secret_key",
            "plaintext",
        ] {
            assert!(!fallback_contents.contains(forbidden));
            assert!(!metadata_contents.contains(forbidden));
        }
    }

    #[tokio::test]
    async fn key_rotation_start_fails_when_primary_and_fallback_both_fail() {
        let fallback_path = temp_path("fallback-directory");
        fs::create_dir(&fallback_path).expect("fallback path directory should be created");
        let config = test_config(fallback_path.clone());
        let appender = FakeAppender::new(Err(AuditAppendError::ExternalDependencyFailed {
            code: "supabase_rpc_failed",
        }));
        let recorder = AuditRecorder::new(
            appender.clone(),
            LocalAuditFallbackStore::new(fallback_path.clone()),
        );

        let error = start(&recorder, &config, &start_args())
            .await
            .expect_err("key_rotation_start should fail when audit primary and fallback fail");

        assert!(matches!(error, KeyRotationCliError::Audit(_)));
        assert_eq!(
            appender.appended_actions(),
            vec!["key_rotation_start".to_owned()]
        );
        assert!(fallback_path.is_dir());

        fs::remove_dir_all(fallback_path).expect("fallback directory should be removed");
    }
}

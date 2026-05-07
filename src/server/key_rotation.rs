use std::fmt;
use std::sync::Arc;

use serde_json::json;

use crate::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditMetadata, AuditResult, RequestId,
};
use crate::crypto::{KeyWrapContext, unwrap_data_key, wrap_data_key};
use crate::server::config::AppConfig;
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts, LedgerAppender};
use crate::server::supabase::{
    KeyRotationApplyRow, KeyRotationBatchRow, SupabaseClient, SupabaseRpcError,
};
use crate::types::{EncryptedDataKey, KeyVersion, SecretId, SecretVersion};
use crate::{LedgerEntryId, LedgerEntryType, LedgerPayload, LedgerResult, SignedLedgerEntry};

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
    let ledger_appender = Arc::new(LedgerAppender::new(
        supabase_client.clone(),
        config.ledger_signing_key.clone(),
    ));

    match command.as_str() {
        "status" => status(supabase_client, command_args).await,
        "start" => start_with_ledger(supabase_client, ledger_appender, &config, command_args).await,
        "rewrap" => rewrap(supabase_client, ledger_appender, &config, command_args).await,
        "complete" => complete(supabase_client, ledger_appender, command_args).await,
        _ => Err(KeyRotationCliError::Usage(usage())),
    }
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

async fn start_with_ledger(
    supabase_client: Arc<SupabaseClient>,
    ledger_appender: Arc<LedgerAppender>,
    config: &AppConfig,
    args: &[String],
) -> Result<(), KeyRotationCliError> {
    let old_key_version = parse_key_version_flag(args, "--old-key-version")?;
    let new_key_version = parse_key_version_flag(args, "--new-key-version")?;
    ensure_keyring_contains(config, old_key_version)?;
    ensure_keyring_contains(config, new_key_version)?;

    let request_id =
        RequestId::generate().map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;
    let event = build_key_rotation_start_event(&request_id, old_key_version, new_key_version)?;
    let ledger_draft = build_key_rotation_ledger_draft(
        &event,
        LedgerEntryType::KeyRotationStarted,
        json!({
            "old_key_version": old_key_version.get(),
            "new_key_version": new_key_version.get(),
        }),
    )?;
    let signed_entry = sign_single_ledger_entry(&ledger_appender, &ledger_draft).await?;

    supabase_client
        .call_append_audit_event_with_ledger(&event, &signed_entry)
        .await
        .map_err(KeyRotationCliError::Supabase)?;

    println!(
        "key_rotation_start request_id={} old_key_version={} new_key_version={}",
        request_id.as_canonical_string(),
        old_key_version.get(),
        new_key_version.get()
    );
    Ok(())
}

async fn rewrap(
    supabase_client: Arc<SupabaseClient>,
    ledger_appender: Arc<LedgerAppender>,
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

    let status_before_apply = supabase_client
        .call_key_rotation_status(old_key_version)
        .await?;
    let batch_size = u64::try_from(apply_rows.len())
        .map_err(|_| KeyRotationCliError::Config("rotation batch size is invalid".to_owned()))?;
    let old_remaining = u64::try_from(status_before_apply.remaining_count).map_err(|_| {
        KeyRotationCliError::Config("rotation remaining_count is invalid".to_owned())
    })?;
    let remaining_count = old_remaining.checked_sub(batch_size).ok_or_else(|| {
        KeyRotationCliError::Config("rotation remaining_count is inconsistent".to_owned())
    })?;
    let request_id =
        RequestId::generate().map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;
    let event = build_key_rotation_reencrypt_event(
        &request_id,
        old_key_version,
        new_key_version,
        batch_size,
        batch_size,
        remaining_count,
    )?;
    let ledger_draft = build_key_rotation_ledger_draft(
        &event,
        LedgerEntryType::KeyRotationReencrypted,
        json!({
            "old_key_version": old_key_version.get(),
            "new_key_version": new_key_version.get(),
            "batch_size": batch_size,
            "processed_count": batch_size,
            "remaining_count": remaining_count,
        }),
    )?;
    let signed_entry = sign_single_ledger_entry(&ledger_appender, &ledger_draft).await?;
    let outcome = supabase_client
        .call_apply_key_rotation_batch(
            &event,
            &signed_entry,
            old_key_version,
            new_key_version,
            apply_rows,
        )
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
    ledger_appender: Arc<LedgerAppender>,
    args: &[String],
) -> Result<(), KeyRotationCliError> {
    let old_key_version = parse_key_version_flag(args, "--old-key-version")?;
    let new_key_version = parse_key_version_flag(args, "--new-key-version")?;
    let request_id =
        RequestId::generate().map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;
    let event =
        build_key_rotation_complete_event(&request_id, old_key_version, new_key_version, 0)?;
    let ledger_draft = build_key_rotation_ledger_draft(
        &event,
        LedgerEntryType::KeyRotationCompleted,
        json!({
            "old_key_version": old_key_version.get(),
            "new_key_version": new_key_version.get(),
            "remaining_count": 0,
        }),
    )?;
    let signed_entry = sign_single_ledger_entry(&ledger_appender, &ledger_draft).await?;
    let outcome = supabase_client
        .call_complete_key_rotation(&event, &signed_entry, old_key_version, new_key_version)
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

fn build_key_rotation_reencrypt_event(
    request_id: &RequestId,
    old_key_version: KeyVersion,
    new_key_version: KeyVersion,
    batch_size: u64,
    processed_count: u64,
    remaining_count: u64,
) -> Result<AuditEvent, KeyRotationCliError> {
    let metadata = AuditMetadata::new(json!({
        "old_key_version": old_key_version.get(),
        "new_key_version": new_key_version.get(),
        "batch_size": batch_size,
        "processed_count": processed_count,
        "remaining_count": remaining_count,
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
        action: AuditAction::KeyRotationReencrypt,
        target_secret_id: None,
        result: AuditResult::Success,
        key_version: Some(new_key_version),
        metadata_json: metadata,
    })
    .map_err(|error| KeyRotationCliError::Audit(error.to_string()))
}

fn build_key_rotation_complete_event(
    request_id: &RequestId,
    old_key_version: KeyVersion,
    new_key_version: KeyVersion,
    remaining_count: u64,
) -> Result<AuditEvent, KeyRotationCliError> {
    let metadata = AuditMetadata::new(json!({
        "old_key_version": old_key_version.get(),
        "new_key_version": new_key_version.get(),
        "remaining_count": remaining_count,
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
        action: AuditAction::KeyRotationComplete,
        target_secret_id: None,
        result: AuditResult::Success,
        key_version: Some(new_key_version),
        metadata_json: metadata,
    })
    .map_err(|error| KeyRotationCliError::Audit(error.to_string()))
}

fn build_key_rotation_ledger_draft(
    event: &AuditEvent,
    entry_type: LedgerEntryType,
    payload_value: serde_json::Value,
) -> Result<LedgerAppendDraft, KeyRotationCliError> {
    let payload = LedgerPayload::new(entry_type, payload_value)
        .map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;
    let source_event_at = event
        .source_event_at()
        .map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;

    LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::generate()
            .map_err(|error| KeyRotationCliError::Audit(error.to_string()))?,
        entry_type,
        source_event_at,
        request_id: event.request_id().clone(),
        source_event_id: Some(event.audit_event_id().clone()),
        target_secret_id: None,
        target_secret_version_id: None,
        actor_user_id: None,
        actor_device_id: None,
        result: LedgerResult::Success,
        error_code: None,
        payload,
    })
    .map_err(|error| KeyRotationCliError::Audit(error.to_string()))
}

async fn sign_single_ledger_entry(
    ledger_appender: &LedgerAppender,
    ledger_draft: &LedgerAppendDraft,
) -> Result<SignedLedgerEntry, KeyRotationCliError> {
    let signed_entries = ledger_appender
        .sign_entries(std::slice::from_ref(ledger_draft))
        .await
        .map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;

    signed_entries.into_iter().next().ok_or_else(|| {
        KeyRotationCliError::Audit("ledger entry signing returned no entry".to_owned())
    })
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

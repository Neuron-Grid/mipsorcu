use std::sync::Arc;

use serde_json::json;

use crate::LedgerEntryType;
use crate::audit::RequestId;
use crate::crypto::{KeyWrapContext, unwrap_data_key, wrap_data_key};
use crate::server::config::AppConfig;
use crate::server::ledger_appender::LedgerAppender;
use crate::server::supabase::{KeyRotationApplyRow, SupabaseClient};
use crate::types::KeyVersion;

use super::KeyRotationCliError;
use super::audit_event::{
    build_key_rotation_complete_event, build_key_rotation_reencrypt_event,
    build_key_rotation_start_event,
};
use super::bytea::encode_bytea;
use super::flags::{parse_key_version_flag, parse_positive_u32_flag};
use super::ledger::{build_key_rotation_ledger_draft, sign_single_ledger_entry};
use super::rotation_row::parse_rotation_batch_row;

pub(super) async fn status(
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

pub(super) async fn start_with_ledger(
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

pub(super) async fn rewrap(
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

pub(super) async fn complete(
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

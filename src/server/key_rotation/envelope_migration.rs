use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;

use crate::aad::AadV1;
use crate::audit::RequestId;
use crate::crypto::{ALGORITHM_XCHACHA20_POLY1305, SecretVersionRecord, open_legacy_v01, seal_v02};
use crate::server::config::AppConfig;
use crate::server::ledger_appender::LedgerAppender;
use crate::server::supabase::SupabaseClient;
use crate::types::supabase::{
    EnvelopeMigrationApplyOutcome, EnvelopeMigrationApplyRow, EnvelopeMigrationBatchRow,
    EnvelopeMigrationFailureRow, EnvelopeMigrationStatus,
};
use crate::types::{
    Ciphertext, Classification, CreatedAt, EncryptedDataKey, KekAlgorithm, KeyVersion, Nonce,
    OwnerUserId, SecretId, SecretVersion, SecretVersionId,
};
use crate::{LedgerEntryType, MasterKeyRing, SecretDecryptError};

use super::KeyRotationCliError;
use super::audit_event::build_key_rotation_envelope_migrated_event;
use super::bytea::{decode_bytea, encode_bytea};
use super::ledger::{build_key_rotation_ledger_draft, sign_single_ledger_entry};

const DEFAULT_BATCH_SIZE: u32 = 100;
const DEFAULT_MAX_BATCHES: u32 = 10;
const MAX_BATCH_SIZE: u32 = 1_000;
const MAX_NONCE_REUSE_RETRIES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone)]
struct EnvelopeMigrationOptions {
    batch_size: u32,
    max_batches: u32,
    dry_run: bool,
    secret_id: Option<SecretId>,
    format: OutputFormat,
}

struct ParsedEnvelopeMigrationRow {
    id: SecretVersionId,
    secret_id: SecretId,
    version: SecretVersion,
    key_version: KeyVersion,
    aad: AadV1,
    record: SecretVersionRecord,
}

struct RowFailure {
    id: SecretVersionId,
    secret_id: SecretId,
    version: SecretVersion,
    key_version: KeyVersion,
    error_code: &'static str,
}

struct RunTotals {
    dry_run: bool,
    selected_count: u64,
    success_count: u64,
    failure_count: u64,
    remaining_legacy_rows: i64,
    last_request_id: Option<String>,
}

pub(super) async fn run(
    supabase_client: Arc<SupabaseClient>,
    ledger_appender: Arc<LedgerAppender>,
    config: &AppConfig,
    args: &[String],
) -> Result<(), KeyRotationCliError> {
    let options = parse_options(args)?;

    if options.dry_run {
        let status = supabase_client
            .call_envelope_migration_status(options.secret_id.as_ref())
            .await?;
        let batch_rows = supabase_client
            .call_list_envelope_migration_batch(options.batch_size, options.secret_id.as_ref())
            .await?;
        let totals = RunTotals {
            dry_run: true,
            selected_count: u64::try_from(batch_rows.len()).map_err(|_| {
                KeyRotationCliError::Config("envelope migration batch size is invalid".to_owned())
            })?,
            success_count: 0,
            failure_count: 0,
            remaining_legacy_rows: status.total_legacy_rows,
            last_request_id: None,
        };
        print_totals(&totals, &status, options.format)?;
        return Ok(());
    }

    let mut totals = RunTotals {
        dry_run: false,
        selected_count: 0,
        success_count: 0,
        failure_count: 0,
        remaining_legacy_rows: 0,
        last_request_id: None,
    };

    for _ in 0..options.max_batches {
        let batch_rows = supabase_client
            .call_list_envelope_migration_batch(options.batch_size, options.secret_id.as_ref())
            .await?;
        if batch_rows.is_empty() {
            break;
        }

        totals.selected_count += u64::try_from(batch_rows.len()).map_err(|_| {
            KeyRotationCliError::Config("envelope migration batch size is invalid".to_owned())
        })?;
        let retry_sources: HashMap<String, EnvelopeMigrationBatchRow> = batch_rows
            .iter()
            .cloned()
            .map(|row| (row.id.clone(), row))
            .collect();
        let prepared = prepare_batch(config, batch_rows)?;
        let outcome =
            apply_prepared_batch(&supabase_client, &ledger_appender, &prepared, &mut totals)
                .await?;

        retry_nonce_reuse_rows(
            &supabase_client,
            &ledger_appender,
            config,
            &retry_sources,
            outcome.retry_secret_version_ids.clone(),
            &mut totals,
        )
        .await?;
        if outcome.success_count == 0 && outcome.failure_count == 0 {
            break;
        }
    }

    let status = supabase_client
        .call_envelope_migration_status(options.secret_id.as_ref())
        .await?;
    totals.remaining_legacy_rows = status.total_legacy_rows;
    print_totals(&totals, &status, options.format)
}

struct PreparedBatch {
    success_rows: Vec<EnvelopeMigrationApplyRow>,
    failure_rows: Vec<EnvelopeMigrationFailureRow>,
}

fn prepare_batch(
    config: &AppConfig,
    rows: Vec<EnvelopeMigrationBatchRow>,
) -> Result<PreparedBatch, KeyRotationCliError> {
    let mut success_rows = Vec::with_capacity(rows.len());
    let mut failure_rows = Vec::new();

    for row in rows {
        match prepare_row(&config.master_key_ring, row) {
            Ok(success_row) => success_rows.push(success_row),
            Err(RowPreparationError::Failure(failure)) => {
                failure_rows.push(failure.into_rpc_row());
            }
            Err(RowPreparationError::Fatal(error)) => return Err(error),
        }
    }

    Ok(PreparedBatch {
        success_rows,
        failure_rows,
    })
}

enum RowPreparationError {
    Failure(RowFailure),
    Fatal(KeyRotationCliError),
}

fn prepare_row(
    master_key_ring: &MasterKeyRing,
    row: EnvelopeMigrationBatchRow,
) -> Result<EnvelopeMigrationApplyRow, RowPreparationError> {
    let identity = parse_row_identity(&row).map_err(RowPreparationError::Fatal)?;
    let parsed = parse_row(row, identity).map_err(RowPreparationError::Failure)?;
    let sealed = {
        let plaintext = open_legacy_v01(master_key_ring, &parsed.record, &parsed.aad)
            .map_err(|error| parsed.failure(map_decrypt_error(error)))?;
        seal_v02(
            master_key_ring.as_envvar_kek(),
            plaintext.as_bytes(),
            &parsed.aad,
        )
        .map_err(|_| parsed.failure("seal_v02_failed"))?
    };
    let (ciphertext, nonce, wrapped_dek, dek_wrap_algorithm, kek_version, _) = sealed.into_parts();

    Ok(EnvelopeMigrationApplyRow {
        id: parsed.id.as_canonical_string(),
        secret_id: parsed.secret_id.as_canonical_string(),
        version: parsed.version.get(),
        key_version: parsed.key_version.get(),
        ciphertext: encode_bytea(ciphertext.as_bytes()),
        nonce_or_iv: encode_bytea(nonce.as_bytes()),
        wrapped_dek: encode_bytea(wrapped_dek.as_bytes()),
        dek_wrap_algorithm: dek_wrap_algorithm.as_str().to_owned(),
        kek_version: kek_version.get(),
    })
}

fn parse_row_identity(
    row: &EnvelopeMigrationBatchRow,
) -> Result<(SecretVersionId, SecretId, SecretVersion, KeyVersion), KeyRotationCliError> {
    let id = SecretVersionId::parse(&row.id)
        .map_err(|_| KeyRotationCliError::Config("migration row id is invalid".to_owned()))?;
    let secret_id = SecretId::parse(&row.secret_id).map_err(|_| {
        KeyRotationCliError::Config("migration row secret_id is invalid".to_owned())
    })?;
    let version = parse_secret_version(row.version, "migration row version is invalid")?;
    let key_version = parse_key_version(row.key_version, "migration row key_version is invalid")?;

    Ok((id, secret_id, version, key_version))
}

fn parse_row(
    row: EnvelopeMigrationBatchRow,
    identity: (SecretVersionId, SecretId, SecretVersion, KeyVersion),
) -> Result<ParsedEnvelopeMigrationRow, RowFailure> {
    let (id, secret_id, version, key_version) = identity;
    let row_failure = |error_code| RowFailure {
        id: id.clone(),
        secret_id: secret_id.clone(),
        version,
        key_version,
        error_code,
    };

    if row.algorithm != ALGORITHM_XCHACHA20_POLY1305 {
        return Err(row_failure("algorithm_invalid"));
    }

    let owner_user_id =
        OwnerUserId::parse(&row.owner_user_id).map_err(|_| row_failure("owner_user_id_invalid"))?;
    let classification = Classification::new(&row.classification)
        .map_err(|_| row_failure("classification_invalid"))?;
    let created_at =
        CreatedAt::parse(&row.created_at).map_err(|_| row_failure("created_at_invalid"))?;
    let stored_aad = AadV1::from_stored_context(&row.aad_context)
        .map_err(|_| row_failure("aad_context_invalid"))?;
    let row_aad = AadV1::from_row_metadata(
        secret_id.clone(),
        version,
        owner_user_id,
        classification,
        created_at,
    );
    let stored_bytes = stored_aad
        .canonical_bytes()
        .map_err(|_| row_failure("aad_context_invalid"))?;
    let row_bytes = row_aad
        .canonical_bytes()
        .map_err(|_| row_failure("aad_context_mismatch"))?;
    if stored_bytes != row_bytes {
        return Err(row_failure("aad_context_mismatch"));
    }

    let encrypted_data_key = EncryptedDataKey::parse(
        &decode_bytea(&row.encrypted_data_key)
            .map_err(|_| row_failure("encrypted_data_key_invalid"))?,
    )
    .map_err(|_| row_failure("encrypted_data_key_invalid"))?;
    let ciphertext = Ciphertext::new(
        decode_bytea(&row.ciphertext).map_err(|_| row_failure("ciphertext_invalid"))?,
    )
    .map_err(|_| row_failure("ciphertext_invalid"))?;
    let nonce =
        Nonce::parse(&decode_bytea(&row.nonce_or_iv).map_err(|_| row_failure("nonce_invalid"))?)
            .map_err(|_| row_failure("nonce_invalid"))?;
    let record = SecretVersionRecord {
        secret_id: secret_id.clone(),
        key_version,
        ciphertext,
        nonce,
        encrypted_data_key: Some(encrypted_data_key),
        wrapped_dek: None,
        dek_wrap_algorithm: Some(KekAlgorithm::LegacyMasterKeyV1),
    };

    Ok(ParsedEnvelopeMigrationRow {
        id,
        secret_id,
        version,
        key_version,
        aad: row_aad,
        record,
    })
}

impl ParsedEnvelopeMigrationRow {
    fn failure(&self, error_code: &'static str) -> RowPreparationError {
        RowPreparationError::Failure(RowFailure {
            id: self.id.clone(),
            secret_id: self.secret_id.clone(),
            version: self.version,
            key_version: self.key_version,
            error_code,
        })
    }
}

async fn apply_prepared_batch(
    supabase_client: &SupabaseClient,
    ledger_appender: &LedgerAppender,
    prepared: &PreparedBatch,
    totals: &mut RunTotals,
) -> Result<EnvelopeMigrationApplyOutcome, KeyRotationCliError> {
    let batch_size = u64::try_from(prepared.success_rows.len() + prepared.failure_rows.len())
        .map_err(|_| {
            KeyRotationCliError::Config("envelope migration batch size is invalid".to_owned())
        })?;
    let success_count = u64::try_from(prepared.success_rows.len()).map_err(|_| {
        KeyRotationCliError::Config("envelope migration success count is invalid".to_owned())
    })?;
    let failure_count = u64::try_from(prepared.failure_rows.len()).map_err(|_| {
        KeyRotationCliError::Config("envelope migration failure count is invalid".to_owned())
    })?;

    let request_id =
        RequestId::generate().map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;
    let event = build_key_rotation_envelope_migrated_event(
        &request_id,
        batch_size,
        success_count,
        failure_count,
    )?;
    let ledger_draft = build_key_rotation_ledger_draft(
        &event,
        LedgerEntryType::EnvelopeMigrationBatchCompleted,
        json!({
            "batch_size": batch_size,
            "success_count": success_count,
            "failure_count": failure_count,
        }),
    )?;
    let signed_entry = sign_single_ledger_entry(ledger_appender, &ledger_draft).await?;
    let outcome = supabase_client
        .call_apply_envelope_migration_batch(
            &event,
            &signed_entry,
            prepared.success_rows.clone(),
            prepared.failure_rows.clone(),
        )
        .await?;

    merge_outcome(totals, &request_id, &outcome)?;
    Ok(outcome)
}

async fn retry_nonce_reuse_rows(
    supabase_client: &SupabaseClient,
    ledger_appender: &LedgerAppender,
    config: &AppConfig,
    retry_sources: &HashMap<String, EnvelopeMigrationBatchRow>,
    mut retry_ids: Vec<String>,
    totals: &mut RunTotals,
) -> Result<(), KeyRotationCliError> {
    for _ in 0..MAX_NONCE_REUSE_RETRIES {
        if retry_ids.is_empty() {
            return Ok(());
        }

        let rows = retry_rows_from_sources(retry_sources, &retry_ids)?;
        let prepared = prepare_batch(config, rows)?;
        let outcome =
            apply_prepared_batch(supabase_client, ledger_appender, &prepared, totals).await?;
        retry_ids = outcome.retry_secret_version_ids;
    }

    if retry_ids.is_empty() {
        return Ok(());
    }

    let failure_rows = retry_ids
        .iter()
        .map(|id| retry_failure_row(retry_sources, id))
        .collect::<Result<Vec<_>, _>>()?;
    let prepared = PreparedBatch {
        success_rows: Vec::new(),
        failure_rows,
    };
    let _ = apply_prepared_batch(supabase_client, ledger_appender, &prepared, totals).await?;

    Ok(())
}

fn retry_rows_from_sources(
    retry_sources: &HashMap<String, EnvelopeMigrationBatchRow>,
    retry_ids: &[String],
) -> Result<Vec<EnvelopeMigrationBatchRow>, KeyRotationCliError> {
    retry_ids
        .iter()
        .map(|id| {
            retry_sources.get(id).cloned().ok_or_else(|| {
                KeyRotationCliError::Config("nonce retry row is missing from batch".to_owned())
            })
        })
        .collect()
}

fn retry_failure_row(
    retry_sources: &HashMap<String, EnvelopeMigrationBatchRow>,
    id: &str,
) -> Result<EnvelopeMigrationFailureRow, KeyRotationCliError> {
    let row = retry_sources.get(id).ok_or_else(|| {
        KeyRotationCliError::Config("nonce retry row is missing from batch".to_owned())
    })?;
    let (id, secret_id, version, key_version) = parse_row_identity(row)?;

    Ok(EnvelopeMigrationFailureRow {
        id: id.as_canonical_string(),
        secret_id: secret_id.as_canonical_string(),
        version: version.get(),
        key_version: key_version.get(),
        error_code: "nonce_reuse_detected".to_owned(),
    })
}

impl RowFailure {
    fn into_rpc_row(self) -> EnvelopeMigrationFailureRow {
        EnvelopeMigrationFailureRow {
            id: self.id.as_canonical_string(),
            secret_id: self.secret_id.as_canonical_string(),
            version: self.version.get(),
            key_version: self.key_version.get(),
            error_code: self.error_code.to_owned(),
        }
    }
}

fn map_decrypt_error(error: SecretDecryptError) -> &'static str {
    match error {
        SecretDecryptError::Aad(_) => "aad_context_invalid",
        SecretDecryptError::Crypto(_) => "legacy_decrypt_failed",
        SecretDecryptError::Integrity(_) => "aad_context_mismatch",
        SecretDecryptError::Keyring(_) => "legacy_key_unavailable",
        SecretDecryptError::Authorization(_) => "legacy_decrypt_failed",
    }
}

fn parse_secret_version(
    value: i32,
    message: &'static str,
) -> Result<SecretVersion, KeyRotationCliError> {
    u32::try_from(value)
        .ok()
        .and_then(|parsed| SecretVersion::new(parsed).ok())
        .ok_or_else(|| KeyRotationCliError::Config(message.to_owned()))
}

fn parse_key_version(value: i32, message: &'static str) -> Result<KeyVersion, KeyRotationCliError> {
    u32::try_from(value)
        .ok()
        .and_then(|parsed| KeyVersion::new(parsed).ok())
        .ok_or_else(|| KeyRotationCliError::Config(message.to_owned()))
}

fn merge_outcome(
    totals: &mut RunTotals,
    request_id: &RequestId,
    outcome: &EnvelopeMigrationApplyOutcome,
) -> Result<(), KeyRotationCliError> {
    let success_count = u64::try_from(outcome.success_count)
        .map_err(|_| KeyRotationCliError::Config("success_count is invalid".to_owned()))?;
    let failure_count = u64::try_from(outcome.failure_count)
        .map_err(|_| KeyRotationCliError::Config("failure_count is invalid".to_owned()))?;
    totals.success_count += success_count;
    totals.failure_count += failure_count;
    totals.remaining_legacy_rows = outcome.remaining_legacy_rows;
    totals.last_request_id = Some(request_id.as_canonical_string());

    Ok(())
}

fn print_totals(
    totals: &RunTotals,
    status: &EnvelopeMigrationStatus,
    format: OutputFormat,
) -> Result<(), KeyRotationCliError> {
    match format {
        OutputFormat::Text => {
            println!(
                "envelope_migration dry_run={} request_id={} selected_count={} success_count={} failure_count={} remaining_legacy_rows={} last_run_at={} last_batch_size={} last_success_count={} last_failure_count={}",
                totals.dry_run,
                totals.last_request_id.as_deref().unwrap_or("-"),
                totals.selected_count,
                totals.success_count,
                totals.failure_count,
                totals.remaining_legacy_rows,
                status.last_run_at.as_deref().unwrap_or("-"),
                format_optional_i64(status.last_batch_size),
                format_optional_i64(status.last_success_count),
                format_optional_i64(status.last_failure_count),
            );
        }
        OutputFormat::Json => {
            let value = json!({
                "envelope_migration": {
                    "dry_run": totals.dry_run,
                    "request_id": totals.last_request_id,
                    "selected_count": totals.selected_count,
                    "success_count": totals.success_count,
                    "failure_count": totals.failure_count,
                    "remaining_legacy_rows": totals.remaining_legacy_rows,
                    "last_run_at": status.last_run_at.clone(),
                    "last_batch_size": status.last_batch_size,
                    "last_success_count": status.last_success_count,
                    "last_failure_count": status.last_failure_count,
                }
            });
            let rendered = serde_json::to_string_pretty(&value)
                .map_err(|error| KeyRotationCliError::Config(error.to_string()))?;
            println!("{rendered}");
        }
    }

    Ok(())
}

fn format_optional_i64(value: Option<i64>) -> String {
    value.map_or_else(|| "-".to_owned(), |count| count.to_string())
}

fn parse_options(args: &[String]) -> Result<EnvelopeMigrationOptions, KeyRotationCliError> {
    let mut batch_size = DEFAULT_BATCH_SIZE;
    let mut max_batches = DEFAULT_MAX_BATCHES;
    let mut dry_run = false;
    let mut secret_id = None;
    let mut format = OutputFormat::Text;
    let mut migrate_seen = false;
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--migrate-envelope" => {
                if migrate_seen {
                    return Err(KeyRotationCliError::Usage(
                        "--migrate-envelope must be provided once".to_owned(),
                    ));
                }
                migrate_seen = true;
                index += 1;
            }
            "--dry-run" => {
                dry_run = true;
                index += 1;
            }
            "--batch-size" => {
                let value = take_flag_value(args, index, "--batch-size")?;
                batch_size = parse_bounded_u32("--batch-size", value, MAX_BATCH_SIZE)?;
                index += 2;
            }
            "--max-batches" => {
                let value = take_flag_value(args, index, "--max-batches")?;
                max_batches = parse_bounded_u32("--max-batches", value, u32::MAX)?;
                index += 2;
            }
            "--secret-id" => {
                let value = take_flag_value(args, index, "--secret-id")?;
                if secret_id.is_some() {
                    return Err(KeyRotationCliError::Usage(
                        "--secret-id must be provided once".to_owned(),
                    ));
                }
                secret_id = Some(SecretId::parse(value).map_err(|_| {
                    KeyRotationCliError::Usage("--secret-id must be a UUID v4".to_owned())
                })?);
                index += 2;
            }
            "--format" => {
                let value = take_flag_value(args, index, "--format")?;
                format = parse_format(value)?;
                index += 2;
            }
            _ => return Err(KeyRotationCliError::Usage(super::usage())),
        }
    }

    if !migrate_seen {
        return Err(KeyRotationCliError::Usage(super::usage()));
    }

    Ok(EnvelopeMigrationOptions {
        batch_size,
        max_batches,
        dry_run,
        secret_id,
        format,
    })
}

fn take_flag_value<'a>(
    args: &'a [String],
    index: usize,
    flag: &'static str,
) -> Result<&'a str, KeyRotationCliError> {
    let value = args
        .get(index + 1)
        .ok_or_else(|| KeyRotationCliError::Usage(format!("{flag} requires a value")))?;
    if value.starts_with("--") {
        return Err(KeyRotationCliError::Usage(format!(
            "{flag} requires a value"
        )));
    }

    Ok(value.as_str())
}

fn parse_bounded_u32(
    flag: &'static str,
    value: &str,
    max_value: u32,
) -> Result<u32, KeyRotationCliError> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| KeyRotationCliError::Usage(format!("{flag} must be a positive integer")))?;
    if parsed == 0 || parsed > max_value {
        return Err(KeyRotationCliError::Usage(format!(
            "{flag} must be between 1 and {max_value}"
        )));
    }

    Ok(parsed)
}

fn parse_format(value: &str) -> Result<OutputFormat, KeyRotationCliError> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        _ => Err(KeyRotationCliError::Usage(
            "--format must be text or json".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::open_dispatched;
    use crate::{
        DeviceId, KekVersion, MASTER_KEY_LENGTH, MasterKey, NewSecretVersionInput, Plaintext,
        prepare_new_secret_version,
    };

    #[test]
    fn prepared_migration_row_round_trips_with_v02_open_dispatched()
    -> Result<(), Box<dyn std::error::Error>> {
        let legacy_key = MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH]);
        let keyring = MasterKeyRing::from_key_entries(
            KeyVersion::new(2)?,
            [
                (
                    KeyVersion::new(1)?,
                    MasterKey::from_bytes([11u8; MASTER_KEY_LENGTH]),
                ),
                (
                    KeyVersion::new(2)?,
                    MasterKey::from_bytes([12u8; MASTER_KEY_LENGTH]),
                ),
            ],
        )?;
        let plaintext_bytes = b"task-07 envelope migration round trip".to_vec();
        let legacy = prepare_new_secret_version(
            &legacy_key,
            NewSecretVersionInput::new(
                OwnerUserId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
                Classification::new("confidential")?,
                DeviceId::new("sbc-device-1")?,
                CreatedAt::parse("2026-04-08T12:00:00Z")?,
                KeyVersion::new(1)?,
                Plaintext::new(plaintext_bytes.clone()),
            ),
        )?;
        let row = EnvelopeMigrationBatchRow {
            id: legacy.secret_version_id().as_canonical_string(),
            secret_id: legacy.secret_id().as_canonical_string(),
            version: i32::try_from(legacy.version().get())?,
            ciphertext: encode_bytea(legacy.ciphertext().as_bytes()),
            encrypted_data_key: encode_bytea(
                legacy
                    .encrypted_data_key()
                    .ok_or("legacy fixture is missing encrypted_data_key")?
                    .as_bytes(),
            ),
            key_version: i32::try_from(legacy.key_version().get())?,
            algorithm: legacy.algorithm().to_owned(),
            classification: legacy.classification().as_str().to_owned(),
            nonce_or_iv: encode_bytea(legacy.nonce_or_iv().as_bytes()),
            aad_context: legacy.aad_context().clone(),
            created_at: legacy.created_at().as_rfc3339_utc()?,
            owner_user_id: legacy.owner_user_id().as_canonical_string(),
        };

        let migrated = match prepare_row(&keyring, row) {
            Ok(row) => row,
            Err(RowPreparationError::Failure(failure)) => {
                panic!("migration fixture failed with {}", failure.error_code);
            }
            Err(RowPreparationError::Fatal(error)) => return Err(Box::new(error)),
        };
        assert_eq!(migrated.dek_wrap_algorithm, "envvar-xchacha-v2");
        assert_eq!(migrated.kek_version, 2);

        let aad = AadV1::from_stored_context(legacy.aad_context())?;
        let record = SecretVersionRecord {
            secret_id: SecretId::parse(&migrated.secret_id)?,
            key_version: KeyVersion::new(migrated.kek_version)?,
            ciphertext: Ciphertext::new(decode_bytea(&migrated.ciphertext)?)?,
            nonce: Nonce::parse(&decode_bytea(&migrated.nonce_or_iv)?)?,
            encrypted_data_key: None,
            wrapped_dek: Some(crate::WrappedDek::parse(
                KekVersion::new(migrated.kek_version)?,
                &decode_bytea(&migrated.wrapped_dek)?,
            )?),
            dek_wrap_algorithm: Some(KekAlgorithm::EnvvarXchachaV2),
        };
        let opened = open_dispatched(&keyring, &record, &aad)?;
        assert_eq!(opened.as_bytes(), plaintext_bytes.as_slice());

        Ok(())
    }
}

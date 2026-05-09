use std::str::FromStr;
use std::sync::Arc;

use serde::Serialize;

use crate::ledger::{
    LedgerChainHead, LedgerError, LedgerSequenceNo, LedgerVerifyingKey, verify_ledger_chain,
};
use crate::server::config::AppConfig;
use crate::server::supabase::{SupabaseClient, classify_export_ledger_error};

#[derive(Debug)]
pub enum AuditorCliError {
    Usage(String),
    Config(String),
    SupabaseRpc(String),
    Ledger(String),
    Io(std::io::Error),
    Serialization(String),
    ExportFailure(String),
}

impl std::fmt::Display for AuditorCliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::Config(message) => write!(formatter, "auditor config error: {message}"),
            Self::SupabaseRpc(message) => {
                write!(formatter, "auditor Supabase RPC error: {message}")
            }
            Self::Ledger(message) => write!(formatter, "auditor ledger error: {message}"),
            Self::Io(error) => write!(formatter, "auditor I/O error: {error}"),
            Self::Serialization(message) => {
                write!(formatter, "auditor serialization error: {message}")
            }
            Self::ExportFailure(message) => write!(formatter, "auditor export failure: {message}"),
        }
    }
}

impl std::error::Error for AuditorCliError {}

pub fn usage() -> String {
    [
        "usage:",
        "  mipsorcu auditor verify --from-sequence <n> --to-sequence <n> --format json",
    ]
    .join("\n")
}

pub async fn run_cli(config: AppConfig, args: &[String]) -> Result<(), AuditorCliError> {
    let mut subcommand: Option<&String> = None;
    let mut from_sequence: Option<u64> = None;
    let mut to_sequence: Option<u64> = None;
    let mut format: Option<&String> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "verify" if subcommand.is_none() => {
                subcommand = Some(arg);
            }
            "--from-sequence" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| AuditorCliError::Usage(usage()))?;
                if value.starts_with("--") {
                    return Err(AuditorCliError::Usage(usage()));
                }
                let parsed = u64::from_str(value).map_err(|_| AuditorCliError::Usage(usage()))?;
                if parsed == 0 {
                    return Err(AuditorCliError::Usage(usage()));
                }
                from_sequence = Some(parsed);
                i += 1;
            }
            "--to-sequence" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| AuditorCliError::Usage(usage()))?;
                if value.starts_with("--") {
                    return Err(AuditorCliError::Usage(usage()));
                }
                let parsed = u64::from_str(value).map_err(|_| AuditorCliError::Usage(usage()))?;
                if parsed == 0 {
                    return Err(AuditorCliError::Usage(usage()));
                }
                to_sequence = Some(parsed);
                i += 1;
            }
            "--format" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| AuditorCliError::Usage(usage()))?;
                if value.starts_with("--") {
                    return Err(AuditorCliError::Usage(usage()));
                }
                format = Some(value);
                i += 1;
            }
            _ => return Err(AuditorCliError::Usage(usage())),
        }
        i += 1;
    }

    match subcommand {
        Some(command) if command == "verify" => {}
        _ => return Err(AuditorCliError::Usage(usage())),
    }

    let from_sequence = from_sequence.ok_or_else(|| AuditorCliError::Usage(usage()))?;
    let to_sequence = to_sequence.ok_or_else(|| AuditorCliError::Usage(usage()))?;

    if from_sequence > to_sequence {
        return Err(AuditorCliError::Usage(
            "from-sequence must be <= to-sequence".to_owned(),
        ));
    }

    match format {
        Some(f) if f == "json" => {}
        _ => return Err(AuditorCliError::Usage(usage())),
    }

    let output = run_verify_command(&config, from_sequence, to_sequence).await?;
    let json_output = serde_json::to_string_pretty(&output)
        .map_err(|error| AuditorCliError::Serialization(error.to_string()))?;
    println!("{json_output}");

    if output.valid {
        Ok(())
    } else {
        Err(AuditorCliError::Ledger(
            "chain verification failed".to_owned(),
        ))
    }
}

#[derive(Debug, Serialize)]
struct AuditorVerifyOutput {
    valid: bool,
    checked_count: u64,
    first_sequence_no: u64,
    last_sequence_no: u64,
    first_error: Option<AuditorVerifyFirstError>,
}

#[derive(Debug, Serialize)]
struct AuditorVerifyFirstError {
    code: String,
    #[serde(rename = "sequence_no")]
    sequence_no: u64,
}

async fn run_verify_command(
    config: &AppConfig,
    from_sequence: u64,
    to_sequence: u64,
) -> Result<AuditorVerifyOutput, AuditorCliError> {
    let http_client = crate::server::config::build_outbound_http_client(config)
        .map_err(|error| AuditorCliError::Config(error.to_string()))?;
    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url.clone(),
        config.supabase_service_role_key.clone(),
        config.supabase_publishable_key.clone(),
    ));

    let start = LedgerSequenceNo::new(from_sequence)
        .map_err(|error| AuditorCliError::Usage(format!("invalid from-sequence: {error}")))?;
    let end = LedgerSequenceNo::new(to_sequence)
        .map_err(|error| AuditorCliError::Usage(format!("invalid to-sequence: {error}")))?;

    let rows = supabase_client
        .export_ledger_verification_materials(start, end)
        .await
        .map_err(|error| {
            let classification = classify_export_ledger_error(&error);
            AuditorCliError::SupabaseRpc(format!("{}: {}", classification.as_error_code(), error))
        })?;

    // Restore signed ledger entries
    let mut entries = Vec::with_capacity(rows.len());
    for row in &rows {
        let entry = row
            .try_restore_signed_ledger_entry()
            .map_err(|error| AuditorCliError::ExportFailure(error.to_string()))?;
        entries.push(entry);
    }

    // Restore verifying keys (deduplicate by key_version)
    let mut verification_keys: Vec<LedgerVerifyingKey> = Vec::new();
    for row in &rows {
        if let Some(key) = row
            .try_restore_verifying_key()
            .map_err(|error| AuditorCliError::ExportFailure(error.to_string()))?
            && !verification_keys
                .iter()
                .any(|existing| existing.key_version() == key.key_version())
        {
            verification_keys.push(key);
        }
    }

    if entries.is_empty() {
        return Ok(AuditorVerifyOutput {
            valid: true,
            checked_count: 0,
            first_sequence_no: from_sequence,
            last_sequence_no: to_sequence,
            first_error: None,
        });
    }

    let first_seq = entries
        .first()
        .map(|e| e.sequence_no().get())
        .unwrap_or(from_sequence);
    let last_seq = entries
        .last()
        .map(|e| e.sequence_no().get())
        .unwrap_or(to_sequence);

    let initial_head = LedgerChainHead::genesis();

    match verify_ledger_chain(&entries, initial_head, &verification_keys) {
        Ok(_) => Ok(AuditorVerifyOutput {
            valid: true,
            checked_count: entries.len() as u64,
            first_sequence_no: first_seq,
            last_sequence_no: last_seq,
            first_error: None,
        }),
        Err(error) => {
            let (code, seq_no) = map_error_to_code_and_sequence(&error, &entries);
            Ok(AuditorVerifyOutput {
                valid: false,
                checked_count: entries.len() as u64,
                first_sequence_no: first_seq,
                last_sequence_no: last_seq,
                first_error: Some(AuditorVerifyFirstError {
                    code,
                    sequence_no: seq_no,
                }),
            })
        }
    }
}

fn map_error_to_code_and_sequence(
    error: &LedgerError,
    _entries: &[crate::ledger::SignedLedgerEntry],
) -> (String, u64) {
    match error {
        LedgerError::SequenceGap {
            expected: _,
            actual,
        } => ("sequence_gap".to_owned(), *actual),
        LedgerError::PreviousHashMismatch { sequence_no } => {
            ("previous_hash_mismatch".to_owned(), *sequence_no)
        }
        LedgerError::HashMismatch { sequence_no } => {
            ("entry_hash_mismatch".to_owned(), *sequence_no)
        }
        LedgerError::SignatureInvalid { sequence_no } => {
            ("signature_invalid".to_owned(), *sequence_no)
        }
        LedgerError::UnknownSignatureKey {
            key_version: _,
            sequence_no,
        } => ("unknown_signature_key".to_owned(), *sequence_no),
        LedgerError::InvalidVerificationKey | LedgerError::InvalidVerificationKeyLength { .. } => {
            ("invalid_exported_material".to_owned(), 0)
        }
        LedgerError::InvalidSignatureEncoding
        | LedgerError::InvalidSignatureLength { .. }
        | LedgerError::InvalidHashEncoding
        | LedgerError::InvalidHashLength { .. } => ("invalid_exported_material".to_owned(), 0),
        LedgerError::SignatureKeyVersionMismatch { .. } => {
            ("invalid_exported_material".to_owned(), 0)
        }
        _ => ("invalid_exported_material".to_owned(), 0),
    }
}

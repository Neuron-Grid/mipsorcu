use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use serde_json::json;

use crate::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditResult, AuditTrigger, RequestId,
    SchedulerJobMetadata, SignatureKeyActivatedMetadata, SignatureKeyCreatedMetadata,
    SignatureKeyRetiredMetadata,
};
use crate::ledger::{
    LEDGER_ED25519_PUBLIC_KEY_LENGTH, LedgerEntryId, LedgerEntryType, LedgerPayload, LedgerResult,
    LedgerSignatureKeyVersion, LedgerSigningKey, LedgerVerifyingKey, SignedLedgerEntry,
};
use crate::server::audit_reporter::{OperationalAuditEvent, build_operational_audit_event};
use crate::server::config::AppConfig;
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts, LedgerAppender};
use crate::server::scheduler;
use crate::server::supabase::{LedgerSigningPublicKeyStatus, SupabaseClient, SupabaseRpcError};
use crate::types::SourceEventAt;

const LEDGER_SIGNATURE_FULL_VERIFY_JOB: &str = "ledger_signature_full_verify";

#[derive(Debug)]
pub enum SignatureKeyCliError {
    Usage(String),
    Config(String),
    Supabase(String),
    Audit(String),
    Ledger(String),
    Serialization(String),
}

impl std::fmt::Display for SignatureKeyCliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::Config(message) => write!(formatter, "signature key config error: {message}"),
            Self::Supabase(message) => {
                write!(formatter, "signature key Supabase RPC error: {message}")
            }
            Self::Audit(message) => write!(formatter, "signature key audit error: {message}"),
            Self::Ledger(message) => write!(formatter, "signature key ledger error: {message}"),
            Self::Serialization(message) => {
                write!(formatter, "signature key serialization error: {message}")
            }
        }
    }
}

impl std::error::Error for SignatureKeyCliError {}

pub fn usage() -> String {
    [
        "usage:",
        "  mipsorcu signature-key public-key --format json",
        "  mipsorcu signature-key status --key-version <n> --format json",
        "  mipsorcu signature-key create --key-version <n> [--public-key-hex <64-hex>]",
        "  mipsorcu signature-key activate --key-version <n>",
        "  mipsorcu signature-key retire --key-version <n>",
        "  mipsorcu signature-key verify-all --format json",
    ]
    .join("\n")
}

pub async fn run_cli(config: AppConfig, args: &[String]) -> Result<(), SignatureKeyCliError> {
    let Some((command, command_args)) = args.split_first() else {
        return Err(SignatureKeyCliError::Usage(usage()));
    };

    match command.as_str() {
        "public-key" => public_key(&config, command_args),
        "status" => status(&config, command_args).await,
        "create" => create(&config, command_args).await,
        "activate" => activate(&config, command_args).await,
        "retire" => retire(&config, command_args).await,
        "verify-all" => verify_all(&config, command_args).await,
        _ => Err(SignatureKeyCliError::Usage(usage())),
    }
}

fn public_key(config: &AppConfig, args: &[String]) -> Result<(), SignatureKeyCliError> {
    parse_format_json(args)?;
    let verification_key = config.ledger_signing_key.verification_key();
    let output = PublicKeyOutput {
        key_version: verification_key.key_version().get(),
        public_key_hex: hex::encode(verification_key.as_bytes()),
        public_key_fingerprint: verification_key.fingerprint_hex(),
    };
    print_json(&output)
}

async fn status(config: &AppConfig, args: &[String]) -> Result<(), SignatureKeyCliError> {
    let key_version = parse_key_version_flag(args, "--key-version")?;
    parse_format_json(args)?;
    let client = build_client(config)?;
    let status = client
        .get_ledger_signing_public_key_status(key_version)
        .await
        .map_err(map_supabase_error)?;
    print_json(&StatusOutput::from(status))
}

async fn create(config: &AppConfig, args: &[String]) -> Result<(), SignatureKeyCliError> {
    let key_version = parse_key_version_flag(args, "--key-version")?;
    let verification_key = parse_public_key_arg(args, key_version, &config.ledger_signing_key)?;
    let client = build_client(config)?;
    ensure_current_signing_key_active(&client, &config.ledger_signing_key).await?;
    let ledger_appender = build_ledger_appender(config, client.clone());
    let source_event_at =
        SourceEventAt::now_utc().map_err(|error| SignatureKeyCliError::Audit(error.to_string()))?;
    let fingerprint = verification_key.fingerprint_hex();
    let event = build_signature_key_event(
        AuditAction::SignatureKeyCreated,
        SignatureKeyCreatedMetadata::new(key_version, fingerprint.clone(), source_event_at.clone())
            .build()
            .map_err(|error| SignatureKeyCliError::Audit(error.to_string()))?,
    )?;
    let signed_entry = sign_signature_key_ledger_entry(
        &ledger_appender,
        &event,
        LedgerEntryType::SignatureKeyCreated,
        source_event_at.as_str(),
        json!({
            "signature_key_version": key_version.get(),
            "public_key_fingerprint": fingerprint,
            "created_at": source_event_at.as_str(),
        }),
    )
    .await?;

    client
        .create_ledger_signing_public_key_with_ledger(&verification_key, &event, &signed_entry)
        .await
        .map_err(map_supabase_error)?;

    println!(
        "signature_key_created key_version={} public_key_fingerprint={}",
        key_version.get(),
        verification_key.fingerprint_hex()
    );
    Ok(())
}

async fn activate(config: &AppConfig, args: &[String]) -> Result<(), SignatureKeyCliError> {
    let key_version = parse_key_version_flag(args, "--key-version")?;
    let client = build_client(config)?;
    ensure_current_signing_key_active(&client, &config.ledger_signing_key).await?;
    let status = client
        .get_ledger_signing_public_key_status(key_version)
        .await
        .map_err(map_supabase_error)?;
    let ledger_appender = build_ledger_appender(config, client.clone());
    let source_event_at =
        SourceEventAt::now_utc().map_err(|error| SignatureKeyCliError::Audit(error.to_string()))?;
    let fingerprint = status.public_key_fingerprint.clone();
    let event = build_signature_key_event(
        AuditAction::SignatureKeyActivated,
        SignatureKeyActivatedMetadata::new(
            key_version,
            fingerprint.clone(),
            source_event_at.clone(),
        )
        .build()
        .map_err(|error| SignatureKeyCliError::Audit(error.to_string()))?,
    )?;
    let signed_entry = sign_signature_key_ledger_entry(
        &ledger_appender,
        &event,
        LedgerEntryType::SignatureKeyActivated,
        source_event_at.as_str(),
        json!({
            "signature_key_version": key_version.get(),
            "public_key_fingerprint": fingerprint,
            "activated_at": source_event_at.as_str(),
        }),
    )
    .await?;

    client
        .activate_ledger_signing_public_key_with_ledger(&event, &signed_entry)
        .await
        .map_err(map_supabase_error)?;

    println!(
        "signature_key_activated key_version={} public_key_fingerprint={}",
        key_version.get(),
        status.public_key_fingerprint
    );
    Ok(())
}

async fn retire(config: &AppConfig, args: &[String]) -> Result<(), SignatureKeyCliError> {
    let key_version = parse_key_version_flag(args, "--key-version")?;
    let client = build_client(config)?;
    ensure_current_signing_key_active(&client, &config.ledger_signing_key).await?;
    let status = client
        .get_ledger_signing_public_key_status(key_version)
        .await
        .map_err(map_supabase_error)?;
    let ledger_appender = build_ledger_appender(config, client.clone());
    let source_event_at =
        SourceEventAt::now_utc().map_err(|error| SignatureKeyCliError::Audit(error.to_string()))?;
    let fingerprint = status.public_key_fingerprint.clone();
    let event = build_signature_key_event(
        AuditAction::SignatureKeyRetired,
        SignatureKeyRetiredMetadata::new(key_version, fingerprint.clone(), source_event_at.clone())
            .build()
            .map_err(|error| SignatureKeyCliError::Audit(error.to_string()))?,
    )?;
    let signed_entry = sign_signature_key_ledger_entry(
        &ledger_appender,
        &event,
        LedgerEntryType::SignatureKeyRetired,
        source_event_at.as_str(),
        json!({
            "signature_key_version": key_version.get(),
            "public_key_fingerprint": fingerprint,
            "retired_at": source_event_at.as_str(),
        }),
    )
    .await?;

    client
        .retire_ledger_signing_public_key_with_ledger(&event, &signed_entry)
        .await
        .map_err(map_supabase_error)?;

    println!(
        "signature_key_retired key_version={} public_key_fingerprint={}",
        key_version.get(),
        status.public_key_fingerprint
    );
    Ok(())
}

async fn verify_all(config: &AppConfig, args: &[String]) -> Result<(), SignatureKeyCliError> {
    parse_format_json(args)?;
    let client = build_client(config)?;
    ensure_current_signing_key_active(&client, &config.ledger_signing_key).await?;
    let ledger_appender = build_ledger_appender(config, client.clone());
    let started_at = Instant::now();
    let outcome = scheduler::verify_full_ledger_signatures(client.as_ref()).await;
    let duration_ms = elapsed_ms(started_at);
    let (valid, checked_count, error_code) = match outcome {
        Ok(summary) => (summary.valid, summary.checked_count, summary.error_code),
        Err(error_code) => (false, 0, Some(error_code)),
    };
    let result = if valid {
        AuditResult::Success
    } else {
        AuditResult::Failure
    };

    record_verify_all_result(&client, &ledger_appender, result, error_code, duration_ms).await?;

    let output = VerifyAllOutput {
        valid,
        checked_count,
        error_code,
    };
    print_json(&output)?;

    if valid {
        Ok(())
    } else {
        Err(SignatureKeyCliError::Ledger(
            error_code
                .unwrap_or("ledger_signature_verification_failed")
                .to_owned(),
        ))
    }
}

async fn ensure_current_signing_key_active(
    client: &SupabaseClient,
    signing_key: &LedgerSigningKey,
) -> Result<(), SignatureKeyCliError> {
    client
        .ensure_active_ledger_signing_public_key(&signing_key.verification_key())
        .await
        .map_err(map_supabase_error)
}

fn build_client(config: &AppConfig) -> Result<Arc<SupabaseClient>, SignatureKeyCliError> {
    let http_client = crate::server::config::build_outbound_http_client(config)
        .map_err(|error| SignatureKeyCliError::Config(error.to_string()))?;
    Ok(Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url.clone(),
        config.supabase_service_role_key.clone(),
        config.supabase_publishable_key.clone(),
    )))
}

fn build_ledger_appender(config: &AppConfig, client: Arc<SupabaseClient>) -> Arc<LedgerAppender> {
    Arc::new(LedgerAppender::new(
        client,
        config.ledger_signing_key.clone(),
    ))
}

fn build_signature_key_event(
    action: AuditAction,
    metadata_json: crate::audit::AuditMetadata,
) -> Result<AuditEvent, SignatureKeyCliError> {
    let audit_event_id =
        AuditEventId::generate().map_err(|error| SignatureKeyCliError::Audit(error.to_string()))?;
    let request_id =
        RequestId::generate().map_err(|error| SignatureKeyCliError::Audit(error.to_string()))?;

    build_operational_audit_event(OperationalAuditEvent {
        audit_event_id,
        request_id,
        actor_user_id: None,
        action,
        result: AuditResult::Success,
        key_version: None,
        metadata: metadata_json,
    })
    .map_err(|error| SignatureKeyCliError::Audit(error.to_string()))
}

async fn sign_signature_key_ledger_entry(
    ledger_appender: &LedgerAppender,
    event: &AuditEvent,
    entry_type: LedgerEntryType,
    source_event_at: &str,
    payload_value: serde_json::Value,
) -> Result<SignedLedgerEntry, SignatureKeyCliError> {
    let payload = LedgerPayload::new(entry_type, payload_value)
        .map_err(|error| SignatureKeyCliError::Ledger(error.to_string()))?;
    let source_event_at = SourceEventAt::parse(source_event_at)
        .map_err(|error| SignatureKeyCliError::Ledger(error.to_string()))?;
    let draft = LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::generate()
            .map_err(|error| SignatureKeyCliError::Ledger(error.to_string()))?,
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
    .map_err(|error| SignatureKeyCliError::Ledger(error.to_string()))?;
    let mut signed_entries = ledger_appender
        .sign_entries(&[draft])
        .await
        .map_err(|error| SignatureKeyCliError::Ledger(error.to_string()))?;

    signed_entries
        .pop()
        .ok_or_else(|| SignatureKeyCliError::Ledger("ledger signing returned no entry".to_owned()))
}

async fn record_verify_all_result(
    client: &SupabaseClient,
    ledger_appender: &LedgerAppender,
    result: AuditResult,
    error_code: Option<&'static str>,
    duration_ms: u64,
) -> Result<(), SignatureKeyCliError> {
    let source_event_at =
        SourceEventAt::now_utc().map_err(|error| SignatureKeyCliError::Audit(error.to_string()))?;
    let mut metadata_builder = SchedulerJobMetadata::new(
        LEDGER_SIGNATURE_FULL_VERIFY_JOB,
        AuditTrigger::Cli,
        source_event_at.clone(),
    )
    .with_duration_ms(duration_ms);
    if let Some(error_code) = error_code {
        metadata_builder = metadata_builder.with_error_code(error_code);
    }
    let metadata = metadata_builder
        .build()
        .map_err(|error| SignatureKeyCliError::Audit(error.to_string()))?;
    let audit_event_id =
        AuditEventId::generate().map_err(|error| SignatureKeyCliError::Audit(error.to_string()))?;
    let request_id =
        RequestId::generate().map_err(|error| SignatureKeyCliError::Audit(error.to_string()))?;
    let event = build_operational_audit_event(OperationalAuditEvent {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        action: AuditAction::SchedulerJob,
        result,
        key_version: None,
        metadata,
    })
    .map_err(|error| SignatureKeyCliError::Audit(error.to_string()))?;

    let entry_type = LedgerEntryType::SchedulerJobCompleted;
    let payload = LedgerPayload::new(
        entry_type,
        json!({
            "duration_ms": duration_ms,
            "job_name": LEDGER_SIGNATURE_FULL_VERIFY_JOB,
            "trigger": AuditTrigger::Cli.as_str(),
        }),
    )
    .map_err(|error| SignatureKeyCliError::Ledger(error.to_string()))?;
    let ledger_result = if result == AuditResult::Success {
        LedgerResult::Success
    } else {
        LedgerResult::Failure
    };
    let draft = LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::generate()
            .map_err(|error| SignatureKeyCliError::Ledger(error.to_string()))?,
        entry_type,
        source_event_at,
        request_id,
        source_event_id: Some(event.audit_event_id().clone()),
        target_secret_id: None,
        target_secret_version_id: None,
        actor_user_id: None,
        actor_device_id: None,
        result: ledger_result,
        error_code: error_code.map(str::to_owned),
        payload,
    })
    .map_err(|error| SignatureKeyCliError::Ledger(error.to_string()))?;
    let mut signed_entries = ledger_appender
        .sign_entries(&[draft])
        .await
        .map_err(|error| SignatureKeyCliError::Ledger(error.to_string()))?;
    let signed_entry = signed_entries.pop().ok_or_else(|| {
        SignatureKeyCliError::Ledger("ledger signing returned no entry".to_owned())
    })?;
    client
        .call_append_audit_event_with_ledger(&event, &signed_entry)
        .await
        .map_err(map_supabase_error)?;

    Ok(())
}

fn parse_key_version_flag(
    args: &[String],
    flag: &'static str,
) -> Result<LedgerSignatureKeyVersion, SignatureKeyCliError> {
    let mut parsed: Option<LedgerSignatureKeyVersion> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            let value = args
                .get(i + 1)
                .ok_or_else(|| SignatureKeyCliError::Usage(usage()))?;
            if value.starts_with("--") {
                return Err(SignatureKeyCliError::Usage(usage()));
            }
            let raw = value
                .parse::<u32>()
                .map_err(|_| SignatureKeyCliError::Usage(usage()))?;
            parsed = Some(
                LedgerSignatureKeyVersion::new(raw)
                    .map_err(|_| SignatureKeyCliError::Usage(usage()))?,
            );
            i += 1;
        }
        i += 1;
    }

    parsed.ok_or_else(|| SignatureKeyCliError::Usage(usage()))
}

fn parse_format_json(args: &[String]) -> Result<(), SignatureKeyCliError> {
    let mut found = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| SignatureKeyCliError::Usage(usage()))?;
                if value != "json" {
                    return Err(SignatureKeyCliError::Usage(usage()));
                }
                found = true;
                i += 1;
            }
            "--key-version" | "--public-key-hex" => {
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    if found {
        Ok(())
    } else {
        Err(SignatureKeyCliError::Usage(usage()))
    }
}

fn parse_public_key_arg(
    args: &[String],
    key_version: LedgerSignatureKeyVersion,
    signing_key: &LedgerSigningKey,
) -> Result<LedgerVerifyingKey, SignatureKeyCliError> {
    let mut public_key_hex: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--public-key-hex" {
            let value = args
                .get(i + 1)
                .ok_or_else(|| SignatureKeyCliError::Usage(usage()))?;
            if value.starts_with("--") {
                return Err(SignatureKeyCliError::Usage(usage()));
            }
            public_key_hex = Some(value.as_str());
            i += 1;
        }
        i += 1;
    }

    let Some(raw_hex) = public_key_hex else {
        let verification_key = signing_key.verification_key();
        if verification_key.key_version() != key_version {
            return Err(SignatureKeyCliError::Usage(
                "key-version must match configured signing key when --public-key-hex is omitted"
                    .to_owned(),
            ));
        }
        return Ok(verification_key);
    };

    let normalized = raw_hex.strip_prefix("\\x").unwrap_or(raw_hex);
    let bytes = hex::decode(normalized).map_err(|_| SignatureKeyCliError::Usage(usage()))?;
    if bytes.len() != LEDGER_ED25519_PUBLIC_KEY_LENGTH {
        return Err(SignatureKeyCliError::Usage(usage()));
    }
    LedgerVerifyingKey::from_public_key_bytes(key_version, &bytes)
        .map_err(|error| SignatureKeyCliError::Usage(error.to_string()))
}

fn map_supabase_error(error: SupabaseRpcError) -> SignatureKeyCliError {
    SignatureKeyCliError::Supabase(error.to_string())
}

fn print_json<T: Serialize>(value: &T) -> Result<(), SignatureKeyCliError> {
    let json_output = serde_json::to_string_pretty(value)
        .map_err(|error| SignatureKeyCliError::Serialization(error.to_string()))?;
    println!("{json_output}");
    Ok(())
}

fn elapsed_ms(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[derive(Serialize)]
struct PublicKeyOutput {
    key_version: u32,
    public_key_hex: String,
    public_key_fingerprint: String,
}

#[derive(Serialize)]
struct StatusOutput {
    key_version: u32,
    public_key_fingerprint: String,
    algorithm: String,
    status: String,
    created_at: String,
    activated_at: Option<String>,
    retired_at: Option<String>,
}

impl From<LedgerSigningPublicKeyStatus> for StatusOutput {
    fn from(status: LedgerSigningPublicKeyStatus) -> Self {
        Self {
            key_version: status.key_version.get(),
            public_key_fingerprint: status.public_key_fingerprint,
            algorithm: status.algorithm,
            status: status.status,
            created_at: status.created_at,
            activated_at: status.activated_at,
            retired_at: status.retired_at,
        }
    }
}

#[derive(Serialize)]
struct VerifyAllOutput {
    valid: bool,
    checked_count: u64,
    error_code: Option<&'static str>,
}

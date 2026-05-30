//! 月次 digest CLI コマンド。
//!
//! 使い方:
//!   mipsorcu digest generate --year-month YYYY-MM --format json
//!   mipsorcu digest verify   --year-month YYYY-MM --format json
//!
//! 信頼境界ノート: digest 生成・検証は SBC 内で完結する。
//! Master Key・Data Key・平文・JWT 全文を処理しない。

use std::sync::Arc;

use serde::Serialize;

use crate::audit::{AuditRecorder, LocalAuditFallbackStore, RequestId};
use crate::incident::{
    DummyNotificationSink, IncidentRecordInput, IncidentRecorder, dedupe_key,
    monthly_digest_incident_type, severity_for_incident,
};
use crate::ledger::{LedgerSignatureKeyVersion, MonthlyDigestPeriod};
use crate::server::config::AppConfig;
use crate::server::supabase::{SupabaseAuditAppender, SupabaseClient};
use crate::server::use_cases::generate_monthly_digest::{
    GenerateMonthlyDigestError, GenerateMonthlyDigestInput, generate_monthly_digest,
    record_monthly_digest_failure_audit, record_monthly_digest_success_audit,
};
use crate::server::use_cases::verify_monthly_digest::{
    VerifyMonthlyDigestError, VerifyMonthlyDigestInput, record_monthly_digest_verify_failure_audit,
    verify_monthly_digest,
};
use crate::types::SourceEventAt;

#[derive(Debug)]
pub enum DigestCliError {
    Usage(String),
    Config(String),
    GenerateFailed(GenerateMonthlyDigestError),
    VerifyFailed(VerifyMonthlyDigestError),
    ListFailed(String),
    Serialization(String),
}

impl std::fmt::Display for DigestCliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::Config(message) => write!(formatter, "digest config error: {message}"),
            Self::GenerateFailed(error) => {
                write!(formatter, "digest generation failed: {error}")
            }
            Self::VerifyFailed(error) => {
                write!(formatter, "digest verification failed: {error}")
            }
            Self::ListFailed(code) => {
                write!(formatter, "digest list failed: {code}")
            }
            Self::Serialization(message) => {
                write!(formatter, "digest serialization error: {message}")
            }
        }
    }
}

impl std::error::Error for DigestCliError {}

pub fn usage() -> String {
    [
        "usage:",
        "  mipsorcu digest generate --year-month YYYY-MM --format json",
        "  mipsorcu digest verify   --year-month YYYY-MM --format json",
        "  mipsorcu digest list     --format json",
    ]
    .join("\n")
}

pub async fn run_cli(config: AppConfig, args: &[String]) -> Result<(), DigestCliError> {
    let mut subcommand: Option<&String> = None;
    let mut year_month: Option<String> = None;
    let mut format: Option<&String> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "generate" | "verify" | "list" if subcommand.is_none() => {
                subcommand = Some(arg);
            }
            "--year-month" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| DigestCliError::Usage(usage()))?;
                if value.starts_with("--") {
                    return Err(DigestCliError::Usage(usage()));
                }
                year_month = Some(value.clone());
                i += 1;
            }
            "--format" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| DigestCliError::Usage(usage()))?;
                if value.starts_with("--") {
                    return Err(DigestCliError::Usage(usage()));
                }
                format = Some(value);
                i += 1;
            }
            _ => return Err(DigestCliError::Usage(usage())),
        }
        i += 1;
    }

    match format {
        Some(f) if f == "json" => {}
        _ => return Err(DigestCliError::Usage(usage())),
    }

    match subcommand {
        Some(cmd) if cmd == "generate" => {
            let period = parse_period(year_month)?;
            let output = run_generate_command(&config, period).await?;
            let json_output = serde_json::to_string_pretty(&output)
                .map_err(|error| DigestCliError::Serialization(error.to_string()))?;
            println!("{json_output}");
        }
        Some(cmd) if cmd == "verify" => {
            let period = parse_period(year_month)?;
            let output = run_verify_command(&config, period).await?;
            let json_output = serde_json::to_string_pretty(&output)
                .map_err(|error| DigestCliError::Serialization(error.to_string()))?;
            println!("{json_output}");
            if let Some(verify_error) = output.error_variant {
                return Err(DigestCliError::VerifyFailed(verify_error));
            }
        }
        Some(cmd) if cmd == "list" => {
            let output = run_list_command(&config).await?;
            let json_output = serde_json::to_string_pretty(&output)
                .map_err(|error| DigestCliError::Serialization(error.to_string()))?;
            println!("{json_output}");
        }
        _ => return Err(DigestCliError::Usage(usage())),
    }

    Ok(())
}

/// `--year-month` を必須として `MonthlyDigestPeriod` にパースする（generate / verify 用）。
fn parse_period(year_month: Option<String>) -> Result<MonthlyDigestPeriod, DigestCliError> {
    let year_month = year_month.ok_or_else(|| DigestCliError::Usage(usage()))?;
    MonthlyDigestPeriod::parse(&year_month)
        .map_err(|error| DigestCliError::Usage(format!("invalid --year-month: {error}")))
}

#[derive(Debug, Serialize)]
struct DigestGenerateOutput {
    period: String,
    start_sequence_no: u64,
    end_sequence_no: u64,
    entry_count: u64,
    digest_hash: String,
    signature_key_version: u32,
    digest_generated_at: String,
}

async fn run_generate_command(
    config: &AppConfig,
    period: MonthlyDigestPeriod,
) -> Result<DigestGenerateOutput, DigestCliError> {
    let http_client = crate::server::config::build_outbound_http_client(config)
        .map_err(|error| DigestCliError::Config(error.to_string()))?;

    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url.clone(),
        config.supabase_service_role_key.clone(),
        config.supabase_publishable_key.clone(),
    ));
    supabase_client
        .ensure_active_ledger_signing_public_key(&config.ledger_signing_key.verification_key())
        .await
        .map_err(|error| DigestCliError::Config(error.to_string()))?;

    let signing_key = config.ledger_signing_key.clone();
    let ledger_appender = Arc::new(crate::server::ledger_appender::LedgerAppender::new(
        supabase_client.clone(),
        signing_key,
    ));
    let audit_recorder = build_audit_recorder(config, supabase_client.clone());

    let generated_at =
        SourceEventAt::now_utc().map_err(|error| DigestCliError::Config(error.to_string()))?;

    let request_id =
        RequestId::generate().map_err(|error| DigestCliError::Config(error.to_string()))?;

    let input = GenerateMonthlyDigestInput {
        period: period.clone(),
        generated_at: generated_at.clone(),
        request_id: request_id.clone(),
    };

    match generate_monthly_digest(&supabase_client, &ledger_appender, input).await {
        Ok(signed_digest) => {
            // 生成成功を audit_events に同期記録する
            record_monthly_digest_success_audit(&audit_recorder, &request_id, &signed_digest).await;

            Ok(DigestGenerateOutput {
                period: signed_digest.period.as_str().to_owned(),
                start_sequence_no: signed_digest.start_sequence_no.get(),
                end_sequence_no: signed_digest.end_sequence_no.get(),
                entry_count: signed_digest.entry_count,
                digest_hash: signed_digest.digest_hash.to_hex(),
                signature_key_version: signed_digest.signature_key_version.get(),
                digest_generated_at: signed_digest.digest_generated_at.as_str().to_owned(),
            })
        }
        Err(error) => {
            // 生成失敗を audit_events に同期記録する
            record_monthly_digest_failure_audit(
                &audit_recorder,
                &request_id,
                &period,
                &error,
                &generated_at,
            )
            .await;

            Err(DigestCliError::GenerateFailed(error))
        }
    }
}

#[derive(Debug, Serialize)]
struct DigestVerifyOutput {
    period: String,
    valid: bool,
    start_sequence_no: Option<u64>,
    end_sequence_no: Option<u64>,
    entry_count: Option<u64>,
    error: Option<DigestVerifyOutputError>,
    #[serde(skip)]
    error_variant: Option<VerifyMonthlyDigestError>,
}

#[derive(Debug, Serialize)]
struct DigestVerifyOutputError {
    code: String,
    message: String,
}

async fn run_verify_command(
    config: &AppConfig,
    period: MonthlyDigestPeriod,
) -> Result<DigestVerifyOutput, DigestCliError> {
    let http_client = crate::server::config::build_outbound_http_client(config)
        .map_err(|error| DigestCliError::Config(error.to_string()))?;

    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url.clone(),
        config.supabase_service_role_key.clone(),
        config.supabase_publishable_key.clone(),
    ));

    let audit_recorder = build_audit_recorder(config, supabase_client.clone());

    let verified_at =
        SourceEventAt::now_utc().map_err(|error| DigestCliError::Config(error.to_string()))?;

    let request_id =
        RequestId::generate().map_err(|error| DigestCliError::Config(error.to_string()))?;

    let input = VerifyMonthlyDigestInput {
        period: period.clone(),
        request_id: request_id.clone(),
    };

    match verify_monthly_digest(&supabase_client, &input).await {
        Ok(info) => Ok(DigestVerifyOutput {
            period: period.as_str().to_owned(),
            valid: true,
            start_sequence_no: Some(info.start_sequence_no.get()),
            end_sequence_no: Some(info.end_sequence_no.get()),
            entry_count: Some(info.entry_count),
            error: None,
            error_variant: None,
        }),
        Err(error) => {
            // 検証失敗を audit_events に同期記録する
            record_monthly_digest_verify_failure_audit(
                &audit_recorder,
                &request_id,
                &period,
                &error,
                &verified_at,
            )
            .await;
            record_monthly_digest_verify_incident(config, supabase_client.clone(), &period, &error)
                .await;

            Ok(DigestVerifyOutput {
                period: period.as_str().to_owned(),
                valid: false,
                start_sequence_no: None,
                end_sequence_no: None,
                entry_count: None,
                error: Some(DigestVerifyOutputError {
                    code: error.as_error_code().to_owned(),
                    message: error.to_string(),
                }),
                error_variant: Some(error),
            })
        }
    }
}

#[derive(Debug, Serialize)]
struct DigestListOutput {
    digests: Vec<DigestListEntry>,
}

#[derive(Debug, Serialize)]
struct DigestListEntry {
    period: String,
    start_sequence_no: u64,
    end_sequence_no: u64,
    entry_count: u64,
    signature_key_version: u32,
    digest_generated_at: String,
}

async fn run_list_command(config: &AppConfig) -> Result<DigestListOutput, DigestCliError> {
    let http_client = crate::server::config::build_outbound_http_client(config)
        .map_err(|error| DigestCliError::Config(error.to_string()))?;

    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url.clone(),
        config.supabase_service_role_key.clone(),
        config.supabase_publishable_key.clone(),
    ));

    let summaries = supabase_client
        .list_monthly_digests()
        .await
        .map_err(|error| {
            tracing::error!(
                error = %error,
                error_code = "monthly_digest_list_failed",
                "monthly digest list fetch failed"
            );
            DigestCliError::ListFailed("monthly_digest_list_failed".to_owned())
        })?;

    let digests = summaries
        .into_iter()
        .map(|summary| DigestListEntry {
            period: summary.target_year_month,
            start_sequence_no: summary.start_sequence_no.get(),
            end_sequence_no: summary.end_sequence_no.get(),
            entry_count: summary.entry_count,
            signature_key_version: summary.signature_key_version.get(),
            digest_generated_at: summary.digest_generated_at.as_str().to_owned(),
        })
        .collect();

    Ok(DigestListOutput { digests })
}

fn build_audit_recorder(
    config: &AppConfig,
    supabase_client: Arc<SupabaseClient>,
) -> Arc<AuditRecorder<SupabaseAuditAppender>> {
    let audit_appender = SupabaseAuditAppender::new(supabase_client);
    let fallback_store = LocalAuditFallbackStore::with_rollover_config(
        &config.audit_fallback_path,
        &config.audit_fallback_archive_dir,
        config.audit_fallback_rotate_size_bytes,
    );
    Arc::new(AuditRecorder::new(audit_appender, fallback_store))
}

async fn record_monthly_digest_verify_incident(
    config: &AppConfig,
    supabase_client: Arc<SupabaseClient>,
    period: &MonthlyDigestPeriod,
    error: &VerifyMonthlyDigestError,
) {
    let error_code = error.as_error_code();
    let Some(incident_type) = monthly_digest_incident_type(error_code) else {
        return;
    };

    let signing_key = config.ledger_signing_key.clone();
    let signing_key_version: LedgerSignatureKeyVersion = signing_key.key_version();
    let ledger_appender = Arc::new(crate::server::ledger_appender::LedgerAppender::new(
        supabase_client.clone(),
        signing_key,
    ));
    let incident_recorder = IncidentRecorder::new(
        supabase_client,
        ledger_appender,
        DummyNotificationSink::new(),
    );
    let detection_source = "monthly_digest_verify";
    let input = IncidentRecordInput::new(
        incident_type,
        severity_for_incident(incident_type),
        detection_source,
        dedupe_key(incident_type, detection_source, Some(period)),
        error_code,
    )
    .with_target_year_month(period.clone());

    match incident_recorder.record(input).await {
        Ok(result) => {
            tracing::info!(
                period = period.as_str(),
                incident_type = incident_type.as_str(),
                notification_result = result.notification_result.as_str(),
                suppressed = result.suppressed,
                signature_key_version = signing_key_version.get(),
                "monthly digest verification incident recorded"
            );
        }
        Err(record_error) => {
            tracing::error!(
                period = period.as_str(),
                incident_type = incident_type.as_str(),
                error = %record_error,
                signature_key_version = signing_key_version.get(),
                "monthly digest verification incident recording failed"
            );
        }
    }
}

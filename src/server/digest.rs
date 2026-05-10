//! 月次 digest 生成 CLI コマンド（Ledger Phase 2 §7.3）。
//!
//! 使い方: `mipsorcu digest generate --year-month YYYY-MM [--format json]`
//!
//! 信頼境界ノート: digest 生成は SBC 内で完結する。
//! Master Key・Data Key・平文・JWT 全文を処理しない。

use std::sync::Arc;

use serde::Serialize;

use crate::audit::RequestId;
use crate::ledger::MonthlyDigestPeriod;
use crate::server::config::AppConfig;
use crate::server::supabase::SupabaseClient;
use crate::server::use_cases::generate_monthly_digest::{
    GenerateMonthlyDigestError, GenerateMonthlyDigestInput, generate_monthly_digest,
    record_monthly_digest_failure_audit,
};
use crate::types::SourceEventAt;

#[derive(Debug)]
pub enum DigestCliError {
    Usage(String),
    Config(String),
    GenerateFailed(GenerateMonthlyDigestError),
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
            "generate" if subcommand.is_none() => {
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

    match subcommand {
        Some(cmd) if cmd == "generate" => {}
        _ => return Err(DigestCliError::Usage(usage())),
    }

    let year_month = year_month.ok_or_else(|| DigestCliError::Usage(usage()))?;

    match format {
        Some(f) if f == "json" => {}
        _ => return Err(DigestCliError::Usage(usage())),
    }

    let period = MonthlyDigestPeriod::parse(&year_month)
        .map_err(|error| DigestCliError::Usage(format!("invalid --year-month: {error}")))?;

    let output = run_generate_command(&config, period).await?;
    let json_output = serde_json::to_string_pretty(&output)
        .map_err(|error| DigestCliError::Serialization(error.to_string()))?;
    println!("{json_output}");

    Ok(())
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

    let signing_key = config.ledger_signing_key.clone();
    let ledger_appender = Arc::new(
        crate::server::ledger_appender::LedgerAppender::new(supabase_client.clone(), signing_key),
    );

    let generated_at = SourceEventAt::now_utc()
        .map_err(|error| DigestCliError::Config(error.to_string()))?;

    let request_id = RequestId::generate()
        .map_err(|error| DigestCliError::Config(error.to_string()))?;

    let input = GenerateMonthlyDigestInput {
        period: period.clone(),
        generated_at: generated_at.clone(),
        request_id: request_id.clone(),
    };

    match generate_monthly_digest(&supabase_client, &ledger_appender, input).await {
        Ok(signed_digest) => Ok(DigestGenerateOutput {
            period: signed_digest.period.as_str().to_owned(),
            start_sequence_no: signed_digest.start_sequence_no.get(),
            end_sequence_no: signed_digest.end_sequence_no.get(),
            entry_count: signed_digest.entry_count,
            digest_hash: signed_digest.digest_hash.to_hex(),
            signature_key_version: signed_digest.signature_key_version.get(),
            digest_generated_at: signed_digest.digest_generated_at.as_str().to_owned(),
        }),
        Err(error) => {
            // 生成失敗を audit_events に同期記録（AGENTS.md §8 フェイルクローズ）
            record_monthly_digest_failure_audit(
                &supabase_client,
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

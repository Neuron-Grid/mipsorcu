//! 外部アーカイブ CLI コマンド。
//!
//! 使い方:
//!   mipsorcu archive send   --month YYYY-MM --format json
//!   mipsorcu archive verify --month YYYY-MM --format json
//!
//! backend は `MIPSORCU_ARCHIVE_BACKEND`（`local_dummy` | `s3_object_lock`）で
//! 選択する。S3 backend の接続情報は `MIPSORCU_ARCHIVE_S3_*`（ADR-0032 §6）から
//! 読む。
//!
//! 信頼境界ノート: `send` / `verify` は SBC 内で完結する。`ArchiveExportPackage`
//! は `SignedMonthlyDigest` からのみ構築され、平文・Master Key・Data Key・JWT を
//! 型レベルで backend へ渡せない。S3 credential は backend 内部の `SecretString`
//! に閉じ、ログ・stdout・stderr に出さない。
//!
//! ADR-0032 / ADR-0033 準拠: object key は `digests/{YYYY-MM}/digest.json`、
//! 監査は単一 `archive_export` action、ledger は `archive_exported` entry。
//! `verify` は read-only であり新規 audit action を追加せず、不一致時は incident を
//! 記録する。

use std::sync::Arc;

use serde::Serialize;

use crate::archive::{
    AnyArchiveBackend, ArchiveBackend, ArchiveExportPackage, ArchiveObjectKey,
    ArchiveVerifyOutcome, LocalFileArchiveBackend, S3ArchiveBackendConfig,
    S3ImmutableArchiveBackend,
};
use crate::audit::{AuditRecorder, LocalAuditFallbackStore, RequestId};
use crate::incident::{IncidentRecorder, archive_incident_input};
use crate::ledger::{
    DigestHash, MonthlyDigestPeriod, SignedMonthlyDigest, build_monthly_digest_canonical_form,
};
use crate::server::config::AppConfig;
use crate::server::ledger_appender::LedgerAppender;
use crate::server::supabase::{
    MonthlyDigestVerificationMaterials, SupabaseAuditAppender, SupabaseClient,
};
use crate::server::use_cases::export_digest_to_archive::{
    ExportDigestToArchiveError, export_digest_to_archive,
};
use crate::server::use_cases::verify_monthly_digest::{
    VerifyMonthlyDigestError, VerifyMonthlyDigestInput, record_monthly_digest_verify_failure_audit,
    record_monthly_digest_verify_success_audit, verify_monthly_digest,
};
use crate::types::SourceEventAt;

const ENV_ARCHIVE_BACKEND: &str = "MIPSORCU_ARCHIVE_BACKEND";
const ENV_ARCHIVE_LOCAL_DIR: &str = "MIPSORCU_ARCHIVE_LOCAL_DIR";
const DEFAULT_ARCHIVE_LOCAL_DIR: &str = "/var/lib/mipsorcu/archive";
const BACKEND_LOCAL_DUMMY: &str = "local_dummy";
const BACKEND_S3_OBJECT_LOCK: &str = "s3_object_lock";

#[derive(Debug)]
pub enum ArchiveCliError {
    Usage(String),
    Config(String),
    DigestNotFound { period: String },
    VerifyDigestFailed(VerifyMonthlyDigestError),
    ExportFailed(ExportDigestToArchiveError),
    VerifyMismatch { verify_result: &'static str },
    Serialization(String),
}

impl std::fmt::Display for ArchiveCliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::Config(message) => write!(formatter, "archive config error: {message}"),
            Self::DigestNotFound { period } => write!(
                formatter,
                "monthly digest not found for {period} (run `mipsorcu digest generate` first)"
            ),
            Self::VerifyDigestFailed(error) => {
                write!(
                    formatter,
                    "archive aborted: digest verification failed: {error}"
                )
            }
            Self::ExportFailed(error) => write!(formatter, "archive export failed: {error}"),
            Self::VerifyMismatch { verify_result } => {
                write!(formatter, "archive verification result: {verify_result}")
            }
            Self::Serialization(message) => {
                write!(formatter, "archive serialization error: {message}")
            }
        }
    }
}

impl std::error::Error for ArchiveCliError {}

pub fn usage() -> String {
    [
        "usage:",
        "  mipsorcu archive send   --month YYYY-MM --format json",
        "  mipsorcu archive verify --month YYYY-MM --format json",
    ]
    .join("\n")
}

/// archive CLI のサブコマンドと、検証済みの実行パラメータ。
#[derive(Debug, PartialEq, Eq)]
enum ArchiveCommand {
    Send { period: MonthlyDigestPeriod },
    Verify { period: MonthlyDigestPeriod },
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedArchiveArgs {
    command: ArchiveCommand,
}

/// CLI 引数を解析し、サブコマンドと検証済み期間を返す（純粋・I/O なし）。
///
/// 解析順序は既存挙動を踏襲する: 引数ループ → `--format json` 検査 →
/// サブコマンド解決 → `--month` のパース。
fn parse_archive_args(args: &[String]) -> Result<ParsedArchiveArgs, ArchiveCliError> {
    let mut subcommand: Option<&str> = None;
    let mut month: Option<String> = None;
    let mut format: Option<&String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            command @ ("send" | "verify") if subcommand.is_none() => {
                subcommand = Some(command);
            }
            "--month" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| ArchiveCliError::Usage(usage()))?;
                if value.starts_with("--") {
                    return Err(ArchiveCliError::Usage(usage()));
                }
                month = Some(value.clone());
                i += 1;
            }
            "--format" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| ArchiveCliError::Usage(usage()))?;
                if value.starts_with("--") {
                    return Err(ArchiveCliError::Usage(usage()));
                }
                format = Some(value);
                i += 1;
            }
            _ => return Err(ArchiveCliError::Usage(usage())),
        }
        i += 1;
    }

    match format {
        Some(f) if f == "json" => {}
        _ => return Err(ArchiveCliError::Usage(usage())),
    }

    let command = match subcommand {
        Some("send") => ArchiveCommand::Send {
            period: parse_period(month)?,
        },
        Some("verify") => ArchiveCommand::Verify {
            period: parse_period(month)?,
        },
        _ => return Err(ArchiveCliError::Usage(usage())),
    };

    Ok(ParsedArchiveArgs { command })
}

pub async fn run_cli(config: AppConfig, args: &[String]) -> Result<(), ArchiveCliError> {
    let ParsedArchiveArgs { command } = parse_archive_args(args)?;

    match command {
        ArchiveCommand::Send { period } => {
            let output = run_send_command(&config, period).await?;
            print_json(&output)?;
        }
        ArchiveCommand::Verify { period } => {
            let output = run_verify_command(&config, period).await?;
            print_json(&output)?;
            if output.verify_result != "match" {
                return Err(ArchiveCliError::VerifyMismatch {
                    verify_result: output.verify_result,
                });
            }
        }
    }

    Ok(())
}

fn print_json<T: Serialize>(output: &T) -> Result<(), ArchiveCliError> {
    let json_output = serde_json::to_string_pretty(output)
        .map_err(|error| ArchiveCliError::Serialization(error.to_string()))?;
    println!("{json_output}");
    Ok(())
}

/// `--month` を必須として `MonthlyDigestPeriod` にパースする。
fn parse_period(month: Option<String>) -> Result<MonthlyDigestPeriod, ArchiveCliError> {
    let month = month.ok_or_else(|| ArchiveCliError::Usage(usage()))?;
    MonthlyDigestPeriod::parse(&month)
        .map_err(|error| ArchiveCliError::Usage(format!("invalid --month: {error}")))
}

#[derive(Debug, Serialize)]
struct ArchiveSendOutput {
    period: String,
    object_key: String,
    digest_hash: String,
    backend_kind: String,
}

async fn run_send_command(
    config: &AppConfig,
    period: MonthlyDigestPeriod,
) -> Result<ArchiveSendOutput, ArchiveCliError> {
    let supabase_client = build_supabase_client(config)?;
    let audit_recorder = build_audit_recorder(config, supabase_client.clone());

    // 1. アーカイブ前に digest を検証する（不正・改ざんされた digest を保全しない）。
    let request_id =
        RequestId::generate().map_err(|error| ArchiveCliError::Config(error.to_string()))?;
    let verified_at =
        SourceEventAt::now_utc().map_err(|error| ArchiveCliError::Config(error.to_string()))?;
    let verify_input = VerifyMonthlyDigestInput {
        period: period.clone(),
        request_id: request_id.clone(),
    };
    if let Err(error) = verify_monthly_digest(&supabase_client, &verify_input).await {
        record_monthly_digest_verify_failure_audit(
            &audit_recorder,
            &request_id,
            &period,
            &error,
            &verified_at,
        )
        .await;
        return Err(ArchiveCliError::VerifyDigestFailed(error));
    }
    record_monthly_digest_verify_success_audit(&audit_recorder, &request_id, &period, &verified_at)
        .await;

    // 2. 再構成のため検証マテリアルを取得し `SignedMonthlyDigest` を復元する。
    let materials = fetch_materials(&supabase_client, &period).await?;
    let signed_digest = reconstruct_signed_digest(&materials)?;

    // 3. backend を構築する（local_dummy / s3_object_lock）。
    let backend = build_backend(config)?;
    let backend_kind = backend.kind();

    // 4. export use case（archive_export 監査 + archive_exported ledger + PUT 後 verify）。
    let ledger_appender = build_ledger_appender(config, supabase_client.clone());
    let export_request_id =
        RequestId::generate().map_err(|error| ArchiveCliError::Config(error.to_string()))?;
    let exported_at =
        SourceEventAt::now_utc().map_err(|error| ArchiveCliError::Config(error.to_string()))?;
    let key = export_digest_to_archive(
        &backend,
        &audit_recorder,
        &ledger_appender,
        &signed_digest,
        export_request_id,
        exported_at,
    )
    .await
    .map_err(ArchiveCliError::ExportFailed)?;

    Ok(ArchiveSendOutput {
        period: period.as_str().to_owned(),
        object_key: key.as_str().to_owned(),
        digest_hash: signed_digest.digest_hash.to_hex(),
        backend_kind: backend_kind.to_owned(),
    })
}

#[derive(Debug, Serialize)]
struct ArchiveVerifyOutput {
    period: String,
    object_key: String,
    verify_result: &'static str,
    backend_kind: String,
}

async fn run_verify_command(
    config: &AppConfig,
    period: MonthlyDigestPeriod,
) -> Result<ArchiveVerifyOutput, ArchiveCliError> {
    let supabase_client = build_supabase_client(config)?;
    let materials = fetch_materials(&supabase_client, &period).await?;
    let signed_digest = reconstruct_signed_digest(&materials)?;

    let package = ArchiveExportPackage::from_digest(&signed_digest)
        .map_err(|error| ArchiveCliError::Config(error.to_string()))?;
    let key = ArchiveObjectKey::for_monthly_digest(&period)
        .map_err(|error| ArchiveCliError::Config(error.to_string()))?;

    let backend = build_backend(config)?;
    let backend_kind = backend.kind();

    let (verify_result, incident_code): (&'static str, Option<&'static str>) =
        match backend.verify_object(&key, &package).await {
            Ok(ArchiveVerifyOutcome::Valid) => ("match", None),
            Ok(ArchiveVerifyOutcome::NotFound) => ("not_found", Some("archive_export_not_found")),
            Ok(ArchiveVerifyOutcome::ContentMismatch) => {
                ("mismatch", Some("archive_export_content_mismatch"))
            }
            Err(error) => {
                tracing::error!(
                    period = period.as_str(),
                    archive_key = key.as_str(),
                    error = %error,
                    error_code = "archive_export_verify_failed",
                    "archive verify backend error"
                );
                ("error", Some("archive_export_verify_failed"))
            }
        };

    if let Some(code) = incident_code {
        record_archive_verify_incident(config, supabase_client.clone(), &period, code).await;
    }

    Ok(ArchiveVerifyOutput {
        period: period.as_str().to_owned(),
        object_key: key.as_str().to_owned(),
        verify_result,
        backend_kind: backend_kind.to_owned(),
    })
}

/// 検証マテリアルから `SignedMonthlyDigest` を決定的に再構成する。
///
/// `verify_monthly_digest` 内部の canonical form 再構築と同一手順。生成時と同じ
/// 入力を `build_monthly_digest_canonical_form` に与えるため、結果の object key /
/// archive bytes は生成時と一致する（再現可能性）。
pub(crate) fn reconstruct_signed_digest(
    materials: &MonthlyDigestVerificationMaterials,
) -> Result<SignedMonthlyDigest, ArchiveCliError> {
    let canonical_bytes = build_monthly_digest_canonical_form(
        &materials.target_year_month,
        materials.start_sequence_no,
        materials.end_sequence_no,
        materials.start_entry_hash,
        materials.end_entry_hash,
        materials.stored_entry_count,
        &materials.digest_generated_at,
        materials.signature_key_version,
    )
    .map_err(|error| {
        ArchiveCliError::Config(format!("failed to rebuild digest canonical form: {error}"))
    })?;
    let digest_hash = DigestHash::from_canonical_bytes(&canonical_bytes);

    Ok(SignedMonthlyDigest {
        period: materials.target_year_month.clone(),
        start_sequence_no: materials.start_sequence_no,
        end_sequence_no: materials.end_sequence_no,
        start_entry_hash: materials.start_entry_hash,
        end_entry_hash: materials.end_entry_hash,
        entry_count: materials.stored_entry_count,
        digest_generated_at: materials.digest_generated_at.clone(),
        signature_key_version: materials.signature_key_version,
        canonical_bytes,
        digest_hash,
        sbc_signature: materials.sbc_signature,
    })
}

pub(crate) async fn fetch_materials(
    supabase_client: &Arc<SupabaseClient>,
    period: &MonthlyDigestPeriod,
) -> Result<MonthlyDigestVerificationMaterials, ArchiveCliError> {
    match supabase_client
        .fetch_monthly_digest_for_verification(period.as_str())
        .await
    {
        Ok(Some(materials)) => Ok(materials),
        Ok(None) => Err(ArchiveCliError::DigestNotFound {
            period: period.as_str().to_owned(),
        }),
        Err(error) => {
            tracing::error!(
                period = period.as_str(),
                error = %error,
                error_code = "archive_digest_fetch_failed",
                "failed to fetch monthly digest materials for archive"
            );
            Err(ArchiveCliError::Config(
                "archive_digest_fetch_failed".to_owned(),
            ))
        }
    }
}

/// `MIPSORCU_ARCHIVE_BACKEND` に従って backend を構築する。
///
/// 値は必須（誤って production digest を local_dummy へ送ることを防ぐ）。
/// S3 接続情報・credential は process 環境変数（`MIPSORCU_ARCHIVE_S3_*`）から読み、
/// backend 内部の `SecretString` に閉じる。
pub(crate) fn build_backend(config: &AppConfig) -> Result<AnyArchiveBackend, ArchiveCliError> {
    let backend_kind = std::env::var(ENV_ARCHIVE_BACKEND)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());

    match backend_kind.as_deref() {
        Some(BACKEND_LOCAL_DUMMY) => {
            let dir = std::env::var(ENV_ARCHIVE_LOCAL_DIR)
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| DEFAULT_ARCHIVE_LOCAL_DIR.to_owned());
            Ok(AnyArchiveBackend::LocalFile(LocalFileArchiveBackend::new(
                dir,
            )))
        }
        Some(BACKEND_S3_OBJECT_LOCK) => {
            let s3_config = S3ArchiveBackendConfig::from_env(|name| std::env::var(name).ok())
                .map_err(|error| ArchiveCliError::Config(error.to_string()))?;
            let http_client = crate::server::config::build_outbound_http_client(config)
                .map_err(|error| ArchiveCliError::Config(error.to_string()))?;
            Ok(AnyArchiveBackend::S3(Box::new(
                S3ImmutableArchiveBackend::new(s3_config, http_client),
            )))
        }
        Some(other) => Err(ArchiveCliError::Config(format!(
            "{ENV_ARCHIVE_BACKEND} has unsupported value '{other}' (expected '{BACKEND_LOCAL_DUMMY}' or '{BACKEND_S3_OBJECT_LOCK}')"
        ))),
        None => Err(ArchiveCliError::Config(format!(
            "{ENV_ARCHIVE_BACKEND} must be set to '{BACKEND_LOCAL_DUMMY}' or '{BACKEND_S3_OBJECT_LOCK}'"
        ))),
    }
}

/// archive verify 失敗（未検出・内容不一致・backend エラー）を incident として
/// 記録する。新規 audit action は追加せず、`incident_detected` 経路を再利用する。
async fn record_archive_verify_incident(
    config: &AppConfig,
    supabase_client: Arc<SupabaseClient>,
    period: &MonthlyDigestPeriod,
    error_code: &str,
) {
    let Some(input) = archive_incident_input("archive_verify", error_code, period) else {
        return;
    };

    let signing_key = config.ledger_signing_key.clone();
    let ledger_appender = Arc::new(LedgerAppender::new(supabase_client.clone(), signing_key));
    let incident_recorder = IncidentRecorder::new(supabase_client, ledger_appender, "none");

    match incident_recorder.record(input).await {
        Ok(result) => {
            tracing::info!(
                period = period.as_str(),
                error_code,
                notification_result = result.notification_result.as_str(),
                suppressed = result.suppressed,
                "archive verify incident recorded"
            );
        }
        Err(record_error) => {
            tracing::error!(
                period = period.as_str(),
                error_code,
                error = %record_error,
                "archive verify incident recording failed"
            );
        }
    }
}

pub(crate) fn build_supabase_client(
    config: &AppConfig,
) -> Result<Arc<SupabaseClient>, ArchiveCliError> {
    let http_client = crate::server::config::build_outbound_http_client(config)
        .map_err(|error| ArchiveCliError::Config(error.to_string()))?;
    Ok(Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url.clone(),
        config.supabase_service_role_key.clone(),
        config.supabase_publishable_key.clone(),
    )))
}

pub(crate) fn build_audit_recorder(
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

pub(crate) fn build_ledger_appender(
    config: &AppConfig,
    supabase_client: Arc<SupabaseClient>,
) -> Arc<LedgerAppender> {
    Arc::new(LedgerAppender::new(
        supabase_client,
        config.ledger_signing_key.clone(),
    ))
}

#[cfg(test)]
#[path = "../../tests/unit/server/archive/tests.rs"]
mod tests;

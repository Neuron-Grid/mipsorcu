//! 外部 timestamping CLI コマンド（task-11、ADR-0040）。
//!
//! 使い方:
//!   mipsorcu timestamping send   --month YYYY-MM --format json
//!   mipsorcu timestamping verify --month YYYY-MM --format json
//!
//! provider は `MIPSORCU_TIMESTAMPING_PROVIDER`（`local_dummy` | `rfc3161`）で選択する。
//! RFC 3161 の TSA URL は `MIPSORCU_TSA_URL`（`,` 区切りで複数指定可、順次 fallback）。
//! credential は `MIPSORCU_TSA_USERNAME` / `MIPSORCU_TSA_PASSWORD`（任意、ログに出さない）。
//! TSA token の保管先 archive backend は `MIPSORCU_ARCHIVE_BACKEND`（archive CLI と共通）。
//!
//! 信頼境界ノート: backend へ渡るのは `&DigestHash`（32B SHA3-256）と token のみ。
//! 平文・鍵・JWT・TSA credential を型レベル / ログレベルで漏らさない。`send` は
//! `digest_timestamped` ledger + `digest_timestamping` 監査を記録し（use case 経由）、
//! 取得した token を archive の opaque object 経路で保管する。`verify` は read-only で
//! あり新規 audit action を足さず、不一致時は既存 `incident_detected` 経路に記録する。

use std::sync::Arc;

use serde::Serialize;

use crate::archive::{ArchiveBackend, ArchiveObjectKey, ArchiveOpaqueObject};
use crate::audit::RequestId;
use crate::incident::{IncidentRecorder, digest_timestamping_incident_input};
use crate::ledger::MonthlyDigestPeriod;
use crate::server::archive::{
    ArchiveCliError, build_audit_recorder, build_backend, build_ledger_appender,
    build_supabase_client, fetch_materials, reconstruct_signed_digest,
};
use crate::server::config::AppConfig;
use crate::server::ledger_appender::LedgerAppender;
use crate::server::supabase::SupabaseClient;
use crate::server::use_cases::request_timestamping_for_digest::{
    RequestTimestampingError, request_timestamping_for_digest,
};
use crate::server::use_cases::verify_monthly_digest::{
    VerifyMonthlyDigestInput, record_monthly_digest_verify_failure_audit,
    record_monthly_digest_verify_success_audit, verify_monthly_digest,
};
use crate::timestamping::{
    AnyTimestampingProvider, InMemoryTimestampingService, RetryingTimestampingService,
    Rfc3161TimestampingService, TimestampVerification, TimestampingRetryPolicy,
    TimestampingService, TimestampingToken, TimestampingTokenHash, TsaCredentials,
};
use crate::types::{SecretString, SourceEventAt};

const ENV_PROVIDER: &str = "MIPSORCU_TIMESTAMPING_PROVIDER";
const ENV_TSA_URL: &str = "MIPSORCU_TSA_URL";
const ENV_TSA_USERNAME: &str = "MIPSORCU_TSA_USERNAME";
const ENV_TSA_PASSWORD: &str = "MIPSORCU_TSA_PASSWORD";
const PROVIDER_LOCAL_DUMMY: &str = "local_dummy";
const PROVIDER_RFC3161: &str = "rfc3161";

#[derive(Debug)]
pub enum TimestampingCliError {
    Usage(String),
    Config(String),
    DigestNotFound { period: String },
    VerifyDigestFailed(String),
    RequestFailed(String),
    ArchivePersistFailed(String),
    VerifyNotValid { verify_result: String },
    Serialization(String),
}

impl std::fmt::Display for TimestampingCliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::Config(message) => write!(formatter, "timestamping config error: {message}"),
            Self::DigestNotFound { period } => write!(
                formatter,
                "monthly digest not found for {period} (run `mipsorcu digest generate` first)"
            ),
            Self::VerifyDigestFailed(message) => write!(
                formatter,
                "timestamping aborted: digest verification failed: {message}"
            ),
            Self::RequestFailed(message) => {
                write!(formatter, "timestamping request failed: {message}")
            }
            Self::ArchivePersistFailed(message) => write!(
                formatter,
                "timestamping token archive persistence failed: {message}"
            ),
            Self::VerifyNotValid { verify_result } => {
                write!(
                    formatter,
                    "timestamping verification result: {verify_result}"
                )
            }
            Self::Serialization(message) => {
                write!(formatter, "timestamping serialization error: {message}")
            }
        }
    }
}

impl std::error::Error for TimestampingCliError {}

impl From<ArchiveCliError> for TimestampingCliError {
    fn from(error: ArchiveCliError) -> Self {
        match error {
            ArchiveCliError::DigestNotFound { period } => Self::DigestNotFound { period },
            other => Self::Config(other.to_string()),
        }
    }
}

pub fn usage() -> String {
    [
        "usage:",
        "  mipsorcu timestamping send   --month YYYY-MM --format json",
        "  mipsorcu timestamping verify --month YYYY-MM --format json",
    ]
    .join("\n")
}

/// timestamping CLI のサブコマンドと、検証済みの実行パラメータ。
#[derive(Debug, PartialEq, Eq)]
enum TimestampingCommand {
    Send { period: MonthlyDigestPeriod },
    Verify { period: MonthlyDigestPeriod },
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedTimestampingArgs {
    command: TimestampingCommand,
}

/// CLI 引数を解析し、サブコマンドと検証済み期間を返す（純粋・I/O なし）。
///
/// 解析順序は既存挙動を踏襲する: 引数ループ → `--format json` 検査 →
/// サブコマンド解決 → `--month` のパース。
fn parse_timestamping_args(
    args: &[String],
) -> Result<ParsedTimestampingArgs, TimestampingCliError> {
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
                    .ok_or_else(|| TimestampingCliError::Usage(usage()))?;
                if value.starts_with("--") {
                    return Err(TimestampingCliError::Usage(usage()));
                }
                month = Some(value.clone());
                i += 1;
            }
            "--format" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| TimestampingCliError::Usage(usage()))?;
                if value.starts_with("--") {
                    return Err(TimestampingCliError::Usage(usage()));
                }
                format = Some(value);
                i += 1;
            }
            _ => return Err(TimestampingCliError::Usage(usage())),
        }
        i += 1;
    }

    match format {
        Some(f) if f == "json" => {}
        _ => return Err(TimestampingCliError::Usage(usage())),
    }

    let command = match subcommand {
        Some("send") => TimestampingCommand::Send {
            period: parse_period(month)?,
        },
        Some("verify") => TimestampingCommand::Verify {
            period: parse_period(month)?,
        },
        _ => return Err(TimestampingCliError::Usage(usage())),
    };

    Ok(ParsedTimestampingArgs { command })
}

pub async fn run_cli(config: AppConfig, args: &[String]) -> Result<(), TimestampingCliError> {
    let ParsedTimestampingArgs { command } = parse_timestamping_args(args)?;

    match command {
        TimestampingCommand::Send { period } => {
            let output = run_send_command(&config, period).await?;
            print_json(&output)?;
        }
        TimestampingCommand::Verify { period } => {
            let output = run_verify_command(&config, period).await?;
            print_json(&output)?;
            if output.verify_result != "valid" {
                return Err(TimestampingCliError::VerifyNotValid {
                    verify_result: output.verify_result,
                });
            }
        }
    }

    Ok(())
}

fn print_json<T: Serialize>(output: &T) -> Result<(), TimestampingCliError> {
    let json_output = serde_json::to_string_pretty(output)
        .map_err(|error| TimestampingCliError::Serialization(error.to_string()))?;
    println!("{json_output}");
    Ok(())
}

fn parse_period(month: Option<String>) -> Result<MonthlyDigestPeriod, TimestampingCliError> {
    let month = month.ok_or_else(|| TimestampingCliError::Usage(usage()))?;
    MonthlyDigestPeriod::parse(&month)
        .map_err(|error| TimestampingCliError::Usage(format!("invalid --month: {error}")))
}

#[derive(Debug, Serialize)]
struct TimestampingSendOutput {
    period: String,
    digest_hash: String,
    provider_kind: String,
    archive_object_key: String,
    timestamp_token_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tsa_serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gen_time: Option<String>,
}

async fn run_send_command(
    config: &AppConfig,
    period: MonthlyDigestPeriod,
) -> Result<TimestampingSendOutput, TimestampingCliError> {
    let supabase_client = build_supabase_client(config)?;
    let audit_recorder = build_audit_recorder(config, supabase_client.clone());

    // 1. timestamping 前に digest を検証する（改ざんされた digest を timestamping しない）。
    let request_id =
        RequestId::generate().map_err(|error| TimestampingCliError::Config(error.to_string()))?;
    let verified_at = SourceEventAt::now_utc()
        .map_err(|error| TimestampingCliError::Config(error.to_string()))?;
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
        return Err(TimestampingCliError::VerifyDigestFailed(error.to_string()));
    }
    record_monthly_digest_verify_success_audit(&audit_recorder, &request_id, &period, &verified_at)
        .await;

    // 2. 検証マテリアルから SignedMonthlyDigest を決定的に再構成する（digest_hash を得る）。
    let materials = fetch_materials(&supabase_client, &period).await?;
    let signed_digest = reconstruct_signed_digest(&materials)?;

    // 3. provider を env から構築する（local_dummy / rfc3161）。
    let provider = build_provider(config)?;
    let provider_kind = provider.kind_label().to_owned();

    // 4. timestamping 要求（digest_timestamped ledger + digest_timestamping 監査）。
    let ledger_appender = build_ledger_appender(config, supabase_client.clone());
    let request_timestamping_id =
        RequestId::generate().map_err(|error| TimestampingCliError::Config(error.to_string()))?;
    let requested_at = SourceEventAt::now_utc()
        .map_err(|error| TimestampingCliError::Config(error.to_string()))?;
    let token = request_timestamping_for_digest(
        &provider,
        &audit_recorder,
        &ledger_appender,
        &signed_digest,
        request_timestamping_id,
        requested_at,
    )
    .await
    .map_err(map_request_error)?;

    let token_hash_hex = TimestampingTokenHash::from_token(&token).to_hex();

    // 5. TSA token を archive の opaque object 経路で保管する（§6.2.3）。
    let backend = build_backend(config)?;
    let object_key = ArchiveObjectKey::for_timestamping_token(&period)
        .map_err(|error| TimestampingCliError::Config(error.to_string()))?;
    let object = ArchiveOpaqueObject::from_timestamping_token(&token);
    backend
        .put_opaque_object(&object_key, &object)
        .await
        .map_err(|error| TimestampingCliError::ArchivePersistFailed(error.to_string()))?;

    // 6. 取得した token を自己検証し、serial / gen_time を出力に載せる（best-effort）。
    let (tsa_serial, gen_time) = match provider
        .verify_timestamp(&token, &signed_digest.digest_hash)
        .await
    {
        Ok(TimestampVerification::Valid(meta)) => (Some(meta.tsa_serial_hex), meta.gen_time),
        Ok(TimestampVerification::Invalid { failure_kind }) => {
            tracing::warn!(
                period = period.as_str(),
                failure_kind = failure_kind.as_str(),
                "obtained timestamp token failed self-verification"
            );
            (None, None)
        }
        Err(error) => {
            tracing::warn!(period = period.as_str(), error = %error, "self-verification of obtained token errored");
            (None, None)
        }
    };

    Ok(TimestampingSendOutput {
        period: period.as_str().to_owned(),
        digest_hash: signed_digest.digest_hash.to_hex(),
        provider_kind,
        archive_object_key: object_key.as_str().to_owned(),
        timestamp_token_hash: token_hash_hex,
        tsa_serial,
        gen_time,
    })
}

#[derive(Debug, Serialize)]
struct TimestampingVerifyOutput {
    period: String,
    object_key: String,
    verify_result: String,
    provider_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tsa_serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gen_time: Option<String>,
}

async fn run_verify_command(
    config: &AppConfig,
    period: MonthlyDigestPeriod,
) -> Result<TimestampingVerifyOutput, TimestampingCliError> {
    let supabase_client = build_supabase_client(config)?;
    let materials = fetch_materials(&supabase_client, &period).await?;
    let signed_digest = reconstruct_signed_digest(&materials)?;

    let provider = build_provider(config)?;
    let provider_kind = provider.kind_label().to_owned();

    let backend = build_backend(config)?;
    let object_key = ArchiveObjectKey::for_timestamping_token(&period)
        .map_err(|error| TimestampingCliError::Config(error.to_string()))?;

    let stored = backend
        .get_opaque_object(&object_key)
        .await
        .map_err(|error| TimestampingCliError::Config(error.to_string()))?;

    let (verify_result, incident_code, tsa_serial, gen_time): (
        &'static str,
        Option<&'static str>,
        Option<String>,
        Option<String>,
    ) = match stored {
        None => (
            "not_found",
            Some("digest_timestamping_verify_not_found"),
            None,
            None,
        ),
        Some(bytes) => match TimestampingToken::new(bytes) {
            Err(_) => (
                "invalid",
                Some("digest_timestamping_verify_invalid"),
                None,
                None,
            ),
            Ok(token) => match provider
                .verify_timestamp(&token, &signed_digest.digest_hash)
                .await
            {
                Ok(TimestampVerification::Valid(meta)) => {
                    ("valid", None, Some(meta.tsa_serial_hex), meta.gen_time)
                }
                Ok(TimestampVerification::Invalid { failure_kind }) => {
                    tracing::warn!(
                        period = period.as_str(),
                        failure_kind = failure_kind.as_str(),
                        "stored timestamp token failed verification"
                    );
                    (
                        "invalid",
                        Some("digest_timestamping_verify_invalid"),
                        None,
                        None,
                    )
                }
                Err(error) => {
                    tracing::error!(period = period.as_str(), error = %error, "timestamp verify backend error");
                    (
                        "error",
                        Some("digest_timestamping_verify_failed"),
                        None,
                        None,
                    )
                }
            },
        },
    };

    if let Some(code) = incident_code {
        record_timestamping_verify_incident(config, supabase_client.clone(), &period, code).await;
    }

    Ok(TimestampingVerifyOutput {
        period: period.as_str().to_owned(),
        object_key: object_key.as_str().to_owned(),
        verify_result: verify_result.to_owned(),
        provider_kind,
        tsa_serial,
        gen_time,
    })
}

/// `RequestTimestampingError` を CLI エラーへ変換する（error code のみ、秘密を含まない）。
fn map_request_error(error: RequestTimestampingError) -> TimestampingCliError {
    TimestampingCliError::RequestFailed(error.as_error_code().to_owned())
}

/// `MIPSORCU_TIMESTAMPING_PROVIDER` に従って provider を構築する。
///
/// 値は必須（誤って production digest を dummy provider へ送らないため）。
/// rfc3161 の場合 `MIPSORCU_TSA_URL`（`,` 区切り）を必須とし、credential は
/// `SecretString` に閉じる。
pub(crate) fn build_provider(
    config: &AppConfig,
) -> Result<AnyTimestampingProvider, TimestampingCliError> {
    let provider_kind = std::env::var(ENV_PROVIDER)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());

    match provider_kind.as_deref() {
        Some(PROVIDER_LOCAL_DUMMY) => Ok(AnyTimestampingProvider::LocalDummy(
            InMemoryTimestampingService::new(),
        )),
        Some(PROVIDER_RFC3161) => {
            let urls = parse_tsa_urls()?;
            let credentials = parse_tsa_credentials()?;
            let http_client = crate::server::config::build_outbound_http_client(config)
                .map_err(|error| TimestampingCliError::Config(error.to_string()))?;
            let backends = urls
                .into_iter()
                .map(|url| {
                    Rfc3161TimestampingService::new(http_client.clone(), url, credentials.clone())
                })
                .collect::<Vec<_>>();
            Ok(AnyTimestampingProvider::Rfc3161(
                RetryingTimestampingService::new(backends, TimestampingRetryPolicy::default()),
            ))
        }
        Some(other) => Err(TimestampingCliError::Config(format!(
            "{ENV_PROVIDER} has unsupported value '{other}' (expected '{PROVIDER_LOCAL_DUMMY}' or '{PROVIDER_RFC3161}')"
        ))),
        None => Err(TimestampingCliError::Config(format!(
            "{ENV_PROVIDER} must be set to '{PROVIDER_LOCAL_DUMMY}' or '{PROVIDER_RFC3161}'"
        ))),
    }
}

/// `MIPSORCU_TSA_URL`（`,` 区切り）から fallback 順の URL 列を取り出す。
fn parse_tsa_urls() -> Result<Vec<String>, TimestampingCliError> {
    let raw = std::env::var(ENV_TSA_URL)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            TimestampingCliError::Config(format!(
                "{ENV_TSA_URL} must be set for the rfc3161 provider"
            ))
        })?;
    let urls = raw
        .split(',')
        .map(|url| url.trim().to_owned())
        .filter(|url| !url.is_empty())
        .collect::<Vec<_>>();
    if urls.is_empty() {
        return Err(TimestampingCliError::Config(format!(
            "{ENV_TSA_URL} did not contain any non-empty TSA URL"
        )));
    }
    Ok(urls)
}

/// 任意の TSA Basic 認証 credential を読む。password は `SecretString` に閉じる。
fn parse_tsa_credentials() -> Result<Option<TsaCredentials>, TimestampingCliError> {
    let username = std::env::var(ENV_TSA_USERNAME)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let password = std::env::var(ENV_TSA_PASSWORD)
        .ok()
        .filter(|value| !value.is_empty());

    match (username, password) {
        (Some(username), Some(password)) => {
            let secret = SecretString::new(password).map_err(|error| {
                TimestampingCliError::Config(format!("{ENV_TSA_PASSWORD}: {error}"))
            })?;
            Ok(Some(TsaCredentials::new(username, secret)))
        }
        (None, None) => Ok(None),
        _ => Err(TimestampingCliError::Config(format!(
            "{ENV_TSA_USERNAME} and {ENV_TSA_PASSWORD} must be set together or not at all"
        ))),
    }
}

/// timestamping verify 失敗（未検出・無効・backend エラー）を incident として記録する。
/// 新規 audit action は追加せず、既存 `incident_detected` 経路を再利用する（archive と同方針）。
async fn record_timestamping_verify_incident(
    config: &AppConfig,
    supabase_client: Arc<SupabaseClient>,
    period: &MonthlyDigestPeriod,
    error_code: &str,
) {
    let Some(input) =
        digest_timestamping_incident_input("digest_timestamping_verify", error_code, period)
    else {
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
                "timestamping verify incident recorded"
            );
        }
        Err(record_error) => {
            tracing::error!(
                period = period.as_str(),
                error_code,
                error = %record_error,
                "timestamping verify incident recording failed"
            );
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/server/timestamping/tests.rs"]
mod tests;

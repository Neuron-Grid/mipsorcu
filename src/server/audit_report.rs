//! Audit report generation CLI.
//!
//! 信頼境界ノート: レポートは Supabase から取得した非秘密メタデータのみで構成する。
//! 平文・Master Key・Data Key・JWT 全文・service_role key は出力しない。

use std::sync::Arc;

use serde::Serialize;

use crate::audit::{
    AuditAction, AuditRecordError, AuditRecordOutcome, AuditRecorder, AuditReportGenerateMetadata,
    AuditResult, LocalAuditFallbackStore, RequestId,
};
use crate::ledger::{
    LedgerChainHead, LedgerError, LedgerSequenceNo, LedgerVerifyingKey, SignedLedgerEntry,
    verify_ledger_chain,
};
use crate::server::audit_reporter::{OperationalAuditEvent, build_operational_audit_event};
use crate::server::config::AppConfig;
use crate::server::supabase::{
    AuditReportSummary, LedgerVerificationMaterialRow, SupabaseAuditAppender, SupabaseClient,
    VerificationFailureReportItem,
};
use crate::types::SourceEventAt;

#[derive(Debug)]
pub enum AuditReportCliError {
    AuditRecordFailed(AuditRecordError),
    Config(String),
    FetchFailed(String),
    Serialization(String),
    Usage(String),
}

impl std::fmt::Display for AuditReportCliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuditRecordFailed(error) => {
                write!(formatter, "audit report audit record failed: {error}")
            }
            Self::Config(message) => write!(formatter, "audit report config error: {message}"),
            Self::FetchFailed(message) => write!(formatter, "audit report fetch failed: {message}"),
            Self::Serialization(message) => {
                write!(formatter, "audit report serialization error: {message}")
            }
            Self::Usage(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for AuditReportCliError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditReportFormat {
    Json,
    Markdown,
}

impl AuditReportFormat {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "json" => Some(Self::Json),
            "markdown" => Some(Self::Markdown),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Markdown => "markdown",
        }
    }
}

#[derive(Debug, Serialize)]
struct AuditReportJson {
    audit_event_count: u64,
    hash_chain_verification: crate::server::supabase::HashChainVerificationSummary,
    integrity_check_status: CheckStatus,
    integrity_checks: Vec<crate::server::supabase::IntegrityCheckReportItem>,
    ledger_entry_count: u64,
    monthly_digests: Vec<crate::server::supabase::MonthlyDigestReportItem>,
    period_end: String,
    period_start: String,
    restore_test_status: CheckStatus,
    restore_tests: Vec<crate::server::supabase::RestoreTestReportItem>,
    secret_count: u64,
    sequence_end: Option<u64>,
    sequence_start: Option<u64>,
    signature_key_versions: Vec<crate::server::supabase::SignatureKeyVersionReportItem>,
    signature_verification: SignatureVerificationSummary,
    verification_failures: Vec<crate::server::supabase::VerificationFailureReportItem>,
}

#[derive(Debug, Serialize)]
struct CheckStatus {
    latest_result: Option<String>,
    performed: bool,
    total_count: u64,
}

#[derive(Debug, Serialize)]
struct SignatureVerificationSummary {
    checked_count: u64,
    detail: Option<String>,
    valid: bool,
}

pub fn usage() -> String {
    [
        "usage:",
        "  mipsorcu audit-report generate --from RFC3339_UTC --to RFC3339_UTC --format json",
        "  mipsorcu audit-report generate --from RFC3339_UTC --to RFC3339_UTC --format markdown",
    ]
    .join("\n")
}

/// audit-report CLI 引数の解析・検証結果（生成に必要な確定値）。
struct ParsedAuditReportArgs {
    period_start: SourceEventAt,
    period_end: SourceEventAt,
    format: AuditReportFormat,
}

/// audit-report CLI 引数を解析・検証し、期間と出力形式の確定値を返す。
fn parse_audit_report_args(args: &[String]) -> Result<ParsedAuditReportArgs, AuditReportCliError> {
    let mut subcommand: Option<&String> = None;
    let mut period_start: Option<String> = None;
    let mut period_end: Option<String> = None;
    let mut format: Option<AuditReportFormat> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "generate" if subcommand.is_none() => subcommand = Some(arg),
            "--from" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| AuditReportCliError::Usage(usage()))?;
                if value.starts_with("--") {
                    return Err(AuditReportCliError::Usage(usage()));
                }
                period_start = Some(value.clone());
                i += 1;
            }
            "--to" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| AuditReportCliError::Usage(usage()))?;
                if value.starts_with("--") {
                    return Err(AuditReportCliError::Usage(usage()));
                }
                period_end = Some(value.clone());
                i += 1;
            }
            "--format" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| AuditReportCliError::Usage(usage()))?;
                if value.starts_with("--") {
                    return Err(AuditReportCliError::Usage(usage()));
                }
                format = AuditReportFormat::parse(value);
                if format.is_none() {
                    return Err(AuditReportCliError::Usage(usage()));
                }
                i += 1;
            }
            _ => return Err(AuditReportCliError::Usage(usage())),
        }
        i += 1;
    }

    match subcommand {
        Some(command) if command == "generate" => {}
        _ => return Err(AuditReportCliError::Usage(usage())),
    }

    let period_start_raw = period_start.ok_or_else(|| AuditReportCliError::Usage(usage()))?;
    let period_end_raw = period_end.ok_or_else(|| AuditReportCliError::Usage(usage()))?;
    let format = format.ok_or_else(|| AuditReportCliError::Usage(usage()))?;
    let period_start = SourceEventAt::parse(&period_start_raw)
        .map_err(|error| AuditReportCliError::Usage(format!("invalid --from: {error}")))?;
    let period_end = SourceEventAt::parse(&period_end_raw)
        .map_err(|error| AuditReportCliError::Usage(format!("invalid --to: {error}")))?;
    if period_start.as_str() >= period_end.as_str() {
        return Err(AuditReportCliError::Usage(
            "--from must be earlier than --to".to_owned(),
        ));
    }

    Ok(ParsedAuditReportArgs {
        period_start,
        period_end,
        format,
    })
}

pub async fn run_cli(config: AppConfig, args: &[String]) -> Result<(), AuditReportCliError> {
    let ParsedAuditReportArgs {
        period_start,
        period_end,
        format,
    } = parse_audit_report_args(args)?;

    let http_client = crate::server::config::build_outbound_http_client(&config)
        .map_err(|error| AuditReportCliError::Config(error.to_string()))?;
    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url.clone(),
        config.supabase_service_role_key.clone(),
        config.supabase_publishable_key.clone(),
    ));
    let audit_recorder = build_audit_recorder(&config, supabase_client.clone());
    let request_id =
        RequestId::generate().map_err(|error| AuditReportCliError::Config(error.to_string()))?;
    let source_event_at =
        SourceEventAt::now_utc().map_err(|error| AuditReportCliError::Config(error.to_string()))?;

    let mut summary = match supabase_client
        .fetch_audit_report_summary(period_start.as_str(), period_end.as_str())
        .await
    {
        Ok(summary) => summary,
        Err(error) => {
            record_audit_report_generation(
                &audit_recorder,
                &request_id,
                format,
                &period_start,
                &period_end,
                &source_event_at,
                AuditResult::Failure,
                Some("audit_report_fetch_failed"),
            )
            .await?;
            return Err(AuditReportCliError::FetchFailed(error.to_string()));
        }
    };

    let signature_verification =
        match verify_signatures_for_summary(&supabase_client, &mut summary).await {
            Ok(summary) => summary,
            Err(error) => {
                record_audit_report_generation(
                    &audit_recorder,
                    &request_id,
                    format,
                    &period_start,
                    &period_end,
                    &source_event_at,
                    AuditResult::Failure,
                    Some("audit_report_signature_verification_failed"),
                )
                .await?;
                return Err(error);
            }
        };

    let report = build_report(summary, signature_verification);
    let output = match format {
        AuditReportFormat::Json => render_json(&report)?,
        AuditReportFormat::Markdown => render_markdown(&report),
    };

    record_audit_report_generation(
        &audit_recorder,
        &request_id,
        format,
        &period_start,
        &period_end,
        &source_event_at,
        AuditResult::Success,
        None,
    )
    .await?;

    print!("{output}");
    Ok(())
}

fn build_report(
    summary: AuditReportSummary,
    signature_verification: SignatureVerificationSummary,
) -> AuditReportJson {
    let restore_test_status = CheckStatus {
        latest_result: summary.restore_tests.last().map(|item| item.result.clone()),
        performed: !summary.restore_tests.is_empty(),
        total_count: summary.restore_tests.len() as u64,
    };
    let integrity_check_status = CheckStatus {
        latest_result: summary
            .integrity_checks
            .last()
            .map(|item| item.result.clone()),
        performed: !summary.integrity_checks.is_empty(),
        total_count: summary.integrity_checks.len() as u64,
    };
    AuditReportJson {
        audit_event_count: summary.audit_event_count,
        hash_chain_verification: summary.hash_chain_verification,
        integrity_check_status,
        integrity_checks: summary.integrity_checks,
        ledger_entry_count: summary.ledger_entry_count,
        monthly_digests: summary.monthly_digests,
        period_end: summary.period_end,
        period_start: summary.period_start,
        restore_test_status,
        restore_tests: summary.restore_tests,
        secret_count: summary.secret_count,
        sequence_end: summary.sequence_end,
        sequence_start: summary.sequence_start,
        signature_key_versions: summary.signature_key_versions,
        signature_verification,
        verification_failures: summary.verification_failures,
    }
}

async fn verify_signatures_for_summary(
    supabase_client: &SupabaseClient,
    summary: &mut AuditReportSummary,
) -> Result<SignatureVerificationSummary, AuditReportCliError> {
    let (Some(sequence_start), Some(sequence_end)) = (summary.sequence_start, summary.sequence_end)
    else {
        return Ok(SignatureVerificationSummary {
            checked_count: 0,
            detail: Some("no ledger entries in period".to_owned()),
            valid: true,
        });
    };

    let start = LedgerSequenceNo::new(sequence_start)
        .map_err(|error| AuditReportCliError::FetchFailed(error.to_string()))?;
    let end = LedgerSequenceNo::new(sequence_end)
        .map_err(|error| AuditReportCliError::FetchFailed(error.to_string()))?;
    let rows = supabase_client
        .export_ledger_verification_materials(start, end)
        .await
        .map_err(|error| AuditReportCliError::FetchFailed(error.to_string()))?;

    if rows.is_empty() {
        let failure = signature_failure_item(
            "ledger_export_empty",
            summary.period_end.clone(),
            Some(sequence_start),
        );
        summary.verification_failures.push(failure);
        return Ok(SignatureVerificationSummary {
            checked_count: 0,
            detail: Some(
                "ledger_export_empty at sequence ".to_owned() + &sequence_start.to_string(),
            ),
            valid: false,
        });
    }

    let (entries, verification_keys) = match restore_entries_and_keys_for_summary(&rows, summary) {
        RestoreOutcome::Restored {
            entries,
            verification_keys,
        } => (entries, verification_keys),
        RestoreOutcome::Failed(summary_result) => return Ok(summary_result),
    };

    build_signature_summary_from_chain(&entries, &verification_keys, summary, sequence_start)
}

/// export 行から署名済みエントリと検証鍵を復元する。途中の復元失敗は失敗サマリとして返す。
enum RestoreOutcome {
    Restored {
        entries: Vec<SignedLedgerEntry>,
        verification_keys: Vec<LedgerVerifyingKey>,
    },
    Failed(SignatureVerificationSummary),
}

fn restore_entries_and_keys_for_summary(
    rows: &[LedgerVerificationMaterialRow],
    summary: &mut AuditReportSummary,
) -> RestoreOutcome {
    let mut entries = Vec::with_capacity(rows.len());
    let mut verification_keys: Vec<LedgerVerifyingKey> = Vec::new();
    for row in rows {
        let entry = match row.try_restore_signed_ledger_entry() {
            Ok(entry) => entry,
            Err(error) => {
                let (code, sequence_no) =
                    map_ledger_error_to_code_and_sequence(&error, Some(row.sequence_no.get()));
                summary.verification_failures.push(signature_failure_item(
                    &code,
                    row.source_event_at.clone(),
                    Some(sequence_no),
                ));
                return RestoreOutcome::Failed(SignatureVerificationSummary {
                    checked_count: entries.len() as u64,
                    detail: Some(format!("{code} at sequence {sequence_no}")),
                    valid: false,
                });
            }
        };
        entries.push(entry);

        let maybe_key = match row.try_restore_verifying_key() {
            Ok(key) => key,
            Err(error) => {
                let (code, sequence_no) =
                    map_ledger_error_to_code_and_sequence(&error, Some(row.sequence_no.get()));
                summary.verification_failures.push(signature_failure_item(
                    &code,
                    row.source_event_at.clone(),
                    Some(sequence_no),
                ));
                return RestoreOutcome::Failed(SignatureVerificationSummary {
                    checked_count: entries.len() as u64,
                    detail: Some(format!("{code} at sequence {sequence_no}")),
                    valid: false,
                });
            }
        };
        if let Some(key) = maybe_key
            && !verification_keys
                .iter()
                .any(|existing| existing.key_version() == key.key_version())
        {
            verification_keys.push(key);
        }
    }

    RestoreOutcome::Restored {
        entries,
        verification_keys,
    }
}

/// 復元済みエントリと検証鍵で署名チェーン検証を実行し、署名サマリを組み立てる。
fn build_signature_summary_from_chain(
    entries: &[SignedLedgerEntry],
    verification_keys: &[LedgerVerifyingKey],
    summary: &mut AuditReportSummary,
    sequence_start: u64,
) -> Result<SignatureVerificationSummary, AuditReportCliError> {
    let initial_head = initial_head_for_report_range(sequence_start, entries)?;
    match verify_ledger_chain(entries, initial_head, verification_keys) {
        Ok(_) => Ok(SignatureVerificationSummary {
            checked_count: entries.len() as u64,
            detail: None,
            valid: true,
        }),
        Err(error) => {
            let (code, sequence_no) = map_ledger_error_to_code_and_sequence(&error, None);
            let occurred_at = entries
                .iter()
                .find(|entry| entry.sequence_no().get() == sequence_no)
                .map(|entry| entry.source_event_at().as_str().to_owned())
                .unwrap_or_else(|| summary.period_end.clone());
            summary.verification_failures.push(signature_failure_item(
                &code,
                occurred_at,
                Some(sequence_no),
            ));
            Ok(SignatureVerificationSummary {
                checked_count: entries.len() as u64,
                detail: Some(format!("{code} at sequence {sequence_no}")),
                valid: false,
            })
        }
    }
}

fn initial_head_for_report_range(
    sequence_start: u64,
    entries: &[SignedLedgerEntry],
) -> Result<LedgerChainHead, AuditReportCliError> {
    if sequence_start == 1 {
        return Ok(LedgerChainHead::genesis());
    }

    let first_entry = entries.first().ok_or_else(|| {
        AuditReportCliError::FetchFailed("ledger export returned no entries".to_owned())
    })?;
    LedgerChainHead::new(sequence_start - 1, first_entry.previous_entry_hash())
        .map_err(|error| AuditReportCliError::FetchFailed(error.to_string()))
}

fn signature_failure_item(
    code: &str,
    occurred_at: String,
    sequence_no: Option<u64>,
) -> VerificationFailureReportItem {
    VerificationFailureReportItem {
        code: code.to_owned(),
        occurred_at,
        sequence_no,
        source: "ledger_signature".to_owned(),
    }
}

fn map_ledger_error_to_code_and_sequence(
    error: &LedgerError,
    fallback_sequence_no: Option<u64>,
) -> (String, u64) {
    match error {
        LedgerError::SequenceGap { actual, .. } => ("sequence_gap".to_owned(), *actual),
        LedgerError::PreviousHashMismatch { sequence_no } => {
            ("previous_hash_mismatch".to_owned(), *sequence_no)
        }
        LedgerError::HashMismatch { sequence_no } => {
            ("entry_hash_mismatch".to_owned(), *sequence_no)
        }
        LedgerError::SignatureInvalid { sequence_no } => {
            ("signature_invalid".to_owned(), *sequence_no)
        }
        LedgerError::UnknownSignatureKey { sequence_no, .. } => {
            ("unknown_signature_key".to_owned(), *sequence_no)
        }
        LedgerError::InvalidVerificationKey
        | LedgerError::InvalidVerificationKeyLength { .. }
        | LedgerError::InvalidSignatureEncoding
        | LedgerError::InvalidSignatureLength { .. }
        | LedgerError::InvalidHashEncoding
        | LedgerError::InvalidHashLength { .. }
        | LedgerError::SignatureKeyVersionMismatch { .. } => (
            "invalid_exported_material".to_owned(),
            fallback_sequence_no.unwrap_or(0),
        ),
        _ => (
            "invalid_exported_material".to_owned(),
            fallback_sequence_no.unwrap_or(0),
        ),
    }
}

fn render_json(report: &AuditReportJson) -> Result<String, AuditReportCliError> {
    let mut json = serde_json::to_string(report)
        .map_err(|error| AuditReportCliError::Serialization(error.to_string()))?;
    json.push('\n');
    Ok(json)
}

fn render_markdown(report: &AuditReportJson) -> String {
    let mut output = String::new();
    output.push_str("# mipsorcu audit report\n\n");
    render_summary_section(&mut output, report);
    render_verification_failures_section(&mut output, report);
    render_signature_key_versions_section(&mut output, report);
    render_monthly_digests_section(&mut output, report);
    output.push('\n');
    output
}

fn render_summary_section(output: &mut String, report: &AuditReportJson) {
    output.push_str("## Summary\n\n");
    push_kv(
        output,
        "Period",
        &format!("{} - {}", report.period_start, report.period_end),
    );
    push_kv(
        output,
        "Sequence range",
        &sequence_range(report.sequence_start, report.sequence_end),
    );
    push_kv(
        output,
        "Ledger entry count",
        &report.ledger_entry_count.to_string(),
    );
    push_kv(
        output,
        "Audit event count",
        &report.audit_event_count.to_string(),
    );
    push_kv(output, "Secret count", &report.secret_count.to_string());
    push_kv(
        output,
        "Restore test performed",
        yes_no(report.restore_test_status.performed),
    );
    push_kv(
        output,
        "Restore test count",
        &report.restore_test_status.total_count.to_string(),
    );
    push_kv(
        output,
        "Restore test latest result",
        optional_text(report.restore_test_status.latest_result.as_deref()),
    );
    push_kv(
        output,
        "Integrity check performed",
        yes_no(report.integrity_check_status.performed),
    );
    push_kv(
        output,
        "Integrity check count",
        &report.integrity_check_status.total_count.to_string(),
    );
    push_kv(
        output,
        "Integrity check latest result",
        optional_text(report.integrity_check_status.latest_result.as_deref()),
    );
    push_kv(
        output,
        "Hash chain valid",
        yes_no(report.hash_chain_verification.valid),
    );
    push_kv(
        output,
        "Hash chain checked count",
        &report.hash_chain_verification.checked_count.to_string(),
    );
    push_kv(
        output,
        "Hash chain detail",
        optional_text(report.hash_chain_verification.detail.as_deref()),
    );
    push_kv(
        output,
        "Signature verification valid",
        yes_no(report.signature_verification.valid),
    );
    push_kv(
        output,
        "Signature verification checked count",
        &report.signature_verification.checked_count.to_string(),
    );
    push_kv(
        output,
        "Signature verification detail",
        optional_text(report.signature_verification.detail.as_deref()),
    );
}

fn render_verification_failures_section(output: &mut String, report: &AuditReportJson) {
    output.push_str("\n## Verification failures\n\n");
    if report.verification_failures.is_empty() {
        output.push_str("- none\n");
    } else {
        for failure in &report.verification_failures {
            output.push_str(&format!(
                "- source={} code={} occurred_at={} sequence_no={}\n",
                failure.source,
                failure.code,
                failure.occurred_at,
                failure
                    .sequence_no
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "n/a".to_owned())
            ));
        }
    }
}

fn render_signature_key_versions_section(output: &mut String, report: &AuditReportJson) {
    output.push_str("\n## Signature key versions\n\n");
    if report.signature_key_versions.is_empty() {
        output.push_str("- none\n");
    } else {
        for key in &report.signature_key_versions {
            output.push_str(&format!(
                "- key_version={} status={}\n",
                key.key_version, key.status
            ));
        }
    }
}

fn render_monthly_digests_section(output: &mut String, report: &AuditReportJson) {
    output.push_str("\n## Monthly digests\n\n");
    if report.monthly_digests.is_empty() {
        output.push_str("- none\n");
    } else {
        for digest in &report.monthly_digests {
            output.push_str(&format!(
                "- target_year_month={} sequence_no={} range={}-{} entry_count={} digest_hash={}\n",
                digest.target_year_month,
                digest.sequence_no,
                digest.start_sequence_no,
                digest.end_sequence_no,
                digest.entry_count,
                digest.digest_hash
            ));
        }
    }
}

fn push_kv(output: &mut String, key: &str, value: &str) {
    output.push_str(&format!("- **{key}**: {value}\n"));
}

fn sequence_range(start: Option<u64>, end: Option<u64>) -> String {
    match (start, end) {
        (Some(start), Some(end)) => format!("{start}-{end}"),
        _ => "n/a".to_owned(),
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn optional_text(value: Option<&str>) -> &str {
    value.unwrap_or("n/a")
}

#[allow(clippy::too_many_arguments)]
async fn record_audit_report_generation(
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    request_id: &RequestId,
    format: AuditReportFormat,
    period_start: &SourceEventAt,
    period_end: &SourceEventAt,
    source_event_at: &SourceEventAt,
    result: AuditResult,
    error_code: Option<&'static str>,
) -> Result<AuditRecordOutcome, AuditReportCliError> {
    let mut metadata_builder = AuditReportGenerateMetadata::new(
        format.as_str(),
        period_start.clone(),
        period_end.clone(),
        source_event_at.clone(),
    );
    if let Some(error_code) = error_code {
        metadata_builder = metadata_builder.with_error_code(error_code);
    }
    let metadata = metadata_builder
        .build()
        .map_err(|error| AuditReportCliError::Config(error.to_string()))?;
    let audit_event_id = crate::audit::AuditEventId::generate()
        .map_err(|error| AuditReportCliError::Config(error.to_string()))?;
    let event = build_operational_audit_event(OperationalAuditEvent {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        action: AuditAction::AuditReportGenerate,
        result,
        key_version: None,
        metadata,
    })
    .map_err(|error| AuditReportCliError::Config(error.to_string()))?;

    audit_recorder
        .record(&event)
        .await
        .map_err(AuditReportCliError::AuditRecordFailed)
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

#[cfg(test)]
#[path = "../../tests/unit/server/audit_report/tests.rs"]
mod tests;

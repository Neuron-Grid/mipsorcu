//! Supabase RPC client for audit report summary generation.
//!
//! 信頼境界ノート: 本モジュールは非秘密メタデータの集計結果のみを取得する。
//! 平文・鍵・JWT 全文を送受信しない。

use serde::{Deserialize, Serialize};

use super::response::ensure_success;
use super::{SupabaseClient, SupabaseRpcError};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReportSummary {
    pub audit_event_count: u64,
    pub hash_chain_verification: HashChainVerificationSummary,
    pub integrity_checks: Vec<IntegrityCheckReportItem>,
    pub ledger_entry_count: u64,
    pub monthly_digests: Vec<MonthlyDigestReportItem>,
    pub period_end: String,
    pub period_start: String,
    pub restore_tests: Vec<RestoreTestReportItem>,
    pub secret_count: u64,
    pub sequence_end: Option<u64>,
    pub sequence_start: Option<u64>,
    pub signature_key_versions: Vec<SignatureKeyVersionReportItem>,
    pub verification_failures: Vec<VerificationFailureReportItem>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HashChainVerificationSummary {
    pub checked_count: u64,
    pub detail: Option<String>,
    pub valid: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityCheckReportItem {
    pub checked_audit_event_count: u64,
    pub checked_secret_count: u64,
    pub checked_secret_version_count: u64,
    pub duration_ms: u64,
    pub occurred_at: String,
    pub result: String,
    pub trigger: Option<String>,
    pub violation_count: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MonthlyDigestReportItem {
    pub digest_hash: String,
    pub end_sequence_no: u64,
    pub entry_count: u64,
    pub sequence_no: u64,
    pub start_sequence_no: u64,
    pub target_year_month: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreTestReportItem {
    pub duration_ms: u64,
    pub occurred_at: String,
    pub result: String,
    pub sample_count: u64,
    pub trigger: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureKeyVersionReportItem {
    pub key_version: u32,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationFailureReportItem {
    pub code: String,
    pub occurred_at: String,
    pub sequence_no: Option<u64>,
    pub source: String,
}

impl SupabaseClient {
    pub async fn fetch_audit_report_summary(
        &self,
        period_start: &str,
        period_end: &str,
    ) -> Result<AuditReportSummary, SupabaseRpcError> {
        let params = AuditReportSummaryParams {
            p_period_end: period_end.to_owned(),
            p_period_start: period_start.to_owned(),
        };
        let response = self.post_rpc("rpc_audit_report_summary", &params).await?;
        let rows: Vec<AuditReportSummaryResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .map(|row| row.report_json)
            .ok_or(SupabaseRpcError::EmptyResult)
    }
}

#[derive(Serialize)]
struct AuditReportSummaryParams {
    p_period_end: String,
    p_period_start: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditReportSummaryResponse {
    report_json: AuditReportSummary,
}

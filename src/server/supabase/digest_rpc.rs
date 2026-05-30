//! Supabase RPC クライアント拡張: 月次 digest 生成サポート（Ledger Phase 2 §7.3）。
//!
//! 信頼境界ノート: 本モジュールは非秘密メタデータ（ledger sequence range、entry hashes）
//! のみを Supabase と交換する。秘密情報（平文・鍵・JWT）を送受しない。

use serde::{Deserialize, Serialize};

use crate::ledger::{LedgerHash, LedgerSequenceNo, LedgerSignatureKeyVersion};
use crate::types::SourceEventAt;

use super::response::{ensure_success, response_contains_marker};
use super::{SupabaseClient, SupabaseRpcError};

const DIGEST_INVALID_RPC_INPUT_MARKER: &str = "invalid_rpc_input";
const DIGEST_DUPLICATE_MARKER: &str = "monthly_digest_already_exists";
const DIGEST_RPC_PERIOD_FORMAT_MARKER: &str = "invalid_year_month_format";

/// 過去に記録された月次 digest の概要（非秘密メタデータのみ）。
///
/// hash・signature・平文といった秘密情報は含まない（`digest list` 表示用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonthlyDigestSummary {
    /// 対象年月（`"YYYY-MM"`）。
    pub target_year_month: String,
    /// 対象月最初のエントリの sequence_no。
    pub start_sequence_no: LedgerSequenceNo,
    /// 対象月最後のエントリの sequence_no。
    pub end_sequence_no: LedgerSequenceNo,
    /// 対象月のエントリ件数。
    pub entry_count: u64,
    /// digest 署名鍵バージョン。
    pub signature_key_version: LedgerSignatureKeyVersion,
    /// digest 生成時刻（RFC3339 UTC, 末尾 `Z`）。
    pub digest_generated_at: SourceEventAt,
}

/// 指定年月の `ledger_entries` 範囲情報。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRangeForMonth {
    /// 対象月最初のエントリの sequence_no。
    pub start_sequence_no: LedgerSequenceNo,
    /// 対象月最後のエントリの sequence_no。
    pub end_sequence_no: LedgerSequenceNo,
    /// 対象月最初のエントリの entry_hash。
    pub start_entry_hash: LedgerHash,
    /// 対象月最後のエントリの entry_hash。
    pub end_entry_hash: LedgerHash,
    /// 対象月のエントリ件数（> 0）。
    pub entry_count: u64,
}

impl SupabaseClient {
    /// 指定年月（`"YYYY-MM"` 形式）の `ledger_entries` 範囲情報を取得する。
    ///
    /// 対象月にエントリが存在しない場合は `Ok(None)` を返す。
    pub async fn fetch_ledger_range_for_month(
        &self,
        year_month: &str,
    ) -> Result<Option<LedgerRangeForMonth>, SupabaseRpcError> {
        let params = FetchLedgerRangeParams {
            p_year_month: year_month.to_owned(),
        };
        let response = self
            .post_rpc("rpc_fetch_ledger_range_for_month", &params)
            .await?;
        let rows: Vec<LedgerRangeResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .map(LedgerRangeForMonth::try_from)
            .transpose()
    }

    /// 指定年月（`"YYYY-MM"` 形式）の `monthly_digest` エントリが既に存在するか確認する。
    ///
    /// 既に存在する場合は `Ok(true)` を返す（重複防止）。
    pub async fn check_monthly_digest_exists(
        &self,
        year_month: &str,
    ) -> Result<bool, SupabaseRpcError> {
        let params = CheckDigestExistsParams {
            p_year_month: year_month.to_owned(),
        };
        let response = self
            .post_rpc("rpc_check_monthly_digest_exists", &params)
            .await?;
        let rows: Vec<DigestExistsResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        Ok(rows.into_iter().next().is_some_and(|r| r.exists))
    }

    /// 記録済みの月次 digest 一覧を取得する（年月順）。
    ///
    /// 非秘密メタデータ（年月・sequence 範囲・件数・署名鍵バージョン・生成時刻）
    /// のみを返す。digest なしの場合は空ベクタ。
    pub async fn list_monthly_digests(
        &self,
    ) -> Result<Vec<MonthlyDigestSummary>, SupabaseRpcError> {
        let response = self
            .post_rpc("rpc_list_monthly_digests", &ListDigestsParams {})
            .await?;
        let rows: Vec<MonthlyDigestSummaryResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .map(MonthlyDigestSummary::try_from)
            .collect()
    }
}

// ---- Request params ----

#[derive(Serialize)]
struct FetchLedgerRangeParams {
    p_year_month: String,
}

#[derive(Serialize)]
struct CheckDigestExistsParams {
    p_year_month: String,
}

#[derive(Serialize)]
struct ListDigestsParams {}

// ---- Response deserialization ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerRangeResponse {
    start_sequence_no: i64,
    end_sequence_no: i64,
    start_entry_hash: String,
    end_entry_hash: String,
    entry_count: i64,
}

impl TryFrom<LedgerRangeResponse> for LedgerRangeForMonth {
    type Error = SupabaseRpcError;

    fn try_from(response: LedgerRangeResponse) -> Result<Self, Self::Error> {
        let start_sequence_no =
            LedgerSequenceNo::from_i64(response.start_sequence_no).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "ledger range RPC returned invalid start_sequence_no".to_owned(),
                )
            })?;
        let end_sequence_no =
            LedgerSequenceNo::from_i64(response.end_sequence_no).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "ledger range RPC returned invalid end_sequence_no".to_owned(),
                )
            })?;
        let start_entry_hash =
            LedgerHash::from_bytea_hex(&response.start_entry_hash).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "ledger range RPC returned invalid start_entry_hash".to_owned(),
                )
            })?;
        let end_entry_hash =
            LedgerHash::from_bytea_hex(&response.end_entry_hash).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "ledger range RPC returned invalid end_entry_hash".to_owned(),
                )
            })?;
        let entry_count = u64::try_from(response.entry_count).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "ledger range RPC returned negative entry_count".to_owned(),
            )
        })?;

        if entry_count == 0 {
            return Err(SupabaseRpcError::InvalidResponse(
                "ledger range RPC returned entry_count=0 but a row was present".to_owned(),
            ));
        }

        Ok(LedgerRangeForMonth {
            start_sequence_no,
            end_sequence_no,
            start_entry_hash,
            end_entry_hash,
            entry_count,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestExistsResponse {
    exists: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MonthlyDigestSummaryResponse {
    target_year_month: String,
    start_sequence_no: i64,
    end_sequence_no: i64,
    entry_count: i64,
    signature_key_version: i32,
    digest_generated_at: String,
}

impl TryFrom<MonthlyDigestSummaryResponse> for MonthlyDigestSummary {
    type Error = SupabaseRpcError;

    fn try_from(response: MonthlyDigestSummaryResponse) -> Result<Self, Self::Error> {
        let start_sequence_no =
            LedgerSequenceNo::from_i64(response.start_sequence_no).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "digest list RPC returned invalid start_sequence_no".to_owned(),
                )
            })?;
        let end_sequence_no =
            LedgerSequenceNo::from_i64(response.end_sequence_no).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "digest list RPC returned invalid end_sequence_no".to_owned(),
                )
            })?;
        let entry_count = u64::try_from(response.entry_count).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "digest list RPC returned negative entry_count".to_owned(),
            )
        })?;
        let signature_key_version_raw =
            u32::try_from(response.signature_key_version).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "digest list RPC returned invalid signature_key_version".to_owned(),
                )
            })?;
        let signature_key_version = LedgerSignatureKeyVersion::new(signature_key_version_raw)
            .map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "digest list RPC returned invalid signature_key_version".to_owned(),
                )
            })?;
        let digest_generated_at =
            SourceEventAt::parse(&response.digest_generated_at).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "digest list RPC returned invalid digest_generated_at".to_owned(),
                )
            })?;

        Ok(MonthlyDigestSummary {
            target_year_month: response.target_year_month,
            start_sequence_no,
            end_sequence_no,
            entry_count,
            signature_key_version,
            digest_generated_at,
        })
    }
}

// ---- Error classification ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestRpcError {
    InvalidRpcInput,
    DuplicateDigest,
    FetchFailed,
}

impl DigestRpcError {
    pub fn as_error_code(self) -> &'static str {
        match self {
            Self::InvalidRpcInput => "monthly_digest_invalid_rpc_input",
            Self::DuplicateDigest => "monthly_digest_already_exists",
            Self::FetchFailed => "monthly_digest_fetch_failed",
        }
    }
}

pub fn classify_digest_rpc_error(error: &SupabaseRpcError) -> DigestRpcError {
    let SupabaseRpcError::NonSuccessStatus { body, .. } = error else {
        return DigestRpcError::FetchFailed;
    };

    if response_contains_marker(body, DIGEST_DUPLICATE_MARKER) {
        DigestRpcError::DuplicateDigest
    } else if response_contains_marker(body, DIGEST_INVALID_RPC_INPUT_MARKER)
        || response_contains_marker(body, DIGEST_RPC_PERIOD_FORMAT_MARKER)
    {
        DigestRpcError::InvalidRpcInput
    } else {
        DigestRpcError::FetchFailed
    }
}

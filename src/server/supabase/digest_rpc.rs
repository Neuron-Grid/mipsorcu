//! Supabase RPC クライアント拡張: 月次 digest 生成サポート（Ledger Phase 2 §7.3）。
//!
//! 信頼境界ノート: 本モジュールは非秘密メタデータ（ledger sequence range、entry hashes）
//! のみを Supabase と交換する。秘密情報（平文・鍵・JWT）を送受しない。

use serde::{Deserialize, Serialize};

use crate::ledger::{LedgerHash, LedgerSequenceNo};

use super::response::{ensure_success, response_contains_marker};
use super::{SupabaseClient, SupabaseRpcError};

const DIGEST_INVALID_RPC_INPUT_MARKER: &str = "invalid_rpc_input";
const DIGEST_DUPLICATE_MARKER: &str = "monthly_digest_already_exists";
const DIGEST_RPC_PERIOD_FORMAT_MARKER: &str = "invalid_year_month_format";

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

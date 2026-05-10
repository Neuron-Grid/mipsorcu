//! Supabase RPC クライアント拡張: 月次 digest 検証サポート（Ledger Phase 2 §7.4）。
//!
//! 信頼境界ノート: 本モジュールは非秘密メタデータ（digest fields, hashes, public key）
//! のみを Supabase から取得する。秘密情報（平文・鍵・JWT）を送受しない。

use serde::{Deserialize, Serialize};

use crate::ledger::{
    LedgerHash, LedgerSequenceNo, LedgerSignature, LedgerSignatureKeyVersion, LedgerVerifyingKey,
};
use crate::ledger::MonthlyDigestPeriod;
use crate::types::SourceEventAt;

use super::response::{ensure_success, response_contains_marker};
use super::{SupabaseClient, SupabaseRpcError};

const VERIFY_DIGEST_INVALID_RPC_INPUT_MARKER: &str = "invalid_rpc_input";

/// digest 検証に必要な全情報。Supabase から一度に取得する。
#[derive(Debug)]
pub struct MonthlyDigestVerificationMaterials {
    pub start_sequence_no: LedgerSequenceNo,
    pub end_sequence_no: LedgerSequenceNo,
    pub stored_entry_count: u64,
    /// payload->>'digest_hash'（64文字 lowercase hex、`\x` プレフィックスなし）。
    pub stored_digest_hash: String,
    pub target_year_month: MonthlyDigestPeriod,
    pub digest_generated_at: SourceEventAt,
    pub signature: LedgerSignature,
    pub signature_key_version: LedgerSignatureKeyVersion,
    /// None = ledger_signing_public_keys にキーが未登録。
    pub public_key: Option<LedgerVerifyingKey>,
    /// 範囲先頭エントリ（sequence_no = start_sequence_no）の entry_hash。
    pub start_entry_hash: LedgerHash,
    /// 範囲末尾エントリ（sequence_no = end_sequence_no）の entry_hash。
    pub end_entry_hash: LedgerHash,
}

impl SupabaseClient {
    /// 指定年月の `monthly_digest` ledger entry から検証に必要な情報を取得する。
    ///
    /// digest が存在しない場合は `Ok(None)` を返す。
    pub async fn fetch_monthly_digest_for_verification(
        &self,
        year_month: &str,
    ) -> Result<Option<MonthlyDigestVerificationMaterials>, SupabaseRpcError> {
        let params = FetchDigestForVerificationParams {
            p_year_month: year_month.to_owned(),
        };
        let response = self
            .post_rpc("rpc_fetch_monthly_digest_for_verification", &params)
            .await?;
        let rows: Vec<DigestForVerificationResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .map(MonthlyDigestVerificationMaterials::try_from)
            .transpose()
    }
}

// ---- Request params ----

#[derive(Serialize)]
struct FetchDigestForVerificationParams {
    p_year_month: String,
}

// ---- Response deserialization ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestForVerificationResponse {
    start_sequence_no: i64,
    end_sequence_no: i64,
    stored_entry_count: i64,
    stored_digest_hash: String,
    target_year_month: String,
    digest_generated_at: String,
    signature: String,
    signature_key_version: i32,
    public_key: Option<String>,
    start_entry_hash: String,
    end_entry_hash: String,
}

impl TryFrom<DigestForVerificationResponse> for MonthlyDigestVerificationMaterials {
    type Error = SupabaseRpcError;

    fn try_from(r: DigestForVerificationResponse) -> Result<Self, Self::Error> {
        let start_sequence_no =
            LedgerSequenceNo::from_i64(r.start_sequence_no).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "digest verification RPC returned invalid start_sequence_no".to_owned(),
                )
            })?;
        let end_sequence_no = LedgerSequenceNo::from_i64(r.end_sequence_no).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "digest verification RPC returned invalid end_sequence_no".to_owned(),
            )
        })?;
        let stored_entry_count = u64::try_from(r.stored_entry_count).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "digest verification RPC returned negative stored_entry_count".to_owned(),
            )
        })?;
        if stored_entry_count == 0 {
            return Err(SupabaseRpcError::InvalidResponse(
                "digest verification RPC returned stored_entry_count=0".to_owned(),
            ));
        }

        let target_year_month =
            MonthlyDigestPeriod::parse(&r.target_year_month).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "digest verification RPC returned invalid target_year_month".to_owned(),
                )
            })?;

        let digest_generated_at =
            SourceEventAt::parse(&r.digest_generated_at).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "digest verification RPC returned invalid digest_generated_at".to_owned(),
                )
            })?;

        let signature = LedgerSignature::from_bytea_hex(&r.signature).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "digest verification RPC returned invalid signature".to_owned(),
            )
        })?;

        let signature_key_version =
            LedgerSignatureKeyVersion::new(r.signature_key_version as u32).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "digest verification RPC returned invalid signature_key_version".to_owned(),
                )
            })?;

        let public_key = r
            .public_key
            .map(|hex| decode_public_key_bytes(&hex, signature_key_version))
            .transpose()?;

        let start_entry_hash =
            LedgerHash::from_bytea_hex(&r.start_entry_hash).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "digest verification RPC returned invalid start_entry_hash".to_owned(),
                )
            })?;
        let end_entry_hash = LedgerHash::from_bytea_hex(&r.end_entry_hash).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "digest verification RPC returned invalid end_entry_hash".to_owned(),
            )
        })?;

        Ok(MonthlyDigestVerificationMaterials {
            start_sequence_no,
            end_sequence_no,
            stored_entry_count,
            stored_digest_hash: r.stored_digest_hash,
            target_year_month,
            digest_generated_at,
            signature,
            signature_key_version,
            public_key,
            start_entry_hash,
            end_entry_hash,
        })
    }
}

fn decode_public_key_bytes(
    hex: &str,
    key_version: LedgerSignatureKeyVersion,
) -> Result<LedgerVerifyingKey, SupabaseRpcError> {
    let raw = hex
        .strip_prefix("\\x")
        .ok_or_else(|| {
            SupabaseRpcError::InvalidResponse(
                "digest verification RPC returned public_key without \\x prefix".to_owned(),
            )
        })
        .and_then(|h| {
            ::hex::decode(h).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "digest verification RPC returned invalid public_key hex".to_owned(),
                )
            })
        })?;

    LedgerVerifyingKey::from_public_key_bytes(key_version, &raw).map_err(|_| {
        SupabaseRpcError::InvalidResponse(
            "digest verification RPC returned invalid Ed25519 public_key".to_owned(),
        )
    })
}

// ---- Error classification ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyDigestRpcError {
    InvalidRpcInput,
    FetchFailed,
}

impl VerifyDigestRpcError {
    pub fn as_error_code(self) -> &'static str {
        match self {
            Self::InvalidRpcInput => "monthly_digest_verify_invalid_rpc_input",
            Self::FetchFailed => "monthly_digest_verify_fetch_failed",
        }
    }
}

pub fn classify_verify_digest_rpc_error(error: &SupabaseRpcError) -> VerifyDigestRpcError {
    let SupabaseRpcError::NonSuccessStatus { body, .. } = error else {
        return VerifyDigestRpcError::FetchFailed;
    };

    if response_contains_marker(body, VERIFY_DIGEST_INVALID_RPC_INPUT_MARKER) {
        VerifyDigestRpcError::InvalidRpcInput
    } else {
        VerifyDigestRpcError::FetchFailed
    }
}

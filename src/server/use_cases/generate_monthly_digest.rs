//! 月次 digest 生成 use case。
//!
//! SBC 内で完結する処理:
//! 1. 重複チェック（同一年月の digest が既に存在しないか確認）
//! 2. 対象月の `ledger_entries` 範囲情報を Supabase から取得
//! 3. 定義済み canonical form を生成（単一関数）
//! 4. digest hash を計算
//! 5. Ed25519 署名
//! 6. `monthly_digest` ledger entry として `rpc_append_ledger_entry` 経由で記録
//! 7. 失敗時は `audit_events` に同期記録
//!
//! 信頼境界ノート: Master Key・Data Key・平文・JWT を使用しない。
//! サービスロールキーは非秘密メタデータの読み書きにのみ使用する。

use std::sync::Arc;

use crate::audit::{
    AuditAction, AuditEvent, AuditEventParts, AuditRecorder, AuditResult,
    MonthlyDigestGenerateMetadata, RequestId,
};
use crate::ledger::{
    DigestHash, LedgerEntryId, LedgerEntryType, LedgerPayload, LedgerResult, MonthlyDigestPeriod,
    SignedMonthlyDigest, build_monthly_digest_canonical_form,
};
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts, LedgerAppender};
use crate::server::supabase::{LedgerRangeForMonth, SupabaseAuditAppender, SupabaseClient};
use crate::types::SourceEventAt;

/// 月次 digest 生成の入力パラメータ。
pub struct GenerateMonthlyDigestInput {
    /// 対象年月（YYYY-MM 形式）。
    pub period: MonthlyDigestPeriod,
    /// digest 生成時刻。SBC が決定。
    pub generated_at: SourceEventAt,
    /// 生成元を示すリクエスト ID。
    pub request_id: RequestId,
}

/// 月次 digest 生成失敗の原因分類。
///
/// 注意: 監査記録の失敗（`record_monthly_digest_failure_audit` RPC 失敗）は
/// エラーとして伝播せず、ログに記録するのみとする。
/// CLI 実行者にはログを確認するよう促す。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateMonthlyDigestError {
    /// 同一年月の digest が既に存在する（重複防止）。
    DuplicateDigest,
    /// 対象月に `ledger_entries` が存在しない。
    NoEntriesForPeriod,
    /// Supabase RPC の失敗（期間取得・重複確認）。
    FetchFailed { code: &'static str },
    /// digest の構築・署名エラー。
    BuildFailed { code: String },
    /// ledger entry への追記エラー。
    AppendFailed { code: &'static str },
}

impl GenerateMonthlyDigestError {
    pub fn as_error_code(&self) -> &str {
        match self {
            Self::DuplicateDigest => "monthly_digest_duplicate",
            Self::NoEntriesForPeriod => "monthly_digest_no_entries",
            Self::FetchFailed { code } => code,
            Self::BuildFailed { code } => code.as_str(),
            Self::AppendFailed { code } => code,
        }
    }
}

impl std::fmt::Display for GenerateMonthlyDigestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateDigest => {
                write!(formatter, "monthly digest already exists for this period")
            }
            Self::NoEntriesForPeriod => {
                write!(formatter, "no ledger entries found for the target period")
            }
            Self::FetchFailed { code } => write!(formatter, "monthly digest fetch failed: {code}"),
            Self::BuildFailed { code } => write!(formatter, "monthly digest build failed: {code}"),
            Self::AppendFailed { code } => {
                write!(formatter, "monthly digest ledger append failed: {code}")
            }
        }
    }
}

impl std::error::Error for GenerateMonthlyDigestError {}

/// 月次 digest を生成し `ledger_entries` に記録する。
///
/// 失敗時は `audit_events` に同期で記録する。
///
/// # 返り値
/// 成功時: `Ok(SignedMonthlyDigest)` — 署名済み digest 情報
/// 失敗時: `Err(GenerateMonthlyDigestError)` — 失敗原因
pub async fn generate_monthly_digest(
    supabase_client: &Arc<SupabaseClient>,
    ledger_appender: &Arc<LedgerAppender>,
    input: GenerateMonthlyDigestInput,
) -> Result<SignedMonthlyDigest, GenerateMonthlyDigestError> {
    let period = &input.period;

    // ── 1. 重複チェック ──
    let already_exists = supabase_client
        .check_monthly_digest_exists(period.as_str())
        .await
        .map_err(|error| {
            tracing::error!(
                request_id = %input.request_id.as_canonical_string(),
                period = period.as_str(),
                error = %error,
                error_code = "monthly_digest_duplicate_check_failed",
                "monthly digest duplicate check failed"
            );
            GenerateMonthlyDigestError::FetchFailed {
                code: "monthly_digest_duplicate_check_failed",
            }
        })?;

    if already_exists {
        tracing::warn!(
            request_id = %input.request_id.as_canonical_string(),
            period = period.as_str(),
            "monthly digest already exists for period"
        );
        return Err(GenerateMonthlyDigestError::DuplicateDigest);
    }

    // ── 2. 対象月のエントリ範囲を取得 ──
    let range = fetch_ledger_range(supabase_client, &input).await?;

    // ── 3. canonical form を生成 ──
    let signature_key_version = ledger_appender.signing_key_version();
    let canonical_bytes = build_monthly_digest_canonical_form(
        period,
        range.start_sequence_no,
        range.end_sequence_no,
        range.start_entry_hash,
        range.end_entry_hash,
        range.entry_count,
        &input.generated_at,
        signature_key_version,
    )
    .map_err(|error| {
        tracing::error!(
            request_id = %input.request_id.as_canonical_string(),
            period = period.as_str(),
            error = %error,
            "monthly digest canonical form build failed"
        );
        GenerateMonthlyDigestError::BuildFailed {
            code: error.to_string(),
        }
    })?;

    // ── 4. digest hash を計算 ──
    let digest_hash = DigestHash::from_canonical_bytes(&canonical_bytes);

    // ── 5. Ed25519 署名 ──
    let sbc_signature = ledger_appender
        .sign_digest_bytes(canonical_bytes.as_bytes())
        .map_err(|error| {
            tracing::error!(
                request_id = %input.request_id.as_canonical_string(),
                period = period.as_str(),
                error = %error,
                "monthly digest signing failed"
            );
            GenerateMonthlyDigestError::BuildFailed {
                code: error.to_string(),
            }
        })?;

    let signed_digest = SignedMonthlyDigest {
        period: period.clone(),
        start_sequence_no: range.start_sequence_no,
        end_sequence_no: range.end_sequence_no,
        start_entry_hash: range.start_entry_hash,
        end_entry_hash: range.end_entry_hash,
        entry_count: range.entry_count,
        digest_generated_at: input.generated_at.clone(),
        signature_key_version,
        canonical_bytes,
        digest_hash,
        sbc_signature,
    };

    // ── 6. ledger entry として追記 ──
    append_digest_ledger_entry(ledger_appender, &signed_digest, &input).await?;

    tracing::info!(
        request_id = %input.request_id.as_canonical_string(),
        period = period.as_str(),
        start_sequence_no = range.start_sequence_no.get(),
        end_sequence_no = range.end_sequence_no.get(),
        entry_count = range.entry_count,
        digest_hash = %signed_digest.digest_hash.to_hex(),
        "monthly digest generated and recorded"
    );

    Ok(signed_digest)
}

/// 対象月のエントリ範囲を Supabase から取得する。
/// エントリが存在しない場合は `NoEntriesForPeriod` を返す。
async fn fetch_ledger_range(
    supabase_client: &SupabaseClient,
    input: &GenerateMonthlyDigestInput,
) -> Result<LedgerRangeForMonth, GenerateMonthlyDigestError> {
    match supabase_client
        .fetch_ledger_range_for_month(input.period.as_str())
        .await
    {
        Ok(Some(range)) => Ok(range),
        Ok(None) => {
            tracing::warn!(
                request_id = %input.request_id.as_canonical_string(),
                period = input.period.as_str(),
                "no ledger entries found for period"
            );
            Err(GenerateMonthlyDigestError::NoEntriesForPeriod)
        }
        Err(error) => {
            tracing::error!(
                request_id = %input.request_id.as_canonical_string(),
                period = input.period.as_str(),
                error = %error,
                error_code = "monthly_digest_range_fetch_failed",
                "monthly digest ledger range fetch failed"
            );
            Err(GenerateMonthlyDigestError::FetchFailed {
                code: "monthly_digest_range_fetch_failed",
            })
        }
    }
}

/// 月次 digest を `monthly_digest` entry として ledger に追記する。
async fn append_digest_ledger_entry(
    ledger_appender: &LedgerAppender,
    signed_digest: &SignedMonthlyDigest,
    input: &GenerateMonthlyDigestInput,
) -> Result<(), GenerateMonthlyDigestError> {
    let entry_type = LedgerEntryType::MonthlyDigest;

    let payload = LedgerPayload::new(
        entry_type,
        serde_json::json!({
            "digest_hash": signed_digest.digest_hash.to_hex(),
            "end_sequence_no": signed_digest.end_sequence_no.get(),
            "entry_count": signed_digest.entry_count,
            "start_sequence_no": signed_digest.start_sequence_no.get(),
            "target_year_month": signed_digest.period.as_str(),
        }),
    )
    .map_err(|error| {
        tracing::error!(
            request_id = %input.request_id.as_canonical_string(),
            period = input.period.as_str(),
            error = %error,
            "monthly digest ledger payload build failed"
        );
        GenerateMonthlyDigestError::BuildFailed {
            code: error.to_string(),
        }
    })?;

    let ledger_entry_id =
        LedgerEntryId::generate().map_err(|error| GenerateMonthlyDigestError::BuildFailed {
            code: error.to_string(),
        })?;

    let draft = LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id,
        entry_type,
        source_event_at: input.generated_at.clone(),
        request_id: input.request_id.clone(),
        source_event_id: None,
        target_secret_id: None,
        target_secret_version_id: None,
        actor_user_id: None,
        actor_device_id: None,
        result: LedgerResult::Success,
        error_code: None,
        payload,
    })
    .map_err(|error| GenerateMonthlyDigestError::BuildFailed {
        code: error.to_string(),
    })?;

    ledger_appender.append(&draft).await.map_err(|error| {
        tracing::error!(
            request_id = %input.request_id.as_canonical_string(),
            period = input.period.as_str(),
            error_code = error.as_error_code(),
            "monthly digest ledger append failed"
        );
        GenerateMonthlyDigestError::AppendFailed {
            code: error.as_error_code(),
        }
    })?;

    Ok(())
}

/// 月次 digest 生成失敗を `audit_events` に同期記録するヘルパー。
///
/// 失敗時は `audit_events` への記録を試みる。
/// 監査記録自体の失敗はログに記録するが、元の失敗を上書きしない。
pub async fn record_monthly_digest_failure_audit(
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    request_id: &RequestId,
    period: &MonthlyDigestPeriod,
    error: &GenerateMonthlyDigestError,
    generated_at: &SourceEventAt,
) {
    let audit_event_id = match crate::audit::AuditEventId::generate() {
        Ok(id) => id,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to generate audit event id for monthly_digest_generate failure audit"
            );
            return;
        }
    };

    let metadata = match MonthlyDigestGenerateMetadata::new(
        period,
        error.as_error_code(),
        generated_at.clone(),
    )
    .build()
    {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to build audit metadata for monthly_digest_generate failure audit"
            );
            return;
        }
    };

    let event = match AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::MonthlyDigestGenerate,
        target_secret_id: None,
        result: AuditResult::Failure,
        key_version: None,
        metadata_json: metadata,
    }) {
        Ok(e) => e,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to build audit event for monthly_digest_generate failure audit"
            );
            return;
        }
    };

    match audit_recorder.record(&event).await {
        Ok(outcome) => {
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                audit_record_outcome = ?outcome,
                "monthly digest failure audit recorded"
            );
        }
        Err(record_error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                error = %record_error,
                error_code = "monthly_digest_failure_audit_record_failed",
                "monthly digest failure audit primary and fallback recording failed"
            );
        }
    }
}

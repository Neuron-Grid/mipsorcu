//! 月次 digest 検証 use case（Ledger Phase 2 §7.4）。
//!
//! 検証フロー（fail-close — 不明な場合は成功扱いしない）:
//! 1. digest 検証マテリアルを取得（RPC）
//! 2. 対象範囲の chain エントリを取得（RPC）
//! 3. chain 連続性を検証（verify_ledger_chain）
//! 4. chain 末尾 hash と digest の end_entry_hash が一致するか確認
//! 5. 公開鍵が存在するか確認（unknown key → 失敗）
//! 6. canonical bytes を再構築し hash を再計算して比較
//! 7. Ed25519 署名を検証
//! 8. 現在の range と digest の range を比較（生成後の変更検知）
//! 9. 失敗時は audit_events に記録
//!
//! 信頼境界ノート: 検証は read-only。ledger_entries には書き込まない。
//! audit_events への失敗記録のみ副作用として許容される。

use std::sync::Arc;

use crate::audit::{AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditMetadata, AuditResult, RequestId};
use crate::ledger::{
    LedgerChainHead, LedgerError, LedgerSequenceNo, LedgerVerifyingKey,
    MonthlyDigestPeriod, build_monthly_digest_canonical_form, verify_ledger_chain, DigestHash,
};
use crate::server::supabase::SupabaseClient;
use crate::types::SourceEventAt;

pub struct VerifyMonthlyDigestInput {
    pub period: MonthlyDigestPeriod,
    pub request_id: RequestId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyMonthlyDigestError {
    DigestNotFound,
    FetchFailed { code: &'static str },
    ChainContinuityError { ledger_error_code: String },
    EndHashMismatch,
    UnknownSignatureKey,
    DigestHashMismatch,
    DigestSignatureInvalid,
    RangeModifiedAfterDigest,
}

impl VerifyMonthlyDigestError {
    pub fn as_error_code(&self) -> &str {
        match self {
            Self::DigestNotFound => "monthly_digest_not_found",
            Self::FetchFailed { code } => code,
            Self::ChainContinuityError { .. } => "monthly_digest_chain_continuity_error",
            Self::EndHashMismatch => "monthly_digest_end_hash_mismatch",
            Self::UnknownSignatureKey => "monthly_digest_unknown_signature_key",
            Self::DigestHashMismatch => "monthly_digest_hash_mismatch",
            Self::DigestSignatureInvalid => "monthly_digest_signature_invalid",
            Self::RangeModifiedAfterDigest => "monthly_digest_range_modified",
        }
    }
}

impl std::fmt::Display for VerifyMonthlyDigestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DigestNotFound => write!(formatter, "monthly digest not found for this period"),
            Self::FetchFailed { code } => write!(formatter, "fetch failed: {code}"),
            Self::ChainContinuityError { ledger_error_code } => {
                write!(formatter, "chain continuity error: {ledger_error_code}")
            }
            Self::EndHashMismatch => write!(
                formatter,
                "chain end hash does not match digest end_entry_hash"
            ),
            Self::UnknownSignatureKey => {
                write!(formatter, "signing public key not registered for this key version")
            }
            Self::DigestHashMismatch => write!(
                formatter,
                "recomputed digest hash does not match stored hash"
            ),
            Self::DigestSignatureInvalid => {
                write!(formatter, "digest Ed25519 signature is invalid")
            }
            Self::RangeModifiedAfterDigest => write!(
                formatter,
                "ledger range was modified after digest was generated"
            ),
        }
    }
}

impl std::error::Error for VerifyMonthlyDigestError {}

/// 検証成功時に返す情報。
#[derive(Debug)]
pub struct VerifiedMonthlyDigestInfo {
    pub start_sequence_no: LedgerSequenceNo,
    pub end_sequence_no: LedgerSequenceNo,
    pub entry_count: u64,
}

/// 月次 digest を検証する。
///
/// 検証は read-only であり ledger_entries に書き込まない。
/// 失敗時は `audit_events` に同期で記録する（呼び出し側が `record_...` を呼ぶこと）。
pub async fn verify_monthly_digest(
    supabase_client: &Arc<SupabaseClient>,
    input: &VerifyMonthlyDigestInput,
) -> Result<VerifiedMonthlyDigestInfo, VerifyMonthlyDigestError> {
    let period = &input.period;

    // ── 1. digest 検証マテリアルを取得 ──
    let materials = match supabase_client
        .fetch_monthly_digest_for_verification(period.as_str())
        .await
    {
        Ok(Some(m)) => m,
        Ok(None) => {
            tracing::warn!(
                request_id = %input.request_id.as_canonical_string(),
                period = period.as_str(),
                "monthly digest not found for verification"
            );
            return Err(VerifyMonthlyDigestError::DigestNotFound);
        }
        Err(error) => {
            tracing::error!(
                request_id = %input.request_id.as_canonical_string(),
                period = period.as_str(),
                error = %error,
                error_code = "monthly_digest_verify_materials_fetch_failed",
                "failed to fetch monthly digest verification materials"
            );
            return Err(VerifyMonthlyDigestError::FetchFailed {
                code: "monthly_digest_verify_materials_fetch_failed",
            });
        }
    };

    // ── 2. 対象範囲の chain エントリを取得 ──
    let rows = match supabase_client
        .export_ledger_verification_materials(materials.start_sequence_no, materials.end_sequence_no)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(
                request_id = %input.request_id.as_canonical_string(),
                period = period.as_str(),
                error = %error,
                error_code = "monthly_digest_chain_export_failed",
                "failed to export ledger verification materials for digest range"
            );
            return Err(VerifyMonthlyDigestError::FetchFailed {
                code: "monthly_digest_chain_export_failed",
            });
        }
    };

    // ── 3. エントリと公開鍵を復元 ──
    if rows.is_empty() {
        tracing::error!(
            request_id = %input.request_id.as_canonical_string(),
            period = period.as_str(),
            error_code = "monthly_digest_chain_empty",
            "chain export returned no entries for digest range"
        );
        return Err(VerifyMonthlyDigestError::FetchFailed {
            code: "monthly_digest_chain_empty",
        });
    }

    let mut entries = Vec::with_capacity(rows.len());
    for row in &rows {
        match row.try_restore_signed_ledger_entry() {
            Ok(entry) => entries.push(entry),
            Err(error) => {
                tracing::error!(
                    request_id = %input.request_id.as_canonical_string(),
                    period = period.as_str(),
                    error = %error,
                    error_code = "monthly_digest_chain_entry_restore_failed",
                    "failed to restore signed ledger entry from export row"
                );
                return Err(VerifyMonthlyDigestError::FetchFailed {
                    code: "monthly_digest_chain_entry_restore_failed",
                });
            }
        }
    }

    let mut verification_keys: Vec<LedgerVerifyingKey> = Vec::new();
    for row in &rows {
        match row.try_restore_verifying_key() {
            Ok(Some(key))
                if !verification_keys
                    .iter()
                    .any(|k| k.key_version() == key.key_version()) =>
            {
                verification_keys.push(key);
            }
            Ok(_) => {}
            Err(error) => {
                tracing::error!(
                    request_id = %input.request_id.as_canonical_string(),
                    period = period.as_str(),
                    error = %error,
                    error_code = "monthly_digest_chain_key_restore_failed",
                    "failed to restore verifying key from export row"
                );
                return Err(VerifyMonthlyDigestError::FetchFailed {
                    code: "monthly_digest_chain_key_restore_failed",
                });
            }
        }
    }

    // ── 4. initial_head を構築（最初のエントリの previous_entry_hash を使用） ──
    let first_previous_hash = rows[0].previous_entry_hash;
    let initial_head =
        LedgerChainHead::new(materials.start_sequence_no.get() - 1, first_previous_hash)
            .map_err(|error| {
                tracing::error!(
                    request_id = %input.request_id.as_canonical_string(),
                    period = period.as_str(),
                    error = %error,
                    error_code = "monthly_digest_chain_head_build_failed",
                    "failed to build initial chain head"
                );
                VerifyMonthlyDigestError::FetchFailed {
                    code: "monthly_digest_chain_head_build_failed",
                }
            })?;

    // ── 5. chain 連続性を検証 ──
    let final_head = match verify_ledger_chain(&entries, initial_head, &verification_keys) {
        Ok(head) => head,
        Err(error) => {
            let code = map_ledger_error_to_code(&error);
            tracing::warn!(
                request_id = %input.request_id.as_canonical_string(),
                period = period.as_str(),
                error = %error,
                error_code = code,
                "chain continuity verification failed"
            );
            return Err(VerifyMonthlyDigestError::ChainContinuityError {
                ledger_error_code: code.to_owned(),
            });
        }
    };

    // ── 6. chain 末尾 hash と digest の end_entry_hash が一致するか確認 ──
    if final_head.last_entry_hash() != materials.end_entry_hash {
        tracing::warn!(
            request_id = %input.request_id.as_canonical_string(),
            period = period.as_str(),
            error_code = "monthly_digest_end_hash_mismatch",
            "chain end hash does not match digest end_entry_hash"
        );
        return Err(VerifyMonthlyDigestError::EndHashMismatch);
    }

    // ── 7. 公開鍵が存在するか確認 ──
    let public_key = match materials.public_key {
        Some(ref key) => key,
        None => {
            tracing::warn!(
                request_id = %input.request_id.as_canonical_string(),
                period = period.as_str(),
                error_code = "monthly_digest_unknown_signature_key",
                "no public key registered for digest signature_key_version"
            );
            return Err(VerifyMonthlyDigestError::UnknownSignatureKey);
        }
    };

    // ── 8. canonical bytes を再構築し hash を再計算して比較 ──
    let canonical_bytes = build_monthly_digest_canonical_form(
        period,
        materials.start_sequence_no,
        materials.end_sequence_no,
        materials.start_entry_hash,
        materials.end_entry_hash,
        materials.stored_entry_count,
        &materials.digest_generated_at,
        materials.signature_key_version,
    )
    .map_err(|error| {
        tracing::error!(
            request_id = %input.request_id.as_canonical_string(),
            period = period.as_str(),
            error = %error,
            error_code = "monthly_digest_canonical_rebuild_failed",
            "failed to rebuild digest canonical form"
        );
        VerifyMonthlyDigestError::FetchFailed {
            code: "monthly_digest_canonical_rebuild_failed",
        }
    })?;

    let computed_hash = DigestHash::from_canonical_bytes(&canonical_bytes).to_hex();
    if computed_hash != materials.stored_digest_hash {
        tracing::warn!(
            request_id = %input.request_id.as_canonical_string(),
            period = period.as_str(),
            error_code = "monthly_digest_hash_mismatch",
            "recomputed digest hash does not match stored hash"
        );
        return Err(VerifyMonthlyDigestError::DigestHashMismatch);
    }

    // ── 9. Ed25519 署名を検証 ──
    if let Err(error) =
        public_key.verify_digest_bytes(canonical_bytes.as_bytes(), &materials.signature)
    {
        tracing::warn!(
            request_id = %input.request_id.as_canonical_string(),
            period = period.as_str(),
            error = %error,
            error_code = "monthly_digest_signature_invalid",
            "digest Ed25519 signature verification failed"
        );
        return Err(VerifyMonthlyDigestError::DigestSignatureInvalid);
    }

    // ── 10. 現在の range と digest の range を比較 ──
    match supabase_client
        .fetch_ledger_range_for_month(period.as_str())
        .await
    {
        Ok(Some(current_range)) => {
            if current_range.entry_count > materials.stored_entry_count
                || current_range.end_sequence_no.get() > materials.end_sequence_no.get()
            {
                tracing::warn!(
                    request_id = %input.request_id.as_canonical_string(),
                    period = period.as_str(),
                    stored_entry_count = materials.stored_entry_count,
                    current_entry_count = current_range.entry_count,
                    stored_end_sequence_no = materials.end_sequence_no.get(),
                    current_end_sequence_no = current_range.end_sequence_no.get(),
                    error_code = "monthly_digest_range_modified",
                    "ledger range was modified after digest was generated"
                );
                return Err(VerifyMonthlyDigestError::RangeModifiedAfterDigest);
            }
        }
        Ok(None) => {
            tracing::error!(
                request_id = %input.request_id.as_canonical_string(),
                period = period.as_str(),
                error_code = "monthly_digest_range_fetch_empty",
                "current ledger range fetch returned no entries despite digest existing"
            );
            return Err(VerifyMonthlyDigestError::FetchFailed {
                code: "monthly_digest_range_fetch_empty",
            });
        }
        Err(error) => {
            tracing::error!(
                request_id = %input.request_id.as_canonical_string(),
                period = period.as_str(),
                error = %error,
                error_code = "monthly_digest_range_fetch_failed",
                "failed to fetch current ledger range for range change detection"
            );
            return Err(VerifyMonthlyDigestError::FetchFailed {
                code: "monthly_digest_range_fetch_failed",
            });
        }
    }

    tracing::info!(
        request_id = %input.request_id.as_canonical_string(),
        period = period.as_str(),
        start_sequence_no = materials.start_sequence_no.get(),
        end_sequence_no = materials.end_sequence_no.get(),
        entry_count = materials.stored_entry_count,
        "monthly digest verified successfully"
    );

    Ok(VerifiedMonthlyDigestInfo {
        start_sequence_no: materials.start_sequence_no,
        end_sequence_no: materials.end_sequence_no,
        entry_count: materials.stored_entry_count,
    })
}

/// 月次 digest 検証失敗を `audit_events` に同期記録するヘルパー。
///
/// AGENTS.md §8 フェイルクローズ: 失敗時は `audit_events` への記録を試みる。
/// 監査記録自体の失敗はログに記録するが、元の失敗を上書きしない。
pub async fn record_monthly_digest_verify_failure_audit(
    supabase_client: &Arc<SupabaseClient>,
    request_id: &RequestId,
    period: &MonthlyDigestPeriod,
    error: &VerifyMonthlyDigestError,
    verified_at: &SourceEventAt,
) {
    let audit_event_id = match AuditEventId::generate() {
        Ok(id) => id,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to generate audit event id for monthly_digest_verify failure audit"
            );
            return;
        }
    };

    let metadata_value = serde_json::json!({
        "error_code": error.as_error_code(),
        "target_year_month": period.as_str(),
        "source_event_at": verified_at.as_str(),
    });

    let metadata = match AuditMetadata::new(metadata_value) {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to build audit metadata for monthly_digest_verify failure audit"
            );
            return;
        }
    };

    let event = match AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::MonthlyDigestVerify,
        target_secret_id: None,
        result: AuditResult::Failure,
        key_version: None,
        metadata_json: metadata,
    }) {
        Ok(e) => e,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to build audit event for monthly_digest_verify failure audit"
            );
            return;
        }
    };

    match supabase_client.call_append_audit_event(&event).await {
        Ok(()) => {
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                "monthly digest verification failure audit recorded"
            );
        }
        Err(rpc_error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                error = %rpc_error,
                error_code = "monthly_digest_verify_failure_audit_rpc_failed",
                "monthly digest verify failure audit RPC failed — manual follow-up required"
            );
        }
    }
}

fn map_ledger_error_to_code(error: &LedgerError) -> &'static str {
    match error {
        LedgerError::SequenceGap { .. } => "chain_sequence_gap",
        LedgerError::PreviousHashMismatch { .. } => "chain_previous_hash_mismatch",
        LedgerError::HashMismatch { .. } => "chain_entry_hash_mismatch",
        LedgerError::SignatureInvalid { .. } => "chain_signature_invalid",
        LedgerError::UnknownSignatureKey { .. } => "chain_unknown_signature_key",
        _ => "chain_verification_error",
    }
}


//! 月次 digest 検証 use case。
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
//! 9. 成功・失敗どちらも audit_events に記録
//!
//! 信頼境界ノート: 検証は read-only。ledger_entries には書き込まない。
//! audit_events への検証結果記録のみ副作用として許容される。

use std::sync::Arc;

use crate::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditRecorder, AuditResult,
    MonthlyDigestVerifyMetadata, RequestId,
};
use crate::ledger::{
    DigestHash, LedgerChainHead, LedgerError, LedgerHash, LedgerSequenceNo, LedgerVerifyingKey,
    MonthlyDigestPeriod, SignedLedgerEntry, build_monthly_digest_canonical_form,
    verify_ledger_chain,
};
use crate::server::supabase::{
    MonthlyDigestVerificationMaterials, SupabaseAuditAppender, SupabaseClient,
};
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
                write!(
                    formatter,
                    "signing public key not registered for this key version"
                )
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
    // 手順1: digest 検証マテリアルを取得。
    let materials = fetch_verification_materials(supabase_client, input).await?;
    // 手順2-3: 対象範囲の chain エントリと公開鍵を取得・復元。
    let chain = export_and_restore_chain(supabase_client, input, &materials).await?;
    // 手順4-6: chain 連続性と末尾 hash の一致を検証。
    verify_chain_continuity(
        input,
        &materials,
        &chain.entries,
        &chain.verification_keys,
        chain.first_previous_hash,
    )?;
    // 手順7-9: digest の hash 再計算と Ed25519 署名を検証。
    verify_digest_hash_and_signature(input, &materials)?;
    // 手順10: 生成後の range 変更を検知。
    detect_range_modification(supabase_client, input, &materials).await?;

    tracing::info!(
        request_id = %input.request_id.as_canonical_string(),
        period = input.period.as_str(),
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

/// 手順2-3 で復元した chain 検証用の素材。
struct RestoredChain {
    entries: Vec<SignedLedgerEntry>,
    verification_keys: Vec<LedgerVerifyingKey>,
    first_previous_hash: LedgerHash,
}

/// 手順1: digest 検証マテリアルを取得する。
async fn fetch_verification_materials(
    supabase_client: &Arc<SupabaseClient>,
    input: &VerifyMonthlyDigestInput,
) -> Result<MonthlyDigestVerificationMaterials, VerifyMonthlyDigestError> {
    let period = &input.period;
    match supabase_client
        .fetch_monthly_digest_for_verification(period.as_str())
        .await
    {
        Ok(Some(m)) => Ok(m),
        Ok(None) => {
            tracing::warn!(
                request_id = %input.request_id.as_canonical_string(),
                period = period.as_str(),
                "monthly digest not found for verification"
            );
            Err(VerifyMonthlyDigestError::DigestNotFound)
        }
        Err(error) => {
            tracing::error!(
                request_id = %input.request_id.as_canonical_string(),
                period = period.as_str(),
                error = %error,
                error_code = "monthly_digest_verify_materials_fetch_failed",
                "failed to fetch monthly digest verification materials"
            );
            Err(VerifyMonthlyDigestError::FetchFailed {
                code: "monthly_digest_verify_materials_fetch_failed",
            })
        }
    }
}

/// 手順2-3: 対象範囲の chain エントリと公開鍵を取得し復元する。
async fn export_and_restore_chain(
    supabase_client: &Arc<SupabaseClient>,
    input: &VerifyMonthlyDigestInput,
    materials: &MonthlyDigestVerificationMaterials,
) -> Result<RestoredChain, VerifyMonthlyDigestError> {
    let period = &input.period;

    let rows = match supabase_client
        .export_ledger_verification_materials(
            materials.start_sequence_no,
            materials.end_sequence_no,
        )
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

    // rows は上で空でないことを確認済みのため [0] は安全。
    let first_previous_hash = rows[0].previous_entry_hash;

    Ok(RestoredChain {
        entries,
        verification_keys,
        first_previous_hash,
    })
}

/// 手順4-6: initial_head を構築し chain 連続性と末尾 hash の一致を検証する。
fn verify_chain_continuity(
    input: &VerifyMonthlyDigestInput,
    materials: &MonthlyDigestVerificationMaterials,
    entries: &[SignedLedgerEntry],
    verification_keys: &[LedgerVerifyingKey],
    first_previous_hash: LedgerHash,
) -> Result<(), VerifyMonthlyDigestError> {
    let period = &input.period;

    // 最初のエントリの previous_entry_hash を initial_head に使用する。
    let initial_head =
        LedgerChainHead::new(materials.start_sequence_no.get() - 1, first_previous_hash).map_err(
            |error| {
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
            },
        )?;

    let final_head = match verify_ledger_chain(entries, initial_head, verification_keys) {
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

    if final_head.last_entry_hash() != materials.end_entry_hash {
        tracing::warn!(
            request_id = %input.request_id.as_canonical_string(),
            period = period.as_str(),
            error_code = "monthly_digest_end_hash_mismatch",
            "chain end hash does not match digest end_entry_hash"
        );
        return Err(VerifyMonthlyDigestError::EndHashMismatch);
    }

    Ok(())
}

/// 手順7-9: 公開鍵の存在確認、canonical bytes の hash 再計算、Ed25519 署名検証。
fn verify_digest_hash_and_signature(
    input: &VerifyMonthlyDigestInput,
    materials: &MonthlyDigestVerificationMaterials,
) -> Result<(), VerifyMonthlyDigestError> {
    let period = &input.period;

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

    // sbc_signature は monthly_digest payload に保存された digest 専用署名であり、
    // ledger_entries.signature（ledger entry 自体の署名）ではない。
    if let Err(error) =
        public_key.verify_digest_bytes(canonical_bytes.as_bytes(), &materials.sbc_signature)
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

    Ok(())
}

/// 手順10: 現在の range と digest の range を比較し、生成後の変更を検知する。
async fn detect_range_modification(
    supabase_client: &Arc<SupabaseClient>,
    input: &VerifyMonthlyDigestInput,
    materials: &MonthlyDigestVerificationMaterials,
) -> Result<(), VerifyMonthlyDigestError> {
    let period = &input.period;

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
            Ok(())
        }
        Ok(None) => {
            tracing::error!(
                request_id = %input.request_id.as_canonical_string(),
                period = period.as_str(),
                error_code = "monthly_digest_range_fetch_empty",
                "current ledger range fetch returned no entries despite digest existing"
            );
            Err(VerifyMonthlyDigestError::FetchFailed {
                code: "monthly_digest_range_fetch_empty",
            })
        }
        Err(error) => {
            tracing::error!(
                request_id = %input.request_id.as_canonical_string(),
                period = period.as_str(),
                error = %error,
                error_code = "monthly_digest_range_fetch_failed",
                "failed to fetch current ledger range for range change detection"
            );
            Err(VerifyMonthlyDigestError::FetchFailed {
                code: "monthly_digest_range_fetch_failed",
            })
        }
    }
}

/// 月次 digest 検証成功を `audit_events` に同期記録するヘルパー。
///
/// 成功時は `monthly_digest_verify` / `success` として記録する。
/// 監査記録自体の失敗はログに記録するが、検証成功そのものは覆さない。
pub async fn record_monthly_digest_verify_success_audit(
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    request_id: &RequestId,
    period: &MonthlyDigestPeriod,
    verified_at: &SourceEventAt,
) {
    let audit_event_id = match AuditEventId::generate() {
        Ok(id) => id,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to generate audit event id for monthly_digest_verify success audit"
            );
            return;
        }
    };

    let metadata = match MonthlyDigestVerifyMetadata::success(period, verified_at.clone()).build() {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to build audit metadata for monthly_digest_verify success audit"
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
        result: AuditResult::Success,
        key_version: None,
        metadata_json: metadata,
    }) {
        Ok(e) => e,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to build audit event for monthly_digest_verify success audit"
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
                "monthly digest verification success audit recorded"
            );
        }
        Err(record_error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                error = %record_error,
                error_code = "monthly_digest_verify_success_audit_record_failed",
                "monthly digest verify success audit primary and fallback recording failed"
            );
        }
    }
}

/// 月次 digest 検証失敗を `audit_events` に同期記録するヘルパー。
///
/// 失敗時は `audit_events` への記録を試みる。
/// 監査記録自体の失敗はログに記録するが、元の失敗を上書きしない。
pub async fn record_monthly_digest_verify_failure_audit(
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
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

    let metadata =
        match MonthlyDigestVerifyMetadata::new(period, error.as_error_code(), verified_at.clone())
            .build()
        {
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

    match audit_recorder.record(&event).await {
        Ok(outcome) => {
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                audit_record_outcome = ?outcome,
                "monthly digest verification failure audit recorded"
            );
        }
        Err(record_error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                period = period.as_str(),
                error = %record_error,
                error_code = "monthly_digest_verify_failure_audit_record_failed",
                "monthly digest verify failure audit primary and fallback recording failed"
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

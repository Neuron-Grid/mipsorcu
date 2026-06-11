//! 台帳検証サマリ `checked_count` の意味統一を不変条件として固定する単体テスト群。
//!
//! bug-08: 失敗時の `checked_count` は失敗種別に依らず「最初の失敗より手前で完全検証
//! できた件数（= 進捗位置）」に統一されている。同じ「2 件正常 + 1 件不正」で、署名側・
//! 連鎖側のいずれの失敗種別でも `checked_count == 2` になることを検証する。
//! forbidden-key 経路は元から部分件数だが、silent drift 封鎖のため明示的に固定する。

use serde_json::json;

use crate::audit::RequestId;
use crate::ledger::{
    LEDGER_CANONICALIZATION_VERSION_V1, LEDGER_HASH_ALGORITHM_SHA3_256,
    LEDGER_SIGNATURE_ALGORITHM_ED25519, LedgerChainHead, LedgerEntryDraft, LedgerEntryDraftParts,
    LedgerEntryId, LedgerEntryType, LedgerHash, LedgerPayload, LedgerResult, LedgerSequenceNo,
    LedgerSignatureKeyVersion, LedgerSigningKey, SignedLedgerEntry,
};
use crate::server::supabase::LedgerVerificationMaterialRow;
use crate::types::SourceEventAt;

use super::jobs::{verify_chain_links, verify_hash_chain_rows, verify_signature_rows};

/// 暗号学的に有効な署名を生成するための固定 ed25519 テスト秘密鍵。
const TEST_SECRET_KEY_BYTES: [u8; 32] = [
    0x98, 0x3b, 0x6e, 0x5f, 0x0f, 0x8a, 0xa1, 0x56, 0x2e, 0x5a, 0x4e, 0x7b, 0x9f, 0x0d, 0x2b, 0x7f,
    0x8c, 0x3a, 0x4d, 0x7e, 0x9f, 0xa2, 0xc1, 0x5d, 0x6b, 0x8e, 0x3f, 0xa2, 0xc1, 0x5d, 0x6b, 0x8e,
];

fn signing_key() -> LedgerSigningKey {
    LedgerSigningKey::from_secret_key_bytes(
        LedgerSignatureKeyVersion::new(1).expect("valid key version"),
        &TEST_SECRET_KEY_BYTES,
    )
    .expect("valid signing key")
}

fn valid_payload() -> LedgerPayload {
    LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "algorithm": "xchacha20-poly1305",
            "classification": "confidential",
            "key_version": 1,
            "version": 1
        }),
    )
    .expect("valid payload")
}

/// 指定 `sequence_no` / `previous_entry_hash` で内部的に整合した署名済みエントリを作る。
fn signed_entry(
    key: &LedgerSigningKey,
    sequence_no: u64,
    previous_entry_hash: LedgerHash,
) -> SignedLedgerEntry {
    let draft = LedgerEntryDraft::new(LedgerEntryDraftParts {
        ledger_entry_id: LedgerEntryId::generate().expect("ledger entry id"),
        sequence_no: LedgerSequenceNo::new(sequence_no).expect("sequence no"),
        entry_type: LedgerEntryType::SecretCreated,
        source_event_at: SourceEventAt::parse("2026-04-08T12:00:00Z").expect("source_event_at"),
        request_id: RequestId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("request id"),
        source_event_id: None,
        target_secret_id: None,
        target_secret_version_id: None,
        actor_user_id: None,
        actor_device_id: None,
        result: LedgerResult::Success,
        error_code: None,
        payload: valid_payload(),
        previous_entry_hash,
        signature_key_version: LedgerSignatureKeyVersion::new(1).expect("valid key version"),
    })
    .expect("valid draft");
    draft.sign(key).expect("valid signature")
}

/// 正常に連鎖した `len` 件のエントリと、それに対応する chain head を作る。
fn signed_chain(key: &LedgerSigningKey, len: u64) -> (Vec<SignedLedgerEntry>, LedgerChainHead) {
    let mut entries = Vec::new();
    let mut previous_hash = LedgerHash::genesis();
    for sequence_no in 1..=len {
        let entry = signed_entry(key, sequence_no, previous_hash);
        previous_hash = entry.entry_hash();
        entries.push(entry);
    }
    let head = LedgerChainHead::new(len, previous_hash).expect("chain head");
    (entries, head)
}

/// 署名済みエントリを検証用 DTO 行に写像する（`include_public_key=false` で鍵欠落を再現）。
fn material_row(
    entry: &SignedLedgerEntry,
    public_key: &[u8],
    include_public_key: bool,
) -> LedgerVerificationMaterialRow {
    LedgerVerificationMaterialRow {
        ledger_entry_id: entry.ledger_entry_id().clone(),
        sequence_no: entry.sequence_no(),
        entry_hash: entry.entry_hash(),
        previous_entry_hash: entry.previous_entry_hash(),
        signature: entry.signature(),
        signature_key_version: entry.signature_key_version(),
        entry_type: entry.entry_type().as_str().to_owned(),
        source_event_at: entry.source_event_at().as_str().to_owned(),
        request_id: entry.request_id().as_canonical_string(),
        source_event_id: entry.source_event_id().map(|id| id.as_canonical_string()),
        target_secret_id: entry.target_secret_id().map(|id| id.as_canonical_string()),
        target_secret_version_id: entry
            .target_secret_version_id()
            .map(|id| id.as_canonical_string()),
        actor_user_id: entry.actor_user_id().map(|id| id.as_canonical_string()),
        actor_device_id: entry.actor_device_id().map(|id| id.as_str().to_owned()),
        result: entry.result().as_str().to_owned(),
        error_code: entry.error_code().map(str::to_owned),
        payload: entry.payload().as_value(),
        canonicalization_version: LEDGER_CANONICALIZATION_VERSION_V1 as i32,
        hash_algorithm: LEDGER_HASH_ALGORITHM_SHA3_256.to_owned(),
        signature_algorithm: LEDGER_SIGNATURE_ALGORITHM_ED25519.to_owned(),
        pk_key_version: include_public_key.then_some(1),
        pk_public_key: include_public_key.then(|| format!("\\x{}", hex::encode(public_key))),
        pk_algorithm: include_public_key.then(|| "ed25519".to_owned()),
        pk_status: include_public_key.then(|| "active".to_owned()),
    }
}

/// 正常に連鎖・署名された `len` 件の検証用行を作る。
fn valid_signature_rows(key: &LedgerSigningKey, len: u64) -> Vec<LedgerVerificationMaterialRow> {
    let public_key = key.verification_key().as_bytes();
    let (entries, _head) = signed_chain(key, len);
    entries
        .iter()
        .map(|entry| material_row(entry, &public_key, true))
        .collect()
}

// ---- 署名検証側: 全失敗種別で checked_count == 手前の正常件数 ----

#[test]
fn signature_forbidden_key_reports_progress_count() {
    let key = signing_key();
    let mut rows = valid_signature_rows(&key, 3);
    rows[2].payload = json!({ "plaintext": "leak" });

    let summary = verify_signature_rows(rows).expect("verification runs");

    assert!(!summary.valid);
    assert_eq!(summary.error_code, Some("ledger_payload_forbidden_key"));
    assert_eq!(summary.checked_count, 2);
}

#[test]
fn signature_invalid_reports_progress_count() {
    let key = signing_key();
    let mut rows = valid_signature_rows(&key, 3);
    // 別エントリ（seq1）の署名を流用すると seq3 の canonical payload には一致しない。
    rows[2].signature = rows[0].signature;

    let summary = verify_signature_rows(rows).expect("verification runs");

    assert!(!summary.valid);
    assert_eq!(summary.error_code, Some("ledger_signature_invalid"));
    assert_eq!(summary.checked_count, 2);
}

#[test]
fn signature_key_missing_reports_progress_count() {
    let key = signing_key();
    let mut rows = valid_signature_rows(&key, 3);
    rows[2].pk_key_version = None;
    rows[2].pk_public_key = None;
    rows[2].pk_algorithm = None;
    rows[2].pk_status = None;

    let summary = verify_signature_rows(rows).expect("verification runs");

    assert!(!summary.valid);
    assert_eq!(summary.error_code, Some("ledger_signature_key_missing"));
    assert_eq!(summary.checked_count, 2);
}

#[test]
fn signature_all_valid_reports_total_count() {
    let key = signing_key();
    let rows = valid_signature_rows(&key, 3);

    let summary = verify_signature_rows(rows).expect("verification runs");

    assert!(summary.valid);
    assert_eq!(summary.error_code, None);
    assert_eq!(summary.checked_count, 3);
}

// ---- ハッシュ連鎖検証側: 全失敗種別で checked_count == 手前の正常件数 ----

#[test]
fn chain_sequence_gap_reports_progress_count() {
    let key = signing_key();
    let e1 = signed_entry(&key, 1, LedgerHash::genesis());
    let e2 = signed_entry(&key, 2, e1.entry_hash());
    let e3 = signed_entry(&key, 5, e2.entry_hash());
    let head = LedgerChainHead::new(5, e3.entry_hash()).expect("chain head");

    let summary = verify_chain_links(&[e1, e2, e3], head).expect("verification runs");

    assert!(!summary.valid);
    assert_eq!(summary.error_code, Some("ledger_sequence_gap"));
    assert_eq!(summary.checked_count, 2);
}

#[test]
fn chain_previous_hash_mismatch_reports_progress_count() {
    let key = signing_key();
    let e1 = signed_entry(&key, 1, LedgerHash::genesis());
    let e2 = signed_entry(&key, 2, e1.entry_hash());
    // 3 件目の previous_entry_hash を e2 と不一致にする。
    let e3 = signed_entry(&key, 3, LedgerHash::genesis());
    let head = LedgerChainHead::new(3, e3.entry_hash()).expect("chain head");

    let summary = verify_chain_links(&[e1, e2, e3], head).expect("verification runs");

    assert!(!summary.valid);
    assert_eq!(summary.error_code, Some("ledger_previous_hash_mismatch"));
    assert_eq!(summary.checked_count, 2);
}

#[test]
fn chain_entry_hash_mismatch_reports_progress_count() {
    let key = signing_key();
    let public_key = key.verification_key().as_bytes();
    let (entries, head) = signed_chain(&key, 3);
    let mut rows: Vec<_> = entries
        .iter()
        .map(|entry| material_row(entry, &public_key, true))
        .collect();
    // 3 件目の entry_hash を改変し recompute と不一致にする（restore は再計算しない）。
    rows[2].entry_hash = LedgerHash::genesis();

    let summary = verify_hash_chain_rows(head, rows).expect("verification runs");

    assert!(!summary.valid);
    assert_eq!(summary.error_code, Some("ledger_entry_hash_mismatch"));
    assert_eq!(summary.checked_count, 2);
}

#[test]
fn chain_forbidden_key_reports_progress_count() {
    let key = signing_key();
    let public_key = key.verification_key().as_bytes();
    let (entries, head) = signed_chain(&key, 3);
    let mut rows: Vec<_> = entries
        .iter()
        .map(|entry| material_row(entry, &public_key, true))
        .collect();
    rows[2].payload = json!({ "plaintext": "leak" });

    let summary = verify_hash_chain_rows(head, rows).expect("verification runs");

    assert!(!summary.valid);
    assert_eq!(summary.error_code, Some("ledger_payload_forbidden_key"));
    assert_eq!(summary.checked_count, 2);
}

#[test]
fn chain_head_mismatch_reports_total_count() {
    let key = signing_key();
    let (entries, _head) = signed_chain(&key, 3);
    // 全リンクは正常だが chain head の last_entry_hash が観測と不一致。
    let wrong_head = LedgerChainHead::new(3, LedgerHash::genesis()).expect("chain head");

    let summary = verify_chain_links(&entries, wrong_head).expect("verification runs");

    assert!(!summary.valid);
    assert_eq!(summary.error_code, Some("ledger_chain_head_mismatch"));
    // 全件が個別検証を通過したため進捗件数は総件数に一致する。
    assert_eq!(summary.checked_count, 3);
}

#[test]
fn chain_all_valid_reports_total_count() {
    let key = signing_key();
    let (entries, head) = signed_chain(&key, 3);

    let summary = verify_chain_links(&entries, head).expect("verification runs");

    assert!(summary.valid);
    assert_eq!(summary.error_code, None);
    assert_eq!(summary.checked_count, 3);
}

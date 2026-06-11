//! incident 通知 free-text guard（`FORBIDDEN_NOTIFICATION_TEXT`）が、監査メタデータ forbidden 正本
//! （`FORBIDDEN_AUDIT_METADATA_KEYS`）を部分一致でカバーすることを恒久強制する parity test（bug-07）。
//!
//! incident 通知の自由文（summary / affected_component / triage_url / correlation_id）は外部 webhook へ
//! 送出されるため、秘密語混入を `validate_non_secret_text`（lowercase + 部分一致 `contains`）で弾く多層防御を持つ。
//! その禁止語集合は正本と独立手書きのため、両者の整合（正本の各語が自由文に現れたら必ず弾かれること
//! ＝「正本 ⊆ text_guard の部分一致カバー」）を担保する test がなく silent drift し得た（bug-05 / bug-06 と同型）。
//! 本 test がそのカバーを CI で固定する。正本へ forbidden 語を追加したら `FORBIDDEN_NOTIFICATION_TEXT` も
//! 追従すること（追従漏れはここで落ちる）。
//!
//! 本件は Rust 内 parity（incident text_guard は SQL 側ガードを持たない）であり、SQL migration 自動発見は使わない。

use mipsorcu::{FORBIDDEN_AUDIT_METADATA_KEYS, FORBIDDEN_NOTIFICATION_TEXT, IncidentSummary};

/// bug-07 で閉じた gap 語。25 語版の `FORBIDDEN_NOTIFICATION_TEXT` ではいずれの語も部分一致せず素通りしていた。
const FORMER_GAP_WORDS: &[&str] = &[
    "alias_fingerprint_key",
    "decrypt_result",
    "ed25519_private_key",
    "ledger_signing_key",
    "secret_body",
];

#[test]
fn canon_subset_covered_by_incident_text_guard() {
    // validate_non_secret_text の判定（lowercase + 部分一致 contains）を鏡写しにして、
    // 正本 forbidden 語のうち incident text_guard がカバーしない語が無いことを集合レベルで検証する。
    let uncovered: Vec<&str> = FORBIDDEN_AUDIT_METADATA_KEYS
        .iter()
        .copied()
        .filter(|canon_key| {
            let lower = canon_key.to_ascii_lowercase();
            !FORBIDDEN_NOTIFICATION_TEXT
                .iter()
                .any(|forbidden| lower.contains(forbidden))
        })
        .collect();

    assert!(
        uncovered.is_empty(),
        "監査メタデータ forbidden 正本のうち incident text_guard が部分一致でカバーしない語がある: {uncovered:?}。\
         FORBIDDEN_NOTIFICATION_TEXT に各語（またはそれを部分文字列として含む語）を追加すること（bug-07）。"
    );
}

#[test]
fn incident_summary_rejects_each_canon_key() {
    // 集合 const と実関数 validate_non_secret_text のバインドを保証する（片側 drift 防止の二重化）。
    // canon 語はすべて短い ascii snake_case なので length/charset 検査は通り、forbidden 判定でのみ Err になる。
    for canon_key in FORBIDDEN_AUDIT_METADATA_KEYS {
        assert!(
            IncidentSummary::new(*canon_key).is_err(),
            "incident summary が監査 forbidden 正本語 `{canon_key}` を受理してしまう（外部 webhook へ漏れ得る）。"
        );
    }
}

#[test]
fn former_gap_words_are_now_rejected() {
    // bug-07 で閉じた 5 語の回帰防止。正本に含まれること、かつ incident 自由文として拒否されることを固定する。
    for word in FORMER_GAP_WORDS {
        assert!(
            FORBIDDEN_AUDIT_METADATA_KEYS.contains(word),
            "former gap word `{word}` は監査 forbidden 正本に含まれるはず"
        );
        assert!(
            IncidentSummary::new(*word).is_err(),
            "former gap word `{word}` must now be rejected by incident text guard"
        );
    }
}

#[test]
fn incident_text_guard_has_no_canon_foreign_word() {
    // 現状 text_guard 固有語（正本に無い語）は 0。将来 text_guard 固有の追加が必要になったら本 test を
    // 意図的に更新する（無言の drift ではなく明示的な設計判断にするためのトリップワイヤ）。
    let foreign: Vec<&str> = FORBIDDEN_NOTIFICATION_TEXT
        .iter()
        .copied()
        .filter(|word| !FORBIDDEN_AUDIT_METADATA_KEYS.contains(word))
        .collect();

    assert!(
        foreign.is_empty(),
        "FORBIDDEN_NOTIFICATION_TEXT に正本 FORBIDDEN_AUDIT_METADATA_KEYS へ無い語がある: {foreign:?}。\
         意図的な text_guard 固有語なら本 test を更新し、そうでなければ綴り誤りを正すこと（bug-07）。"
    );
}

#[test]
fn benign_incident_summary_is_accepted() {
    // 固定テンプレ相当の通知文は受理される（gap 5 語の追加で正規の通知文を誤拒否していないことの確認）。
    for summary in [
        "ledger anomaly detected by scheduler",
        "scheduler job monthly_hash_chain_verify failed 3 consecutive times",
        "envelope migration failure burst reached 10 events",
        "global auth failure burst reached 20 events",
    ] {
        assert!(
            IncidentSummary::new(summary).is_ok(),
            "benign summary should be accepted: {summary:?}"
        );
    }
}

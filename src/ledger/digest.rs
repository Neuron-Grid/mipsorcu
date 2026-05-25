//! 月次 digest canonical form。
//!
//! **`build_monthly_digest_canonical_form` が canonical form 生成の唯一の実装である。**
//! 呼び出し側で独自に JSON を組み立てることは禁止されている。
//!
//! 信頼境界ノート: digest 生成・署名は SBC 内で完結する。Master Key・Data Key・平文を
//! 含まず、ledger の非秘密メタデータのみを扱う。

use std::fmt;

use serde::Serialize;
use sha3::{Digest as _, Sha3_256};

use super::constants::{
    LEDGER_HASH_ALGORITHM_SHA3_256, LEDGER_HASH_LENGTH, LEDGER_SIGNATURE_ALGORITHM_ED25519,
};
use super::error::LedgerError;
use super::hash::LedgerHash;
use super::ids::LedgerSequenceNo;
use super::signature::{LedgerSignature, LedgerSignatureKeyVersion};
use crate::types::SourceEventAt;

/// digest canonical form の schema version。
/// 既存の `canonicalization_version` とは独立した系統。
pub const DIGEST_SCHEMA_VERSION_V1: u32 = 1;

/// digest 生成主体の固定識別子（`generated_by`）。
pub const DIGEST_GENERATED_BY: &str = "mipsorcu-sbc";

/// 月次 digest の対象年月。`YYYY-MM` 形式で検証済み。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MonthlyDigestPeriod(String);

impl MonthlyDigestPeriod {
    /// `"YYYY-MM"` 形式の文字列から生成する。
    /// 月は 01〜12 の範囲でなければならない（ゼロパディング必須）。
    pub fn parse(value: &str) -> Result<Self, LedgerError> {
        validate_year_month_format(value)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_year_month_format(value: &str) -> Result<(), LedgerError> {
    let bytes = value.as_bytes();
    // "YYYY-MM" = 7 bytes
    if bytes.len() != 7 || bytes[4] != b'-' {
        return Err(LedgerError::InvalidMonthlyDigestPeriod);
    }
    if !bytes[..4].iter().all(|b| b.is_ascii_digit()) {
        return Err(LedgerError::InvalidMonthlyDigestPeriod);
    }
    if !bytes[5..].iter().all(|b| b.is_ascii_digit()) {
        return Err(LedgerError::InvalidMonthlyDigestPeriod);
    }
    let month: u8 = value[5..].parse().unwrap_or(0);
    if month == 0 || month > 12 {
        return Err(LedgerError::InvalidMonthlyDigestPeriod);
    }
    Ok(())
}

/// digest canonical form のバイト列。
///
/// SHA3-256 digest hash および Ed25519 署名の入力。
/// `serde_json` compact 出力（余分な空白・改行なし）を UTF-8 として保持する。
#[derive(Clone, PartialEq, Eq)]
pub struct DigestCanonicalBytes(Vec<u8>);

impl DigestCanonicalBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for DigestCanonicalBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigestCanonicalBytes")
            .field("len", &self.0.len())
            .finish()
    }
}

/// digest canonical form の SHA3-256 hash（32 バイト）。
///
/// `LedgerHash::from_canonical_payload` と同一方式（SHA3-256）を
/// digest canonical form に適用する。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DigestHash([u8; LEDGER_HASH_LENGTH]);

impl DigestHash {
    /// canonical bytes の SHA3-256 hash を計算して生成する。
    pub fn from_canonical_bytes(bytes: &DigestCanonicalBytes) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(bytes.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; LEDGER_HASH_LENGTH];
        hash.copy_from_slice(&result);
        Self(hash)
    }

    /// 小文字 hex 文字列（64 文字）に変換する。既存の `LedgerHash::to_hex()` と互換。
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; LEDGER_HASH_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for DigestHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigestHash")
            .field("hex", &self.to_hex())
            .finish()
    }
}

/// SBC が署名した月次 digest。
///
/// `ledger_entries` への記録と外部アーカイブの入力に使用する。
/// 秘密情報（Master Key・Data Key・平文）を一切含まない。
#[derive(Clone)]
pub struct SignedMonthlyDigest {
    /// 対象年月（YYYY-MM）。
    pub period: MonthlyDigestPeriod,
    /// 対象範囲の sequence_no 開始値。
    pub start_sequence_no: LedgerSequenceNo,
    /// 対象範囲の sequence_no 終了値。
    pub end_sequence_no: LedgerSequenceNo,
    /// 対象範囲の先頭 entry_hash。
    pub start_entry_hash: LedgerHash,
    /// 対象範囲の末尾 entry_hash。
    pub end_entry_hash: LedgerHash,
    /// 対象エントリ件数（> 0）。
    pub entry_count: u64,
    /// digest 生成時刻（RFC 3339 UTC、末尾 Z）。SBC が決定。
    pub digest_generated_at: SourceEventAt,
    /// 署名に使用した Ed25519 鍵のバージョン。
    pub signature_key_version: LedgerSignatureKeyVersion,
    /// canonical JSON バイト列（署名対象）。
    pub canonical_bytes: DigestCanonicalBytes,
    /// canonical bytes の SHA3-256 hash（外部アーカイブ・timestamping 用）。
    pub digest_hash: DigestHash,
    /// digest canonical bytes に対する Ed25519 署名。
    pub sbc_signature: LedgerSignature,
}

impl fmt::Debug for SignedMonthlyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedMonthlyDigest")
            .field("period", &self.period)
            .field("start_sequence_no", &self.start_sequence_no)
            .field("end_sequence_no", &self.end_sequence_no)
            .field("entry_count", &self.entry_count)
            .field("signature_key_version", &self.signature_key_version)
            .field("digest_hash", &self.digest_hash)
            .field("sbc_signature", &"<redacted>")
            .finish()
    }
}

/// 定義済みの 12 フィールドを含む canonical JSON を生成する。
///
/// **この関数が monthly digest canonical form 生成の唯一の実装である。**
/// 呼び出し側が独自に JSON を組み立てることは禁止されている。
///
/// フィールドはアルファベット順（辞書順）に固定されている。
/// 構造変更時は `DIGEST_SCHEMA_VERSION_V1` をインクリメントする。
///
/// 引数が多い理由: 定義済み 12 フィールドのうち呼び出し側が決定する
/// 全フィールドを受け取る必要があり、構造体でラップすることはしない。
#[allow(clippy::too_many_arguments)]
pub fn build_monthly_digest_canonical_form(
    period: &MonthlyDigestPeriod,
    start_sequence_no: LedgerSequenceNo,
    end_sequence_no: LedgerSequenceNo,
    start_entry_hash: LedgerHash,
    end_entry_hash: LedgerHash,
    entry_count: u64,
    digest_generated_at: &SourceEventAt,
    signature_key_version: LedgerSignatureKeyVersion,
) -> Result<DigestCanonicalBytes, LedgerError> {
    // hex 文字列はローカル変数に保持してライフタイムを確保する
    let start_hash_hex = start_entry_hash.to_hex();
    let end_hash_hex = end_entry_hash.to_hex();

    // フィールド宣言順 == アルファベット順
    let document = DigestCanonicalDocument {
        digest_generated_at: digest_generated_at.as_str(),
        digest_schema_version: DIGEST_SCHEMA_VERSION_V1,
        end_entry_hash: &end_hash_hex,
        end_sequence_no: end_sequence_no.get(),
        entry_count,
        generated_by: DIGEST_GENERATED_BY,
        hash_algorithm: LEDGER_HASH_ALGORITHM_SHA3_256,
        signature_algorithm: LEDGER_SIGNATURE_ALGORITHM_ED25519,
        signature_key_version: signature_key_version.get(),
        start_entry_hash: &start_hash_hex,
        start_sequence_no: start_sequence_no.get(),
        target_year_month: period.as_str(),
    };

    let bytes = serde_json::to_vec(&document)
        .map_err(|error| LedgerError::SerializationFailed(error.to_string()))?;

    Ok(DigestCanonicalBytes(bytes))
}

/// 定義済みフィールド一覧（アルファベット順固定）。
///
/// `serde_json::to_vec` はフィールド宣言順で JSON を生成するため、
/// 宣言順がアルファベット順と一致していることが canonical 性の保証となる。
/// フィールドの追加・並び替えはスキーマバージョンアップを要する。
#[derive(Serialize)]
struct DigestCanonicalDocument<'a> {
    // 1. digest_generated_at
    digest_generated_at: &'a str,
    // 2. digest_schema_version
    digest_schema_version: u32,
    // 3. end_entry_hash
    end_entry_hash: &'a str,
    // 4. end_sequence_no
    end_sequence_no: u64,
    // 5. entry_count
    entry_count: u64,
    // 6. generated_by
    generated_by: &'a str,
    // 7. hash_algorithm
    hash_algorithm: &'static str,
    // 8. signature_algorithm
    signature_algorithm: &'static str,
    // 9. signature_key_version
    signature_key_version: u32,
    // 10. start_entry_hash
    start_entry_hash: &'a str,
    // 11. start_sequence_no
    start_sequence_no: u64,
    // 12. target_year_month
    target_year_month: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::hash::LedgerHash;
    use crate::ledger::ids::LedgerSequenceNo;
    use crate::ledger::signature::LedgerSignatureKeyVersion;
    use crate::types::SourceEventAt;

    fn make_test_period() -> MonthlyDigestPeriod {
        MonthlyDigestPeriod::parse("2026-05").expect("valid period")
    }

    fn make_test_generated_at() -> SourceEventAt {
        SourceEventAt::parse("2026-06-01T00:00:00Z").expect("valid timestamp")
    }

    fn make_test_hash(byte: u8) -> LedgerHash {
        LedgerHash::from_bytes(&[byte; 32]).expect("valid hash")
    }

    fn make_test_key_version() -> LedgerSignatureKeyVersion {
        LedgerSignatureKeyVersion::new(1).expect("valid key version")
    }

    fn make_canonical_bytes() -> DigestCanonicalBytes {
        build_monthly_digest_canonical_form(
            &make_test_period(),
            LedgerSequenceNo::new(1).expect("valid seq"),
            LedgerSequenceNo::new(42).expect("valid seq"),
            make_test_hash(0xaa),
            make_test_hash(0xbb),
            42,
            &make_test_generated_at(),
            make_test_key_version(),
        )
        .expect("canonical form build must succeed")
    }

    #[test]
    fn canonical_form_is_valid_json() {
        let bytes = make_canonical_bytes();
        let parsed: serde_json::Value =
            serde_json::from_slice(bytes.as_bytes()).expect("must be valid JSON");
        assert!(parsed.is_object());
    }

    #[test]
    fn canonical_form_keys_are_alphabetical() {
        let bytes = make_canonical_bytes();
        let json_str = std::str::from_utf8(bytes.as_bytes()).expect("valid UTF-8");

        // JSON キーの出現順序がアルファベット順であることを確認
        let expected_keys = [
            "digest_generated_at",
            "digest_schema_version",
            "end_entry_hash",
            "end_sequence_no",
            "entry_count",
            "generated_by",
            "hash_algorithm",
            "signature_algorithm",
            "signature_key_version",
            "start_entry_hash",
            "start_sequence_no",
            "target_year_month",
        ];

        let mut positions = expected_keys.iter().map(|key| {
            json_str
                .find(&format!("\"{key}\""))
                .unwrap_or_else(|| panic!("key {key:?} not found in canonical form"))
        });

        let mut prev = positions.next().expect("at least one key");
        for pos in positions {
            assert!(
                pos > prev,
                "keys are not in alphabetical order in canonical form"
            );
            prev = pos;
        }
    }

    #[test]
    fn canonical_form_is_stable() {
        let bytes1 = make_canonical_bytes();
        let bytes2 = make_canonical_bytes();
        assert_eq!(bytes1, bytes2, "canonical form must be stable across calls");
    }

    #[test]
    fn canonical_form_has_no_extra_whitespace() {
        let bytes = make_canonical_bytes();
        let json_str = std::str::from_utf8(bytes.as_bytes()).expect("valid UTF-8");
        // compact JSON: no spaces after colons or commas
        assert!(
            !json_str.contains(": "),
            "canonical form must not have spaces after colon"
        );
        assert!(
            !json_str.contains(", "),
            "canonical form must not have spaces after comma"
        );
    }

    #[test]
    fn canonical_form_contains_correct_schema_version() {
        let bytes = make_canonical_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
        assert_eq!(
            parsed["digest_schema_version"].as_u64(),
            Some(u64::from(DIGEST_SCHEMA_VERSION_V1))
        );
    }

    #[test]
    fn canonical_form_contains_correct_generated_by() {
        let bytes = make_canonical_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
        assert_eq!(parsed["generated_by"].as_str(), Some(DIGEST_GENERATED_BY));
    }

    #[test]
    fn digest_hash_is_sha3_256_of_canonical_bytes() {
        let bytes = make_canonical_bytes();
        let hash = DigestHash::from_canonical_bytes(&bytes);
        assert_eq!(hash.to_hex().len(), 64);
    }

    #[test]
    fn monthly_digest_period_parse_valid() {
        assert!(MonthlyDigestPeriod::parse("2026-05").is_ok());
        assert!(MonthlyDigestPeriod::parse("2024-01").is_ok());
        assert!(MonthlyDigestPeriod::parse("9999-12").is_ok());
    }

    #[test]
    fn monthly_digest_period_parse_invalid() {
        assert!(MonthlyDigestPeriod::parse("2026-00").is_err()); // month 0
        assert!(MonthlyDigestPeriod::parse("2026-13").is_err()); // month 13
        assert!(MonthlyDigestPeriod::parse("2026-5").is_err()); // not zero-padded
        assert!(MonthlyDigestPeriod::parse("202605").is_err()); // no dash
        assert!(MonthlyDigestPeriod::parse("2026/05").is_err()); // wrong separator
        assert!(MonthlyDigestPeriod::parse("").is_err()); // empty
        assert!(MonthlyDigestPeriod::parse("abcd-ef").is_err()); // not digits
    }

    #[test]
    fn canonical_form_matches_adr_sample_structure() {
        // サンプル JSON との構造的整合性を確認する
        let bytes = build_monthly_digest_canonical_form(
            &MonthlyDigestPeriod::parse("2026-05").unwrap(),
            LedgerSequenceNo::new(109).unwrap(),
            LedgerSequenceNo::new(150).unwrap(),
            LedgerHash::from_hex(
                "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
            )
            .unwrap(),
            LedgerHash::from_hex(
                "8f2c1b3e9d0a4f5c6b7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b",
            )
            .unwrap(),
            42,
            &SourceEventAt::parse("2026-06-01T00:00:00Z").unwrap(),
            LedgerSignatureKeyVersion::new(1).unwrap(),
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
        assert_eq!(parsed["target_year_month"].as_str(), Some("2026-05"));
        assert_eq!(parsed["start_sequence_no"].as_u64(), Some(109));
        assert_eq!(parsed["end_sequence_no"].as_u64(), Some(150));
        assert_eq!(parsed["entry_count"].as_u64(), Some(42));
        assert_eq!(
            parsed["hash_algorithm"].as_str(),
            Some(LEDGER_HASH_ALGORITHM_SHA3_256)
        );
        assert_eq!(
            parsed["signature_algorithm"].as_str(),
            Some(LEDGER_SIGNATURE_ALGORITHM_ED25519)
        );
        assert_eq!(parsed["generated_by"].as_str(), Some(DIGEST_GENERATED_BY));
        assert_eq!(
            parsed["digest_schema_version"].as_u64(),
            Some(u64::from(DIGEST_SCHEMA_VERSION_V1))
        );
    }
}

//! `ArchiveExportPackage` の定義とシリアライズ。
//!
//! 信頼境界ノート: `ArchiveExportPackage` は `SignedMonthlyDigest` からのみ
//! 構築可能であり（private fields）、平文・Master Key・Data Key・JWT を
//! 型レベルで含むことが不可能。

use serde::Serialize;
use serde_json::Value;

use crate::ledger::SignedMonthlyDigest;

use super::backend::ArchiveBackendError;

/// アーカイブファイルのスキーマバージョン（digest_schema_version とは独立）。
pub const ARCHIVE_SCHEMA_VERSION: u32 = 1;

/// 外部アーカイブへ書き込む export パッケージ。
///
/// `from_digest` が唯一のコンストラクタであり、`SignedMonthlyDigest` からのみ
/// 構築可能。これにより、アーカイブバックエンドへ渡せるデータが型レベルで
/// 非秘密情報に限定される。
///
/// Clone を実装しないのは、シリアライズ済みバイト列のメモリ上への不用意な
/// 複製を防ぐため。
pub struct ArchiveExportPackage {
    digest_hash_hex: String,
    sbc_signature_hex: String,
    signature_key_version: u32,
    /// canonical_bytes を JSON としてパースした Value::Object。
    /// 文字列ではなくオブジェクトとして埋め込むことで、アーカイブファイルが
    /// 人間可読な形式になる。
    digest_canonical: Value,
}

impl ArchiveExportPackage {
    /// `SignedMonthlyDigest` から構築する。
    ///
    /// これがこの型の唯一のコンストラクタ。`SignedMonthlyDigest` には
    /// `Plaintext`・`MasterKey`・`DataKey`・`RawJwt` が含まれないため、
    /// 秘密情報除外の保証が型レベルで成立する。
    pub fn from_digest(digest: &SignedMonthlyDigest) -> Result<Self, ArchiveBackendError> {
        let digest_canonical: Value = serde_json::from_slice(digest.canonical_bytes.as_bytes())
            .map_err(|error| {
                ArchiveBackendError::SerializationFailed(format!(
                    "failed to parse digest canonical bytes: {error}"
                ))
            })?;

        Ok(Self {
            digest_hash_hex: digest.digest_hash.to_hex(),
            sbc_signature_hex: hex::encode(digest.sbc_signature.as_bytes()),
            signature_key_version: digest.signature_key_version.get(),
            digest_canonical,
        })
    }

    /// アーカイブファイルに書き込む JSON バイト列を生成する。
    ///
    /// アーカイブ JSON 形式（フィールドはアルファベット順）:
    /// ```json
    /// {
    ///   "archive_schema_version": 1,
    ///   "digest": { ...定義済みの 12 フィールド... },
    ///   "digest_hash": "<64文字小文字 hex>",
    ///   "sbc_signature": "<128文字小文字 hex>",
    ///   "signature_key_version": 1
    /// }
    /// ```
    ///
    /// `sbc_signature` は Ed25519 署名値（非秘密）。外部検証者が署名を確認するため
    /// アーカイブに含める。
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ArchiveBackendError> {
        let doc = ArchiveDocument {
            archive_schema_version: ARCHIVE_SCHEMA_VERSION,
            digest: &self.digest_canonical,
            digest_hash: &self.digest_hash_hex,
            sbc_signature: &self.sbc_signature_hex,
            signature_key_version: self.signature_key_version,
        };
        serde_json::to_vec(&doc).map_err(|error| {
            ArchiveBackendError::SerializationFailed(format!(
                "failed to serialize archive document: {error}"
            ))
        })
    }

    pub fn digest_hash_hex(&self) -> &str {
        &self.digest_hash_hex
    }
}

impl std::fmt::Debug for ArchiveExportPackage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArchiveExportPackage")
            .field("digest_hash_hex", &self.digest_hash_hex)
            .field("signature_key_version", &self.signature_key_version)
            .field("sbc_signature", &"<redacted>")
            .finish()
    }
}

/// アーカイブ JSON ドキュメントのレイアウト（アルファベット順固定）。
///
/// `serde_json::to_vec` はフィールド宣言順で JSON を生成するため、
/// 宣言順がアルファベット順と一致していることが canonical 性の保証となる。
#[derive(Serialize)]
struct ArchiveDocument<'a> {
    // 1. archive_schema_version
    archive_schema_version: u32,
    // 2. digest
    digest: &'a Value,
    // 3. digest_hash
    digest_hash: &'a str,
    // 4. sbc_signature
    sbc_signature: &'a str,
    // 5. signature_key_version
    signature_key_version: u32,
}

#[cfg(test)]
#[path = "../../tests/unit/archive/export/tests.rs"]
mod tests;

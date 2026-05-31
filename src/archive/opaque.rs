//! archive backend に保存する非 digest の opaque object（task-11、ADR-0040 §3 追補）。
//!
//! 信頼境界ノート: `ArchiveOpaqueObject` の唯一のコンストラクタは
//! [`from_timestamping_token`](ArchiveOpaqueObject::from_timestamping_token) であり、
//! `TimestampingToken`（TSA 応答 / dummy backend からのみ生成される非秘密バイト列）
//! からのみ構築できる。`Plaintext` / `MasterKey` / `DataKey` / `RawJwt` を型レベルで
//! 含められない（[`ArchiveExportPackage`](super::export::ArchiveExportPackage) と同思想）。
//!
//! 月次 digest 本体は `ArchiveExportPackage` 経路、TSA token はこの opaque 経路で
//! 保管する。両者で archive backend へ渡せるデータを非秘密に限定する。

use crate::timestamping::TimestampingToken;

/// archive backend に保管する不透明バイト列（現状は RFC 3161 TSA token 専用）。
///
/// `Clone` を実装しないのは、保管バイト列のメモリ上への不用意な複製を避けるため。
pub struct ArchiveOpaqueObject {
    bytes: Vec<u8>,
}

impl ArchiveOpaqueObject {
    /// timestamping token（RFC 3161 `TimeStampResp` の DER 等）から構築する。
    ///
    /// これがこの型の唯一のコンストラクタ。token は外部 TSA 応答 / dummy backend
    /// 由来の非秘密バイト列であり、秘密情報除外の保証が型レベルで成立する。
    pub fn from_timestamping_token(token: &TimestampingToken) -> Self {
        Self {
            bytes: token.as_bytes().to_vec(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for ArchiveOpaqueObject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArchiveOpaqueObject")
            .field("len", &self.bytes.len())
            .finish()
    }
}

//! `TimestampingService` trait と関連型の定義。
//!
//! 信頼境界ノート: `request_timestamp` の引数型は `&DigestHash`（32 バイト SHA-256）に
//! 限定される。`LedgerEntry` 全件・`SignedMonthlyDigest` の他フィールド・平文・Master Key・
//! Data Key・JWT を引数として渡すことが型レベルで不可能。

use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::ledger::DigestHash;

/// timestamping token のバイト長下限。空 token を構造的に排除する。
const TIMESTAMPING_TOKEN_MIN_LENGTH: usize = 1;

/// timestamping token のバイト長上限（4 MiB）。
/// RFC 3161 の TimeStampResp は通常数 KiB に収まるが、将来的な大きな token
/// （複数の中間証明書を含む）にも対応する余裕を持たせる。
const TIMESTAMPING_TOKEN_MAX_LENGTH: usize = 4 * 1024 * 1024;

/// timestamping token hash のバイト長（SHA-256）。
const TIMESTAMPING_TOKEN_HASH_LENGTH: usize = 32;

/// 外部 timestamping サービスから返された不透明な token バイト列。
///
/// RFC 3161 では DER エンコードされた `TimeStampResp` 全体を保持する想定。
/// 中身の解釈はバックエンド実装に閉じる。
#[derive(Clone, PartialEq, Eq)]
pub struct TimestampingToken(Vec<u8>);

impl TimestampingToken {
    /// バイト列から token を構築する。空または上限超過は拒否する。
    pub fn new(bytes: Vec<u8>) -> Result<Self, TimestampingServiceError> {
        if bytes.len() < TIMESTAMPING_TOKEN_MIN_LENGTH {
            return Err(TimestampingServiceError::InvalidResponse {
                reason: "timestamping token must not be empty",
            });
        }
        if bytes.len() > TIMESTAMPING_TOKEN_MAX_LENGTH {
            return Err(TimestampingServiceError::InvalidResponse {
                reason: "timestamping token exceeds maximum allowed length",
            });
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for TimestampingToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TimestampingToken")
            .field("len", &self.0.len())
            .finish()
    }
}

/// timestamping token の SHA-256 ハッシュ（32 バイト）。
///
/// `ledger_entries.payload.timestamp_token_hash` および
/// `audit_events.metadata_json.timestamp_token_hash` 用の相関 ID。
/// 64 文字小文字 hex で記録する（既存 `DigestHash::to_hex` と同方式）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimestampingTokenHash([u8; TIMESTAMPING_TOKEN_HASH_LENGTH]);

impl TimestampingTokenHash {
    /// token のバイト列から SHA-256 ハッシュを計算する。
    pub fn from_token(token: &TimestampingToken) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; TIMESTAMPING_TOKEN_HASH_LENGTH];
        hash.copy_from_slice(&result);
        Self(hash)
    }

    pub fn as_bytes(&self) -> &[u8; TIMESTAMPING_TOKEN_HASH_LENGTH] {
        &self.0
    }

    /// 小文字 hex 文字列（64 文字）に変換する。
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

/// timestamping バックエンドのエラー型。
#[derive(Debug)]
pub enum TimestampingServiceError {
    /// バックエンドの I/O・ネットワーク・プロトコル操作が失敗した。
    BackendFailed { code: String },
    /// バックエンドから返ってきた応答が不正（空 token、不正フォーマット等）。
    InvalidResponse { reason: &'static str },
}

impl fmt::Display for TimestampingServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendFailed { code } => {
                write!(formatter, "timestamping backend failed: {code}")
            }
            Self::InvalidResponse { reason } => {
                write!(formatter, "timestamping invalid response: {reason}")
            }
        }
    }
}

impl std::error::Error for TimestampingServiceError {}

/// 外部 timestamping サービスの抽象化 trait。
///
/// # 型安全保証
///
/// `request_timestamp` の引数型は `&DigestHash` に限定されている。
/// `DigestHash` は `[u8; 32]` の sealed wrapper であり、`SignedMonthlyDigest`
/// 全体・`LedgerEntry` 全件・平文・鍵・JWT を含むことが構造的に不可能。
///
/// 返り値の `TimestampingToken` は不透明バイト列であり、ledger には
/// `TimestampingTokenHash` のみを記録し、token raw bytes は呼び出し側責務で
/// 永続化する（非秘密情報のみを ledger に保存するため）。
#[allow(async_fn_in_trait)]
pub trait TimestampingService: Send + Sync + 'static {
    /// digest hash に対する timestamping を要求する。
    ///
    /// 引数は 32 バイトの SHA-256 ハッシュのみ。バックエンドは hash 以外の
    /// 情報にアクセスできない。
    async fn request_timestamp(
        &self,
        digest_hash: &DigestHash,
    ) -> Result<TimestampingToken, TimestampingServiceError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_new_rejects_empty() {
        let error = TimestampingToken::new(Vec::new()).expect_err("empty must be rejected");
        assert!(matches!(
            error,
            TimestampingServiceError::InvalidResponse { .. }
        ));
    }

    #[test]
    fn token_new_accepts_one_byte() {
        let token = TimestampingToken::new(vec![0x01]).expect("one byte must be accepted");
        assert_eq!(token.len(), 1);
        assert!(!token.is_empty());
    }

    #[test]
    fn token_new_rejects_oversize() {
        let bytes = vec![0u8; TIMESTAMPING_TOKEN_MAX_LENGTH + 1];
        let error = TimestampingToken::new(bytes).expect_err("oversize must be rejected");
        assert!(matches!(
            error,
            TimestampingServiceError::InvalidResponse { .. }
        ));
    }

    #[test]
    fn token_debug_redacts_contents() {
        let token = TimestampingToken::new(vec![0xaa, 0xbb, 0xcc]).unwrap();
        let debug = format!("{token:?}");
        assert!(debug.contains("len"));
        assert!(!debug.contains("aa"));
        assert!(!debug.contains("bb"));
    }

    #[test]
    fn token_hash_is_sha256() {
        let token = TimestampingToken::new(b"abc".to_vec()).unwrap();
        let hash = TimestampingTokenHash::from_token(&token);
        // SHA-256("abc")
        assert_eq!(
            hash.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn token_hash_hex_is_64_char_lowercase() {
        let token = TimestampingToken::new(vec![0x42; 100]).unwrap();
        let hex = TimestampingTokenHash::from_token(&token).to_hex();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
    }

    #[test]
    fn token_hash_is_deterministic() {
        let token = TimestampingToken::new(vec![0x01, 0x02, 0x03]).unwrap();
        let hash1 = TimestampingTokenHash::from_token(&token);
        let hash2 = TimestampingTokenHash::from_token(&token);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn token_hash_differs_for_different_tokens() {
        let token_a = TimestampingToken::new(vec![0x01]).unwrap();
        let token_b = TimestampingToken::new(vec![0x02]).unwrap();
        let hash_a = TimestampingTokenHash::from_token(&token_a);
        let hash_b = TimestampingTokenHash::from_token(&token_b);
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn error_display_backend_failed() {
        let error = TimestampingServiceError::BackendFailed {
            code: "network".to_owned(),
        };
        assert_eq!(format!("{error}"), "timestamping backend failed: network");
    }

    #[test]
    fn error_display_invalid_response() {
        let error = TimestampingServiceError::InvalidResponse {
            reason: "empty payload",
        };
        assert_eq!(
            format!("{error}"),
            "timestamping invalid response: empty payload"
        );
    }
}

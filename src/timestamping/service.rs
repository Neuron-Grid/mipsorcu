//! `TimestampingService` trait と関連型の定義。
//!
//! 信頼境界ノート: `request_timestamp` の引数型は `&DigestHash`（32 バイト SHA3-256）に
//! 限定される。`LedgerEntry` 全件・`SignedMonthlyDigest` の他フィールド・平文・Master Key・
//! Data Key・JWT を引数として渡すことが型レベルで不可能。

use std::fmt;

use sha3::{Digest as _, Sha3_256};

use crate::ledger::DigestHash;

/// timestamping token のバイト長下限。空 token を構造的に排除する。
const TIMESTAMPING_TOKEN_MIN_LENGTH: usize = 1;

/// timestamping token のバイト長上限（4 MiB）。
/// RFC 3161 の TimeStampResp は通常数 KiB に収まるが、将来的な大きな token
/// （複数の中間証明書を含む）にも対応する余裕を持たせる。
const TIMESTAMPING_TOKEN_MAX_LENGTH: usize = 4 * 1024 * 1024;

/// timestamping token hash のバイト長（SHA3-256）。
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

/// timestamping token の SHA3-256 ハッシュ（32 バイト）。
///
/// `ledger_entries.payload.timestamp_token_hash` および
/// `audit_events.metadata_json.timestamp_token_hash` 用の相関 ID。
/// 64 文字小文字 hex で記録する（既存 `DigestHash::to_hex` と同方式）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimestampingTokenHash([u8; TIMESTAMPING_TOKEN_HASH_LENGTH]);

impl TimestampingTokenHash {
    /// token のバイト列から SHA3-256 ハッシュを計算する。
    pub fn from_token(token: &TimestampingToken) -> Self {
        let mut hasher = Sha3_256::new();
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

/// timestamping backend の種別（表示・ログ用。秘密情報を含まない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimestampingProviderKind {
    /// テスト用 in-memory dummy backend。
    LocalDummy,
    /// RFC 3161 互換 TSA backend。
    Rfc3161,
}

impl TimestampingProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalDummy => "local_dummy",
            Self::Rfc3161 => "rfc3161",
        }
    }
}

impl fmt::Display for TimestampingProviderKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// `verify_timestamp` の検証結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampVerification {
    /// token は有効。imprint が `expected_hash` と一致し、TSA 署名も検証済み。
    Valid(VerifiedTimestamp),
    /// 検証に失敗した（理由つき）。token 自体は秘密ではないため理由を保持してよい。
    Invalid {
        failure_kind: TimestampVerificationFailureKind,
    },
}

/// 検証に成功した timestamp から取り出した非秘密メタデータ。
///
/// いずれも CLI 出力・structured log 用であり、ledger / audit_events には
/// 記録しない（ADR-0040 の payload allowlist を変えない）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifiedTimestamp {
    /// TSA serial number（小文字 hex）。dummy backend では固定値。
    pub tsa_serial_hex: String,
    /// TSA の gen_time（RFC 3339）。dummy backend では `None`。
    pub gen_time: Option<String>,
}

/// timestamp 検証失敗の分類。`audit_events`/incident には `as_str` の固定文字列を使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimestampVerificationFailureKind {
    /// token を RFC 3161 TimeStampResp / TST として解析できない。
    Malformed,
    /// PKIStatus が granted / grantedWithMods でない。
    NotGranted,
    /// TST の MessageImprint（hash algorithm / value）が `expected_hash` と一致しない。
    ImprintMismatch,
    /// TSA 署名が証明書チェーンに対して無効。
    SignatureInvalid,
}

impl TimestampVerificationFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NotGranted => "not_granted",
            Self::ImprintMismatch => "imprint_mismatch",
            Self::SignatureInvalid => "signature_invalid",
        }
    }
}

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
    /// 引数は 32 バイトの SHA3-256 ハッシュのみ。バックエンドは hash 以外の
    /// 情報にアクセスできない。
    async fn request_timestamp(
        &self,
        digest_hash: &DigestHash,
    ) -> Result<TimestampingToken, TimestampingServiceError>;

    /// 取得済み token が `expected_hash`（32 バイト SHA3-256）に対する有効な
    /// timestamp かを検証する。
    ///
    /// ネットワーク不要のオフライン検証。RFC 3161 backend では token 内の
    /// TSA 証明書チェーンに対して署名を検証し、TST の MessageImprint が
    /// `expected_hash` と一致することを確認する。引数は token と hash のみで、
    /// 秘密情報・credential を必要としない。
    async fn verify_timestamp(
        &self,
        token: &TimestampingToken,
        expected_hash: &DigestHash,
    ) -> Result<TimestampVerification, TimestampingServiceError>;

    /// backend 種別を返す（表示・ログ用、秘密情報なし）。
    fn provider_kind(&self) -> TimestampingProviderKind;
}

#[cfg(test)]
#[path = "../../tests/unit/timestamping/service/tests.rs"]
mod tests;

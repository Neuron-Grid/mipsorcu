//! `AnyTimestampingProvider` — 実行時に backend 実装を選択するディスパッチ enum。
//!
//! `TimestampingService` trait は `async fn` を含むため dyn 化できない。
//! `AnyArchiveBackend` / `AnySiemSink` と同じ方針で enum 経由の静的ディスパッチを
//! 提供し、CLI が `MIPSORCU_TIMESTAMPING_PROVIDER` の値に応じて backend を切り替え
//! られるようにする。
//!
//! 信頼境界ノート: いずれの variant も `request_timestamp` の引数型は trait 経由で
//! `&DigestHash` に固定される。秘密情報を backend へ渡せない構造を維持する。

use crate::ledger::DigestHash;

use super::dummy::InMemoryTimestampingService;
use super::rfc3161::Rfc3161TimestampingService;
use super::sender::RetryingTimestampingService;
use super::service::{
    TimestampVerification, TimestampingProviderKind, TimestampingService, TimestampingServiceError,
    TimestampingToken,
};

/// 実行時に選択された timestamping backend。
///
/// `LocalDummy` はテスト・開発用途（本番禁止）、`Rfc3161` は production 用途
/// （複数 TSA URL の順次 fallback を内包する）。
pub enum AnyTimestampingProvider {
    /// in-memory dummy backend（`local_dummy`、本番禁止）。
    LocalDummy(InMemoryTimestampingService),
    /// RFC 3161 互換 TSA backend（`rfc3161`、順次 fallback + retry 付き）。
    Rfc3161(RetryingTimestampingService<Rfc3161TimestampingService>),
}

impl AnyTimestampingProvider {
    /// 出力・ログ用の backend 種別ラベル（秘密情報を含まない）。
    pub fn kind_label(&self) -> &'static str {
        self.provider_kind().as_str()
    }
}

impl TimestampingService for AnyTimestampingProvider {
    async fn request_timestamp(
        &self,
        digest_hash: &DigestHash,
    ) -> Result<TimestampingToken, TimestampingServiceError> {
        match self {
            Self::LocalDummy(backend) => backend.request_timestamp(digest_hash).await,
            Self::Rfc3161(backend) => backend.request_timestamp(digest_hash).await,
        }
    }

    async fn verify_timestamp(
        &self,
        token: &TimestampingToken,
        expected_hash: &DigestHash,
    ) -> Result<TimestampVerification, TimestampingServiceError> {
        match self {
            Self::LocalDummy(backend) => backend.verify_timestamp(token, expected_hash).await,
            Self::Rfc3161(backend) => backend.verify_timestamp(token, expected_hash).await,
        }
    }

    fn provider_kind(&self) -> TimestampingProviderKind {
        match self {
            Self::LocalDummy(backend) => backend.provider_kind(),
            Self::Rfc3161(backend) => backend.provider_kind(),
        }
    }
}

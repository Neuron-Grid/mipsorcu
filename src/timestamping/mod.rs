//! 外部 timestamping 抽象化レイヤー（Phase 2 §8、ADR 0040）。
//!
//! 月次 digest hash に対する RFC 3161 互換または同等の外部 timestamping を
//! 統合するための `TimestampingService` trait と関連型を定義する。
//! 具体的なバックエンド実装（FreeTSA / DigiCert 等）は別モジュールで行う。
//!
//! 信頼境界ノート: `TimestampingService::request_timestamp` の引数型は
//! `&DigestHash`（32 バイト SHA3-256）に限定される。`LedgerEntry` 全件・
//! `SignedMonthlyDigest` の他フィールド・平文・鍵・JWT が型レベルで送信不可。

pub mod dummy;
pub mod service;

pub use dummy::{FailingTimestampingService, InMemoryTimestampingService};
pub use service::{
    TimestampingService, TimestampingServiceError, TimestampingToken, TimestampingTokenHash,
};

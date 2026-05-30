//! 外部アーカイブ抽象化レイヤー。
//!
//! 月次 digest を外部アーカイブへ保全するための `ArchiveBackend` trait と
//! 関連型を定義する。具体的なバックエンド実装（S3 等）は別モジュールで行う。
//!
//! 信頼境界ノート: `ArchiveExportPackage` は `SignedMonthlyDigest` からのみ
//! 構築可能。平文・Master Key・Data Key・JWT が型レベルで排除される。

pub mod any;
pub mod backend;
pub mod dummy;
pub mod export;
pub mod s3;

pub use any::AnyArchiveBackend;
pub use backend::{ArchiveBackend, ArchiveBackendError, ArchiveObjectKey, ArchiveVerifyOutcome};
pub use dummy::{InMemoryArchiveBackend, LocalFileArchiveBackend};
pub use export::{ARCHIVE_SCHEMA_VERSION, ArchiveExportPackage};
pub use s3::{
    S3ArchiveBackendConfig, S3ArchiveBackendConfigError, S3ImmutableArchiveBackend,
    S3ObjectLockMode,
};

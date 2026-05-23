//! S3 互換 immutable object storage backend。
//!
//! `ArchiveBackend` trait の production 実装。AWS Signature Version 4 で
//! 署名し、Object Lock ヘッダで WORM を強制する。`If-None-Match: *` で
//! 上書きを拒否し、5xx / 接続失敗は指数バックオフで自動リトライする。
//!
//! 信頼境界ノート: 引数型は trait 経由で `&ArchiveExportPackage` 固定。
//! 平文・Master Key・Data Key・JWT を型レベルで受け取れない。env から
//! 読んだ S3 アクセスキーは SBC 内部にのみ保持し、Supabase 側には渡さない。
//!
//! 運用ノート: 本モジュールは opt-in の S3 backend 実装のみを提供する。
//! 標準 runtime / scheduler への backend 選択・設定結線はこのモジュールの
//! 責務外であり、v0.1.0 では S3 archive は限定運用扱いである。

pub mod backend;
pub mod client;
pub mod config;
pub mod error;
pub mod object_lock;
pub mod queue;
pub mod retry;
pub mod sigv4;

pub use backend::S3ImmutableArchiveBackend;
pub use config::{S3ArchiveBackendConfig, S3ArchiveBackendConfigError};
pub use object_lock::S3ObjectLockMode;
pub use queue::{
    ArchivePutOrQueueOutcome, ArchiveQueueError, LocalArchiveQueue, QueuedArchiveObject,
    ResendArchiveSummary,
};

//! `AnyArchiveBackend` — 実行時に backend 実装を選択するためのディスパッチ enum。
//!
//! `ArchiveBackend` trait は `async fn` を含むため dyn 化できない。`AnySiemSink` /
//! `AnyNotificationSink` と同じ方針で enum 経由の静的ディスパッチを提供し、CLI や
//! scheduler が `MIPSORCU_ARCHIVE_BACKEND` 等の設定値に応じて backend を切り替え
//! られるようにする。
//!
//! 信頼境界ノート: いずれの variant も `put_object` の引数型は trait 経由で
//! `&ArchiveExportPackage` に固定される。秘密情報を backend へ渡せない構造を維持
//! する。

use super::backend::{ArchiveBackend, ArchiveBackendError, ArchiveObjectKey, ArchiveVerifyOutcome};
use super::dummy::LocalFileArchiveBackend;
use super::export::ArchiveExportPackage;
use super::opaque::ArchiveOpaqueObject;
use super::s3::S3ImmutableArchiveBackend;

/// 実行時に選択された archive backend。
///
/// `LocalFile` は開発・dummy 用途（本番禁止）、`S3` は production 用途。
#[derive(Clone)]
pub enum AnyArchiveBackend {
    /// ローカルファイルシステム backend（`local_dummy`、本番禁止）。
    LocalFile(LocalFileArchiveBackend),
    /// S3 互換 immutable object storage backend（`s3_object_lock`）。
    S3(Box<S3ImmutableArchiveBackend>),
}

impl AnyArchiveBackend {
    /// 出力・ログ用の backend 種別ラベル（秘密情報を含まない）。
    pub fn kind(&self) -> &'static str {
        match self {
            Self::LocalFile(_) => "local_dummy",
            Self::S3(_) => "s3_object_lock",
        }
    }
}

impl ArchiveBackend for AnyArchiveBackend {
    async fn put_object(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
    ) -> Result<(), ArchiveBackendError> {
        match self {
            Self::LocalFile(backend) => backend.put_object(key, package).await,
            Self::S3(backend) => backend.put_object(key, package).await,
        }
    }

    async fn verify_object(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
    ) -> Result<ArchiveVerifyOutcome, ArchiveBackendError> {
        match self {
            Self::LocalFile(backend) => backend.verify_object(key, package).await,
            Self::S3(backend) => backend.verify_object(key, package).await,
        }
    }

    async fn list_objects(&self) -> Result<Vec<ArchiveObjectKey>, ArchiveBackendError> {
        match self {
            Self::LocalFile(backend) => backend.list_objects().await,
            Self::S3(backend) => backend.list_objects().await,
        }
    }

    async fn put_opaque_object(
        &self,
        key: &ArchiveObjectKey,
        object: &ArchiveOpaqueObject,
    ) -> Result<(), ArchiveBackendError> {
        match self {
            Self::LocalFile(backend) => backend.put_opaque_object(key, object).await,
            Self::S3(backend) => backend.put_opaque_object(key, object).await,
        }
    }

    async fn get_opaque_object(
        &self,
        key: &ArchiveObjectKey,
    ) -> Result<Option<Vec<u8>>, ArchiveBackendError> {
        match self {
            Self::LocalFile(backend) => backend.get_opaque_object(key).await,
            Self::S3(backend) => backend.get_opaque_object(key).await,
        }
    }
}

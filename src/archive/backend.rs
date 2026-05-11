//! `ArchiveBackend` trait と関連型の定義。
//!
//! 信頼境界ノート: `put_object` の引数型は `ArchiveExportPackage` であり、
//! `SignedMonthlyDigest` からのみ構築可能。平文・Master Key・Data Key・JWT を
//! 引数として受け取ることが型レベルで不可能。

use std::fmt;

use super::export::ArchiveExportPackage;

/// 外部アーカイブ内のオブジェクトを識別するキー。
///
/// 非空かつ 256 文字以内の文字列でなければならない。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArchiveObjectKey(String);

impl ArchiveObjectKey {
    pub fn new(key: impl Into<String>) -> Result<Self, ArchiveBackendError> {
        let key = key.into();
        if key.is_empty() {
            return Err(ArchiveBackendError::InvalidKey {
                reason: "archive object key must not be empty",
            });
        }
        if key.len() > 256 {
            return Err(ArchiveBackendError::InvalidKey {
                reason: "archive object key must not exceed 256 characters",
            });
        }
        Ok(Self(key))
    }

    /// 月次 digest 用の標準キーを生成する。
    /// 形式: `digests/{YYYY-MM}/digest.json`
    pub fn for_monthly_digest(
        period: &crate::ledger::MonthlyDigestPeriod,
    ) -> Result<Self, ArchiveBackendError> {
        let key = format!("digests/{}/digest.json", period.as_str());
        Self::new(key)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ArchiveObjectKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// `verify_object` の検証結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveVerifyOutcome {
    /// オブジェクトが存在し、内容が一致する。
    Valid,
    /// オブジェクトがバックエンドに存在しない。
    NotFound,
    /// オブジェクトは存在するが、内容が一致しない。
    ContentMismatch,
}

/// アーカイブバックエンド操作のエラー型。
#[derive(Debug)]
pub enum ArchiveBackendError {
    /// キーが不正（空文字または長すぎる）。
    InvalidKey { reason: &'static str },
    /// エクスポートパッケージのシリアライズに失敗した。
    SerializationFailed(String),
    /// バックエンドの I/O またはネットワーク操作が失敗した。
    BackendFailed { code: String },
    /// ローカルファイル操作の I/O エラー（LocalFileArchiveBackend 用）。
    IoError(std::io::Error),
}

impl fmt::Display for ArchiveBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey { reason } => write!(formatter, "invalid archive key: {reason}"),
            Self::SerializationFailed(message) => {
                write!(formatter, "archive serialization failed: {message}")
            }
            Self::BackendFailed { code } => write!(formatter, "archive backend failed: {code}"),
            Self::IoError(error) => write!(formatter, "archive I/O error: {error}"),
        }
    }
}

impl std::error::Error for ArchiveBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(error) => Some(error),
            _ => None,
        }
    }
}

/// 外部アーカイブバックエンドの抽象化 trait。
///
/// # 型安全保証
///
/// `put_object` の引数型は `&ArchiveExportPackage` であり、
/// `ArchiveExportPackage::from_digest(&SignedMonthlyDigest)` からのみ構築可能。
/// `SignedMonthlyDigest` は `Plaintext`・`MasterKey`・`DataKey`・`RawJwt` を
/// フィールドに持たないため、バックエンドに秘密情報を渡すことが型レベルで不可能。
#[allow(async_fn_in_trait)]
pub trait ArchiveBackend: Send + Sync + 'static {
    async fn put_object(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
    ) -> Result<(), ArchiveBackendError>;

    async fn verify_object(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
    ) -> Result<ArchiveVerifyOutcome, ArchiveBackendError>;

    async fn list_objects(&self) -> Result<Vec<ArchiveObjectKey>, ArchiveBackendError>;
}

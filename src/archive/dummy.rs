//! テスト用ダミーバックエンド。
//!
//! `InMemoryArchiveBackend`: スレッドセーフなメモリ上のキーバリューストア。
//! `LocalFileArchiveBackend`: ローカルファイルシステムへの書き込み（開発・テスト専用）。
//!
//! いずれも本番用途禁止（耐久性・WORM 保証なし）。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::backend::{ArchiveBackend, ArchiveBackendError, ArchiveObjectKey, ArchiveVerifyOutcome};
use super::export::ArchiveExportPackage;

// ─────────────────────────────────────────────────────────────────────────────
// InMemoryArchiveBackend
// ─────────────────────────────────────────────────────────────────────────────

/// メモリ上のアーカイブバックエンド（テスト専用）。
///
/// `Arc<Mutex<...>>` で複数スレッドから安全に共有できる。
/// `clone()` すると同じストアを共有するため、テスト内で複数の参照を持てる。
///
/// **本番用途禁止**: プロセス終了でデータが失われる。
#[derive(Debug, Clone, Default)]
pub struct InMemoryArchiveBackend {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl InMemoryArchiveBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// 指定キーに保存されたバイト列を返す（テストヘルパー）。
    pub fn get_bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.store
            .lock()
            .ok()
            .and_then(|guard| guard.get(key).cloned())
    }

    /// ストア内のオブジェクト数を返す（テストヘルパー）。
    pub fn len(&self) -> usize {
        self.store.lock().map_or(0, |guard| guard.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ArchiveBackend for InMemoryArchiveBackend {
    async fn put_object(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
    ) -> Result<(), ArchiveBackendError> {
        let bytes = package.to_json_bytes()?;
        let mut guard = self
            .store
            .lock()
            .map_err(|_| ArchiveBackendError::BackendFailed {
                code: "mutex_poisoned".into(),
            })?;
        guard.insert(key.as_str().to_owned(), bytes);
        Ok(())
    }

    async fn verify_object(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
    ) -> Result<ArchiveVerifyOutcome, ArchiveBackendError> {
        let expected = package.to_json_bytes()?;
        let guard = self
            .store
            .lock()
            .map_err(|_| ArchiveBackendError::BackendFailed {
                code: "mutex_poisoned".into(),
            })?;
        match guard.get(key.as_str()) {
            None => Ok(ArchiveVerifyOutcome::NotFound),
            Some(stored) if *stored == expected => Ok(ArchiveVerifyOutcome::Valid),
            Some(_) => Ok(ArchiveVerifyOutcome::ContentMismatch),
        }
    }

    async fn list_objects(&self) -> Result<Vec<ArchiveObjectKey>, ArchiveBackendError> {
        let guard = self
            .store
            .lock()
            .map_err(|_| ArchiveBackendError::BackendFailed {
                code: "mutex_poisoned".into(),
            })?;
        guard
            .keys()
            .map(|k| ArchiveObjectKey::new(k.clone()))
            .collect::<Result<Vec<_>, _>>()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LocalFileArchiveBackend
// ─────────────────────────────────────────────────────────────────────────────

/// ローカルファイルシステムへのアーカイブバックエンド（開発・テスト専用）。
///
/// `put_object` は `base_dir/<key>` にファイルを書き込む。
/// キーにスラッシュが含まれる場合はサブディレクトリを作成する。
///
/// **本番用途禁止**: アトミック性・WORM 保証なし。
///
/// path traversal 防止: キー内の `..` コンポーネントを拒否する。
#[derive(Debug, Clone)]
pub struct LocalFileArchiveBackend {
    base_dir: PathBuf,
}

impl LocalFileArchiveBackend {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    fn resolve_path(&self, key: &ArchiveObjectKey) -> Result<PathBuf, ArchiveBackendError> {
        let key_path = std::path::Path::new(key.as_str());
        for component in key_path.components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(ArchiveBackendError::InvalidKey {
                    reason: "archive key must not contain '..' components",
                });
            }
        }
        Ok(self.base_dir.join(key.as_str()))
    }
}

impl ArchiveBackend for LocalFileArchiveBackend {
    async fn put_object(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
    ) -> Result<(), ArchiveBackendError> {
        let bytes = package.to_json_bytes()?;
        let path = self.resolve_path(key)?;
        tokio::task::spawn_blocking(move || {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(ArchiveBackendError::IoError)?;
            }
            std::fs::write(&path, &bytes).map_err(ArchiveBackendError::IoError)
        })
        .await
        .map_err(|_| join_failed_archive_error())?
    }

    async fn verify_object(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
    ) -> Result<ArchiveVerifyOutcome, ArchiveBackendError> {
        let expected = package.to_json_bytes()?;
        let path = self.resolve_path(key)?;
        tokio::task::spawn_blocking(move || match std::fs::read(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ArchiveVerifyOutcome::NotFound)
            }
            Err(error) => Err(ArchiveBackendError::IoError(error)),
            Ok(stored) if stored == expected => Ok(ArchiveVerifyOutcome::Valid),
            Ok(_) => Ok(ArchiveVerifyOutcome::ContentMismatch),
        })
        .await
        .map_err(|_| join_failed_archive_error())?
    }

    async fn list_objects(&self) -> Result<Vec<ArchiveObjectKey>, ArchiveBackendError> {
        let base_dir = self.base_dir.clone();
        tokio::task::spawn_blocking(move || {
            let entries = std::fs::read_dir(&base_dir).map_err(ArchiveBackendError::IoError)?;
            let mut result = Vec::new();
            for entry in entries {
                let entry = entry.map_err(ArchiveBackendError::IoError)?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                result.push(ArchiveObjectKey::new(name_str.as_ref()).map_err(|error| {
                    ArchiveBackendError::BackendFailed {
                        code: format!("invalid_key_from_filesystem: {error}"),
                    }
                })?);
            }
            Ok(result)
        })
        .await
        .map_err(|_| join_failed_archive_error())?
    }
}

fn join_failed_archive_error() -> ArchiveBackendError {
    ArchiveBackendError::IoError(std::io::Error::other("join failed"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "../../tests/unit/archive/dummy/tests.rs"]
mod tests;

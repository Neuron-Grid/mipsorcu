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
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(ArchiveBackendError::IoError)?;
        }
        std::fs::write(&path, &bytes).map_err(ArchiveBackendError::IoError)
    }

    async fn verify_object(
        &self,
        key: &ArchiveObjectKey,
        package: &ArchiveExportPackage,
    ) -> Result<ArchiveVerifyOutcome, ArchiveBackendError> {
        let expected = package.to_json_bytes()?;
        let path = self.resolve_path(key)?;
        match std::fs::read(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ArchiveVerifyOutcome::NotFound)
            }
            Err(error) => Err(ArchiveBackendError::IoError(error)),
            Ok(stored) if stored == expected => Ok(ArchiveVerifyOutcome::Valid),
            Ok(_) => Ok(ArchiveVerifyOutcome::ContentMismatch),
        }
    }

    async fn list_objects(&self) -> Result<Vec<ArchiveObjectKey>, ArchiveBackendError> {
        let entries = std::fs::read_dir(&self.base_dir).map_err(ArchiveBackendError::IoError)?;
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
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::export::ArchiveExportPackage;
    use crate::ledger::{
        DigestHash, LedgerHash, LedgerSequenceNo, LedgerSignature, LedgerSignatureKeyVersion,
        MonthlyDigestPeriod, SignedMonthlyDigest, build_monthly_digest_canonical_form,
    };
    use crate::types::SourceEventAt;

    fn make_test_digest() -> SignedMonthlyDigest {
        let period = MonthlyDigestPeriod::parse("2026-05").expect("valid period");
        let start_hash = LedgerHash::from_bytes(&[0xaa; 32]).expect("valid hash");
        let end_hash = LedgerHash::from_bytes(&[0xbb; 32]).expect("valid hash");
        let generated_at = SourceEventAt::parse("2026-06-01T00:00:00Z").expect("valid timestamp");
        let key_version = LedgerSignatureKeyVersion::new(1).expect("valid key version");
        let start_seq = LedgerSequenceNo::new(1).expect("valid seq");
        let end_seq = LedgerSequenceNo::new(42).expect("valid seq");

        let canonical_bytes = build_monthly_digest_canonical_form(
            &period,
            start_seq,
            end_seq,
            start_hash,
            end_hash,
            42,
            &generated_at,
            key_version,
        )
        .expect("build");

        let digest_hash = DigestHash::from_canonical_bytes(&canonical_bytes);
        let sbc_signature = LedgerSignature::from_bytes(&[0u8; 64]).expect("valid sig");

        SignedMonthlyDigest {
            period,
            start_sequence_no: start_seq,
            end_sequence_no: end_seq,
            start_entry_hash: start_hash,
            end_entry_hash: end_hash,
            entry_count: 42,
            digest_generated_at: generated_at,
            signature_key_version: key_version,
            canonical_bytes,
            digest_hash,
            sbc_signature,
        }
    }

    fn make_package() -> ArchiveExportPackage {
        ArchiveExportPackage::from_digest(&make_test_digest()).expect("package build")
    }

    fn make_key() -> ArchiveObjectKey {
        ArchiveObjectKey::for_monthly_digest(&MonthlyDigestPeriod::parse("2026-05").unwrap())
            .expect("key build")
    }

    #[tokio::test]
    async fn in_memory_put_then_verify_valid() {
        let backend = InMemoryArchiveBackend::new();
        let key = make_key();
        let package = make_package();

        backend
            .put_object(&key, &package)
            .await
            .expect("put must succeed");
        let outcome = backend
            .verify_object(&key, &package)
            .await
            .expect("verify must succeed");
        assert_eq!(outcome, ArchiveVerifyOutcome::Valid);
    }

    #[tokio::test]
    async fn in_memory_verify_not_found_before_put() {
        let backend = InMemoryArchiveBackend::new();
        let key = make_key();
        let package = make_package();

        let outcome = backend
            .verify_object(&key, &package)
            .await
            .expect("verify must succeed");
        assert_eq!(outcome, ArchiveVerifyOutcome::NotFound);
    }

    #[tokio::test]
    async fn in_memory_list_objects_returns_put_keys() {
        let backend = InMemoryArchiveBackend::new();
        let key = make_key();
        let package = make_package();

        assert!(backend.list_objects().await.unwrap().is_empty());
        backend.put_object(&key, &package).await.unwrap();
        let keys = backend.list_objects().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].as_str(), key.as_str());
    }

    #[tokio::test]
    async fn in_memory_put_twice_overwrites() {
        let backend = InMemoryArchiveBackend::new();
        let key = make_key();
        let package = make_package();

        backend.put_object(&key, &package).await.unwrap();
        backend.put_object(&key, &package).await.unwrap();
        assert_eq!(backend.len(), 1);
    }
}

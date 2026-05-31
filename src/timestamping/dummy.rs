//! テスト用 dummy timestamping backend。
//!
//! `InMemoryTimestampingService` は `Arc<Mutex<...>>` で複数スレッドから安全に共有でき、
//! 同じ `DigestHash` を再要求した場合は同じ token を決定的に返す（冪等）。
//!
//! **本番用途禁止**: プロセス終了でデータが失われ、外部 timestamping authority の
//! 法的タイムスタンプ性質を持たない。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::ledger::DigestHash;

use super::service::{
    TimestampVerification, TimestampVerificationFailureKind, TimestampingProviderKind,
    TimestampingService, TimestampingServiceError, TimestampingToken, VerifiedTimestamp,
};

/// dummy backend が返す token の固定 prefix。
/// 本番 RFC 3161 token と取り違えないための識別子。
const DUMMY_TOKEN_PREFIX: &[u8] = b"DUMMY-TST-V1:";

/// dummy backend が `verify_timestamp` 成功時に返す固定 serial（hex）。
/// 本番 TSA serial ではないことを示す識別子。
const DUMMY_TSA_SERIAL_HEX: &str = "00";

/// メモリ上の timestamping backend（テスト専用）。
///
/// 同じ `DigestHash` で複数回呼ばれた場合は同じ token を返す（決定性）。
/// `clone()` すると同じストアを共有する。
#[derive(Debug, Clone, Default)]
pub struct InMemoryTimestampingService {
    issued: Arc<Mutex<HashMap<[u8; 32], TimestampingToken>>>,
}

impl InMemoryTimestampingService {
    pub fn new() -> Self {
        Self::default()
    }

    /// これまで発行された token の総数を返す（テストヘルパ）。
    pub fn issued_count(&self) -> usize {
        self.issued.lock().map_or(0, |guard| guard.len())
    }

    /// 指定された digest hash 用に発行済みの token を返す（テストヘルパ）。
    pub fn token_for(&self, digest_hash: &DigestHash) -> Option<TimestampingToken> {
        self.issued
            .lock()
            .ok()
            .and_then(|guard| guard.get(digest_hash.as_bytes()).cloned())
    }
}

impl TimestampingService for InMemoryTimestampingService {
    async fn request_timestamp(
        &self,
        digest_hash: &DigestHash,
    ) -> Result<TimestampingToken, TimestampingServiceError> {
        let mut guard =
            self.issued
                .lock()
                .map_err(|_| TimestampingServiceError::BackendFailed {
                    code: "mutex_poisoned".into(),
                })?;
        if let Some(existing) = guard.get(digest_hash.as_bytes()) {
            return Ok(existing.clone());
        }

        let token = build_dummy_token(digest_hash)?;
        guard.insert(*digest_hash.as_bytes(), token.clone());
        Ok(token)
    }

    async fn verify_timestamp(
        &self,
        token: &TimestampingToken,
        expected_hash: &DigestHash,
    ) -> Result<TimestampVerification, TimestampingServiceError> {
        Ok(verify_dummy_token(token, expected_hash))
    }

    fn provider_kind(&self) -> TimestampingProviderKind {
        TimestampingProviderKind::LocalDummy
    }
}

/// dummy token（`DUMMY-TST-V1:` + digest_hash 32 バイト）を検証する。
///
/// 本番 RFC 3161 検証の代替であり、prefix と埋め込まれた hash が `expected_hash`
/// と一致するかのみを確認する（法的時刻保証性は持たない）。
fn verify_dummy_token(
    token: &TimestampingToken,
    expected_hash: &DigestHash,
) -> TimestampVerification {
    let bytes = token.as_bytes();
    let Some(embedded_hash) = bytes.strip_prefix(DUMMY_TOKEN_PREFIX) else {
        return TimestampVerification::Invalid {
            failure_kind: TimestampVerificationFailureKind::Malformed,
        };
    };
    if embedded_hash == expected_hash.as_bytes() {
        TimestampVerification::Valid(VerifiedTimestamp {
            tsa_serial_hex: DUMMY_TSA_SERIAL_HEX.to_owned(),
            gen_time: None,
        })
    } else {
        TimestampVerification::Invalid {
            failure_kind: TimestampVerificationFailureKind::ImprintMismatch,
        }
    }
}

fn build_dummy_token(
    digest_hash: &DigestHash,
) -> Result<TimestampingToken, TimestampingServiceError> {
    let hash_bytes = digest_hash.as_bytes();
    let mut bytes = Vec::with_capacity(DUMMY_TOKEN_PREFIX.len() + hash_bytes.len());
    bytes.extend_from_slice(DUMMY_TOKEN_PREFIX);
    bytes.extend_from_slice(hash_bytes);
    TimestampingToken::new(bytes)
}

/// 失敗をシミュレートするテスト用 backend。常に `BackendFailed` を返す。
#[derive(Debug, Clone, Default)]
pub struct FailingTimestampingService {
    code: String,
}

impl FailingTimestampingService {
    pub fn new(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }
}

impl TimestampingService for FailingTimestampingService {
    async fn request_timestamp(
        &self,
        _digest_hash: &DigestHash,
    ) -> Result<TimestampingToken, TimestampingServiceError> {
        Err(TimestampingServiceError::BackendFailed {
            code: self.code.clone(),
        })
    }

    async fn verify_timestamp(
        &self,
        _token: &TimestampingToken,
        _expected_hash: &DigestHash,
    ) -> Result<TimestampVerification, TimestampingServiceError> {
        Err(TimestampingServiceError::BackendFailed {
            code: self.code.clone(),
        })
    }

    fn provider_kind(&self) -> TimestampingProviderKind {
        TimestampingProviderKind::LocalDummy
    }
}

#[cfg(test)]
#[path = "../../tests/unit/timestamping/dummy/tests.rs"]
mod tests;

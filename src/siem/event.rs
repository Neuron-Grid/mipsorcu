//! SIEM 送信専用 DTO `SiemEvent`。
//!
//! 信頼境界ノート: 本 DTO は `AuditEvent` 等の SBC 内正本オブジェクトから
//! **構築時に** 非秘密フィールドだけを抽出する。`Plaintext` / `MasterKey` /
//! `DataKey` / `EncryptedDataKey` / `RawJwt` 等の秘密型は本構造体のフィールド
//! として **そもそも存在しない**（型レベル排除）。
//!
//! `metadata` には `AuditMetadata::as_value()` をそのまま転載するが、
//! `AuditMetadata` 自身が `FORBIDDEN_AUDIT_METADATA_KEYS` を構築時に拒否する
//! （[audit/event/metadata.rs](../audit/event/metadata.rs) 参照）ため、平文・
//! 鍵・JWT 等の禁止語キーは値レベルでも入り得ない。すなわち「型レベル + 監査
//! メタデータ allowlist」の二重防御により、SIEM 送信データへの秘密情報混入を
//! 構造的に防止する。

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::audit::{AuditAction, AuditEvent, AuditMetadata, AuditResult};
use crate::ledger::SignedLedgerEntry;
use crate::types::{KeyVersion, OwnerUserId, SecretId};

/// SIEM 送信時のスキーマバージョン。互換性のない変更を導入する場合は値を上げる。
pub const SIEM_EVENT_SCHEMA_VERSION: u32 = 1;

/// SIEM へ送信する非秘密イベント DTO。
///
/// シリアライズ形式は安定キー集合（`schema_version` / `event_id` /
/// `event_type` / `result` / `request_id` / `actor_user_id` /
/// `actor_device_id` / `target_secret_id` / `key_version` / `source_event_at` /
/// `metadata`）に固定される。`metadata` は元 `AuditMetadata` のキーをそのまま
/// 保持するが、`AuditMetadata` 側 allowlist により禁止キーは入り得ない。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiemEvent {
    schema_version: u32,
    event_id: String,
    event_type: String,
    result: String,
    request_id: String,
    actor_user_id: Option<String>,
    actor_device_id: Option<String>,
    target_secret_id: Option<String>,
    key_version: Option<u32>,
    source_event_at: String,
    metadata: Value,
}

impl SiemEvent {
    /// `AuditEvent` から SIEM 送信用 DTO を構築する。
    ///
    /// 取り出すフィールドは全て非秘密で、秘密型（`Plaintext` / `MasterKey` /
    /// `DataKey` / `RawJwt` 等）は本関数の引数にも戻り値にも現れない。
    pub fn from_audit_event(event: &AuditEvent) -> Self {
        // AuditEvent::new は source_event_at 必須性を構築時に保証するため、
        // ここでの取り出しは常に Ok（unwrap_or で no-op の保険を入れる）。
        let source_event_at = event
            .source_event_at()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_default();

        Self {
            schema_version: SIEM_EVENT_SCHEMA_VERSION,
            event_id: event.audit_event_id().as_canonical_string(),
            event_type: event.action().as_str().to_owned(),
            result: event.result().as_str().to_owned(),
            request_id: event.request_id().as_canonical_string(),
            actor_user_id: event.actor_user_id().map(OwnerUserId::as_canonical_string),
            actor_device_id: event
                .actor_device_id()
                .map(|device_id| device_id.as_str().to_owned()),
            target_secret_id: event.target_secret_id().map(SecretId::as_canonical_string),
            key_version: event.key_version().map(KeyVersion::get),
            source_event_at,
            metadata: event.metadata_json().as_value().clone(),
        }
    }

    /// `ledger_entries` の署名済み行から SIEM 送信用 DTO を構築する。
    ///
    /// `SignedLedgerEntry` は ledger の正本型だが、ここでは SIEM 送信専用 DTO に
    /// 非秘密フィールドだけを再配置する。`payload` は `LedgerPayload` 側で
    /// action ごとの allowlist と forbidden-key 検査を通過済みの値のみを保持する。
    /// 署名バイト列そのものは送信せず、hash と key version だけを送る。
    pub fn from_signed_ledger_entry(entry: &SignedLedgerEntry) -> Self {
        let metadata = json!({
            "event_family": "ledger",
            "entry_hash": entry.entry_hash().to_hex(),
            "ledger_entry_id": entry.ledger_entry_id().as_canonical_string(),
            "payload": entry.payload().as_value(),
            "previous_entry_hash": entry.previous_entry_hash().to_hex(),
            "sequence_no": entry.sequence_no().get(),
            "signature_algorithm": "ed25519",
            "signature_key_version": entry.signature_key_version().get(),
            "source_event_id": entry
                .source_event_id()
                .map(|id| id.as_canonical_string()),
            "target_secret_version_id": entry
                .target_secret_version_id()
                .map(|id| id.as_canonical_string()),
        });

        Self {
            schema_version: SIEM_EVENT_SCHEMA_VERSION,
            event_id: entry.ledger_entry_id().as_canonical_string(),
            event_type: entry.entry_type().as_str().to_owned(),
            result: entry.result().as_str().to_owned(),
            request_id: entry.request_id().as_canonical_string(),
            actor_user_id: entry.actor_user_id().map(OwnerUserId::as_canonical_string),
            actor_device_id: entry
                .actor_device_id()
                .map(|device_id| device_id.as_str().to_owned()),
            target_secret_id: entry.target_secret_id().map(SecretId::as_canonical_string),
            key_version: Some(entry.signature_key_version().get()),
            source_event_at: entry.source_event_at().as_str().to_owned(),
            metadata,
        }
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    pub fn result(&self) -> &str {
        &self.result
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn actor_user_id(&self) -> Option<&str> {
        self.actor_user_id.as_deref()
    }

    pub fn actor_device_id(&self) -> Option<&str> {
        self.actor_device_id.as_deref()
    }

    pub fn target_secret_id(&self) -> Option<&str> {
        self.target_secret_id.as_deref()
    }

    pub fn key_version(&self) -> Option<u32> {
        self.key_version
    }

    pub fn source_event_at(&self) -> &str {
        &self.source_event_at
    }

    pub fn metadata(&self) -> &Value {
        &self.metadata
    }
}

impl fmt::Debug for SiemEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 中身（特に metadata）の文字列展開を避け、構造のみを表示する。
        formatter
            .debug_struct("SiemEvent")
            .field("schema_version", &self.schema_version)
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .field("result", &self.result)
            .field("request_id", &self.request_id)
            .field("source_event_at", &self.source_event_at)
            .field("metadata", &"<redacted>")
            .finish()
    }
}

/// SIEM へ送信する DTO の安定キー集合。`serde_json::to_value` 出力のキーが
/// この集合の部分集合であることを `SiemEvent::serialized_top_level_keys` で
/// 検証できる。
pub const SIEM_EVENT_TOP_LEVEL_KEYS: &[&str] = &[
    "actor_device_id",
    "actor_user_id",
    "event_id",
    "event_type",
    "key_version",
    "metadata",
    "request_id",
    "result",
    "schema_version",
    "source_event_at",
    "target_secret_id",
];

/// 内部ヘルパ: 本 DTO が `AuditMetadata` に依存することを compile 時に検証する。
#[allow(dead_code)]
const fn _assert_metadata_uses_audit_layer<T>(_: fn(&AuditMetadata) -> T) {}
#[allow(dead_code)]
const _ASSERT_AUDIT_RESULT: fn(AuditResult) -> &'static str = AuditResult::as_str;
#[allow(dead_code)]
const _ASSERT_AUDIT_ACTION: fn(AuditAction) -> &'static str = AuditAction::as_str;

#[cfg(test)]
#[path = "../../tests/unit/siem/event/tests.rs"]
mod tests;

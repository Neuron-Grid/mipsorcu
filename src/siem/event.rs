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
use serde_json::Value;

use crate::audit::{AuditAction, AuditEvent, AuditMetadata, AuditResult};
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
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use crate::audit::{
        AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditResult, AuthFailureMetadata,
        DecryptMetadata, RequestId,
    };
    use crate::types::{DeviceId, KeyVersion, OwnerUserId, SecretId};

    use super::*;

    fn make_owner() -> OwnerUserId {
        OwnerUserId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap()
    }

    fn make_secret() -> SecretId {
        SecretId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    fn make_device() -> DeviceId {
        DeviceId::new("device-1").unwrap()
    }

    fn make_key_version() -> KeyVersion {
        KeyVersion::new(7).unwrap()
    }

    fn build_decrypt_failure_event() -> AuditEvent {
        let metadata = DecryptMetadata::failure()
            .with_attempted_secret_id(make_secret())
            .build()
            .unwrap()
            .with_current_source_event_at()
            .unwrap();

        AuditEvent::new(AuditEventParts {
            audit_event_id: AuditEventId::generate().unwrap(),
            request_id: RequestId::generate().unwrap(),
            actor_user_id: Some(make_owner()),
            actor_device_id: Some(make_device()),
            action: AuditAction::Decrypt,
            target_secret_id: Some(make_secret()),
            result: AuditResult::Failure,
            key_version: Some(make_key_version()),
            metadata_json: metadata,
        })
        .unwrap()
    }

    fn build_auth_failure_event() -> AuditEvent {
        let metadata = AuthFailureMetadata::new("authorization_header_missing")
            .build()
            .unwrap()
            .with_current_source_event_at()
            .unwrap();

        AuditEvent::new(AuditEventParts {
            audit_event_id: AuditEventId::generate().unwrap(),
            request_id: RequestId::nil(),
            actor_user_id: None,
            actor_device_id: None,
            action: AuditAction::AuthFailure,
            target_secret_id: None,
            result: AuditResult::Failure,
            key_version: None,
            metadata_json: metadata,
        })
        .unwrap()
    }

    #[test]
    fn from_audit_event_preserves_non_secret_fields() {
        let event = build_decrypt_failure_event();
        let siem = SiemEvent::from_audit_event(&event);

        assert_eq!(siem.schema_version(), SIEM_EVENT_SCHEMA_VERSION);
        assert_eq!(siem.event_type(), "decrypt");
        assert_eq!(siem.result(), "failure");
        assert_eq!(
            siem.event_id(),
            &event.audit_event_id().as_canonical_string()
        );
        assert_eq!(siem.request_id(), &event.request_id().as_canonical_string());
        assert_eq!(
            siem.actor_user_id(),
            Some(make_owner().as_canonical_string().as_str())
        );
        assert_eq!(siem.actor_device_id(), Some(make_device().as_str()));
        assert_eq!(
            siem.target_secret_id(),
            Some(make_secret().as_canonical_string().as_str())
        );
        assert_eq!(siem.key_version(), Some(7));
    }

    #[test]
    fn from_audit_event_allows_null_optional_fields() {
        let event = build_auth_failure_event();
        let siem = SiemEvent::from_audit_event(&event);

        assert_eq!(siem.actor_user_id(), None);
        assert_eq!(siem.actor_device_id(), None);
        assert_eq!(siem.target_secret_id(), None);
        assert_eq!(siem.key_version(), None);
    }

    #[test]
    fn serialize_top_level_keys_match_allowlist() {
        let event = build_decrypt_failure_event();
        let siem = SiemEvent::from_audit_event(&event);
        let value = serde_json::to_value(&siem).expect("serialize must succeed");
        let object = value.as_object().expect("must serialize as object");
        let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
        let expected: BTreeSet<&str> = SIEM_EVENT_TOP_LEVEL_KEYS.iter().copied().collect();
        assert_eq!(keys, expected, "siem event JSON keys must match allowlist");
    }

    #[test]
    fn debug_does_not_expose_metadata_contents() {
        let event = build_decrypt_failure_event();
        let siem = SiemEvent::from_audit_event(&event);
        let debug_string = format!("{siem:?}");
        // metadata は <redacted> として表示されるため、attempted_secret_id（実値）
        // が Debug 出力に現れないことを確認する。
        assert!(
            !debug_string.contains(&make_secret().as_canonical_string()),
            "Debug output must not expose secret_id from metadata: {debug_string}"
        );
        assert!(debug_string.contains("<redacted>"));
    }

    #[test]
    fn serialize_never_contains_forbidden_metadata_keys() {
        // AuditMetadata 側で禁止キーは構造的に弾かれるが、ここでも
        // serialized JSON 中に禁止語彙が含まれないことを念のため確認する。
        let event = build_decrypt_failure_event();
        let siem = SiemEvent::from_audit_event(&event);
        let json_str = serde_json::to_string(&siem).unwrap();
        for forbidden in crate::audit::FORBIDDEN_AUDIT_METADATA_KEYS {
            // metadata のキーとして含まれていないこと（"forbidden":value のパターン）。
            let needle = format!("\"{forbidden}\":");
            assert!(
                !json_str.contains(&needle),
                "serialized SiemEvent must not contain forbidden key {forbidden}: {json_str}"
            );
        }
    }

    #[test]
    fn metadata_round_trip_preserves_allowed_keys() {
        let event = build_decrypt_failure_event();
        let siem = SiemEvent::from_audit_event(&event);
        let serialized = siem.metadata();
        assert_eq!(serialized, event.metadata_json().as_value());
    }

    #[test]
    fn schema_version_is_serialized_as_number() {
        let event = build_auth_failure_event();
        let siem = SiemEvent::from_audit_event(&event);
        let value = serde_json::to_value(&siem).unwrap();
        assert_eq!(value["schema_version"], json!(SIEM_EVENT_SCHEMA_VERSION));
    }
}

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

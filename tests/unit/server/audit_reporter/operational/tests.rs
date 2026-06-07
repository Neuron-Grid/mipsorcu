use super::*;

/// `AuditEvent::new` の検証は `source_event_at` を必須とする。`Decrypt`(success) は
/// 許可・必須キーが `source_event_at` のみで済むため、builder のフィールド対応を
/// 検証する最小 fixture として用いる（builder は action 非依存）。
fn valid_metadata() -> AuditMetadata {
    AuditMetadata::empty()
        .with_current_source_event_at()
        .expect("metadata with source_event_at")
}

#[test]
fn build_forces_device_and_target_none_and_passes_through() {
    let request_id = RequestId::generate().expect("request id");
    let audit_event_id = AuditEventId::generate().expect("audit event id");
    let event = build_operational_audit_event(OperationalAuditEvent {
        audit_event_id: audit_event_id.clone(),
        request_id: request_id.clone(),
        actor_user_id: None,
        action: AuditAction::Decrypt,
        result: AuditResult::Success,
        key_version: None,
        metadata: valid_metadata(),
    })
    .expect("event builds");

    assert_eq!(event.audit_event_id(), &audit_event_id);
    assert_eq!(event.request_id(), &request_id);
    assert_eq!(event.action(), AuditAction::Decrypt);
    assert_eq!(event.result(), AuditResult::Success);
    assert!(event.actor_user_id().is_none());
    assert!(event.actor_device_id().is_none());
    assert!(event.target_secret_id().is_none());
    assert!(event.key_version().is_none());
}

#[test]
fn build_preserves_key_version() {
    let request_id = RequestId::generate().expect("request id");
    let audit_event_id = AuditEventId::generate().expect("audit event id");
    let key_version = KeyVersion::new(1).expect("key version");
    let event = build_operational_audit_event(OperationalAuditEvent {
        audit_event_id,
        request_id,
        actor_user_id: None,
        action: AuditAction::Decrypt,
        result: AuditResult::Success,
        key_version: Some(key_version),
        metadata: valid_metadata(),
    })
    .expect("event builds");

    assert_eq!(event.key_version(), Some(key_version));
}

/// builder の出力が `AuditEvent::new(AuditEventParts { .. })` 直書きと同一であることを
/// 固定し、call site 置換が AuditEvent を不変に保つことを保証する。
#[test]
fn build_matches_direct_audit_event_new() {
    let request_id = RequestId::generate().expect("request id");
    let audit_event_id = AuditEventId::generate().expect("audit event id");
    let metadata = valid_metadata();

    let via_builder = build_operational_audit_event(OperationalAuditEvent {
        audit_event_id: audit_event_id.clone(),
        request_id: request_id.clone(),
        actor_user_id: None,
        action: AuditAction::Decrypt,
        result: AuditResult::Success,
        key_version: None,
        metadata: metadata.clone(),
    })
    .expect("builder event");

    let via_direct = AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id,
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::Decrypt,
        target_secret_id: None,
        result: AuditResult::Success,
        key_version: None,
        metadata_json: metadata,
    })
    .expect("direct event");

    assert!(via_builder == via_direct);
}

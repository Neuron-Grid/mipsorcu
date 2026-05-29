use crate::audit::error::AuditEventError;
use crate::audit::event::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditMetadata, AuditResult, RequestId,
};
use crate::types::{DeviceId, KeyVersion, OwnerUserId, SecretId};

fn nil_request_id() -> RequestId {
    RequestId::nil()
}

fn valid_owner() -> OwnerUserId {
    OwnerUserId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap()
}

fn valid_secret() -> SecretId {
    SecretId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap()
}

fn valid_device() -> DeviceId {
    DeviceId::new("test-device").unwrap()
}

fn valid_key_version() -> KeyVersion {
    KeyVersion::new(1).unwrap()
}

#[test]
fn build_with_current_source_event_at_includes_source_event_at() {
    let event = AuditEvent::build_with_current_source_event_at(
        nil_request_id(),
        Some(valid_owner()),
        Some(valid_device()),
        AuditAction::Decrypt,
        Some(valid_secret()),
        AuditResult::Success,
        Some(valid_key_version()),
        AuditMetadata::empty(),
    )
    .unwrap();

    assert!(event.source_event_at().is_ok());
}

#[test]
fn build_with_current_source_event_at_rejects_forbidden_metadata_keys() {
    // AuditMetadata constructor enforces the invariant; forbidden keys cannot
    // propagate through the common API because AuditMetadata cannot be built
    // with them in the first place.
    let metadata_value = serde_json::json!({ "plaintext": "secret" });
    let result = AuditMetadata::new(metadata_value);
    assert!(
        matches!(result, Err(AuditEventError::ForbiddenMetadataKey { .. })),
        "forbidden metadata key must be rejected, got {result:?}"
    );

    // Confirm the common API path works with valid metadata.
    let event = AuditEvent::build_with_current_source_event_at(
        nil_request_id(),
        Some(valid_owner()),
        None,
        AuditAction::Decrypt,
        Some(valid_secret()),
        AuditResult::Success,
        None,
        AuditMetadata::empty(),
    );
    assert!(event.is_ok());
}

#[test]
fn build_with_current_source_event_at_rejects_auth_failure_with_success() {
    let result = AuditEvent::build_with_current_source_event_at(
        nil_request_id(),
        None,
        None,
        AuditAction::AuthFailure,
        None,
        AuditResult::Success,
        None,
        AuditMetadata::empty(),
    );

    assert!(
        matches!(
            result,
            Err(AuditEventError::FailureOnlyActionSuccessNotAllowed { .. })
        ),
        "expected failure-only action error, got {result:?}"
    );
}

#[test]
fn build_with_current_source_event_at_auth_failure_preserves_null_fields() {
    let metadata = AuditMetadata::new(serde_json::json!({
        "error_code": "authorization_header_missing"
    }))
    .unwrap();
    let event = AuditEvent::build_with_current_source_event_at(
        nil_request_id(),
        None,
        None,
        AuditAction::AuthFailure,
        None,
        AuditResult::Failure,
        None,
        metadata,
    )
    .unwrap();

    assert_eq!(event.actor_user_id(), None);
    assert_eq!(event.actor_device_id(), None);
    assert_eq!(event.target_secret_id(), None);
    assert_eq!(event.key_version(), None);
    assert_eq!(event.action(), AuditAction::AuthFailure);
    assert_eq!(event.result(), AuditResult::Failure);
}

#[test]
fn build_with_current_source_event_at_matches_parts_validation_semantics() {
    let parts = AuditEventParts {
        audit_event_id: AuditEventId::generate().unwrap(),
        request_id: nil_request_id(),
        actor_user_id: Some(valid_owner()),
        actor_device_id: None,
        action: AuditAction::Decrypt,
        target_secret_id: Some(valid_secret()),
        result: AuditResult::Success,
        key_version: Some(valid_key_version()),
        metadata_json: AuditMetadata::new(serde_json::json!({
            "source_event_at": "2026-04-08T12:00:00Z"
        }))
        .unwrap(),
    };

    let from_parts = AuditEvent::new(parts.clone());
    let from_build = AuditEvent::build_with_current_source_event_at(
        parts.request_id.clone(),
        parts.actor_user_id.clone(),
        parts.actor_device_id.clone(),
        parts.action,
        parts.target_secret_id.clone(),
        parts.result,
        parts.key_version,
        AuditMetadata::new(serde_json::json!({
            "source_event_at": "2026-04-08T12:00:00Z"
        }))
        .unwrap(),
    );

    assert!(
        from_parts.is_ok() && from_build.is_ok(),
        "both paths should succeed for valid input"
    );

    // Verify write-success-only rejection works the same for both paths
    let bad_parts = AuditEventParts {
        audit_event_id: AuditEventId::generate().unwrap(),
        request_id: nil_request_id(),
        actor_user_id: Some(valid_owner()),
        actor_device_id: None,
        action: AuditAction::EncryptCreate,
        target_secret_id: Some(valid_secret()),
        result: AuditResult::Success,
        key_version: Some(valid_key_version()),
        metadata_json: AuditMetadata::empty()
            .with_current_source_event_at()
            .unwrap(),
    };
    let _bad_from_parts = AuditEvent::new(bad_parts.clone());
    let bad_build = AuditEvent::build_with_current_source_event_at(
        bad_parts.request_id.clone(),
        bad_parts.actor_user_id.clone(),
        bad_parts.actor_device_id.clone(),
        bad_parts.action,
        bad_parts.target_secret_id.clone(),
        bad_parts.result,
        bad_parts.key_version,
        AuditMetadata::empty(),
    );
    assert!(
        matches!(
            _bad_from_parts,
            Err(AuditEventError::WriteSuccessActionNotAllowed { .. })
        ),
        "parts path should reject write-success-only action success"
    );
    assert!(
        matches!(
            bad_build,
            Err(AuditEventError::WriteSuccessActionNotAllowed { .. })
        ),
        "build path should reject write-success-only action success"
    );
}

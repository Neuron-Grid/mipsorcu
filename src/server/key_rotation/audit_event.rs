use crate::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditResult,
    KeyRotationCompleteMetadata, KeyRotationReencryptMetadata, KeyRotationStartMetadata,
    RequestId,
};
use crate::types::KeyVersion;

use super::KeyRotationCliError;

pub(super) fn build_key_rotation_start_event(
    request_id: &RequestId,
    old_key_version: KeyVersion,
    new_key_version: KeyVersion,
) -> Result<AuditEvent, KeyRotationCliError> {
    let metadata = KeyRotationStartMetadata::new(old_key_version, new_key_version)
        .build()
        .and_then(|m| m.with_current_source_event_at())
        .map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;
    let audit_event_id =
        AuditEventId::generate().map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;

    AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::KeyRotationStart,
        target_secret_id: None,
        result: AuditResult::Success,
        key_version: Some(new_key_version),
        metadata_json: metadata,
    })
    .map_err(|error| KeyRotationCliError::Audit(error.to_string()))
}

pub(super) fn build_key_rotation_reencrypt_event(
    request_id: &RequestId,
    old_key_version: KeyVersion,
    new_key_version: KeyVersion,
    batch_size: u64,
    processed_count: u64,
    remaining_count: u64,
) -> Result<AuditEvent, KeyRotationCliError> {
    let metadata = KeyRotationReencryptMetadata::new(
        old_key_version,
        new_key_version,
        batch_size,
        processed_count,
        remaining_count,
    )
    .build()
    .and_then(|m| m.with_current_source_event_at())
    .map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;
    let audit_event_id =
        AuditEventId::generate().map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;

    AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::KeyRotationReencrypt,
        target_secret_id: None,
        result: AuditResult::Success,
        key_version: Some(new_key_version),
        metadata_json: metadata,
    })
    .map_err(|error| KeyRotationCliError::Audit(error.to_string()))
}

pub(super) fn build_key_rotation_complete_event(
    request_id: &RequestId,
    old_key_version: KeyVersion,
    new_key_version: KeyVersion,
    remaining_count: u64,
) -> Result<AuditEvent, KeyRotationCliError> {
    let metadata = KeyRotationCompleteMetadata::new(old_key_version, new_key_version, remaining_count)
        .build()
        .and_then(|m| m.with_current_source_event_at())
        .map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;
    let audit_event_id =
        AuditEventId::generate().map_err(|error| KeyRotationCliError::Audit(error.to_string()))?;

    AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::KeyRotationComplete,
        target_secret_id: None,
        result: AuditResult::Success,
        key_version: Some(new_key_version),
        metadata_json: metadata,
    })
    .map_err(|error| KeyRotationCliError::Audit(error.to_string()))
}

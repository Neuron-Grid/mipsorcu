use serde_json::{Map, Value};

use crate::types::SourceEventAt;

use super::super::error::AuditEventError;
use super::action::{AuditAction, AuditResult};
use super::metadata::SOURCE_EVENT_AT_KEY;
use super::model::AuditEventParts;

pub(super) fn validate_event_parts(parts: &AuditEventParts) -> Result<(), AuditEventError> {
    if parts.result == AuditResult::Success && parts.action.is_write_success_only() {
        return Err(AuditEventError::WriteSuccessActionNotAllowed {
            action: parts.action,
        });
    }
    if parts.result == AuditResult::Success && parts.action.is_failure_only() {
        return Err(AuditEventError::FailureOnlyActionSuccessNotAllowed {
            action: parts.action,
        });
    }
    if parts.action == AuditAction::AuthFailure {
        validate_auth_failure_parts(parts)?;
    }

    parts.metadata_json.require_source_event_at()?;
    parts
        .metadata_json
        .validate_allowlist_for_action(parts.action, parts.result)?;

    Ok(())
}

pub(super) fn canonicalize_source_event_at(
    object: &mut Map<String, Value>,
) -> Result<(), AuditEventError> {
    let Some(value) = object.get(SOURCE_EVENT_AT_KEY) else {
        return Ok(());
    };
    let text = value
        .as_str()
        .ok_or(AuditEventError::InvalidSourceEventAt)?;
    let canonical =
        SourceEventAt::parse(text).map_err(|_| AuditEventError::InvalidSourceEventAt)?;
    object.insert(
        SOURCE_EVENT_AT_KEY.to_owned(),
        Value::String(canonical.as_str().to_owned()),
    );

    Ok(())
}

fn validate_auth_failure_parts(parts: &AuditEventParts) -> Result<(), AuditEventError> {
    if parts.actor_user_id.is_some() {
        return Err(AuditEventError::AuthFailureFieldMustBeNull {
            field: "actor_user_id",
        });
    }
    if parts.actor_device_id.is_some() {
        return Err(AuditEventError::AuthFailureFieldMustBeNull {
            field: "actor_device_id",
        });
    }
    if parts.target_secret_id.is_some() {
        return Err(AuditEventError::AuthFailureFieldMustBeNull {
            field: "target_secret_id",
        });
    }
    if parts.key_version.is_some() {
        return Err(AuditEventError::AuthFailureFieldMustBeNull {
            field: "key_version",
        });
    }

    Ok(())
}

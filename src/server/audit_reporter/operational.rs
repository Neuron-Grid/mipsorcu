use crate::audit::{
    AuditAction, AuditEvent, AuditEventError, AuditEventId, AuditEventParts, AuditMetadata,
    AuditResult, RequestId,
};
use crate::types::{KeyVersion, OwnerUserId};

/// `actor_device_id` / `target_secret_id` を持たない操作監査イベントの構築入力。
///
/// `audit_event_id` は呼出側が生成して渡す（生成失敗時のログ・エラー処理を
/// 呼出側の文脈に残すため）。`metadata` は action 固有の builder で構築済みのものを渡す。
pub(crate) struct OperationalAuditEvent {
    pub audit_event_id: AuditEventId,
    pub request_id: RequestId,
    pub actor_user_id: Option<OwnerUserId>,
    pub action: AuditAction,
    pub result: AuditResult,
    pub key_version: Option<KeyVersion>,
    pub metadata: AuditMetadata,
}

/// 操作監査イベントの `AuditEvent` 構築を集約した純粋関数。
///
/// `actor_device_id` / `target_secret_id` は本種別では常に `None`。返り値は
/// `AuditEvent::new(AuditEventParts { .. })` 直書きと同一の `AuditEvent`。
pub(crate) fn build_operational_audit_event(
    input: OperationalAuditEvent,
) -> Result<AuditEvent, AuditEventError> {
    AuditEvent::new(AuditEventParts {
        audit_event_id: input.audit_event_id,
        request_id: input.request_id,
        actor_user_id: input.actor_user_id,
        actor_device_id: None,
        action: input.action,
        target_secret_id: None,
        result: input.result,
        key_version: input.key_version,
        metadata_json: input.metadata,
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/server/audit_reporter/operational/tests.rs"]
mod tests;

use std::sync::Arc;

use http::StatusCode;
use serde::Serialize;
use serde_json::Value;

use crate::audit::{AuditAppendError, AuditEvent, AuditEventAppender};

use super::response::{ensure_success, response_contains_marker};
use super::{SupabaseClient, SupabaseRpcError};

const AUDIT_EVENT_ID_CONFLICT_MARKER: &str = "audit_event_id_conflict";

impl SupabaseClient {
    pub async fn call_append_audit_event(
        &self,
        event: &AuditEvent,
    ) -> Result<(), SupabaseRpcError> {
        let params = AppendAuditEventParams::from_event(event);
        let response = self.post_rpc("rpc_append_audit_event", &params).await?;
        ensure_success(response).await.map(|_| ())
    }
}

#[derive(Serialize)]
struct AppendAuditEventParams {
    p_audit_event_id: String,
    p_request_id: String,
    p_actor_user_id: Option<String>,
    p_actor_device_id: Option<String>,
    p_action: String,
    p_target_secret_id: Option<String>,
    p_result: String,
    p_key_version: Option<u32>,
    p_metadata_json: Value,
}

impl AppendAuditEventParams {
    fn from_event(event: &AuditEvent) -> Self {
        Self {
            p_audit_event_id: event.audit_event_id().as_canonical_string(),
            p_request_id: event.request_id().as_canonical_string(),
            p_actor_user_id: event.actor_user_id().map(|u| u.as_canonical_string()),
            p_actor_device_id: event.actor_device_id().map(|d| d.as_str().to_owned()),
            p_action: event.action().as_str().to_owned(),
            p_target_secret_id: event.target_secret_id().map(|s| s.as_canonical_string()),
            p_result: event.result().as_str().to_owned(),
            p_key_version: event.key_version().map(|kv| kv.get()),
            p_metadata_json: event.metadata_json().as_value().clone(),
        }
    }
}

pub struct SupabaseAuditAppender {
    client: Arc<SupabaseClient>,
}

impl SupabaseAuditAppender {
    /// Builds the Supabase-backed audit appender.
    pub fn new(client: Arc<SupabaseClient>) -> Self {
        Self { client }
    }
}

impl AuditEventAppender for SupabaseAuditAppender {
    async fn append_audit_event(&self, event: &AuditEvent) -> Result<(), AuditAppendError> {
        self.client
            .call_append_audit_event(event)
            .await
            .map_err(classify_append_audit_error)
    }
}

fn classify_append_audit_error(error: SupabaseRpcError) -> AuditAppendError {
    match error {
        SupabaseRpcError::NonSuccessStatus { status, body }
            if status == StatusCode::CONFLICT.as_u16()
                && response_contains_audit_event_id_conflict(&body) =>
        {
            AuditAppendError::IdempotencyConflict
        }
        SupabaseRpcError::Network(_)
        | SupabaseRpcError::NonSuccessStatus { .. }
        | SupabaseRpcError::InvalidResponse(_)
        | SupabaseRpcError::EmptyResult => AuditAppendError::ExternalDependencyFailed {
            code: "supabase_rpc_failed",
        },
    }
}

fn response_contains_audit_event_id_conflict(body: &str) -> bool {
    response_contains_marker(body, AUDIT_EVENT_ID_CONFLICT_MARKER)
}

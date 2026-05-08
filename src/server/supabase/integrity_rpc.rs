use serde::Deserialize;

use crate::types::supabase::{IntegrityCheckSummary, IntegrityCheckViolationSummary};

use super::response::ensure_success;
use super::{SupabaseClient, SupabaseRpcError};

impl SupabaseClient {
    pub async fn call_integrity_check(&self) -> Result<IntegrityCheckSummary, SupabaseRpcError> {
        let params = serde_json::json!({});
        let response = self.post_rpc("rpc_integrity_check", &params).await?;
        let rows: Vec<IntegrityCheckResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .map(IntegrityCheckSummary::from)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntegrityCheckResponse {
    checked_secret_count: u64,
    checked_secret_version_count: u64,
    checked_audit_event_count: u64,
    violation_count: u64,
    violation_summary: IntegrityCheckViolationSummary,
}

impl From<IntegrityCheckResponse> for IntegrityCheckSummary {
    fn from(response: IntegrityCheckResponse) -> Self {
        Self {
            checked_secret_count: response.checked_secret_count,
            checked_secret_version_count: response.checked_secret_version_count,
            checked_audit_event_count: response.checked_audit_event_count,
            violation_count: response.violation_count,
            violation_summary: response.violation_summary,
        }
    }
}

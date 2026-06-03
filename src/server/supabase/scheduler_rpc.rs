use serde::Serialize;

use super::response::ensure_success;
use super::{SupabaseClient, SupabaseRpcError};

impl SupabaseClient {
    pub async fn acquire_scheduler_lock(
        &self,
        job_name: &str,
        ttl_seconds: u32,
    ) -> Result<bool, SupabaseRpcError> {
        let params = SchedulerAcquireLockParams {
            p_job_name: job_name.to_owned(),
            p_ttl_seconds: ttl_seconds,
        };
        let response = self.post_rpc("rpc_acquire_scheduler_lock", &params).await?;
        ensure_success(response)
            .await?
            .json::<bool>()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))
    }

    pub async fn release_scheduler_lock(&self, job_name: &str) -> Result<bool, SupabaseRpcError> {
        let params = SchedulerReleaseLockParams {
            p_job_name: job_name.to_owned(),
        };
        let response = self.post_rpc("rpc_release_scheduler_lock", &params).await?;
        ensure_success(response)
            .await?
            .json::<bool>()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))
    }
}

#[derive(Serialize)]
struct SchedulerAcquireLockParams {
    p_job_name: String,
    p_ttl_seconds: u32,
}

#[derive(Serialize)]
struct SchedulerReleaseLockParams {
    p_job_name: String,
}

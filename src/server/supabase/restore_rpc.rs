use serde::Serialize;

use crate::types::supabase::RestoreTestSampleRow;

use super::response::ensure_success;
use super::{SupabaseClient, SupabaseRpcError};

impl SupabaseClient {
    pub async fn call_sample_restore_test(
        &self,
        limit: u32,
    ) -> Result<Vec<RestoreTestSampleRow>, SupabaseRpcError> {
        let params = SampleRestoreTestParams { p_limit: limit };
        let response = self.post_rpc("rpc_sample_restore_test", &params).await?;
        ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))
    }
}

#[derive(Serialize)]
struct SampleRestoreTestParams {
    p_limit: u32,
}

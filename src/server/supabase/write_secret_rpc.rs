use serde::Deserialize;

use crate::types::supabase::{WriteSecretVersionOutcome, WriteSecretVersionParams};
use crate::{SecretId, SecretVersion, SecretVersionId};

use super::response::ensure_success;
use super::{SupabaseClient, SupabaseRpcError};

impl SupabaseClient {
    pub async fn call_write_secret_version(
        &self,
        params: &WriteSecretVersionParams,
    ) -> Result<WriteSecretVersionOutcome, SupabaseRpcError> {
        let response = self.post_rpc("rpc_write_secret_version", params).await?;
        let rows: Vec<WriteSecretVersionResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(WriteSecretVersionOutcome::try_from)
    }
}

#[derive(Debug, Deserialize)]
struct WriteSecretVersionResponse {
    secret_id: String,
    secret_version_id: String,
    version: i32,
    purged_version_ids: Vec<String>,
}

impl TryFrom<WriteSecretVersionResponse> for WriteSecretVersionOutcome {
    type Error = SupabaseRpcError;

    fn try_from(response: WriteSecretVersionResponse) -> Result<Self, Self::Error> {
        let version = u32::try_from(response.version)
            .ok()
            .and_then(|value| SecretVersion::new(value).ok())
            .ok_or_else(|| {
                SupabaseRpcError::InvalidResponse("write RPC returned invalid version".to_owned())
            })?;

        let secret_id = SecretId::parse(&response.secret_id).map_err(|_| {
            SupabaseRpcError::InvalidResponse("write RPC returned invalid secret_id".to_owned())
        })?;
        let secret_version_id =
            SecretVersionId::parse(&response.secret_version_id).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "write RPC returned invalid secret_version_id".to_owned(),
                )
            })?;

        Ok(Self::new(
            secret_id,
            secret_version_id,
            version,
            response.purged_version_ids,
        ))
    }
}

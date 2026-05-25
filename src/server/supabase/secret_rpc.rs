use serde::Deserialize;

use crate::auth::RawJwt;
use crate::types::supabase::{
    SecretVersionReadRow, SecretVersionRetentionSnapshot, SecretVersionWriteStateRow,
};
use crate::{KeyVersion, SecretId, SecretVersion, SecretVersionId};

use super::response::ensure_success;
use super::{SupabaseClient, SupabaseRpcError};

const CURRENT_SECRET_VERSION_READ_COLUMNS: &str = "\
id,secret_id,version,ciphertext,encrypted_data_key,key_version,\
algorithm,classification,nonce_or_iv,aad_context,created_by_user_id,\
created_at,secrets!inner(current_version_id,owner_user_id,classification)";
const CURRENT_SECRET_VERSION_WRITE_STATE_COLUMNS: &str = "\
id,secret_id,version,classification,created_by_user_id,created_at,\
secrets!inner(current_version_id,owner_user_id,classification)";
const SECRET_VERSION_RETENTION_SNAPSHOT_COLUMNS: &str = "id,version,key_version";

impl SupabaseClient {
    pub async fn fetch_current_secret_version_for_user(
        &self,
        secret_id: &SecretId,
        raw_jwt: &RawJwt,
    ) -> Result<Vec<SecretVersionReadRow>, SupabaseRpcError> {
        let secret_id = secret_id.as_canonical_string();
        let url = format!(
            "{}/rest/v1/secret_versions?select={CURRENT_SECRET_VERSION_READ_COLUMNS}&secret_id=eq.{secret_id}",
            self.base_url
        );
        let response = self
            .http_client
            .get(&url)
            .header("apikey", &self.publishable_key)
            .bearer_auth(raw_jwt.as_str())
            .send()
            .await
            .map_err(SupabaseRpcError::Network)?;

        let rows: Vec<SecretVersionReadRow> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        Ok(rows)
    }

    pub async fn fetch_current_secret_write_state_for_user(
        &self,
        secret_id: &SecretId,
        raw_jwt: &RawJwt,
    ) -> Result<Vec<SecretVersionWriteStateRow>, SupabaseRpcError> {
        let secret_id = secret_id.as_canonical_string();
        let url = format!(
            "{}/rest/v1/secret_versions?select={CURRENT_SECRET_VERSION_WRITE_STATE_COLUMNS}&secret_id=eq.{secret_id}",
            self.base_url
        );
        let response = self
            .http_client
            .get(&url)
            .header("apikey", &self.publishable_key)
            .bearer_auth(raw_jwt.as_str())
            .send()
            .await
            .map_err(SupabaseRpcError::Network)?;

        let rows: Vec<SecretVersionWriteStateRow> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        Ok(rows)
    }

    pub async fn fetch_secret_version_retention_snapshot(
        &self,
        secret_id: &SecretId,
    ) -> Result<Vec<SecretVersionRetentionSnapshot>, SupabaseRpcError> {
        let secret_id = secret_id.as_canonical_string();
        let url = format!(
            "{}/rest/v1/secret_versions?select={SECRET_VERSION_RETENTION_SNAPSHOT_COLUMNS}&secret_id=eq.{secret_id}&order=version.desc",
            self.base_url
        );
        let response = self
            .http_client
            .get(&url)
            .header("apikey", &self.service_role_key)
            .bearer_auth(&self.service_role_key)
            .send()
            .await
            .map_err(SupabaseRpcError::Network)?;

        let rows: Vec<SecretVersionRetentionSnapshotResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .map(SecretVersionRetentionSnapshot::try_from)
            .collect()
    }
}

#[derive(Debug, Deserialize)]
struct SecretVersionRetentionSnapshotResponse {
    id: String,
    version: i32,
    key_version: i32,
}

impl TryFrom<SecretVersionRetentionSnapshotResponse> for SecretVersionRetentionSnapshot {
    type Error = SupabaseRpcError;

    fn try_from(response: SecretVersionRetentionSnapshotResponse) -> Result<Self, Self::Error> {
        let secret_version_id = SecretVersionId::parse(&response.id).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "retention snapshot returned invalid secret version id".to_owned(),
            )
        })?;
        let version = u32::try_from(response.version)
            .ok()
            .and_then(|value| SecretVersion::new(value).ok())
            .ok_or_else(|| {
                SupabaseRpcError::InvalidResponse(
                    "retention snapshot returned invalid version".to_owned(),
                )
            })?;
        let key_version = u32::try_from(response.key_version)
            .ok()
            .and_then(|value| KeyVersion::new(value).ok())
            .ok_or_else(|| {
                SupabaseRpcError::InvalidResponse(
                    "retention snapshot returned invalid key version".to_owned(),
                )
            })?;

        Ok(Self::new(secret_version_id, version, key_version))
    }
}

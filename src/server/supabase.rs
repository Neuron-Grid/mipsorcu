use std::fmt;
use std::sync::Arc;

use reqwest::Response;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::{AuditAppendError, AuditEvent, AuditEventAppender};
use crate::auth::RawJwt;

#[derive(Debug)]
pub enum SupabaseRpcError {
    Network(reqwest::Error),
    NonSuccessStatus { status: u16, body: String },
    InvalidResponse(String),
    EmptyResult,
}

impl fmt::Display for SupabaseRpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(error) => write!(formatter, "supabase network error: {error}"),
            Self::NonSuccessStatus { status, body } => {
                write!(
                    formatter,
                    "supabase returned status {status} with response body length {}",
                    body.len()
                )
            }
            Self::InvalidResponse(message) => {
                write!(formatter, "supabase invalid response: {message}")
            }
            Self::EmptyResult => write!(formatter, "supabase RPC returned no rows"),
        }
    }
}

impl std::error::Error for SupabaseRpcError {}

pub struct SupabaseClient {
    http_client: reqwest::Client,
    base_url: String,
    service_role_key: String,
    publishable_key: String,
}

impl SupabaseClient {
    pub fn new(
        http_client: reqwest::Client,
        base_url: impl Into<String>,
        service_role_key: impl Into<String>,
        publishable_key: impl Into<String>,
    ) -> Self {
        Self {
            http_client,
            base_url: base_url.into(),
            service_role_key: service_role_key.into(),
            publishable_key: publishable_key.into(),
        }
    }

    pub async fn call_write_secret_version(
        &self,
        params: &WriteSecretVersionParams,
    ) -> Result<WriteSecretVersionResponse, SupabaseRpcError> {
        let response = self.post_rpc("rpc_write_secret_version", params).await?;
        let rows: Vec<WriteSecretVersionResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter().next().ok_or(SupabaseRpcError::EmptyResult)
    }

    pub async fn call_append_audit_event(
        &self,
        event: &AuditEvent,
    ) -> Result<(), SupabaseRpcError> {
        let params = AppendAuditEventParams::from_event(event);
        let response = self.post_rpc("rpc_append_audit_event", &params).await?;
        ensure_success(response).await.map(|_| ())
    }

    pub async fn fetch_current_secret_version_for_user(
        &self,
        secret_id: &str,
        raw_jwt: &RawJwt,
    ) -> Result<Vec<SecretVersionReadRow>, SupabaseRpcError> {
        let select = "id,secret_id,version,ciphertext,encrypted_data_key,key_version,algorithm,nonce_or_iv,aad_context,created_by_user_id,created_at,secrets!inner(current_version_id,owner_user_id,classification)";
        let url = format!(
            "{}/rest/v1/secret_versions?select={select}&secret_id=eq.{secret_id}",
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

    pub async fn fetch_restore_test_current_secret_version(
        &self,
    ) -> Result<Option<SecretVersionReadRow>, SupabaseRpcError> {
        let select = "id,secret_id,version,ciphertext,encrypted_data_key,key_version,algorithm,nonce_or_iv,aad_context,created_by_user_id,created_at,secrets!inner(current_version_id,owner_user_id,classification)";
        let url = format!(
            "{}/rest/v1/secret_versions?select={select}&order=created_at.desc&limit=100",
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

        let rows: Vec<SecretVersionReadRow> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        Ok(rows
            .into_iter()
            .find(|row| row.secrets.current_version_id == row.id))
    }

    pub async fn check_connectivity(&self) -> bool {
        let url = format!("{}/rest/v1/", self.base_url);
        self.http_client
            .head(&url)
            .header("apikey", &self.service_role_key)
            .bearer_auth(&self.service_role_key)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
    }

    async fn post_rpc<T: Serialize + ?Sized>(
        &self,
        rpc_name: &str,
        params: &T,
    ) -> Result<Response, SupabaseRpcError> {
        let url = format!("{}/rest/v1/rpc/{rpc_name}", self.base_url);

        self.http_client
            .post(&url)
            .header("apikey", &self.service_role_key)
            .bearer_auth(&self.service_role_key)
            .json(params)
            .send()
            .await
            .map_err(SupabaseRpcError::Network)
    }
}

async fn ensure_success(response: Response) -> Result<Response, SupabaseRpcError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }

    let body = response.text().await.unwrap_or_else(|_| String::new());
    Err(SupabaseRpcError::NonSuccessStatus {
        status: status.as_u16(),
        body,
    })
}

impl fmt::Debug for SupabaseClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupabaseClient")
            .field("base_url", &self.base_url)
            .field("service_role_key", &"<redacted>")
            .field("publishable_key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
pub struct SecretVersionReadRow {
    pub id: String,
    pub secret_id: String,
    pub version: i32,
    pub ciphertext: String,
    pub encrypted_data_key: String,
    pub key_version: i32,
    pub algorithm: String,
    pub nonce_or_iv: String,
    pub aad_context: Value,
    pub created_by_user_id: String,
    pub created_at: String,
    pub secrets: SecretReadJoin,
}

#[derive(Debug, Deserialize)]
pub struct SecretReadJoin {
    pub current_version_id: String,
    pub owner_user_id: String,
    pub classification: String,
}

#[derive(Serialize)]
pub struct WriteSecretVersionParams {
    pub p_request_id: String,
    pub p_action: String,
    pub p_secret_id: String,
    pub p_owner_user_id: String,
    pub p_classification: String,
    pub p_created_by_device_id: String,
    pub p_created_at: String,
    pub p_version: u32,
    pub p_ciphertext: String,
    pub p_encrypted_data_key: String,
    pub p_key_version: u32,
    pub p_algorithm: String,
    pub p_nonce_or_iv: String,
    pub p_aad_context: Value,
}

#[derive(Debug, Deserialize)]
pub struct WriteSecretVersionResponse {
    pub secret_id: String,
    pub secret_version_id: String,
    pub version: i32,
    #[allow(dead_code)]
    pub purged_version_ids: Vec<String>,
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
    runtime_handle: tokio::runtime::Handle,
}

impl SupabaseAuditAppender {
    pub fn new(client: Arc<SupabaseClient>, runtime_handle: tokio::runtime::Handle) -> Self {
        Self {
            client,
            runtime_handle,
        }
    }
}

impl AuditEventAppender for SupabaseAuditAppender {
    fn append_audit_event(&self, event: &AuditEvent) -> Result<(), AuditAppendError> {
        self.runtime_handle
            .block_on(self.client.call_append_audit_event(event))
            .map_err(|_| AuditAppendError::ExternalDependencyFailed {
                code: "supabase_rpc_failed",
            })
    }
}

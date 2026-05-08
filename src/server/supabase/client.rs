use std::fmt;

use reqwest::Response;
use serde::Serialize;

use super::SupabaseRpcError;

pub struct SupabaseClient {
    pub(super) http_client: reqwest::Client,
    pub(super) base_url: String,
    pub(super) service_role_key: String,
    pub(super) publishable_key: String,
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

    pub(super) async fn post_rpc<T: Serialize + ?Sized>(
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

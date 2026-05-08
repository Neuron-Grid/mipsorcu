use http::StatusCode;

use super::SupabaseClient;

impl SupabaseClient {
    pub async fn probe_readiness(&self) -> bool {
        let url = format!("{}/rest/v1/", self.base_url);

        match self.readiness_probe_status(&url, None).await {
            Ok(status) if status.is_success() => true,
            Ok(StatusCode::UNAUTHORIZED) | Ok(StatusCode::FORBIDDEN) => self
                .readiness_probe_status(&url, Some(&self.publishable_key))
                .await
                .is_ok_and(|status| status.is_success()),
            Ok(_) | Err(_) => false,
        }
    }

    async fn readiness_probe_status(
        &self,
        url: &str,
        api_key: Option<&str>,
    ) -> Result<StatusCode, reqwest::Error> {
        let request = self.http_client.head(url);
        let request = match api_key {
            Some(api_key) => request.header("apikey", api_key),
            None => request,
        };

        request.send().await.map(|response| response.status())
    }
}

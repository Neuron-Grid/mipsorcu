use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateSecretRequest {
    pub classification: String,
    pub device_id: String,
    pub plaintext: String,
}

#[derive(Serialize)]
pub struct CreateSecretResponse {
    pub secret_id: String,
    pub version: u32,
    pub secret_version_id: String,
}

#[derive(Serialize)]
pub struct DecryptSecretResponse {
    pub secret_id: String,
    pub version: u32,
    pub plaintext: String,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub supabase: &'static str,
    pub master_key: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_space_mb: Option<u64>,
}

#[derive(Serialize)]
pub struct ApiErrorResponse {
    pub error: String,
    pub code: String,
}

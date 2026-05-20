use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSecretRequest {
    pub classification: String,
    pub device_id: String,
    pub plaintext_hex: String,
}

#[derive(Serialize)]
pub struct CreateSecretResponse {
    pub secret_id: String,
    pub version: u32,
    pub secret_version_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateSecretRequest {
    pub device_id: String,
    pub plaintext_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSecretAliasRequest {
    pub alias: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSecretAliasRequest {
    pub alias: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveSecretAliasRequest {
    pub alias: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListSecretAliasesQuery {
    #[serde(default = "default_list_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

#[derive(Serialize)]
pub struct RotateSecretResponse {
    pub secret_id: String,
    pub version: u32,
    pub secret_version_id: String,
}

#[derive(Serialize)]
pub struct CreateSecretAliasResponse {
    pub secret_alias_id: String,
    pub secret_id: String,
}

#[derive(Serialize)]
pub struct UpdateSecretAliasResponse {
    pub secret_alias_id: String,
}

#[derive(Serialize)]
pub struct ResolveSecretAliasResponse {
    pub secret_alias_id: String,
    pub secret_id: String,
}

#[derive(Serialize)]
pub struct SecretAliasSummary {
    pub secret_alias_id: String,
    pub secret_id: String,
    pub alias: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize)]
pub struct ListSecretAliasesResponse {
    pub aliases: Vec<SecretAliasSummary>,
    pub limit: u32,
    pub offset: u32,
    pub total_returned: u32,
}

#[derive(Serialize)]
pub struct DecryptSecretResponse {
    pub secret_id: String,
    pub version: u32,
    pub plaintext_hex: String,
    pub encoding: &'static str,
}

impl DecryptSecretResponse {
    pub fn new(secret_id: String, version: u32, plaintext: &[u8]) -> Self {
        Self {
            secret_id,
            version,
            plaintext_hex: hex::encode(plaintext),
            encoding: "hex",
        }
    }
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub supabase: &'static str,
    pub master_key: &'static str,
    pub disk_free_mb: Option<u64>,
}

#[derive(Serialize)]
pub struct ApiErrorResponse {
    pub code: String,
    pub request_id: String,
}

fn default_list_limit() -> u32 {
    100
}

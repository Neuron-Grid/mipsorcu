use serde::{Deserialize, Serialize};

use crate::ledger::LedgerVerifyingKey;

use super::response::{ensure_success, response_contains_marker};
use super::{SupabaseClient, SupabaseRpcError};

const REGISTER_PUBLIC_KEY_CONFLICT_MARKER: &str = "ledger_signing_public_key_conflict";
const REGISTER_PUBLIC_KEY_RETIRED_MARKER: &str = "ledger_signing_public_key_retired";
const REGISTER_INVALID_RPC_INPUT_MARKER: &str = "invalid_rpc_input";

impl SupabaseClient {
    pub async fn register_ledger_signing_public_key(
        &self,
        verification_key: &LedgerVerifyingKey,
    ) -> Result<RegisterLedgerSigningPublicKeyOutcome, SupabaseRpcError> {
        let params = RegisterLedgerSigningPublicKeyParams::from_verifying_key(verification_key);
        let response = self
            .post_rpc("rpc_register_ledger_signing_public_key", &params)
            .await?;
        let rows: Vec<RegisterLedgerSigningPublicKeyResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .next()
            .ok_or(SupabaseRpcError::EmptyResult)
            .and_then(RegisterLedgerSigningPublicKeyOutcome::try_from)
    }
}

#[derive(Serialize)]
struct RegisterLedgerSigningPublicKeyParams {
    p_key_version: u32,
    p_public_key: String,
}

impl RegisterLedgerSigningPublicKeyParams {
    fn from_verifying_key(verification_key: &LedgerVerifyingKey) -> Self {
        Self {
            p_key_version: verification_key.key_version().get(),
            p_public_key: encode_public_key_as_bytea(verification_key.as_bytes()),
        }
    }
}

fn encode_public_key_as_bytea(bytes: [u8; 32]) -> String {
    format!("\\x{}", hex::encode(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterLedgerSigningPublicKeyOutcome {
    replayed: bool,
}

impl RegisterLedgerSigningPublicKeyOutcome {
    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    dead_code,
    reason = "fields exist for serde(deny_unknown_fields) validation"
)]
struct RegisterLedgerSigningPublicKeyResponse {
    out_key_version: i32,
    public_key: String,
    algorithm: String,
    status: String,
    created_at: String,
    retired_at: Option<String>,
    replayed: bool,
}

impl TryFrom<RegisterLedgerSigningPublicKeyResponse> for RegisterLedgerSigningPublicKeyOutcome {
    type Error = SupabaseRpcError;

    fn try_from(response: RegisterLedgerSigningPublicKeyResponse) -> Result<Self, Self::Error> {
        if response.out_key_version <= 0 {
            return Err(SupabaseRpcError::InvalidResponse(
                "register ledger signing public key RPC returned invalid out_key_version"
                    .to_owned(),
            ));
        }

        Ok(Self {
            replayed: response.replayed,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterPublicKeyError {
    Conflict,
    Retired,
    InvalidRpcInput,
    RegisterFailed,
}

impl RegisterPublicKeyError {
    pub fn as_error_code(self) -> &'static str {
        match self {
            Self::Conflict => REGISTER_PUBLIC_KEY_CONFLICT_MARKER,
            Self::Retired => REGISTER_PUBLIC_KEY_RETIRED_MARKER,
            Self::InvalidRpcInput => REGISTER_INVALID_RPC_INPUT_MARKER,
            Self::RegisterFailed => "ledger_public_key_register_failed",
        }
    }
}

pub fn classify_register_public_key_error(error: &SupabaseRpcError) -> RegisterPublicKeyError {
    let SupabaseRpcError::NonSuccessStatus { body, .. } = error else {
        return RegisterPublicKeyError::RegisterFailed;
    };

    if response_contains_marker(body, REGISTER_PUBLIC_KEY_CONFLICT_MARKER) {
        RegisterPublicKeyError::Conflict
    } else if response_contains_marker(body, REGISTER_PUBLIC_KEY_RETIRED_MARKER) {
        RegisterPublicKeyError::Retired
    } else if response_contains_marker(body, REGISTER_INVALID_RPC_INPUT_MARKER) {
        RegisterPublicKeyError::InvalidRpcInput
    } else {
        RegisterPublicKeyError::RegisterFailed
    }
}

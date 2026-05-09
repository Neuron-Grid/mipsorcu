use serde::{Deserialize, Serialize};

use crate::ledger::{
    LedgerError, LedgerHash, LedgerSequenceNo, LedgerSignature, LedgerSignatureKeyVersion,
    LedgerVerifyingKey, SignedLedgerEntry, SignedLedgerEntryParts,
};

use super::response::ensure_success;
use super::{SupabaseClient, SupabaseRpcError};

const LEDGER_EXPORT_INVALID_RPC_INPUT_MARKER: &str = "invalid_rpc_input";

impl SupabaseClient {
    pub async fn export_ledger_verification_materials(
        &self,
        start_sequence_no: LedgerSequenceNo,
        end_sequence_no: LedgerSequenceNo,
    ) -> Result<Vec<LedgerVerificationMaterialRow>, SupabaseRpcError> {
        let params =
            ExportLedgerVerificationMaterialsParams::from_range(start_sequence_no, end_sequence_no);
        let response = self
            .post_rpc("rpc_export_ledger_verification_materials", &params)
            .await?;
        let rows: Vec<LedgerVerificationMaterialResponse> = ensure_success(response)
            .await?
            .json()
            .await
            .map_err(|error| SupabaseRpcError::InvalidResponse(error.to_string()))?;

        rows.into_iter()
            .map(LedgerVerificationMaterialRow::try_from)
            .collect()
    }
}

#[derive(Serialize)]
struct ExportLedgerVerificationMaterialsParams {
    p_start_sequence_no: i64,
    p_end_sequence_no: i64,
}

impl ExportLedgerVerificationMaterialsParams {
    fn from_range(start_sequence_no: LedgerSequenceNo, end_sequence_no: LedgerSequenceNo) -> Self {
        Self {
            p_start_sequence_no: start_sequence_no.get() as i64,
            p_end_sequence_no: end_sequence_no.get() as i64,
        }
    }
}

// DTO
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerVerificationMaterialRow {
    pub sequence_no: LedgerSequenceNo,
    pub entry_hash: LedgerHash,
    pub previous_entry_hash: LedgerHash,
    pub signature: LedgerSignature,
    pub signature_key_version: LedgerSignatureKeyVersion,
    pub entry_type: String,
    pub source_event_at: String,
    pub canonicalization_version: i32,
    pub hash_algorithm: String,
    pub signature_algorithm: String,
    pub pk_key_version: Option<i32>,
    pub pk_public_key: Option<String>,
    pub pk_algorithm: Option<String>,
    pub pk_status: Option<String>,
}

impl LedgerVerificationMaterialRow {
    pub fn try_restore_verifying_key(&self) -> Result<Option<LedgerVerifyingKey>, LedgerError> {
        let pk_key_version = match self.pk_key_version {
            Some(v) => v,
            None => return Ok(None),
        };

        let pk_public_key = match &self.pk_public_key {
            Some(k) => k,
            None => return Ok(None),
        };

        let pk_algorithm = match &self.pk_algorithm {
            Some(a) => a.as_str(),
            None => {
                return Err(LedgerError::InvalidVerificationKey);
            }
        };

        let pk_status = match &self.pk_status {
            Some(s) => s.as_str(),
            None => {
                return Err(LedgerError::InvalidVerificationKey);
            }
        };

        // Reject non-ed25519 algorithm
        if pk_algorithm != "ed25519" {
            return Err(LedgerError::InvalidVerificationKey);
        }

        // Accept both active and retired keys
        if pk_status != "active" && pk_status != "retired" {
            return Err(LedgerError::InvalidVerificationKey);
        }

        // key_version must match
        let key_version = LedgerSignatureKeyVersion::new(pk_key_version as u32)?;
        if key_version != self.signature_key_version {
            return Err(LedgerError::SignatureKeyVersionMismatch {
                expected: self.signature_key_version.get(),
                actual: key_version.get(),
            });
        }

        let public_key_bytes =
            decode_bytea_hex(pk_public_key).map_err(|_| LedgerError::InvalidVerificationKey)?;

        LedgerVerifyingKey::from_public_key_bytes(key_version, &public_key_bytes).map(Some)
    }

    pub fn try_restore_signed_ledger_entry(&self) -> Result<SignedLedgerEntry, LedgerError> {
        use crate::audit::RequestId;
        use crate::ledger::{LedgerEntryId, LedgerPayload, LedgerResult};
        use crate::types::SourceEventAt;

        let entry_type = crate::ledger::LedgerEntryType::parse(&self.entry_type).map_err(|_| {
            LedgerError::UnknownEntryType {
                value: self.entry_type.clone(),
            }
        })?;

        let source_event_at = SourceEventAt::parse(&self.source_event_at)
            .map_err(|_| LedgerError::SerializationFailed("invalid source_event_at".to_owned()))?;

        // Placeholder values for fields not in the export RPC.
        // Using well-known nil-like UUIDs that are valid v4.
        let placeholder_ledger_entry_id =
            LedgerEntryId::parse("00000000-0000-4000-8000-000000000000").map_err(|_| {
                LedgerError::InvalidUuid {
                    field: "ledger_entry_id",
                }
            })?;
        let placeholder_request_id = RequestId::parse("00000000-0000-4000-8000-000000000000")
            .map_err(|_| LedgerError::InvalidUuid {
                field: "request_id",
            })?;
        let placeholder_payload = LedgerPayload::empty(entry_type)?;

        let parts = SignedLedgerEntryParts {
            ledger_entry_id: placeholder_ledger_entry_id,
            sequence_no: self.sequence_no,
            entry_type,
            source_event_at,
            request_id: placeholder_request_id,
            source_event_id: None,
            target_secret_id: None,
            target_secret_version_id: None,
            actor_user_id: None,
            actor_device_id: None,
            result: LedgerResult::Success,
            error_code: None,
            payload: placeholder_payload,
            previous_entry_hash: self.previous_entry_hash,
            entry_hash: self.entry_hash,
            signature: self.signature,
            signature_key_version: self.signature_key_version,
        };

        SignedLedgerEntry::from_stored_parts(parts)
    }
}

// ---- Internal response deserialization ----

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerVerificationMaterialResponse {
    sequence_no: i64,
    entry_hash: Option<String>,
    previous_entry_hash: Option<String>,
    signature: Option<String>,
    signature_key_version: Option<i32>,
    entry_type: Option<String>,
    source_event_at: Option<String>,
    canonicalization_version: Option<i32>,
    hash_algorithm: Option<String>,
    signature_algorithm: Option<String>,
    pk_key_version: Option<i32>,
    pk_public_key: Option<String>,
    pk_algorithm: Option<String>,
    pk_status: Option<String>,
    #[expect(
        dead_code,
        reason = "fields exist for serde(deny_unknown_fields) validation"
    )]
    pk_created_at: Option<String>,
    #[expect(
        dead_code,
        reason = "fields exist for serde(deny_unknown_fields) validation"
    )]
    pk_retired_at: Option<String>,
}

impl TryFrom<LedgerVerificationMaterialResponse> for LedgerVerificationMaterialRow {
    type Error = SupabaseRpcError;

    fn try_from(response: LedgerVerificationMaterialResponse) -> Result<Self, Self::Error> {
        let sequence_no = LedgerSequenceNo::from_i64(response.sequence_no).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned invalid sequence_no".to_owned(),
            )
        })?;

        let entry_hash_raw = response.entry_hash.ok_or_else(|| {
            SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned null entry_hash".to_owned(),
            )
        })?;
        let entry_hash = LedgerHash::from_bytea_hex(&entry_hash_raw).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned invalid entry_hash".to_owned(),
            )
        })?;

        let previous_entry_hash_raw = response.previous_entry_hash.ok_or_else(|| {
            SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned null previous_entry_hash"
                    .to_owned(),
            )
        })?;
        let previous_entry_hash =
            LedgerHash::from_bytea_hex(&previous_entry_hash_raw).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                    "export ledger verification materials RPC returned invalid previous_entry_hash"
                        .to_owned(),
                )
            })?;

        let signature_raw = response.signature.ok_or_else(|| {
            SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned null signature".to_owned(),
            )
        })?;
        let signature = LedgerSignature::from_bytea_hex(&signature_raw).map_err(|_| {
            SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned invalid signature".to_owned(),
            )
        })?;

        let signature_key_version_raw = response.signature_key_version.ok_or_else(|| {
            SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned null signature_key_version"
                    .to_owned(),
            )
        })?;
        let signature_key_version =
            LedgerSignatureKeyVersion::new(signature_key_version_raw as u32).map_err(|_| {
                SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned invalid signature_key_version"
                    .to_owned(),
            )
            })?;

        let entry_type = response.entry_type.ok_or_else(|| {
            SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned null entry_type".to_owned(),
            )
        })?;

        let source_event_at = response.source_event_at.ok_or_else(|| {
            SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned null source_event_at".to_owned(),
            )
        })?;

        let canonicalization_version = response.canonicalization_version.ok_or_else(|| {
            SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned null canonicalization_version"
                    .to_owned(),
            )
        })?;

        let hash_algorithm = response.hash_algorithm.ok_or_else(|| {
            SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned null hash_algorithm".to_owned(),
            )
        })?;

        let signature_algorithm = response.signature_algorithm.ok_or_else(|| {
            SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned null signature_algorithm"
                    .to_owned(),
            )
        })?;

        if response.pk_public_key.is_some() && response.pk_key_version.is_none() {
            return Err(SupabaseRpcError::InvalidResponse(
                "export ledger verification materials RPC returned pk_public_key without pk_key_version".to_owned(),
            ));
        }

        Ok(Self {
            sequence_no,
            entry_hash,
            previous_entry_hash,
            signature,
            signature_key_version,
            entry_type,
            source_event_at,
            canonicalization_version,
            hash_algorithm,
            signature_algorithm,
            pk_key_version: response.pk_key_version,
            pk_public_key: response.pk_public_key,
            pk_algorithm: response.pk_algorithm,
            pk_status: response.pk_status,
        })
    }
}

// Helpers
fn decode_bytea_hex(value: &str) -> Result<Vec<u8>, ()> {
    let hex_value = value.strip_prefix("\\x").ok_or(())?;
    hex::decode(hex_value).map_err(|_| ())
}

// Error classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportLedgerError {
    InvalidRpcInput,
    ExportFailed,
}

impl ExportLedgerError {
    pub fn as_error_code(self) -> &'static str {
        match self {
            Self::InvalidRpcInput => "ledger_export_invalid_rpc_input",
            Self::ExportFailed => "ledger_export_failed",
        }
    }
}

pub fn classify_export_ledger_error(error: &SupabaseRpcError) -> ExportLedgerError {
    let SupabaseRpcError::NonSuccessStatus { body, .. } = error else {
        return ExportLedgerError::ExportFailed;
    };

    if super::response::response_contains_marker(body, LEDGER_EXPORT_INVALID_RPC_INPUT_MARKER) {
        ExportLedgerError::InvalidRpcInput
    } else {
        ExportLedgerError::ExportFailed
    }
}

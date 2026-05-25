use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ledger::{
    LedgerChainHead, LedgerEntryId, LedgerHash, LedgerSequenceNo, SignedLedgerEntry,
};
use crate::{KeyVersion, SecretId, SecretVersion, SecretVersionId};

#[derive(Deserialize)]
pub struct SecretVersionReadRow {
    pub id: String,
    pub secret_id: String,
    pub version: i32,
    pub ciphertext: String,
    pub encrypted_data_key: Option<String>,
    pub key_version: i32,
    pub algorithm: String,
    pub classification: String,
    pub nonce_or_iv: String,
    pub aad_context: Value,
    pub created_by_user_id: String,
    pub created_at: String,
    pub wrapped_dek: Option<String>,
    pub dek_wrap_algorithm: Option<String>,
    pub kek_version: Option<i32>,
    pub secrets: SecretReadJoin,
}

#[derive(Deserialize)]
pub struct SecretVersionWriteStateRow {
    pub id: String,
    pub secret_id: String,
    pub version: i32,
    pub classification: String,
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

#[derive(Deserialize)]
pub struct SecretAliasListRow {
    pub id: String,
    pub secret_id: String,
    pub alias_ciphertext: String,
    pub alias_nonce: String,
    pub alias_key_version: i32,
    pub alias_fingerprint: String,
    pub alias_fingerprint_key_version: i32,
    pub alias_fingerprint_schema_version: i32,
    pub aad_context: Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Deserialize)]
pub struct SecretAliasResolveRow {
    pub id: String,
    pub secret_id: String,
    pub alias_ciphertext: String,
    pub alias_nonce: String,
    pub alias_key_version: i32,
    pub aad_context: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretVersionRetentionSnapshot {
    secret_version_id: SecretVersionId,
    version: SecretVersion,
    key_version: KeyVersion,
}

impl SecretVersionRetentionSnapshot {
    pub(crate) fn new(
        secret_version_id: SecretVersionId,
        version: SecretVersion,
        key_version: KeyVersion,
    ) -> Self {
        Self {
            secret_version_id,
            version,
            key_version,
        }
    }

    pub fn secret_version_id(&self) -> &SecretVersionId {
        &self.secret_version_id
    }

    pub fn version(&self) -> SecretVersion {
        self.version
    }

    pub fn key_version(&self) -> KeyVersion {
        self.key_version
    }
}

#[derive(Deserialize)]
pub struct RestoreTestSampleRow {
    pub id: String,
    pub secret_id: String,
    pub version: i32,
    pub ciphertext: String,
    pub encrypted_data_key: Option<String>,
    pub key_version: i32,
    pub nonce_or_iv: String,
    pub aad_context: Value,
    pub classification: String,
    pub created_at: String,
    pub wrapped_dek: Option<String>,
    pub dek_wrap_algorithm: Option<String>,
    pub kek_version: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegrityCheckSummary {
    pub checked_secret_count: u64,
    pub checked_secret_version_count: u64,
    pub checked_audit_event_count: u64,
    pub violation_count: u64,
    pub violation_summary: IntegrityCheckViolationSummary,
}

impl IntegrityCheckSummary {
    pub fn zero() -> Self {
        Self {
            checked_secret_count: 0,
            checked_secret_version_count: 0,
            checked_audit_event_count: 0,
            violation_count: 0,
            violation_summary: IntegrityCheckViolationSummary::zero(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityCheckViolationSummary {
    pub current_version_invalid: u64,
    pub version_invalid: u64,
    pub retention_exceeded: u64,
    pub ciphertext_empty: u64,
    pub encrypted_data_key_empty: u64,
    pub nonce_length_invalid: u64,
    pub algorithm_invalid: u64,
    pub nonce_duplicate: u64,
    pub aad_keys_invalid: u64,
    pub aad_row_mismatch: u64,
    pub created_at_mismatch: u64,
    pub audit_action_invalid: u64,
    pub audit_result_invalid: u64,
    pub audit_metadata_not_object: u64,
    pub audit_metadata_forbidden_key: u64,
    pub audit_source_event_at_invalid: u64,
}

impl IntegrityCheckViolationSummary {
    pub fn zero() -> Self {
        Self {
            current_version_invalid: 0,
            version_invalid: 0,
            retention_exceeded: 0,
            ciphertext_empty: 0,
            encrypted_data_key_empty: 0,
            nonce_length_invalid: 0,
            algorithm_invalid: 0,
            nonce_duplicate: 0,
            aad_keys_invalid: 0,
            aad_row_mismatch: 0,
            created_at_mismatch: 0,
            audit_action_invalid: 0,
            audit_result_invalid: 0,
            audit_metadata_not_object: 0,
            audit_metadata_forbidden_key: 0,
            audit_source_event_at_invalid: 0,
        }
    }
}

#[derive(Deserialize)]
pub struct KeyRotationBatchRow {
    pub id: String,
    pub secret_id: String,
    pub version: i32,
    pub encrypted_data_key: String,
    pub key_version: i32,
}

#[derive(Clone, Serialize)]
pub struct KeyRotationApplyRow {
    pub id: String,
    pub encrypted_data_key: String,
}

#[derive(Debug)]
pub struct KeyRotationStatus {
    pub key_version: i32,
    pub remaining_count: i64,
}

impl KeyRotationStatus {
    pub(crate) fn new(key_version: i32, remaining_count: i64) -> Self {
        Self {
            key_version,
            remaining_count,
        }
    }
}

#[derive(Debug)]
pub struct KeyRotationApplyOutcome {
    pub processed_count: i64,
    pub remaining_count: i64,
}

impl KeyRotationApplyOutcome {
    pub(crate) fn new(processed_count: i64, remaining_count: i64) -> Self {
        Self {
            processed_count,
            remaining_count,
        }
    }
}

#[derive(Debug)]
pub struct KeyRotationCompleteOutcome {
    pub remaining_count: i64,
}

impl KeyRotationCompleteOutcome {
    pub(crate) fn new(remaining_count: i64) -> Self {
        Self { remaining_count }
    }
}

#[derive(Clone, Serialize)]
pub struct LedgerEntryRpcParams {
    pub(crate) p_ledger_entry_id: String,
    pub(crate) p_sequence_no: u64,
    pub(crate) p_entry_type: String,
    pub(crate) p_source_event_at: String,
    pub(crate) p_request_id: String,
    pub(crate) p_source_event_id: Option<String>,
    pub(crate) p_target_secret_id: Option<String>,
    pub(crate) p_target_secret_version_id: Option<String>,
    pub(crate) p_actor_user_id: Option<String>,
    pub(crate) p_actor_device_id: Option<String>,
    pub(crate) p_result: String,
    pub(crate) p_error_code: Option<String>,
    pub(crate) p_payload: Value,
    pub(crate) p_canonicalization_version: u8,
    pub(crate) p_previous_entry_hash: String,
    pub(crate) p_entry_hash: String,
    pub(crate) p_hash_algorithm: String,
    pub(crate) p_signature: String,
    pub(crate) p_signature_algorithm: String,
    pub(crate) p_signature_key_version: u32,
}

impl LedgerEntryRpcParams {
    pub fn from_signed_entry(entry: &SignedLedgerEntry) -> Self {
        Self {
            p_ledger_entry_id: entry.ledger_entry_id().as_canonical_string(),
            p_sequence_no: entry.sequence_no().get(),
            p_entry_type: entry.entry_type().as_str().to_owned(),
            p_source_event_at: entry.source_event_at().as_str().to_owned(),
            p_request_id: entry.request_id().as_canonical_string(),
            p_source_event_id: entry
                .source_event_id()
                .map(|event_id| event_id.as_canonical_string()),
            p_target_secret_id: entry
                .target_secret_id()
                .map(|secret_id| secret_id.as_canonical_string()),
            p_target_secret_version_id: entry
                .target_secret_version_id()
                .map(|version_id| version_id.as_canonical_string()),
            p_actor_user_id: entry
                .actor_user_id()
                .map(|user_id| user_id.as_canonical_string()),
            p_actor_device_id: entry
                .actor_device_id()
                .map(|device_id| device_id.as_str().to_owned()),
            p_result: entry.result().as_str().to_owned(),
            p_error_code: entry.error_code().map(str::to_owned),
            p_payload: entry.payload().as_value(),
            p_canonicalization_version: crate::ledger::LEDGER_CANONICALIZATION_VERSION_V1,
            p_previous_entry_hash: entry.previous_entry_hash().to_bytea_hex(),
            p_entry_hash: entry.entry_hash().to_bytea_hex(),
            p_hash_algorithm: crate::ledger::LEDGER_HASH_ALGORITHM_SHA3_256.to_owned(),
            p_signature: entry.signature().to_bytea_hex(),
            p_signature_algorithm: crate::ledger::LEDGER_SIGNATURE_ALGORITHM_ED25519.to_owned(),
            p_signature_key_version: entry.signature_key_version().get(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendLedgerEntryOutcome {
    ledger_entry_id: LedgerEntryId,
    sequence_no: LedgerSequenceNo,
    entry_hash: LedgerHash,
    chain_head: LedgerChainHead,
    replayed: bool,
}

impl AppendLedgerEntryOutcome {
    pub(crate) fn new(
        ledger_entry_id: LedgerEntryId,
        sequence_no: LedgerSequenceNo,
        entry_hash: LedgerHash,
        chain_head: LedgerChainHead,
        replayed: bool,
    ) -> Self {
        Self {
            ledger_entry_id,
            sequence_no,
            entry_hash,
            chain_head,
            replayed,
        }
    }

    pub fn ledger_entry_id(&self) -> &LedgerEntryId {
        &self.ledger_entry_id
    }

    pub fn sequence_no(&self) -> LedgerSequenceNo {
        self.sequence_no
    }

    pub fn entry_hash(&self) -> LedgerHash {
        self.entry_hash
    }

    pub fn chain_head(&self) -> LedgerChainHead {
        self.chain_head
    }

    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerAppendRpcFailure {
    EntryIdConflict,
    EntryHashConflict,
    SequenceMismatch,
    PreviousHashMismatch,
    PayloadSchemaViolation,
    ChainStateMissing,
    InvalidRpcInput,
    AppendFailed,
}

impl LedgerAppendRpcFailure {
    pub fn as_error_code(self) -> &'static str {
        match self {
            Self::EntryIdConflict => "ledger_entry_id_conflict",
            Self::EntryHashConflict => "ledger_entry_hash_conflict",
            Self::SequenceMismatch => "ledger_sequence_mismatch",
            Self::PreviousHashMismatch => "ledger_previous_hash_mismatch",
            Self::PayloadSchemaViolation => "ledger_payload_schema_violation",
            Self::ChainStateMissing => "ledger_chain_state_mismatch",
            Self::InvalidRpcInput | Self::AppendFailed => "ledger_append_failed",
        }
    }
}

#[derive(Serialize)]
pub struct WriteSecretVersionParams {
    pub p_request_id: String,
    pub p_action: String,
    pub p_secret_id: String,
    pub p_secret_version_id: String,
    pub p_owner_user_id: String,
    pub p_classification: String,
    pub p_created_by_device_id: String,
    pub p_created_at: String,
    pub p_version: u32,
    pub p_ciphertext: String,
    pub p_encrypted_data_key: Option<String>,
    pub p_key_version: u32,
    pub p_algorithm: String,
    pub p_nonce_or_iv: String,
    pub p_aad_context: Value,
    pub p_ledger_entries: Vec<LedgerEntryRpcParams>,
    pub p_wrapped_dek: Option<String>,
    pub p_dek_wrap_algorithm: Option<String>,
    pub p_kek_version: Option<u32>,
}

#[derive(Debug)]
pub struct WriteSecretVersionOutcome {
    secret_id: SecretId,
    secret_version_id: SecretVersionId,
    version: SecretVersion,
    purged_version_ids: Vec<String>,
}

impl WriteSecretVersionOutcome {
    pub(crate) fn new(
        secret_id: SecretId,
        secret_version_id: SecretVersionId,
        version: SecretVersion,
        purged_version_ids: Vec<String>,
    ) -> Self {
        Self {
            secret_id,
            secret_version_id,
            version,
            purged_version_ids,
        }
    }

    pub fn secret_id(&self) -> &SecretId {
        &self.secret_id
    }

    pub fn secret_version_id(&self) -> &SecretVersionId {
        &self.secret_version_id
    }

    pub fn version(&self) -> SecretVersion {
        self.version
    }

    #[allow(dead_code)]
    pub fn purged_version_ids(&self) -> &[String] {
        &self.purged_version_ids
    }
}

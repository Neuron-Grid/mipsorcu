use std::fmt;

use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::{Map, Value};

use crate::audit::{AuditEventId, RequestId};
use crate::types::{DeviceId, OwnerUserId, SecretId, SourceEventAt};

use super::constants::{
    LEDGER_CANONICAL_SCHEMA_V1, LEDGER_CANONICALIZATION_VERSION_V1, LEDGER_HASH_ALGORITHM_SHA256,
    LEDGER_SIGNATURE_ALGORITHM_ED25519,
};
use super::entry_type::LedgerEntryType;
use super::error::LedgerError;
use super::hash::LedgerHash;
use super::ids::{LedgerSequenceNo, LedgerTargetSecretVersionId};
use super::payload::LedgerPayload;
use super::result::LedgerResult;
use super::signature::LedgerSignatureKeyVersion;

#[derive(Clone, PartialEq, Eq)]
pub struct LedgerCanonicalPayload(Vec<u8>);

impl LedgerCanonicalPayload {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for LedgerCanonicalPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerCanonicalPayload")
            .field("len", &self.0.len())
            .finish()
    }
}

pub(super) struct CanonicalBuildFields<'a> {
    pub(super) sequence_no: LedgerSequenceNo,
    pub(super) entry_type: LedgerEntryType,
    pub(super) source_event_at: &'a SourceEventAt,
    pub(super) request_id: &'a RequestId,
    pub(super) source_event_id: Option<&'a AuditEventId>,
    pub(super) target_secret_id: Option<&'a SecretId>,
    pub(super) target_secret_version_id: Option<&'a LedgerTargetSecretVersionId>,
    pub(super) actor_user_id: Option<&'a OwnerUserId>,
    pub(super) actor_device_id: Option<&'a DeviceId>,
    pub(super) result: LedgerResult,
    pub(super) error_code: Option<&'a str>,
    pub(super) payload: &'a LedgerPayload,
    pub(super) previous_entry_hash: LedgerHash,
    pub(super) signature_key_version: LedgerSignatureKeyVersion,
}

pub(super) fn build_canonical_payload(
    fields: CanonicalBuildFields<'_>,
) -> Result<LedgerCanonicalPayload, LedgerError> {
    let request_id = fields.request_id.as_canonical_string();
    let source_event_id = fields
        .source_event_id
        .map(AuditEventId::as_canonical_string);
    let target_secret_id = fields.target_secret_id.map(SecretId::as_canonical_string);
    let target_secret_version_id = fields
        .target_secret_version_id
        .map(LedgerTargetSecretVersionId::as_canonical_string);
    let actor_user_id = fields.actor_user_id.map(OwnerUserId::as_canonical_string);
    let actor_device_id = fields
        .actor_device_id
        .map(|device_id| device_id.as_str().to_owned());
    let previous_entry_hash = fields.previous_entry_hash.to_hex();

    let document = CanonicalLedgerDocument {
        schema: LEDGER_CANONICAL_SCHEMA_V1,
        sequence_no: fields.sequence_no.get(),
        entry_type: fields.entry_type.as_str(),
        source_event_at: fields.source_event_at.as_str(),
        request_id: &request_id,
        source_event_id: source_event_id.as_deref(),
        target_secret_id: target_secret_id.as_deref(),
        target_secret_version_id: target_secret_version_id.as_deref(),
        actor_user_id: actor_user_id.as_deref(),
        actor_device_id: actor_device_id.as_deref(),
        result: fields.result.as_str(),
        error_code: fields.error_code,
        payload: fields.payload.canonical_serializer(),
        canonicalization_version: LEDGER_CANONICALIZATION_VERSION_V1,
        previous_entry_hash: &previous_entry_hash,
        hash_algorithm: LEDGER_HASH_ALGORITHM_SHA256,
        signature_algorithm: LEDGER_SIGNATURE_ALGORITHM_ED25519,
        signature_key_version: fields.signature_key_version.get(),
    };
    let bytes = serde_json::to_vec(&document)
        .map_err(|error| LedgerError::SerializationFailed(error.to_string()))?;

    Ok(LedgerCanonicalPayload(bytes))
}

#[derive(Serialize)]
struct CanonicalLedgerDocument<'a> {
    schema: &'static str,
    sequence_no: u64,
    entry_type: &'static str,
    source_event_at: &'a str,
    request_id: &'a str,
    source_event_id: Option<&'a str>,
    target_secret_id: Option<&'a str>,
    target_secret_version_id: Option<&'a str>,
    actor_user_id: Option<&'a str>,
    actor_device_id: Option<&'a str>,
    result: &'static str,
    error_code: Option<&'a str>,
    payload: CanonicalPayloadObject<'a>,
    canonicalization_version: u8,
    previous_entry_hash: &'a str,
    hash_algorithm: &'static str,
    signature_algorithm: &'static str,
    signature_key_version: u32,
}

pub(super) struct CanonicalPayloadObject<'a> {
    pub(super) entry_type: LedgerEntryType,
    pub(super) object: &'a Map<String, Value>,
}

impl Serialize for CanonicalPayloadObject<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.object.len()))?;
        for key in self.entry_type.allowed_payload_keys() {
            if let Some(value) = self.object.get(*key) {
                map.serialize_entry(key, value)?;
            }
        }
        map.end()
    }
}

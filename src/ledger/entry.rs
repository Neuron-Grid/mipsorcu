use std::fmt;

use crate::audit::{AuditEventId, RequestId};
use crate::types::{DeviceId, OwnerUserId, SecretId, SourceEventAt};

use super::canonical::{CanonicalBuildFields, LedgerCanonicalPayload, build_canonical_payload};
use super::entry_type::LedgerEntryType;
use super::error::LedgerError;
use super::hash::LedgerHash;
use super::ids::{LedgerEntryId, LedgerSequenceNo, LedgerTargetSecretVersionId};
use super::payload::LedgerPayload;
use super::result::LedgerResult;
use super::signature::{
    LedgerSignature, LedgerSignatureKeyVersion, LedgerSigningKey, LedgerVerifyingKey,
};

#[derive(Clone)]
pub struct LedgerEntryDraft {
    ledger_entry_id: LedgerEntryId,
    sequence_no: LedgerSequenceNo,
    entry_type: LedgerEntryType,
    source_event_at: SourceEventAt,
    request_id: RequestId,
    source_event_id: Option<AuditEventId>,
    target_secret_id: Option<SecretId>,
    target_secret_version_id: Option<LedgerTargetSecretVersionId>,
    actor_user_id: Option<OwnerUserId>,
    actor_device_id: Option<DeviceId>,
    result: LedgerResult,
    error_code: Option<String>,
    payload: LedgerPayload,
    previous_entry_hash: LedgerHash,
    signature_key_version: LedgerSignatureKeyVersion,
}

impl LedgerEntryDraft {
    pub fn new(parts: LedgerEntryDraftParts) -> Result<Self, LedgerError> {
        if parts.payload.entry_type() != parts.entry_type {
            return Err(LedgerError::UnknownPayloadKey {
                key: "payload.entry_type".to_owned(),
                entry_type: parts.entry_type,
            });
        }

        validate_error_code(parts.result, parts.error_code.as_deref(), "error_code")?;
        validate_actor_device_id(parts.actor_device_id.as_ref())?;

        Ok(Self {
            ledger_entry_id: parts.ledger_entry_id,
            sequence_no: parts.sequence_no,
            entry_type: parts.entry_type,
            source_event_at: parts.source_event_at,
            request_id: parts.request_id,
            source_event_id: parts.source_event_id,
            target_secret_id: parts.target_secret_id,
            target_secret_version_id: parts.target_secret_version_id,
            actor_user_id: parts.actor_user_id,
            actor_device_id: parts.actor_device_id,
            result: parts.result,
            error_code: parts.error_code,
            payload: parts.payload,
            previous_entry_hash: parts.previous_entry_hash,
            signature_key_version: parts.signature_key_version,
        })
    }

    pub fn canonical_payload(&self) -> Result<LedgerCanonicalPayload, LedgerError> {
        build_canonical_payload(CanonicalBuildFields {
            sequence_no: self.sequence_no,
            entry_type: self.entry_type,
            source_event_at: &self.source_event_at,
            request_id: &self.request_id,
            source_event_id: self.source_event_id.as_ref(),
            target_secret_id: self.target_secret_id.as_ref(),
            target_secret_version_id: self.target_secret_version_id.as_ref(),
            actor_user_id: self.actor_user_id.as_ref(),
            actor_device_id: self.actor_device_id.as_ref(),
            result: self.result,
            error_code: self.error_code.as_deref(),
            payload: &self.payload,
            previous_entry_hash: self.previous_entry_hash,
            signature_key_version: self.signature_key_version,
        })
    }

    pub fn sign(&self, signing_key: &LedgerSigningKey) -> Result<SignedLedgerEntry, LedgerError> {
        let canonical_payload = self.canonical_payload()?;
        let entry_hash = LedgerHash::from_canonical_payload(&canonical_payload);
        let signature = signing_key.sign_payload(self.signature_key_version, &canonical_payload)?;

        Ok(SignedLedgerEntry {
            ledger_entry_id: self.ledger_entry_id.clone(),
            sequence_no: self.sequence_no,
            entry_type: self.entry_type,
            source_event_at: self.source_event_at.clone(),
            request_id: self.request_id.clone(),
            source_event_id: self.source_event_id.clone(),
            target_secret_id: self.target_secret_id.clone(),
            target_secret_version_id: self.target_secret_version_id.clone(),
            actor_user_id: self.actor_user_id.clone(),
            actor_device_id: self.actor_device_id.clone(),
            result: self.result,
            error_code: self.error_code.clone(),
            payload: self.payload.clone(),
            canonical_payload,
            previous_entry_hash: self.previous_entry_hash,
            entry_hash,
            signature,
            signature_key_version: self.signature_key_version,
        })
    }
}

impl fmt::Debug for LedgerEntryDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerEntryDraft")
            .field("ledger_entry_id", &self.ledger_entry_id)
            .field("sequence_no", &self.sequence_no)
            .field("entry_type", &self.entry_type)
            .field("source_event_at", &self.source_event_at)
            .field("request_id", &self.request_id)
            .field("source_event_id", &self.source_event_id)
            .field("target_secret_id", &self.target_secret_id)
            .field("target_secret_version_id", &self.target_secret_version_id)
            .field("actor_user_id", &self.actor_user_id)
            .field("actor_device_id", &self.actor_device_id)
            .field("result", &self.result)
            .field("error_code", &self.error_code)
            .field("payload", &self.payload)
            .field("previous_entry_hash", &self.previous_entry_hash)
            .field("signature_key_version", &self.signature_key_version)
            .finish()
    }
}

pub struct LedgerEntryDraftParts {
    pub ledger_entry_id: LedgerEntryId,
    pub sequence_no: LedgerSequenceNo,
    pub entry_type: LedgerEntryType,
    pub source_event_at: SourceEventAt,
    pub request_id: RequestId,
    pub source_event_id: Option<AuditEventId>,
    pub target_secret_id: Option<SecretId>,
    pub target_secret_version_id: Option<LedgerTargetSecretVersionId>,
    pub actor_user_id: Option<OwnerUserId>,
    pub actor_device_id: Option<DeviceId>,
    pub result: LedgerResult,
    pub error_code: Option<String>,
    pub payload: LedgerPayload,
    pub previous_entry_hash: LedgerHash,
    pub signature_key_version: LedgerSignatureKeyVersion,
}

#[derive(Clone)]
pub struct SignedLedgerEntry {
    ledger_entry_id: LedgerEntryId,
    sequence_no: LedgerSequenceNo,
    entry_type: LedgerEntryType,
    source_event_at: SourceEventAt,
    request_id: RequestId,
    source_event_id: Option<AuditEventId>,
    target_secret_id: Option<SecretId>,
    target_secret_version_id: Option<LedgerTargetSecretVersionId>,
    actor_user_id: Option<OwnerUserId>,
    actor_device_id: Option<DeviceId>,
    result: LedgerResult,
    error_code: Option<String>,
    payload: LedgerPayload,
    canonical_payload: LedgerCanonicalPayload,
    previous_entry_hash: LedgerHash,
    entry_hash: LedgerHash,
    signature: LedgerSignature,
    signature_key_version: LedgerSignatureKeyVersion,
}

impl SignedLedgerEntry {
    pub fn from_stored_parts(parts: SignedLedgerEntryParts) -> Result<Self, LedgerError> {
        if parts.payload.entry_type() != parts.entry_type {
            return Err(LedgerError::UnknownPayloadKey {
                key: "payload.entry_type".to_owned(),
                entry_type: parts.entry_type,
            });
        }

        validate_error_code(parts.result, parts.error_code.as_deref(), "error_code")?;
        validate_actor_device_id(parts.actor_device_id.as_ref())?;

        let canonical_payload = build_canonical_payload(CanonicalBuildFields {
            sequence_no: parts.sequence_no,
            entry_type: parts.entry_type,
            source_event_at: &parts.source_event_at,
            request_id: &parts.request_id,
            source_event_id: parts.source_event_id.as_ref(),
            target_secret_id: parts.target_secret_id.as_ref(),
            target_secret_version_id: parts.target_secret_version_id.as_ref(),
            actor_user_id: parts.actor_user_id.as_ref(),
            actor_device_id: parts.actor_device_id.as_ref(),
            result: parts.result,
            error_code: parts.error_code.as_deref(),
            payload: &parts.payload,
            previous_entry_hash: parts.previous_entry_hash,
            signature_key_version: parts.signature_key_version,
        })?;

        Ok(Self {
            ledger_entry_id: parts.ledger_entry_id,
            sequence_no: parts.sequence_no,
            entry_type: parts.entry_type,
            source_event_at: parts.source_event_at,
            request_id: parts.request_id,
            source_event_id: parts.source_event_id,
            target_secret_id: parts.target_secret_id,
            target_secret_version_id: parts.target_secret_version_id,
            actor_user_id: parts.actor_user_id,
            actor_device_id: parts.actor_device_id,
            result: parts.result,
            error_code: parts.error_code,
            payload: parts.payload,
            canonical_payload,
            previous_entry_hash: parts.previous_entry_hash,
            entry_hash: parts.entry_hash,
            signature: parts.signature,
            signature_key_version: parts.signature_key_version,
        })
    }

    pub fn ledger_entry_id(&self) -> &LedgerEntryId {
        &self.ledger_entry_id
    }

    pub fn sequence_no(&self) -> LedgerSequenceNo {
        self.sequence_no
    }

    pub fn entry_type(&self) -> LedgerEntryType {
        self.entry_type
    }

    pub fn source_event_at(&self) -> &SourceEventAt {
        &self.source_event_at
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn source_event_id(&self) -> Option<&AuditEventId> {
        self.source_event_id.as_ref()
    }

    pub fn target_secret_id(&self) -> Option<&SecretId> {
        self.target_secret_id.as_ref()
    }

    pub fn target_secret_version_id(&self) -> Option<&LedgerTargetSecretVersionId> {
        self.target_secret_version_id.as_ref()
    }

    pub fn actor_user_id(&self) -> Option<&OwnerUserId> {
        self.actor_user_id.as_ref()
    }

    pub fn actor_device_id(&self) -> Option<&DeviceId> {
        self.actor_device_id.as_ref()
    }

    pub fn result(&self) -> LedgerResult {
        self.result
    }

    pub fn error_code(&self) -> Option<&str> {
        self.error_code.as_deref()
    }

    pub fn payload(&self) -> &LedgerPayload {
        &self.payload
    }

    pub fn canonical_payload(&self) -> &LedgerCanonicalPayload {
        &self.canonical_payload
    }

    pub fn previous_entry_hash(&self) -> LedgerHash {
        self.previous_entry_hash
    }

    pub fn entry_hash(&self) -> LedgerHash {
        self.entry_hash
    }

    pub fn signature(&self) -> LedgerSignature {
        self.signature
    }

    pub fn signature_key_version(&self) -> LedgerSignatureKeyVersion {
        self.signature_key_version
    }

    pub fn recompute_entry_hash(&self) -> LedgerHash {
        LedgerHash::from_canonical_payload(&self.canonical_payload)
    }

    pub fn verify_signature(&self, key: &LedgerVerifyingKey) -> Result<(), LedgerError> {
        key.verify_payload(
            self.signature_key_version,
            &self.canonical_payload,
            &self.signature,
        )
    }
}

impl fmt::Debug for SignedLedgerEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedLedgerEntry")
            .field("ledger_entry_id", &self.ledger_entry_id)
            .field("sequence_no", &self.sequence_no)
            .field("entry_type", &self.entry_type)
            .field("source_event_at", &self.source_event_at)
            .field("request_id", &self.request_id)
            .field("source_event_id", &self.source_event_id)
            .field("target_secret_id", &self.target_secret_id)
            .field("target_secret_version_id", &self.target_secret_version_id)
            .field("actor_user_id", &self.actor_user_id)
            .field("actor_device_id", &self.actor_device_id)
            .field("result", &self.result)
            .field("error_code", &self.error_code)
            .field("payload", &self.payload)
            .field("canonical_payload", &self.canonical_payload)
            .field("previous_entry_hash", &self.previous_entry_hash)
            .field("entry_hash", &self.entry_hash)
            .field("signature", &self.signature)
            .field("signature_key_version", &self.signature_key_version)
            .finish()
    }
}

pub struct SignedLedgerEntryParts {
    pub ledger_entry_id: LedgerEntryId,
    pub sequence_no: LedgerSequenceNo,
    pub entry_type: LedgerEntryType,
    pub source_event_at: SourceEventAt,
    pub request_id: RequestId,
    pub source_event_id: Option<AuditEventId>,
    pub target_secret_id: Option<SecretId>,
    pub target_secret_version_id: Option<LedgerTargetSecretVersionId>,
    pub actor_user_id: Option<OwnerUserId>,
    pub actor_device_id: Option<DeviceId>,
    pub result: LedgerResult,
    pub error_code: Option<String>,
    pub payload: LedgerPayload,
    pub previous_entry_hash: LedgerHash,
    pub entry_hash: LedgerHash,
    pub signature: LedgerSignature,
    pub signature_key_version: LedgerSignatureKeyVersion,
}

fn validate_error_code(
    result: LedgerResult,
    error_code: Option<&str>,
    field: &'static str,
) -> Result<(), LedgerError> {
    if result == LedgerResult::Success && error_code.is_some() {
        return Err(LedgerError::InvalidErrorCode { field });
    }

    if let Some(value) = error_code
        && (value.trim().is_empty() || value.len() > 128)
    {
        return Err(LedgerError::InvalidErrorCode { field });
    }

    Ok(())
}

fn validate_actor_device_id(actor_device_id: Option<&DeviceId>) -> Result<(), LedgerError> {
    if actor_device_id.is_some_and(|device_id| device_id.as_str().len() > 128) {
        return Err(LedgerError::InvalidActorDeviceId);
    }

    Ok(())
}

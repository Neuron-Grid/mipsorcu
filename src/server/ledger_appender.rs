use std::fmt;
use std::sync::Arc;

use crate::audit::{AuditEventId, RequestId};
use crate::ledger::{
    LedgerChainHead, LedgerEntryDraft, LedgerEntryDraftParts, LedgerEntryId, LedgerEntryType,
    LedgerError, LedgerHash, LedgerPayload, LedgerResult, LedgerSequenceNo, LedgerSignature,
    LedgerSignatureKeyVersion, LedgerSigningKey, LedgerTargetSecretVersionId, SignedLedgerEntry,
};
use crate::server::supabase::{SupabaseClient, SupabaseRpcError, classify_append_ledger_error};
use crate::types::supabase::{AppendLedgerEntryOutcome, LedgerAppendRpcFailure};
use crate::types::{DeviceId, OwnerUserId, SecretId, SourceEventAt};

const DEFAULT_MAX_CONFLICT_RETRIES: u8 = 1;
const MAX_CONFLICT_RETRIES: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerAppenderConfig {
    max_conflict_retries: u8,
}

impl LedgerAppenderConfig {
    pub fn new(max_conflict_retries: u8) -> Self {
        Self {
            max_conflict_retries: max_conflict_retries.min(MAX_CONFLICT_RETRIES),
        }
    }

    pub fn max_conflict_retries(self) -> u8 {
        self.max_conflict_retries
    }
}

impl Default for LedgerAppenderConfig {
    fn default() -> Self {
        Self {
            max_conflict_retries: DEFAULT_MAX_CONFLICT_RETRIES,
        }
    }
}

pub struct LedgerAppender {
    client: Arc<SupabaseClient>,
    signing_key: LedgerSigningKey,
    config: LedgerAppenderConfig,
}

impl LedgerAppender {
    pub fn new(client: Arc<SupabaseClient>, signing_key: LedgerSigningKey) -> Self {
        Self::with_config(client, signing_key, LedgerAppenderConfig::default())
    }

    pub fn with_config(
        client: Arc<SupabaseClient>,
        signing_key: LedgerSigningKey,
        config: LedgerAppenderConfig,
    ) -> Self {
        Self {
            client,
            signing_key,
            config,
        }
    }

    /// 現在の署名鍵バージョンを返す。
    pub fn signing_key_version(&self) -> LedgerSignatureKeyVersion {
        self.signing_key.key_version()
    }

    /// digest canonical bytes（任意の &[u8]）に対して Ed25519 署名を生成する。
    ///
    /// 既存の `LedgerSigningKey` を再利用して digest bytes に署名する。
    /// ledger entry canonical payload への署名とは別の操作。
    pub fn sign_digest_bytes(&self, bytes: &[u8]) -> Result<LedgerSignature, LedgerError> {
        self.signing_key
            .sign_raw_bytes(self.signing_key.key_version(), bytes)
    }

    pub async fn append(
        &self,
        draft: &LedgerAppendDraft,
    ) -> Result<AppendLedgerEntryOutcome, LedgerAppendError> {
        let max_conflict_retries = self.config.max_conflict_retries();

        for retry_index in 0..=max_conflict_retries {
            let attempts = u32::from(retry_index) + 1;
            let chain_head = self.fetch_chain_head(attempts).await?;
            let signed_entry = draft
                .sign_with_chain_head(chain_head, &self.signing_key)
                .map_err(|_| LedgerAppendError::InvalidEntry {
                    code: "ledger_entry_build_failed",
                })?;

            match self.client.call_append_ledger_entry(&signed_entry).await {
                Ok(outcome) => return Ok(outcome),
                Err(error) => {
                    let failure = classify_append_ledger_error(&error);
                    if is_retryable_conflict(failure) && retry_index < max_conflict_retries {
                        continue;
                    }

                    return Err(classify_appender_error(failure, &error, attempts));
                }
            }
        }

        Err(LedgerAppendError::ExternalDependencyFailed {
            code: "ledger_append_retry_exhausted",
            upstream_status: None,
            attempts: u32::from(max_conflict_retries) + 1,
        })
    }

    pub async fn sign_entries(
        &self,
        drafts: &[LedgerAppendDraft],
    ) -> Result<Vec<SignedLedgerEntry>, LedgerAppendError> {
        let chain_head = self.fetch_chain_head(1).await?;
        self.sign_entries_from_head(drafts, chain_head)
    }

    pub fn sign_entries_from_head(
        &self,
        drafts: &[LedgerAppendDraft],
        chain_head: LedgerChainHead,
    ) -> Result<Vec<SignedLedgerEntry>, LedgerAppendError> {
        let mut previous_sequence_no = chain_head.last_sequence_no();
        let mut previous_hash = chain_head.last_entry_hash();
        let mut signed_entries = Vec::with_capacity(drafts.len());

        for draft in drafts {
            let next_sequence_no =
                previous_sequence_no
                    .checked_add(1)
                    .ok_or(LedgerAppendError::InvalidEntry {
                        code: "ledger_sequence_overflow",
                    })?;
            let sequence_no = LedgerSequenceNo::new(next_sequence_no).map_err(|_| {
                LedgerAppendError::InvalidEntry {
                    code: "ledger_entry_build_failed",
                }
            })?;
            let signed_entry = draft
                .sign_with_sequence(sequence_no, previous_hash, &self.signing_key)
                .map_err(|_| LedgerAppendError::InvalidEntry {
                    code: "ledger_entry_build_failed",
                })?;

            previous_sequence_no = signed_entry.sequence_no().get();
            previous_hash = signed_entry.entry_hash();
            signed_entries.push(signed_entry);
        }

        Ok(signed_entries)
    }

    async fn fetch_chain_head(&self, attempts: u32) -> Result<LedgerChainHead, LedgerAppendError> {
        self.client
            .fetch_ledger_chain_head()
            .await
            .map_err(|error| LedgerAppendError::ExternalDependencyFailed {
                code: "ledger_chain_head_fetch_failed",
                upstream_status: error.upstream_status(),
                attempts,
            })
    }
}

impl fmt::Debug for LedgerAppender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerAppender")
            .field("client", &self.client)
            .field("signing_key", &self.signing_key)
            .field("config", &self.config)
            .finish()
    }
}

#[derive(Clone)]
pub struct LedgerAppendDraft {
    ledger_entry_id: LedgerEntryId,
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
}

impl LedgerAppendDraft {
    pub fn new(parts: LedgerAppendDraftParts) -> Result<Self, LedgerError> {
        if parts.payload.entry_type() != parts.entry_type {
            return Err(LedgerError::UnknownPayloadKey {
                key: "payload.entry_type".to_owned(),
                entry_type: parts.entry_type,
            });
        }

        Ok(Self {
            ledger_entry_id: parts.ledger_entry_id,
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
        })
    }

    pub fn ledger_entry_id(&self) -> &LedgerEntryId {
        &self.ledger_entry_id
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    fn sign_with_chain_head(
        &self,
        chain_head: LedgerChainHead,
        signing_key: &LedgerSigningKey,
    ) -> Result<crate::SignedLedgerEntry, LedgerError> {
        self.sign_with_sequence(
            chain_head.next_sequence_no()?,
            chain_head.last_entry_hash(),
            signing_key,
        )
    }

    fn sign_with_sequence(
        &self,
        sequence_no: LedgerSequenceNo,
        previous_entry_hash: LedgerHash,
        signing_key: &LedgerSigningKey,
    ) -> Result<crate::SignedLedgerEntry, LedgerError> {
        let draft = LedgerEntryDraft::new(LedgerEntryDraftParts {
            ledger_entry_id: self.ledger_entry_id.clone(),
            sequence_no,
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
            previous_entry_hash,
            signature_key_version: signing_key.key_version(),
        })?;

        draft.sign(signing_key)
    }
}

impl fmt::Debug for LedgerAppendDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerAppendDraft")
            .field("ledger_entry_id", &self.ledger_entry_id)
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
            .finish()
    }
}

pub struct LedgerAppendDraftParts {
    pub ledger_entry_id: LedgerEntryId,
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
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LedgerAppendError {
    Conflict {
        failure: LedgerAppendRpcFailure,
        attempts: u32,
    },
    InvalidEntry {
        code: &'static str,
    },
    ExternalDependencyFailed {
        code: &'static str,
        upstream_status: Option<u16>,
        attempts: u32,
    },
}

impl LedgerAppendError {
    pub fn as_error_code(self) -> &'static str {
        match self {
            Self::Conflict { failure, .. } => failure.as_error_code(),
            Self::InvalidEntry { code } | Self::ExternalDependencyFailed { code, .. } => code,
        }
    }

    pub fn attempts(self) -> Option<u32> {
        match self {
            Self::Conflict { attempts, .. } | Self::ExternalDependencyFailed { attempts, .. } => {
                Some(attempts)
            }
            Self::InvalidEntry { .. } => None,
        }
    }

    pub fn upstream_status(self) -> Option<u16> {
        match self {
            Self::ExternalDependencyFailed {
                upstream_status, ..
            } => upstream_status,
            Self::Conflict { .. } | Self::InvalidEntry { .. } => None,
        }
    }
}

impl fmt::Debug for LedgerAppendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict { failure, attempts } => formatter
                .debug_struct("Conflict")
                .field("failure", failure)
                .field("attempts", attempts)
                .finish(),
            Self::InvalidEntry { code } => formatter
                .debug_struct("InvalidEntry")
                .field("code", code)
                .finish(),
            Self::ExternalDependencyFailed {
                code,
                upstream_status,
                attempts,
            } => formatter
                .debug_struct("ExternalDependencyFailed")
                .field("code", code)
                .field("upstream_status", upstream_status)
                .field("attempts", attempts)
                .finish(),
        }
    }
}

impl fmt::Display for LedgerAppendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict { failure, attempts } => write!(
                formatter,
                "ledger append conflict after {attempts} attempt(s): {}",
                failure.as_error_code()
            ),
            Self::InvalidEntry { code } => {
                write!(formatter, "ledger append invalid entry: {code}")
            }
            Self::ExternalDependencyFailed {
                code,
                upstream_status,
                attempts,
            } => match upstream_status {
                Some(status) => write!(
                    formatter,
                    "ledger append external dependency failed after {attempts} attempt(s): {code}, upstream status {status}"
                ),
                None => write!(
                    formatter,
                    "ledger append external dependency failed after {attempts} attempt(s): {code}"
                ),
            },
        }
    }
}

impl std::error::Error for LedgerAppendError {}

fn classify_appender_error(
    failure: LedgerAppendRpcFailure,
    upstream: &SupabaseRpcError,
    attempts: u32,
) -> LedgerAppendError {
    match failure {
        LedgerAppendRpcFailure::EntryIdConflict
        | LedgerAppendRpcFailure::EntryHashConflict
        | LedgerAppendRpcFailure::MonthlyDigestDuplicate
        | LedgerAppendRpcFailure::SequenceMismatch
        | LedgerAppendRpcFailure::PreviousHashMismatch => {
            LedgerAppendError::Conflict { failure, attempts }
        }
        LedgerAppendRpcFailure::PayloadSchemaViolation
        | LedgerAppendRpcFailure::InvalidRpcInput => LedgerAppendError::InvalidEntry {
            code: failure.as_error_code(),
        },
        LedgerAppendRpcFailure::ChainStateMissing | LedgerAppendRpcFailure::AppendFailed => {
            LedgerAppendError::ExternalDependencyFailed {
                code: failure.as_error_code(),
                upstream_status: upstream.upstream_status(),
                attempts,
            }
        }
    }
}

fn is_retryable_conflict(failure: LedgerAppendRpcFailure) -> bool {
    matches!(
        failure,
        LedgerAppendRpcFailure::SequenceMismatch | LedgerAppendRpcFailure::PreviousHashMismatch
    )
}

use serde_json::{Map, Value};

use crate::ledger::LedgerSignatureKeyVersion;
use crate::types::SourceEventAt;

use super::super::{AuditEventError, AuditMetadata, SOURCE_EVENT_AT_KEY};

/// `signature_key_created` action metadata builder.
#[derive(Debug, Clone)]
pub struct SignatureKeyCreatedMetadata {
    signature_key_version: LedgerSignatureKeyVersion,
    public_key_fingerprint: String,
    created_at: SourceEventAt,
    source_event_at: SourceEventAt,
}

impl SignatureKeyCreatedMetadata {
    pub fn new(
        signature_key_version: LedgerSignatureKeyVersion,
        public_key_fingerprint: impl Into<String>,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            signature_key_version,
            public_key_fingerprint: public_key_fingerprint.into(),
            created_at: source_event_at.clone(),
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "signature_key_version".to_owned(),
            Value::Number(self.signature_key_version.get().into()),
        );
        object.insert(
            "public_key_fingerprint".to_owned(),
            Value::String(self.public_key_fingerprint),
        );
        object.insert(
            "created_at".to_owned(),
            Value::String(self.created_at.as_str().to_owned()),
        );
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::new(Value::Object(object))
    }
}

/// `signature_key_activated` action metadata builder.
#[derive(Debug, Clone)]
pub struct SignatureKeyActivatedMetadata {
    signature_key_version: LedgerSignatureKeyVersion,
    public_key_fingerprint: String,
    activated_at: SourceEventAt,
    source_event_at: SourceEventAt,
}

impl SignatureKeyActivatedMetadata {
    pub fn new(
        signature_key_version: LedgerSignatureKeyVersion,
        public_key_fingerprint: impl Into<String>,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            signature_key_version,
            public_key_fingerprint: public_key_fingerprint.into(),
            activated_at: source_event_at.clone(),
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "signature_key_version".to_owned(),
            Value::Number(self.signature_key_version.get().into()),
        );
        object.insert(
            "public_key_fingerprint".to_owned(),
            Value::String(self.public_key_fingerprint),
        );
        object.insert(
            "activated_at".to_owned(),
            Value::String(self.activated_at.as_str().to_owned()),
        );
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::new(Value::Object(object))
    }
}

/// `signature_key_retired` action metadata builder.
#[derive(Debug, Clone)]
pub struct SignatureKeyRetiredMetadata {
    signature_key_version: LedgerSignatureKeyVersion,
    public_key_fingerprint: String,
    retired_at: SourceEventAt,
    source_event_at: SourceEventAt,
}

impl SignatureKeyRetiredMetadata {
    pub fn new(
        signature_key_version: LedgerSignatureKeyVersion,
        public_key_fingerprint: impl Into<String>,
        source_event_at: SourceEventAt,
    ) -> Self {
        Self {
            signature_key_version,
            public_key_fingerprint: public_key_fingerprint.into(),
            retired_at: source_event_at.clone(),
            source_event_at,
        }
    }

    pub fn build(self) -> Result<AuditMetadata, AuditEventError> {
        let mut object = Map::new();
        object.insert(
            "signature_key_version".to_owned(),
            Value::Number(self.signature_key_version.get().into()),
        );
        object.insert(
            "public_key_fingerprint".to_owned(),
            Value::String(self.public_key_fingerprint),
        );
        object.insert(
            "retired_at".to_owned(),
            Value::String(self.retired_at.as_str().to_owned()),
        );
        object.insert(
            SOURCE_EVENT_AT_KEY.to_owned(),
            Value::String(self.source_event_at.as_str().to_owned()),
        );
        AuditMetadata::new(Value::Object(object))
    }
}

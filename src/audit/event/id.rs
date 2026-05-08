use uuid::{Builder, Uuid};

use super::super::error::AuditEventError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditEventId(Uuid);

impl AuditEventId {
    pub fn generate() -> Result<Self, AuditEventError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| AuditEventError::InvalidUuid {
            field: "audit_event_id",
        })?;
        let uuid = Builder::from_random_bytes(bytes).into_uuid();

        Ok(Self(uuid))
    }

    pub fn parse(value: &str) -> Result<Self, AuditEventError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| AuditEventError::InvalidUuid {
                field: "audit_event_id",
            })
    }

    pub fn as_canonical_string(&self) -> String {
        self.0.hyphenated().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestId(Uuid);

impl RequestId {
    pub fn generate() -> Result<Self, AuditEventError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| AuditEventError::InvalidUuid {
            field: "request_id",
        })?;
        let uuid = Builder::from_random_bytes(bytes).into_uuid();

        Ok(Self(uuid))
    }

    pub fn nil() -> Self {
        Self(Uuid::nil())
    }

    pub fn parse(value: &str) -> Result<Self, AuditEventError> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(|_| AuditEventError::InvalidUuid {
                field: "request_id",
            })
    }

    pub fn as_canonical_string(&self) -> String {
        self.0.hyphenated().to_string()
    }
}

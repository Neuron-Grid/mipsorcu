use std::fmt;

use crate::error::JwtVerificationError;
use crate::types::OwnerUserId;

#[derive(Clone, PartialEq, Eq)]
pub struct RawJwt(String);

impl RawJwt {
    pub fn new(value: &str) -> Result<Self, JwtVerificationError> {
        if value.trim().is_empty() {
            return Err(JwtVerificationError::EmptyToken);
        }

        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RawJwt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawJwt")
            .field("len", &self.0.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedJwtClaims {
    subject_user_id: OwnerUserId,
    issuer: String,
    audience: String,
    expires_at: u64,
}

impl VerifiedJwtClaims {
    pub fn from_verified_subject(owner_user_id: OwnerUserId) -> Self {
        Self {
            subject_user_id: owner_user_id,
            issuer: String::new(),
            audience: String::new(),
            expires_at: 0,
        }
    }

    pub(crate) fn new(
        subject_user_id: OwnerUserId,
        issuer: String,
        audience: String,
        expires_at: u64,
    ) -> Self {
        Self {
            subject_user_id,
            issuer,
            audience,
            expires_at,
        }
    }

    pub fn subject_user_id(&self) -> &OwnerUserId {
        &self.subject_user_id
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

impl fmt::Debug for VerifiedJwtClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedJwtClaims")
            .field("subject_user_id", &self.subject_user_id)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Validation, decode, decode_header};
use serde::Deserialize;

use crate::error::JwtVerificationError;
use crate::types::OwnerUserId;

use super::jwks::{Jwks, JwksCache, SUPPORTED_JWT_ALGORITHM};
use super::jwt::{RawJwt, VerifiedJwtClaims};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtVerifierConfig {
    issuer: String,
    audience: String,
    leeway_seconds: u64,
}

impl JwtVerifierConfig {
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, JwtVerificationError> {
        Self::with_leeway_seconds(issuer, audience, 0)
    }

    pub fn with_leeway_seconds(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        leeway_seconds: u64,
    ) -> Result<Self, JwtVerificationError> {
        let issuer = issuer.into();
        let audience = audience.into();

        if issuer.trim().is_empty() || audience.trim().is_empty() {
            return Err(JwtVerificationError::MalformedClaims);
        }

        Ok(Self {
            issuer,
            audience,
            leeway_seconds,
        })
    }
}

#[derive(Debug, Clone)]
pub struct JwtVerifier {
    config: JwtVerifierConfig,
    jwks_cache: JwksCache,
}

impl JwtVerifier {
    pub fn new(config: JwtVerifierConfig, jwks: Jwks) -> Self {
        Self::with_cache(config, JwksCache::new(jwks))
    }

    pub fn with_cache(config: JwtVerifierConfig, jwks_cache: JwksCache) -> Self {
        Self { config, jwks_cache }
    }

    pub fn jwks_cache(&self) -> JwksCache {
        self.jwks_cache.clone()
    }

    pub fn verify(&self, raw_jwt: &RawJwt) -> Result<VerifiedJwtClaims, JwtVerificationError> {
        let header = decode_header(raw_jwt.as_str()).map_err(map_jwt_error)?;

        if header.alg != SUPPORTED_JWT_ALGORITHM {
            return Err(JwtVerificationError::UnsupportedAlgorithm);
        }

        let key_id = header.kid.ok_or(JwtVerificationError::MissingKeyId)?;
        let jwks = self.jwks_cache.snapshot()?;
        let jwk = jwks.find_signing_key(&key_id)?;
        let decoding_key = jwk.decoding_key()?;
        let mut validation = Validation::new(SUPPORTED_JWT_ALGORITHM);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.leeway = self.config.leeway_seconds;

        let token = decode::<RegisteredJwtClaims>(raw_jwt.as_str(), &decoding_key, &validation)
            .map_err(map_jwt_error)?;

        let subject_user_id = OwnerUserId::parse(&token.claims.sub)
            .map_err(|_| JwtVerificationError::InvalidSubject)?;

        Ok(VerifiedJwtClaims::new(
            subject_user_id,
            token.claims.iss,
            token.claims.aud,
            token.claims.exp,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RegisteredJwtClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
}

fn map_jwt_error(error: jsonwebtoken::errors::Error) -> JwtVerificationError {
    match error.kind() {
        ErrorKind::InvalidSignature => JwtVerificationError::InvalidSignature,
        ErrorKind::ExpiredSignature => JwtVerificationError::Expired,
        ErrorKind::InvalidIssuer => JwtVerificationError::InvalidIssuer,
        ErrorKind::InvalidAudience => JwtVerificationError::InvalidAudience,
        ErrorKind::InvalidAlgorithm => JwtVerificationError::UnsupportedAlgorithm,
        ErrorKind::Json(_) => JwtVerificationError::MalformedClaims,
        _ => JwtVerificationError::InvalidToken,
    }
}

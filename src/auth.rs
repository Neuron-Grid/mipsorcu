use std::fmt;

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

use crate::error::JwtVerificationError;
use crate::types::OwnerUserId;

const SUPPORTED_JWT_ALGORITHM: Algorithm = Algorithm::RS256;
const SUPPORTED_JWT_ALGORITHM_NAME: &str = "RS256";

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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

impl Jwks {
    pub fn new(keys: Vec<Jwk>) -> Result<Self, JwtVerificationError> {
        if keys.is_empty() {
            return Err(JwtVerificationError::InvalidJwks);
        }

        Ok(Self { keys })
    }

    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }

    fn find_signing_key(&self, key_id: &str) -> Result<&Jwk, JwtVerificationError> {
        self.keys
            .iter()
            .find(|key| key.kid == key_id)
            .ok_or(JwtVerificationError::KeyNotFound)
            .and_then(|key| {
                key.validate_for_rs256()?;
                Ok(key)
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Jwk {
    kty: String,
    kid: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    public_key_use: Option<String>,
    n: String,
    e: String,
}

impl Jwk {
    pub fn new(
        kty: impl Into<String>,
        kid: impl Into<String>,
        alg: Option<String>,
        public_key_use: Option<String>,
        n: impl Into<String>,
        e: impl Into<String>,
    ) -> Self {
        Self {
            kty: kty.into(),
            kid: kid.into(),
            alg,
            public_key_use,
            n: n.into(),
            e: e.into(),
        }
    }

    pub fn key_id(&self) -> &str {
        &self.kid
    }

    fn validate_for_rs256(&self) -> Result<(), JwtVerificationError> {
        if self.kty != "RSA" {
            return Err(JwtVerificationError::InvalidJwks);
        }

        if self
            .public_key_use
            .as_deref()
            .is_some_and(|value| value != "sig")
        {
            return Err(JwtVerificationError::InvalidJwks);
        }

        if self
            .alg
            .as_deref()
            .is_some_and(|value| value != SUPPORTED_JWT_ALGORITHM_NAME)
        {
            return Err(JwtVerificationError::UnsupportedAlgorithm);
        }

        if self.kid.trim().is_empty() || self.n.trim().is_empty() || self.e.trim().is_empty() {
            return Err(JwtVerificationError::InvalidJwks);
        }

        Ok(())
    }

    fn decoding_key(&self) -> Result<DecodingKey, JwtVerificationError> {
        DecodingKey::from_rsa_components(&self.n, &self.e)
            .map_err(|_| JwtVerificationError::InvalidJwks)
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtVerifier {
    config: JwtVerifierConfig,
    jwks: Jwks,
}

impl JwtVerifier {
    pub fn new(config: JwtVerifierConfig, jwks: Jwks) -> Self {
        Self { config, jwks }
    }

    pub fn verify(&self, raw_jwt: &RawJwt) -> Result<VerifiedJwtClaims, JwtVerificationError> {
        let header = decode_header(raw_jwt.as_str()).map_err(map_jwt_error)?;

        if header.alg != SUPPORTED_JWT_ALGORITHM {
            return Err(JwtVerificationError::UnsupportedAlgorithm);
        }

        let key_id = header.kid.ok_or(JwtVerificationError::MissingKeyId)?;
        let jwk = self.jwks.find_signing_key(&key_id)?;
        let decoding_key = jwk.decoding_key()?;
        let mut validation = Validation::new(SUPPORTED_JWT_ALGORITHM);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.leeway = self.config.leeway_seconds;

        let token = decode::<RegisteredJwtClaims>(raw_jwt.as_str(), &decoding_key, &validation)
            .map_err(map_jwt_error)?;

        let subject_user_id = OwnerUserId::parse(&token.claims.sub)
            .map_err(|_| JwtVerificationError::InvalidSubject)?;

        Ok(VerifiedJwtClaims {
            subject_user_id,
            issuer: token.claims.iss,
            audience: token.claims.aud,
            expires_at: token.claims.exp,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RegisteredJwtClaims {
    sub: String,
    iss: String,
    aud: String,
    exp: u64,
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

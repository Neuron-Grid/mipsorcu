use std::fmt;
use std::sync::{Arc, RwLock};

use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;

use crate::error::JwtVerificationError;

pub(super) const SUPPORTED_JWT_ALGORITHM: Algorithm = Algorithm::RS256;
const SUPPORTED_JWT_ALGORITHM_NAME: &str = "RS256";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

impl Jwks {
    pub fn new(keys: Vec<Jwk>) -> Result<Self, JwtVerificationError> {
        if keys.is_empty() {
            return Err(JwtVerificationError::InvalidJwks);
        }

        for key in &keys {
            key.validate_for_rs256()?;
        }

        Ok(Self { keys })
    }

    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }

    pub(super) fn find_signing_key(&self, key_id: &str) -> Result<&Jwk, JwtVerificationError> {
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

#[derive(Clone)]
pub struct JwksCache {
    inner: Arc<RwLock<Jwks>>,
}

impl JwksCache {
    pub fn new(jwks: Jwks) -> Self {
        Self {
            inner: Arc::new(RwLock::new(jwks)),
        }
    }

    pub fn snapshot(&self) -> Result<Jwks, JwtVerificationError> {
        self.inner
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| JwtVerificationError::InvalidJwks)
    }

    pub fn replace(&self, jwks: Jwks) -> Result<(), JwtVerificationError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| JwtVerificationError::InvalidJwks)?;
        *guard = jwks;
        Ok(())
    }
}

impl fmt::Debug for JwksCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.snapshot() {
            Ok(jwks) => formatter
                .debug_struct("JwksCache")
                .field("key_count", &jwks.keys().len())
                .finish(),
            Err(_) => formatter
                .debug_struct("JwksCache")
                .field("state", &"unavailable")
                .finish(),
        }
    }
}

#[derive(Debug)]
pub enum JwksFetchError {
    Network(reqwest::Error),
    NonSuccessStatus { status: u16 },
    InvalidResponse(String),
    InvalidJwks(JwtVerificationError),
}

impl fmt::Display for JwksFetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(error) => write!(formatter, "jwks fetch network error: {error}"),
            Self::NonSuccessStatus { status } => {
                write!(formatter, "jwks endpoint returned status {status}")
            }
            Self::InvalidResponse(message) => {
                write!(
                    formatter,
                    "jwks endpoint returned invalid response: {message}"
                )
            }
            Self::InvalidJwks(error) => write!(formatter, "jwks validation failed: {error}"),
        }
    }
}

impl std::error::Error for JwksFetchError {}

pub async fn fetch_jwks(
    http_client: &reqwest::Client,
    jwks_url: &str,
) -> Result<Jwks, JwksFetchError> {
    let response = http_client
        .get(jwks_url)
        .send()
        .await
        .map_err(JwksFetchError::Network)?;
    let status = response.status();

    if !status.is_success() {
        return Err(JwksFetchError::NonSuccessStatus {
            status: status.as_u16(),
        });
    }

    let jwks = response
        .json::<Jwks>()
        .await
        .map_err(|error| JwksFetchError::InvalidResponse(error.to_string()))?;

    Jwks::new(jwks.keys).map_err(JwksFetchError::InvalidJwks)
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

    pub(super) fn validate_for_rs256(&self) -> Result<(), JwtVerificationError> {
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

    pub(super) fn decoding_key(&self) -> Result<DecodingKey, JwtVerificationError> {
        DecodingKey::from_rsa_components(&self.n, &self.e)
            .map_err(|_| JwtVerificationError::InvalidJwks)
    }
}

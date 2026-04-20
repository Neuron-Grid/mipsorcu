use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use http::header::AUTHORIZATION;
use std::fmt;

use crate::auth::{RawJwt, VerifiedJwtClaims};

use super::errors::ApiError;
use super::state::AppState;

const BEARER_PREFIX: &str = "Bearer ";

pub struct AuthenticatedUser {
    pub claims: VerifiedJwtClaims,
    pub raw_jwt: RawJwt,
}

impl fmt::Debug for AuthenticatedUser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedUser")
            .field("claims", &self.claims)
            .field("raw_jwt", &self.raw_jwt)
            .finish()
    }
}

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let raw_jwt = parse_bearer_token(parts)?;
        let claims = state.jwt_verifier.verify(&raw_jwt)?;

        Ok(Self { claims, raw_jwt })
    }
}

fn parse_bearer_token(parts: &Parts) -> Result<RawJwt, ApiError> {
    let header_value = parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("missing authorization header".to_owned()))?;

    let token = header_value
        .strip_prefix(BEARER_PREFIX)
        .ok_or_else(|| ApiError::Unauthorized("invalid authorization scheme".to_owned()))?;

    RawJwt::new(token).map_err(ApiError::from)
}

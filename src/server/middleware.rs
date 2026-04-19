use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use http::header::AUTHORIZATION;

use mipsorcu::auth::{RawJwt, VerifiedJwtClaims};

use super::errors::ApiError;
use super::state::AppState;

const BEARER_PREFIX: &str = "Bearer ";

pub struct AuthenticatedUser(pub VerifiedJwtClaims);

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header_value = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError::Unauthorized("missing authorization header".to_owned()))?;

        let token = header_value
            .strip_prefix(BEARER_PREFIX)
            .ok_or_else(|| ApiError::Unauthorized("invalid authorization scheme".to_owned()))?;

        let raw_jwt = RawJwt::new(token)?;
        let claims = state.jwt_verifier.verify(&raw_jwt)?;

        Ok(Self(claims))
    }
}

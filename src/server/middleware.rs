use http::header::AUTHORIZATION;
use http::request::Parts;
use http::{Extensions, StatusCode};
use std::convert::Infallible;
use std::fmt;

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, FromRequestParts, Json, Request};
use axum::middleware::Next;
use axum::response::Response;
use serde::de::DeserializeOwned;

use crate::RequestId;
use crate::auth::{RawJwt, VerifiedJwtClaims};

use super::errors::{ApiError, RequestAwareApiError};
use super::state::AppState;

const BEARER_PREFIX: &str = "Bearer ";

#[derive(Debug, Clone)]
pub struct RequestContext {
    request_id: RequestId,
}

impl RequestContext {
    pub fn new(request_id: RequestId) -> Self {
        Self { request_id }
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn into_request_id(self) -> RequestId {
        self.request_id
    }
}

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

pub struct RequestJson<T>(pub T);

impl FromRequestParts<AppState> for RequestContext {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self {
            request_id: current_request_id(&parts.extensions),
        })
    }
}

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = RequestAwareApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let request_id = current_request_id(&parts.extensions);
        let raw_jwt =
            parse_bearer_token(parts).map_err(|error| error.with_request_id(&request_id))?;
        let claims = state
            .jwt_verifier
            .verify(&raw_jwt)
            .map_err(|error| ApiError::from(error).with_request_id(&request_id))?;

        Ok(Self { claims, raw_jwt })
    }
}

impl<S, T> FromRequest<S> for RequestJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = RequestAwareApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let request_id = current_request_id(req.extensions());
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|rejection| {
                json_rejection_to_api_error(rejection).with_request_id(&request_id)
            })?;

        Ok(Self(value))
    }
}

pub async fn attach_request_context(mut request: Request, next: Next) -> Response {
    let request_id = RequestId::generate().unwrap_or_else(|error| {
        tracing::error!(
            error = %error,
            error_code = "request_id_generation_failed",
            "failed to generate request id; using nil request id"
        );
        RequestId::nil()
    });
    request.extensions_mut().insert(request_id);

    next.run(request).await
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

fn current_request_id(extensions: &Extensions) -> RequestId {
    extensions
        .get::<RequestId>()
        .cloned()
        .unwrap_or_else(RequestId::nil)
}

fn json_rejection_to_api_error(rejection: JsonRejection) -> ApiError {
    match rejection.status() {
        StatusCode::UNSUPPORTED_MEDIA_TYPE => {
            ApiError::UnsupportedMediaType("unsupported media type".to_owned())
        }
        StatusCode::PAYLOAD_TOO_LARGE => ApiError::PayloadTooLarge("payload too large".to_owned()),
        _ => ApiError::BadRequest("invalid request body".to_owned()),
    }
}

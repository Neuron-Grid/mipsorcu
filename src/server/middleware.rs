use http::header::AUTHORIZATION;
use http::request::Parts;
use http::{Extensions, StatusCode};
use std::convert::Infallible;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, FromRequestParts, Json, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::RequestId;
use crate::audit::{AuditAction, AuditMetadata};
use crate::auth::{RawJwt, VerifiedJwtClaims};
use crate::server::audit_reporter::FailureAuditContext;

use super::errors::{ApiError, RequestAwareApiError};
use super::state::AppState;

const BEARER_PREFIX: &str = "Bearer ";
const HEALTH_PATH: &str = "/health";
const READY_PATH: &str = "/ready";

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

#[derive(Debug, Clone)]
pub struct RuntimeResilience {
    handler_timeout: Duration,
    rate_limiter: FixedWindowRateLimiter,
}

impl RuntimeResilience {
    pub fn new(
        handler_timeout: Duration,
        rate_limit_requests: u64,
        rate_limit_window: Duration,
    ) -> Self {
        Self {
            handler_timeout,
            rate_limiter: FixedWindowRateLimiter::new(rate_limit_requests, rate_limit_window),
        }
    }
}

#[derive(Debug, Clone)]
struct FixedWindowRateLimiter {
    inner: Arc<Mutex<FixedWindowRateLimiterState>>,
    max_requests: u64,
    window: Duration,
}

impl FixedWindowRateLimiter {
    fn new(max_requests: u64, window: Duration) -> Self {
        let now = Instant::now();
        Self {
            inner: Arc::new(Mutex::new(FixedWindowRateLimiterState {
                reset_at: now.checked_add(window).unwrap_or(now),
                remaining: max_requests,
            })),
            max_requests,
            window,
        }
    }

    fn try_acquire(&self) -> Result<bool, ()> {
        let now = Instant::now();
        let mut state = self.inner.lock().map_err(|_| ())?;

        if now >= state.reset_at {
            state.reset_at = now.checked_add(self.window).unwrap_or(now);
            state.remaining = self.max_requests;
        }

        if state.remaining == 0 {
            return Ok(false);
        }

        state.remaining = state.remaining.saturating_sub(1);
        Ok(true)
    }
}

#[derive(Debug)]
struct FixedWindowRateLimiterState {
    reset_at: Instant,
    remaining: u64,
}

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
        let raw_jwt = match parse_bearer_token(parts) {
            Ok(raw_jwt) => raw_jwt,
            Err(error) => {
                record_auth_failure(state, &request_id, error.audit_error_code()).await;
                return Err(error.into_api_error().with_request_id(&request_id));
            }
        };
        let claims = match state.jwt_verifier.verify(&raw_jwt) {
            Ok(claims) => claims,
            Err(error) => {
                record_auth_failure(state, &request_id, "jwt_verification_failed").await;
                return Err(ApiError::from(error).with_request_id(&request_id));
            }
        };

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

pub async fn enforce_runtime_resilience(
    State(runtime): State<RuntimeResilience>,
    request: Request,
    next: Next,
) -> Response {
    let request_id = current_request_id(request.extensions());
    let is_rate_limit_exempt = is_rate_limit_exempt_path(request.uri().path());

    if !is_rate_limit_exempt {
        match runtime.rate_limiter.try_acquire() {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    request_id = %request_id.as_canonical_string(),
                    error_code = "rate_limited",
                    "request rejected by process rate limit"
                );
                return ApiError::RateLimited
                    .with_request_id(&request_id)
                    .into_response();
            }
            Err(()) => {
                tracing::error!(
                    request_id = %request_id.as_canonical_string(),
                    error_code = "rate_limiter_unavailable",
                    "rate limiter state is unavailable"
                );
                return ApiError::InternalError("rate limiter unavailable".to_owned())
                    .with_request_id(&request_id)
                    .into_response();
            }
        }
    }

    match tokio::time::timeout(runtime.handler_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => {
            tracing::warn!(
                request_id = %request_id.as_canonical_string(),
                error_code = "request_timeout",
                "request exceeded handler timeout"
            );
            ApiError::RequestTimeout
                .with_request_id(&request_id)
                .into_response()
        }
    }
}

fn is_rate_limit_exempt_path(path: &str) -> bool {
    matches!(path, HEALTH_PATH | READY_PATH)
}

async fn record_auth_failure(state: &AppState, request_id: &RequestId, error_code: &'static str) {
    let metadata = match AuditMetadata::new(json!({ "error_code": error_code })) {
        Ok(metadata) => metadata,
        Err(error) => {
            state.readiness_state.mark_failure_audit_both_failed();
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = AuditAction::AuthFailure.as_str(),
                result = "failure",
                error_code = "audit_metadata_build_failed",
                "failed to construct auth failure audit metadata"
            );
            return;
        }
    };

    let audit_context =
        FailureAuditContext::new(state, request_id, None, None, AuditAction::AuthFailure);

    if let Err(error) = audit_context.record_with_metadata(metadata).await {
        tracing::error!(
            request_id = %request_id.as_canonical_string(),
            error = %error,
            action = AuditAction::AuthFailure.as_str(),
            result = "failure",
            error_code = "auth_failure_audit_record_failed",
            "auth failure audit recording failed"
        );
    }
}

fn parse_bearer_token(parts: &Parts) -> Result<RawJwt, AuthFailure> {
    let header_value = parts
        .headers
        .get(AUTHORIZATION)
        .ok_or(AuthFailure::MissingAuthorizationHeader)?;
    let header_value = header_value
        .to_str()
        .map_err(|_| AuthFailure::InvalidAuthorizationHeader)?;

    let token = header_value
        .strip_prefix(BEARER_PREFIX)
        .ok_or(AuthFailure::InvalidAuthorizationScheme)?;

    RawJwt::new(token).map_err(|_| AuthFailure::MalformedRawJwt)
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

#[derive(Debug, Clone, Copy)]
enum AuthFailure {
    MissingAuthorizationHeader,
    InvalidAuthorizationHeader,
    InvalidAuthorizationScheme,
    MalformedRawJwt,
}

impl AuthFailure {
    fn audit_error_code(self) -> &'static str {
        match self {
            Self::MissingAuthorizationHeader => "authorization_header_missing",
            Self::InvalidAuthorizationHeader => "authorization_header_invalid",
            Self::InvalidAuthorizationScheme => "authorization_scheme_invalid",
            Self::MalformedRawJwt => "raw_jwt_malformed",
        }
    }

    fn into_api_error(self) -> ApiError {
        let message = match self {
            Self::MissingAuthorizationHeader => "missing authorization header",
            Self::InvalidAuthorizationHeader => "invalid authorization header",
            Self::InvalidAuthorizationScheme => "invalid authorization scheme",
            Self::MalformedRawJwt => "invalid bearer token",
        };

        ApiError::Unauthorized(message.to_owned())
    }
}

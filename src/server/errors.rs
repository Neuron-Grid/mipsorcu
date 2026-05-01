use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::fmt;

use crate::audit::RequestId;
use crate::error::{JwtVerificationError, SecretDecryptError, SecretWriteError};

use super::dto::ApiErrorResponse;
use super::supabase::SupabaseRpcError;

#[derive(Debug)]
pub enum ApiError {
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    BadRequest(String),
    UnsupportedMediaType(String),
    PayloadTooLarge(String),
    RequestTimeout,
    RateLimited,
    DecryptFailed,
    KeyUnavailable,
    AuditRecordFailed,
    SupabaseError(SupabaseRpcError),
    DbIntegrityViolation(String),
    InternalInvariantViolation(String),
    InternalError(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized(message) => write!(formatter, "unauthorized: {message}"),
            Self::Forbidden(message) => write!(formatter, "forbidden: {message}"),
            Self::NotFound(message) => write!(formatter, "not found: {message}"),
            Self::BadRequest(message) => write!(formatter, "bad request: {message}"),
            Self::UnsupportedMediaType(message) => {
                write!(formatter, "unsupported media type: {message}")
            }
            Self::PayloadTooLarge(message) => write!(formatter, "payload too large: {message}"),
            Self::RequestTimeout => write!(formatter, "request timeout"),
            Self::RateLimited => write!(formatter, "rate limited"),
            Self::DecryptFailed => write!(formatter, "decrypt failed"),
            Self::KeyUnavailable => write!(formatter, "key unavailable"),
            Self::AuditRecordFailed => write!(formatter, "audit record failed"),
            Self::SupabaseError(error) => write!(formatter, "{error}"),
            Self::DbIntegrityViolation(message) => {
                write!(formatter, "db integrity violation: {message}")
            }
            Self::InternalInvariantViolation(message) => {
                write!(formatter, "internal invariant violation: {message}")
            }
            Self::InternalError(message) => write!(formatter, "internal error: {message}"),
        }
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    fn status_and_code(&self) -> (StatusCode, &str) {
        match self {
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::UnsupportedMediaType(_) => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
            }
            Self::PayloadTooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::RequestTimeout => (StatusCode::SERVICE_UNAVAILABLE, "request_timeout"),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::DecryptFailed => (StatusCode::BAD_REQUEST, "decrypt_failed"),
            Self::KeyUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "key_unavailable"),
            Self::AuditRecordFailed => (StatusCode::SERVICE_UNAVAILABLE, "audit_record_failed"),
            Self::SupabaseError(_) => (StatusCode::BAD_GATEWAY, "upstream_dependency_failed"),
            Self::DbIntegrityViolation(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "db_integrity_violation")
            }
            Self::InternalInvariantViolation(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_invariant_violation",
            ),
            Self::InternalError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        }
    }

    pub fn with_request_id(self, request_id: &RequestId) -> RequestAwareApiError {
        RequestAwareApiError::new(self, request_id.clone())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        self.with_request_id(&RequestId::nil()).into_response()
    }
}

impl From<JwtVerificationError> for ApiError {
    fn from(error: JwtVerificationError) -> Self {
        Self::Unauthorized(error.to_string())
    }
}

impl From<SecretWriteError> for ApiError {
    fn from(error: SecretWriteError) -> Self {
        match &error {
            SecretWriteError::Input(_) | SecretWriteError::Aad(_) => {
                Self::BadRequest(error.to_string())
            }
            SecretWriteError::Keyring(_) => Self::KeyUnavailable,
            SecretWriteError::Crypto(_) => Self::InternalError(error.to_string()),
        }
    }
}

impl From<SecretDecryptError> for ApiError {
    fn from(error: SecretDecryptError) -> Self {
        match error {
            SecretDecryptError::Authorization(_) => Self::Forbidden("forbidden".to_owned()),
            SecretDecryptError::Keyring(_) => Self::KeyUnavailable,
            SecretDecryptError::Aad(_)
            | SecretDecryptError::Crypto(_)
            | SecretDecryptError::Integrity(_) => Self::DecryptFailed,
        }
    }
}

impl From<SupabaseRpcError> for ApiError {
    fn from(error: SupabaseRpcError) -> Self {
        Self::SupabaseError(error)
    }
}

#[derive(Debug)]
pub struct RequestAwareApiError {
    error: ApiError,
    request_id: RequestId,
}

impl RequestAwareApiError {
    pub fn new(error: ApiError, request_id: RequestId) -> Self {
        Self { error, request_id }
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }
}

impl fmt::Display for RequestAwareApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for RequestAwareApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl IntoResponse for RequestAwareApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.error.status_and_code();
        let body = ApiErrorResponse {
            code: code.to_owned(),
            request_id: self.request_id.as_canonical_string(),
        };
        (status, Json(body)).into_response()
    }
}

pub type ServerResult<T> = Result<T, RequestAwareApiError>;

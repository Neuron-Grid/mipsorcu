use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::fmt;

use crate::error::{JwtVerificationError, SecretDecryptError, SecretWriteError};

use super::dto::ApiErrorResponse;
use super::supabase::SupabaseRpcError;

#[derive(Debug)]
pub enum ApiError {
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    BadRequest(String),
    DecryptFailed,
    AuditAppendFailed,
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
            Self::DecryptFailed => write!(formatter, "decrypt failed"),
            Self::AuditAppendFailed => write!(formatter, "audit append failed"),
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
            Self::DecryptFailed => (StatusCode::BAD_REQUEST, "decrypt_failed"),
            Self::AuditAppendFailed => (StatusCode::INTERNAL_SERVER_ERROR, "audit_append_failed"),
            Self::SupabaseError(_) => (StatusCode::BAD_GATEWAY, "supabase_error"),
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

    fn client_message(&self) -> String {
        match self {
            Self::Unauthorized(message)
            | Self::Forbidden(message)
            | Self::NotFound(message)
            | Self::BadRequest(message) => message.clone(),
            Self::DecryptFailed => "decrypt failed".to_owned(),
            Self::AuditAppendFailed => "audit append failed".to_owned(),
            Self::SupabaseError(_) => "upstream service error".to_owned(),
            Self::DbIntegrityViolation(_)
            | Self::InternalInvariantViolation(_)
            | Self::InternalError(_) => "internal error".to_owned(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        let body = ApiErrorResponse {
            error: self.client_message(),
            code: code.to_owned(),
        };
        (status, Json(body)).into_response()
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
            SecretWriteError::Crypto(_) => Self::InternalError(error.to_string()),
        }
    }
}

impl From<SecretDecryptError> for ApiError {
    fn from(error: SecretDecryptError) -> Self {
        match error {
            SecretDecryptError::Authorization(_) => Self::Forbidden("forbidden".to_owned()),
            SecretDecryptError::Aad(_)
            | SecretDecryptError::Crypto(_)
            | SecretDecryptError::Integrity(_) => Self::DecryptFailed,
        }
    }
}

impl From<SupabaseRpcError> for ApiError {
    fn from(error: SupabaseRpcError) -> Self {
        match error {
            SupabaseRpcError::NonSuccessStatus { status: 401, .. } => {
                Self::Unauthorized("unauthorized".to_owned())
            }
            SupabaseRpcError::NonSuccessStatus { status: 403, .. } => {
                Self::Forbidden("forbidden".to_owned())
            }
            SupabaseRpcError::NonSuccessStatus { status: 404, .. } => {
                Self::NotFound("not found".to_owned())
            }
            other => Self::SupabaseError(other),
        }
    }
}

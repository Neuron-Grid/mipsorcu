use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::fmt;

use mipsorcu::error::{JwtVerificationError, SecretWriteError};

use super::dto::ApiErrorResponse;
use super::supabase::SupabaseRpcError;

#[derive(Debug)]
pub enum ApiError {
    Unauthorized(String),
    BadRequest(String),
    SupabaseError(SupabaseRpcError),
    InternalError(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized(message) => write!(formatter, "unauthorized: {message}"),
            Self::BadRequest(message) => write!(formatter, "bad request: {message}"),
            Self::SupabaseError(error) => write!(formatter, "{error}"),
            Self::InternalError(message) => write!(formatter, "internal error: {message}"),
        }
    }
}

impl std::error::Error for ApiError {}

impl ApiError {
    fn status_and_code(&self) -> (StatusCode, &str) {
        match self {
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::SupabaseError(_) => (StatusCode::BAD_GATEWAY, "supabase_error"),
            Self::InternalError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        }
    }

    fn client_message(&self) -> String {
        match self {
            Self::Unauthorized(message)
            | Self::BadRequest(message)
            | Self::InternalError(message) => message.clone(),
            Self::SupabaseError(_) => "upstream service error".to_owned(),
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

impl From<SupabaseRpcError> for ApiError {
    fn from(error: SupabaseRpcError) -> Self {
        Self::SupabaseError(error)
    }
}

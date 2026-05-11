//! S3 backend 固有のエラー → `ArchiveBackendError` への変換。
//!
//! 上位 `export_digest_to_archive` は `BackendFailed { code }` の `code` を
//! 失敗監査の `metadata_json.error_code` にそのまま流すため、`code` は
//! `archive_export_*` プレフィクスを持つ static string で公開する。

use crate::archive::backend::ArchiveBackendError;

/// S3 backend 操作で発生する分類済みエラー。
#[derive(Debug)]
pub enum S3BackendError {
    /// 設定が不正（URL parse 失敗等）。
    InvalidConfig(&'static str),
    /// HTTP リクエスト構築失敗。
    RequestBuild(String),
    /// ネットワーク・接続失敗。retriable。
    Network(String),
    /// HTTP 401 / 403。non-retriable。
    Unauthenticated,
    /// HTTP 412 — `If-None-Match: *` で上書き拒否された。non-retriable。
    OverwriteRejected,
    /// HTTP 404 — verify 時のオブジェクト不存在。
    NotFound,
    /// HTTP 5xx / 429 / 408。retriable。
    ServerError { status: u16 },
    /// 想定外のステータス。non-retriable。
    Unexpected { status: u16 },
    /// レスポンスボディの読み出し失敗。
    ResponseRead(String),
}

impl S3BackendError {
    pub fn as_error_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig(_) => "archive_export_invalid_config",
            Self::RequestBuild(_) => "archive_export_request_build_failed",
            Self::Network(_) => "archive_export_network_failed",
            Self::Unauthenticated => "archive_export_unauthenticated",
            Self::OverwriteRejected => "archive_export_overwrite_rejected",
            Self::NotFound => "archive_export_not_found",
            Self::ServerError { .. } => "archive_export_server_error",
            Self::Unexpected { .. } => "archive_export_unexpected_status",
            Self::ResponseRead(_) => "archive_export_response_read_failed",
        }
    }

    pub fn is_retriable(&self) -> bool {
        matches!(self, Self::Network(_) | Self::ServerError { .. })
    }
}

impl std::fmt::Display for S3BackendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid s3 config: {reason}"),
            Self::RequestBuild(reason) => write!(formatter, "s3 request build failed: {reason}"),
            Self::Network(reason) => write!(formatter, "s3 network error: {reason}"),
            Self::Unauthenticated => formatter.write_str("s3 authentication failed"),
            Self::OverwriteRejected => formatter.write_str("s3 overwrite rejected"),
            Self::NotFound => formatter.write_str("s3 object not found"),
            Self::ServerError { status } => write!(formatter, "s3 server error: {status}"),
            Self::Unexpected { status } => write!(formatter, "s3 unexpected status: {status}"),
            Self::ResponseRead(reason) => write!(formatter, "s3 response read failed: {reason}"),
        }
    }
}

impl std::error::Error for S3BackendError {}

impl From<S3BackendError> for ArchiveBackendError {
    fn from(error: S3BackendError) -> Self {
        Self::BackendFailed {
            code: error.as_error_code().to_owned(),
        }
    }
}

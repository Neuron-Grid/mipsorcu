use std::fmt;

pub enum SupabaseRpcError {
    Network(reqwest::Error),
    NonSuccessStatus { status: u16, body: String },
    InvalidResponse(String),
    EmptyResult,
}

impl fmt::Display for SupabaseRpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(error) => write!(formatter, "supabase network error: {error}"),
            Self::NonSuccessStatus { status, body } => {
                write!(
                    formatter,
                    "supabase returned status {status} with response body length {}",
                    body.len()
                )
            }
            Self::InvalidResponse(message) => {
                write!(formatter, "supabase invalid response: {message}")
            }
            Self::EmptyResult => write!(formatter, "supabase RPC returned no rows"),
        }
    }
}

impl std::error::Error for SupabaseRpcError {}

impl SupabaseRpcError {
    pub fn upstream_status(&self) -> Option<u16> {
        match self {
            Self::NonSuccessStatus { status, .. } => Some(*status),
            _ => None,
        }
    }
}

impl fmt::Debug for SupabaseRpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(error) => formatter
                .debug_struct("Network")
                .field("error", &error.to_string())
                .finish(),
            Self::NonSuccessStatus { status, body } => formatter
                .debug_struct("NonSuccessStatus")
                .field("status", status)
                .field("body_len", &body.len())
                .finish(),
            Self::InvalidResponse(message) => formatter
                .debug_struct("InvalidResponse")
                .field("message", message)
                .finish(),
            Self::EmptyResult => formatter.write_str("EmptyResult"),
        }
    }
}

use std::fmt;

use crate::server::supabase::SupabaseRpcError;

#[derive(Debug)]
pub enum KeyRotationCliError {
    Usage(String),
    Config(String),
    Audit(String),
    Crypto(String),
    Supabase(SupabaseRpcError),
}

impl fmt::Display for KeyRotationCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::Config(message) => {
                write!(formatter, "key rotation configuration error: {message}")
            }
            Self::Audit(message) => write!(formatter, "key rotation audit error: {message}"),
            Self::Crypto(message) => write!(formatter, "key rotation crypto error: {message}"),
            Self::Supabase(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for KeyRotationCliError {}

impl From<SupabaseRpcError> for KeyRotationCliError {
    fn from(error: SupabaseRpcError) -> Self {
        Self::Supabase(error)
    }
}

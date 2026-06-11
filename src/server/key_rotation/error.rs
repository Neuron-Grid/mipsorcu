use std::fmt;

use crate::server::supabase::SupabaseRpcError;

#[derive(Debug)]
pub enum KeyRotationCliError {
    Usage(String),
    Config(String),
    Audit(String),
    Crypto(String),
    Supabase(SupabaseRpcError),
    /// envelope migration の適用 RPC が 40001（nonce 再利用 / 行衝突 / 行ロック）で
    /// バッチ全体を中断・ロールバックした場合の retryable conflict。残存 legacy 行は
    /// 次回スケジューラ実行で再処理される。汎用 `Supabase` 失敗と区別して分類する。
    EnvelopeMigrationConflict,
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
            Self::EnvelopeMigrationConflict => write!(
                formatter,
                "envelope migration batch aborted on a retryable conflict"
            ),
        }
    }
}

impl std::error::Error for KeyRotationCliError {}

impl KeyRotationCliError {
    pub(crate) fn incident_error_code(&self) -> Option<&'static str> {
        match self {
            Self::Usage(_) => None,
            Self::Config(_) => Some("key_rotation_config_failed"),
            Self::Audit(_) => Some("key_rotation_audit_failed"),
            Self::Crypto(_) => Some("key_rotation_crypto_failed"),
            Self::Supabase(_) => Some("key_rotation_supabase_failed"),
            Self::EnvelopeMigrationConflict => Some("key_rotation_envelope_conflict"),
        }
    }
}

impl From<SupabaseRpcError> for KeyRotationCliError {
    fn from(error: SupabaseRpcError) -> Self {
        Self::Supabase(error)
    }
}

mod audit_rpc;
mod client;
mod error;
mod integrity_rpc;
mod key_rotation_rpc;
mod ledger_rpc;
mod readiness;
mod response;
mod restore_rpc;
mod secret_rpc;
mod write_secret_rpc;

pub use audit_rpc::SupabaseAuditAppender;
pub use client::SupabaseClient;
pub use error::SupabaseRpcError;
pub use ledger_rpc::classify_append_ledger_error;

pub use crate::types::supabase::{
    AppendLedgerEntryOutcome, IntegrityCheckSummary, IntegrityCheckViolationSummary,
    KeyRotationApplyOutcome, KeyRotationApplyRow, KeyRotationBatchRow, KeyRotationCompleteOutcome,
    KeyRotationStatus, LedgerAppendRpcFailure, LedgerEntryRpcParams, RestoreTestSampleRow,
    SecretReadJoin, SecretVersionReadRow, SecretVersionRetentionSnapshot,
    WriteSecretVersionOutcome, WriteSecretVersionParams,
};

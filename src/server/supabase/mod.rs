mod alias_rpc;
mod audit_report_rpc;
mod audit_rpc;
mod audit_ui_rpc;
mod client;
mod digest_rpc;
mod error;
mod incident_rpc;
mod integrity_rpc;
mod key_rotation_rpc;
mod ledger_export_rpc;
mod ledger_public_key_rpc;
mod ledger_rpc;
mod readiness;
mod response;
mod restore_rpc;
mod secret_rpc;
mod verify_digest_rpc;
mod write_secret_rpc;

pub use alias_rpc::{
    CreateSecretAliasParams, DeleteSecretAliasParams, ListSecretAliasesParams, SecretAliasRpcError,
    UpdateSecretAliasParams, classify_secret_alias_rpc_error,
};
pub use audit_report_rpc::{
    AuditReportSummary, HashChainVerificationSummary, IntegrityCheckReportItem,
    MonthlyDigestReportItem, RestoreTestReportItem, SignatureKeyVersionReportItem,
    VerificationFailureReportItem,
};
pub use audit_rpc::SupabaseAuditAppender;
pub use audit_ui_rpc::{
    AuditUiAuditEventRow, AuditUiAuditEventsParams, AuditUiHashChainVerification,
    AuditUiIntegrityStatusRow, AuditUiLedgerEntriesParams, AuditUiLedgerEntryRow,
    AuditUiSecretInventoryRow, AuditUiVerificationFailureRow, AuditUiVerificationFailuresParams,
};
pub use client::SupabaseClient;
pub use digest_rpc::{DigestRpcError, LedgerRangeForMonth, classify_digest_rpc_error};
pub use error::SupabaseRpcError;
pub use incident_rpc::IncidentRecordOutcome;
pub use ledger_export_rpc::{
    ExportLedgerError, LedgerVerificationMaterialRow, classify_export_ledger_error,
};
pub use ledger_public_key_rpc::{
    LedgerSigningPublicKeyStatus, RegisterPublicKeyError, classify_register_public_key_error,
};
pub use ledger_rpc::classify_append_ledger_error;
pub use verify_digest_rpc::{
    MonthlyDigestVerificationMaterials, VerifyDigestRpcError, classify_verify_digest_rpc_error,
};

pub use crate::types::supabase::{
    AppendLedgerEntryOutcome, IntegrityCheckSummary, IntegrityCheckViolationSummary,
    KeyRotationApplyOutcome, KeyRotationApplyRow, KeyRotationBatchRow, KeyRotationCompleteOutcome,
    KeyRotationStatus, LedgerAppendRpcFailure, LedgerEntryRpcParams, RestoreTestSampleRow,
    SecretAliasListRow, SecretAliasResolveRow, SecretReadJoin, SecretVersionReadRow,
    SecretVersionRetentionSnapshot, SecretVersionWriteStateRow, WriteSecretVersionOutcome,
    WriteSecretVersionParams,
};

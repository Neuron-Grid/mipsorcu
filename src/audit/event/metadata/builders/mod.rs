//! Action 別の typed audit metadata builder 群。
//!
//! 各 builder は対応する `AuditAction` の許可キー集合のみを公開し、未知キーや
//! 禁止キーを呼び出し側から構造的に挿入できないようにする。ドメインごとに
//! サブモジュールへ分割している。

mod alias;
mod digest;
mod integrity;
mod key_rotation;
mod monitoring;
mod report;
mod secret_ops;
mod signature_key;

pub use alias::{
    SecretAliasCreateMetadata, SecretAliasDeleteMetadata, SecretAliasListMetadata,
    SecretAliasUpdateMetadata,
};
pub use digest::{
    ArchiveExportMetadata, DigestTimestampingMetadata, MonthlyDigestGenerateMetadata,
    MonthlyDigestVerifyMetadata,
};
pub use integrity::{IntegrityCheckMetadata, RestoreTestMetadata, SchedulerJobMetadata};
pub use key_rotation::{
    KeyRotationCompleteMetadata, KeyRotationEnvelopeFailedMetadata,
    KeyRotationEnvelopeMigratedMetadata, KeyRotationReencryptMetadata, KeyRotationStartMetadata,
};
pub use monitoring::{
    IncidentDetectedMetadata, IncidentNotificationFailedMetadata, IncidentNotificationSentMetadata,
    IncidentNotificationSuppressedMetadata, SiemBufferFlushedMetadata, SiemEventFailedMetadata,
    SiemEventForwardedMetadata, SiemForwardFailureMetadata,
};
pub use report::{AuditReportGenerateMetadata, AuditUiReadMetadata};
pub use secret_ops::{
    AuthFailureMetadata, DecryptMetadata, EncryptCreateMetadata, EncryptRotateMetadata,
    VersionPurgeMetadata,
};
pub use signature_key::{
    SignatureKeyActivatedMetadata, SignatureKeyCreatedMetadata, SignatureKeyRetiredMetadata,
};

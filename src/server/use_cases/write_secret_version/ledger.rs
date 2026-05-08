use crate::audit::{AuditEventId, RequestId};
use crate::server::ledger_appender::{LedgerAppendDraft, LedgerAppendDraftParts};
use crate::types::supabase::SecretVersionRetentionSnapshot;
use crate::{
    ALGORITHM_XCHACHA20_POLY1305, LedgerEntryId, LedgerEntryType, LedgerPayload, LedgerResult,
    LedgerTargetSecretVersionId, PreparedSecretVersion, SecretVersion, SecretVersionId,
    SecretWriteAction, SourceEventAt,
};

const SECRET_VERSION_RETENTION_LIMIT: usize = 4;

pub(super) fn build_write_ledger_draft(
    request_id: &RequestId,
    prepared: &PreparedSecretVersion,
) -> Result<LedgerAppendDraft, crate::LedgerError> {
    let source_event_at =
        SourceEventAt::now_utc().map_err(|_| crate::LedgerError::RandomnessUnavailable)?;
    let entry_type = match prepared.write_action() {
        SecretWriteAction::EncryptCreate => LedgerEntryType::SecretCreated,
        SecretWriteAction::EncryptRotate => LedgerEntryType::SecretVersionCreated,
    };
    let payload = LedgerPayload::new(
        entry_type,
        serde_json::json!({
            "algorithm": ALGORITHM_XCHACHA20_POLY1305,
            "classification": prepared.classification().as_str(),
            "key_version": prepared.key_version().get(),
            "version": prepared.version().get(),
        }),
    )?;
    let target_secret_version_id =
        LedgerTargetSecretVersionId::from_secret_version_id(prepared.secret_version_id())?;

    LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::generate()?,
        entry_type,
        source_event_at,
        request_id: request_id.clone(),
        source_event_id: Some(AuditEventId::generate().map_err(|_| {
            crate::LedgerError::InvalidUuid {
                field: "source_event_id",
            }
        })?),
        target_secret_id: Some(prepared.secret_id().clone()),
        target_secret_version_id: Some(target_secret_version_id),
        actor_user_id: Some(prepared.owner_user_id().clone()),
        actor_device_id: Some(prepared.created_by_device_id().clone()),
        result: LedgerResult::Success,
        error_code: None,
        payload,
    })
}

#[derive(Clone)]
struct RetentionVersionSnapshot {
    secret_version_id: SecretVersionId,
    version: SecretVersion,
    key_version: crate::KeyVersion,
}

pub(super) fn build_purge_ledger_drafts(
    request_id: &RequestId,
    prepared: &PreparedSecretVersion,
    retention_snapshot: Vec<SecretVersionRetentionSnapshot>,
) -> Result<Vec<LedgerAppendDraft>, crate::LedgerError> {
    if !matches!(prepared.write_action(), SecretWriteAction::EncryptRotate) {
        return Ok(Vec::new());
    }

    let mut versions = retention_snapshot
        .into_iter()
        .map(|snapshot| RetentionVersionSnapshot {
            secret_version_id: snapshot.secret_version_id().clone(),
            version: snapshot.version(),
            key_version: snapshot.key_version(),
        })
        .collect::<Vec<_>>();
    versions.push(RetentionVersionSnapshot {
        secret_version_id: prepared.secret_version_id().clone(),
        version: prepared.version(),
        key_version: prepared.key_version(),
    });
    versions.sort_by_key(|snapshot| std::cmp::Reverse(snapshot.version.get()));

    let mut purged_versions = versions
        .into_iter()
        .skip(SECRET_VERSION_RETENTION_LIMIT)
        .collect::<Vec<_>>();
    purged_versions.sort_by_key(|snapshot| snapshot.version.get());

    purged_versions
        .iter()
        .map(|purged| build_purge_ledger_draft(request_id, prepared, purged))
        .collect()
}

fn build_purge_ledger_draft(
    request_id: &RequestId,
    prepared: &PreparedSecretVersion,
    purged: &RetentionVersionSnapshot,
) -> Result<LedgerAppendDraft, crate::LedgerError> {
    let entry_type = LedgerEntryType::SecretVersionPurged;
    let payload = LedgerPayload::new(
        entry_type,
        serde_json::json!({
            "key_version": purged.key_version.get(),
            "retention_limit": SECRET_VERSION_RETENTION_LIMIT,
            "version": purged.version.get(),
        }),
    )?;
    let target_secret_version_id =
        LedgerTargetSecretVersionId::from_secret_version_id(&purged.secret_version_id)?;

    LedgerAppendDraft::new(LedgerAppendDraftParts {
        ledger_entry_id: LedgerEntryId::generate()?,
        entry_type,
        source_event_at: SourceEventAt::now_utc()
            .map_err(|_| crate::LedgerError::RandomnessUnavailable)?,
        request_id: request_id.clone(),
        source_event_id: Some(AuditEventId::generate().map_err(|_| {
            crate::LedgerError::InvalidUuid {
                field: "source_event_id",
            }
        })?),
        target_secret_id: Some(prepared.secret_id().clone()),
        target_secret_version_id: Some(target_secret_version_id),
        actor_user_id: Some(prepared.owner_user_id().clone()),
        actor_device_id: Some(prepared.created_by_device_id().clone()),
        result: LedgerResult::Success,
        error_code: None,
        payload,
    })
}

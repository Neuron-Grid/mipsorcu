use mipsorcu::{
    AuditAction, AuditResult, KeyRotationEnvelopeFailedMetadata,
    KeyRotationEnvelopeMigratedMetadata, LedgerEntryType, LedgerPayload, SecretVersion,
    SecretVersionId, SourceEventAt,
};
use serde_json::json;

#[test]
fn envelope_migration_audit_and_ledger_vocabulary_is_accepted()
-> Result<(), Box<dyn std::error::Error>> {
    let source_event_at = SourceEventAt::parse("2026-04-08T12:00:00Z")?;
    let migrated = KeyRotationEnvelopeMigratedMetadata::new(100, 99, 1)
        .with_source_event_at(source_event_at.clone())
        .build()?;
    migrated.validate_allowlist_for_action(
        AuditAction::KeyRotationEnvelopeMigrated,
        AuditResult::Success,
    )?;

    let secret_version_id = SecretVersionId::parse("550e8400-e29b-41d4-a716-446655440000")?;
    let failed = KeyRotationEnvelopeFailedMetadata::new(
        secret_version_id,
        SecretVersion::new(7)?,
        "aad_context_mismatch",
    )
    .with_source_event_at(source_event_at)
    .build()?;
    failed.validate_allowlist_for_action(
        AuditAction::KeyRotationEnvelopeFailed,
        AuditResult::Failure,
    )?;

    let payload = LedgerPayload::new(
        LedgerEntryType::EnvelopeMigrationBatchCompleted,
        json!({
            "batch_size": 100,
            "success_count": 99,
            "failure_count": 1,
        }),
    )?;
    assert_eq!(payload.as_value()["success_count"], 99);

    Ok(())
}

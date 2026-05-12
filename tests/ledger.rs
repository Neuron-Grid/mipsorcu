use mipsorcu::{
    DeviceId, LEDGER_HASH_LENGTH, LedgerChainHead, LedgerEntryDraft, LedgerEntryDraftParts,
    LedgerEntryId, LedgerEntryType, LedgerError, LedgerHash, LedgerPayload, LedgerResult,
    LedgerSequenceNo, LedgerSignatureKeyVersion, LedgerSigningKey, LedgerTargetSecretVersionId,
    LedgerVerifyingKey, OwnerUserId, RequestId, SecretId, SignedLedgerEntry,
    SignedLedgerEntryParts, SourceEventAt, verify_ledger_chain,
};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CANONICAL_VECTOR: &str = r#"{"schema":"mipsorcu.ledger_entry.v1","sequence_no":1,"entry_type":"secret_created","source_event_at":"2026-04-08T12:00:00Z","request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","source_event_id":null,"target_secret_id":"550e8400-e29b-41d4-a716-446655440000","target_secret_version_id":"11111111-2222-4333-8444-555555555555","actor_user_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479","actor_device_id":"sbc-device-1","result":"success","error_code":null,"payload":{"algorithm":"xchacha20-poly1305","classification":"confidential","key_version":1,"version":1},"canonicalization_version":1,"previous_entry_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash_algorithm":"sha-256","signature_algorithm":"ed25519","signature_key_version":1}"#;
const CANONICAL_VECTOR_HASH: &str =
    "8d63bba7d0c4b972f0134df8ffad728330897312bb556ddbea27ff708294a93b";

#[test]
fn ledger_canonical_payload_matches_fixed_vector_and_is_stable() -> TestResult {
    let entry = sample_signed_entry(sample_payload_ordered()?, LedgerSequenceNo::new(1)?)?;
    let canonical = std::str::from_utf8(entry.canonical_payload().as_bytes())?;

    assert_eq!(canonical, CANONICAL_VECTOR);
    assert_eq!(entry.entry_hash().to_hex(), CANONICAL_VECTOR_HASH);
    assert_eq!(
        entry.canonical_payload().as_bytes(),
        CANONICAL_VECTOR.as_bytes()
    );

    Ok(())
}

#[test]
fn ledger_canonical_payload_excludes_noncanonical_storage_fields() -> TestResult {
    let entry = sample_signed_entry(sample_payload_ordered()?, LedgerSequenceNo::new(1)?)?;
    let document: Value = serde_json::from_slice(entry.canonical_payload().as_bytes())?;
    let object = document
        .as_object()
        .ok_or(LedgerError::PayloadMustBeObject)?;

    for excluded_field in ["id", "entry_hash", "signature", "created_at"] {
        assert!(!object.contains_key(excluded_field));
    }

    assert_eq!(
        object.get("source_event_at").and_then(Value::as_str),
        Some("2026-04-08T12:00:00Z")
    );
    assert_eq!(object.get("source_event_id"), Some(&Value::Null));
    assert_eq!(
        object.get("previous_entry_hash").and_then(Value::as_str),
        Some("0000000000000000000000000000000000000000000000000000000000000000")
    );

    Ok(())
}

#[test]
fn ledger_canonical_payload_preserves_json_null_for_absent_optional_fields() -> TestResult {
    let draft = LedgerEntryDraft::new(LedgerEntryDraftParts {
        ledger_entry_id: LedgerEntryId::parse("22222222-2222-4222-8222-222222222222")?,
        sequence_no: LedgerSequenceNo::new(1)?,
        entry_type: LedgerEntryType::IntegrityCheckCompleted,
        source_event_at: SourceEventAt::parse("2026-04-08T12:00:00Z").map_err(|_| {
            LedgerError::InvalidPayloadField {
                key: "source_event_at".to_owned(),
                expected: "a canonical UTC RFC3339 timestamp",
            }
        })?,
        request_id: RequestId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").map_err(|_| {
            LedgerError::InvalidUuid {
                field: "request_id",
            }
        })?,
        source_event_id: None,
        target_secret_id: None,
        target_secret_version_id: None,
        actor_user_id: None,
        actor_device_id: None,
        result: LedgerResult::Success,
        error_code: None,
        payload: LedgerPayload::empty(LedgerEntryType::IntegrityCheckCompleted)?,
        previous_entry_hash: LedgerHash::genesis(),
        signature_key_version: LedgerSignatureKeyVersion::new(1)?,
    })?;

    let canonical_payload = draft.canonical_payload()?;
    let document: Value = serde_json::from_slice(canonical_payload.as_bytes())?;
    let object = document
        .as_object()
        .ok_or(LedgerError::PayloadMustBeObject)?;

    for nullable_field in [
        "source_event_id",
        "target_secret_id",
        "target_secret_version_id",
        "actor_user_id",
        "actor_device_id",
        "error_code",
    ] {
        assert_eq!(object.get(nullable_field), Some(&Value::Null));
    }

    assert_eq!(object.get("payload"), Some(&json!({})));

    Ok(())
}

#[test]
fn ledger_same_meaning_uuid_and_payload_order_produce_same_canonical_payload() -> TestResult {
    let entry = sample_signed_entry(sample_payload_ordered()?, LedgerSequenceNo::new(1)?)?;
    let variant = LedgerEntryDraft::new(LedgerEntryDraftParts {
        ledger_entry_id: LedgerEntryId::parse("22222222-2222-4222-8222-222222222222")?,
        sequence_no: LedgerSequenceNo::new(1)?,
        entry_type: LedgerEntryType::SecretCreated,
        source_event_at: SourceEventAt::parse("2026-04-08T12:00:00Z")?,
        request_id: RequestId::parse("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")?,
        source_event_id: None,
        target_secret_id: Some(SecretId::parse("550E8400-E29B-41D4-A716-446655440000")?),
        target_secret_version_id: Some(LedgerTargetSecretVersionId::parse(
            "11111111-2222-4333-8444-555555555555",
        )?),
        actor_user_id: Some(OwnerUserId::parse("F47AC10B-58CC-4372-A567-0E02B2C3D479")?),
        actor_device_id: Some(DeviceId::new("sbc-device-1")?),
        result: LedgerResult::Success,
        error_code: None,
        payload: sample_payload_reordered()?,
        previous_entry_hash: LedgerHash::genesis(),
        signature_key_version: LedgerSignatureKeyVersion::new(1)?,
    })?
    .sign(&sample_signing_key(1)?)?;

    assert_eq!(
        entry.canonical_payload().as_bytes(),
        variant.canonical_payload().as_bytes()
    );
    assert_eq!(entry.entry_hash(), variant.entry_hash());

    Ok(())
}

#[test]
fn ledger_payload_key_order_does_not_change_hash() -> TestResult {
    let ordered = sample_signed_entry(sample_payload_ordered()?, LedgerSequenceNo::new(1)?)?;
    let reordered = sample_signed_entry(sample_payload_reordered()?, LedgerSequenceNo::new(1)?)?;

    assert_eq!(ordered.entry_hash(), reordered.entry_hash());

    Ok(())
}

#[test]
fn ledger_previous_entry_hash_participates_in_canonical_hash() -> TestResult {
    let base_draft = sample_entry_draft(sample_payload_ordered()?, LedgerSequenceNo::new(1)?)?;
    let base_canonical = base_draft.canonical_payload()?;
    let base_hash = LedgerHash::from_canonical_payload(&base_canonical);
    let changed_previous_hash =
        LedgerHash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")?;
    let changed_draft = sample_entry_draft_with_previous_hash(
        sample_payload_ordered()?,
        LedgerSequenceNo::new(1)?,
        changed_previous_hash,
    )?;
    let changed_canonical = changed_draft.canonical_payload()?;
    let changed_hash = LedgerHash::from_canonical_payload(&changed_canonical);

    assert_ne!(base_canonical.as_bytes(), changed_canonical.as_bytes());
    assert_ne!(base_hash, changed_hash);

    Ok(())
}

#[test]
fn ledger_hash_is_sha256_fixed_32_bytes() -> TestResult {
    let entry = sample_signed_entry(sample_payload_ordered()?, LedgerSequenceNo::new(1)?)?;
    let recomputed_hash = LedgerHash::from_canonical_payload(entry.canonical_payload());

    assert_eq!(recomputed_hash, entry.entry_hash());
    assert_eq!(recomputed_hash.as_bytes().len(), LEDGER_HASH_LENGTH);
    assert_eq!(recomputed_hash.as_bytes().len(), 32);

    Ok(())
}

#[test]
fn ledger_payload_rejects_non_object() {
    let result = LedgerPayload::new(LedgerEntryType::SecretCreated, json!("not-an-object"));

    assert!(matches!(result, Err(LedgerError::PayloadMustBeObject)));
}

#[test]
fn ledger_payload_rejects_unknown_key() {
    let result = LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "algorithm": "xchacha20-poly1305",
            "unexpected": 1
        }),
    );
    assert!(matches!(result, Err(LedgerError::UnknownPayloadKey { .. })));
}

#[test]
fn ledger_payload_rejects_top_level_forbidden_key() {
    let result = LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "algorithm": "xchacha20-poly1305",
            "classification": "confidential",
            "key_version": 1,
            "version": 1,
            " TOKEN ": "redacted"
        }),
    );

    assert!(matches!(
        result,
        Err(LedgerError::ForbiddenPayloadKey { .. })
    ));
}

#[test]
fn ledger_payload_rejects_nested_forbidden_key() {
    let result = LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "algorithm": "xchacha20-poly1305",
            "classification": "confidential",
            "key_version": 1,
            "version": 1,
            "safe": { " jwt ": "redacted" }
        }),
    );

    assert!(matches!(
        result,
        Err(LedgerError::ForbiddenPayloadKey { .. })
    ));
}

#[test]
fn ledger_payload_rejects_forbidden_key_inside_array_object() {
    let result = LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "algorithm": "xchacha20-poly1305",
            "classification": "confidential",
            "key_version": 1,
            "version": 1,
            "safe": [
                { "Master_Key": "redacted" }
            ]
        }),
    );

    assert!(matches!(
        result,
        Err(LedgerError::ForbiddenPayloadKey { .. })
    ));
}

#[test]
fn ledger_payload_rejects_non_scalar_allowed_value() {
    let result = LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "algorithm": { "value": "xchacha20-poly1305" },
            "classification": "confidential",
            "key_version": 1,
            "version": 1
        }),
    );

    assert!(matches!(
        result,
        Err(LedgerError::PayloadValueMustBeScalar { .. })
    ));
}

#[test]
fn ledger_payload_accepts_allowed_keys_only() -> TestResult {
    let payload = LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "algorithm": "xchacha20-poly1305",
            "classification": "confidential",
            "key_version": 1,
            "version": 1
        }),
    )?;

    assert_eq!(payload.entry_type(), LedgerEntryType::SecretCreated);
    assert_eq!(
        payload.as_value(),
        json!({
            "algorithm": "xchacha20-poly1305",
            "classification": "confidential",
            "key_version": 1,
            "version": 1
        })
    );

    Ok(())
}

#[test]
fn scheduler_job_completed_payload_accepts_valid_job_name() -> TestResult {
    let payload = LedgerPayload::new(
        LedgerEntryType::SchedulerJobCompleted,
        json!({
            "duration_ms": 12,
            "job_name": "monthly_digest_generate",
            "target_year_month": "2026-05",
            "trigger": "background"
        }),
    )?;

    assert_eq!(payload.entry_type(), LedgerEntryType::SchedulerJobCompleted);
    assert_eq!(payload.as_value()["job_name"], "monthly_digest_generate");

    Ok(())
}

#[test]
fn scheduler_job_completed_payload_rejects_invalid_job_name() {
    let blank = LedgerPayload::new(
        LedgerEntryType::SchedulerJobCompleted,
        json!({
            "duration_ms": 12,
            "job_name": " ",
            "trigger": "background"
        }),
    );
    assert!(matches!(
        blank,
        Err(LedgerError::InvalidPayloadField { .. })
    ));

    let non_string = LedgerPayload::new(
        LedgerEntryType::SchedulerJobCompleted,
        json!({
            "duration_ms": 12,
            "job_name": 7,
            "trigger": "background"
        }),
    );
    assert!(matches!(
        non_string,
        Err(LedgerError::InvalidPayloadField { .. })
    ));

    let oversized = LedgerPayload::new(
        LedgerEntryType::SchedulerJobCompleted,
        json!({
            "duration_ms": 12,
            "job_name": "x".repeat(129),
            "trigger": "background"
        }),
    );
    assert!(matches!(
        oversized,
        Err(LedgerError::InvalidPayloadField { .. })
    ));
}

#[test]
fn ledger_signature_verifies_and_chain_verification_accepts_valid_entry() -> TestResult {
    let signing_key = sample_signing_key(1)?;
    let verification_key = signing_key.verification_key();
    let entry = sample_entry_draft(sample_payload_ordered()?, LedgerSequenceNo::new(1)?)?
        .sign(&signing_key)?;

    entry.verify_signature(&verification_key)?;
    let head = verify_ledger_chain(&[entry], LedgerChainHead::genesis(), &[verification_key])?;

    assert_eq!(head.last_sequence_no(), 1);
    assert_eq!(head.last_entry_hash().to_hex(), CANONICAL_VECTOR_HASH);

    Ok(())
}

#[test]
fn ledger_payload_tampering_makes_signature_verification_fail() -> TestResult {
    let signing_key = sample_signing_key(1)?;
    let verification_key = signing_key.verification_key();
    let entry = sample_entry_draft(sample_payload_ordered()?, LedgerSequenceNo::new(1)?)?
        .sign(&signing_key)?;
    let tampered_payload = LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "version": 1,
            "key_version": 1,
            "classification": "restricted",
            "algorithm": "xchacha20-poly1305"
        }),
    )?;
    let tampered_draft = sample_entry_draft(tampered_payload.clone(), LedgerSequenceNo::new(1)?)?;
    let tampered_canonical = tampered_draft.canonical_payload()?;
    let tampered = SignedLedgerEntry::from_stored_parts(SignedLedgerEntryParts {
        ledger_entry_id: entry.ledger_entry_id().clone(),
        sequence_no: entry.sequence_no(),
        entry_type: entry.entry_type(),
        source_event_at: entry.source_event_at().clone(),
        request_id: entry.request_id().clone(),
        source_event_id: entry.source_event_id().cloned(),
        target_secret_id: entry.target_secret_id().cloned(),
        target_secret_version_id: entry.target_secret_version_id().cloned(),
        actor_user_id: entry.actor_user_id().cloned(),
        actor_device_id: entry.actor_device_id().cloned(),
        result: entry.result(),
        error_code: entry.error_code().map(str::to_owned),
        payload: tampered_payload,
        previous_entry_hash: entry.previous_entry_hash(),
        entry_hash: LedgerHash::from_canonical_payload(&tampered_canonical),
        signature: entry.signature(),
        signature_key_version: entry.signature_key_version(),
    })?;

    assert!(matches!(
        tampered.verify_signature(&verification_key),
        Err(LedgerError::SignatureInvalid { .. })
    ));

    Ok(())
}

#[test]
fn ledger_previous_hash_tampering_makes_signature_verification_fail() -> TestResult {
    let signing_key = sample_signing_key(1)?;
    let verification_key = signing_key.verification_key();
    let entry = sample_entry_draft(sample_payload_ordered()?, LedgerSequenceNo::new(1)?)?
        .sign(&signing_key)?;
    let tampered_previous_hash =
        LedgerHash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")?;
    let tampered_draft = sample_entry_draft_with_previous_hash(
        entry.payload().clone(),
        entry.sequence_no(),
        tampered_previous_hash,
    )?;
    let tampered_canonical = tampered_draft.canonical_payload()?;
    let tampered = SignedLedgerEntry::from_stored_parts(SignedLedgerEntryParts {
        ledger_entry_id: entry.ledger_entry_id().clone(),
        sequence_no: entry.sequence_no(),
        entry_type: entry.entry_type(),
        source_event_at: entry.source_event_at().clone(),
        request_id: entry.request_id().clone(),
        source_event_id: entry.source_event_id().cloned(),
        target_secret_id: entry.target_secret_id().cloned(),
        target_secret_version_id: entry.target_secret_version_id().cloned(),
        actor_user_id: entry.actor_user_id().cloned(),
        actor_device_id: entry.actor_device_id().cloned(),
        result: entry.result(),
        error_code: entry.error_code().map(str::to_owned),
        payload: entry.payload().clone(),
        previous_entry_hash: tampered_previous_hash,
        entry_hash: LedgerHash::from_canonical_payload(&tampered_canonical),
        signature: entry.signature(),
        signature_key_version: entry.signature_key_version(),
    })?;

    assert!(matches!(
        tampered.verify_signature(&verification_key),
        Err(LedgerError::SignatureInvalid { .. })
    ));

    Ok(())
}

#[test]
fn ledger_previous_hash_tampering_and_sequence_gap_are_detected() -> TestResult {
    let signing_key = sample_signing_key(1)?;
    let verification_key = signing_key.verification_key();
    let entry = sample_entry_draft(sample_payload_ordered()?, LedgerSequenceNo::new(1)?)?
        .sign(&signing_key)?;
    let tampered_previous_hash =
        LedgerHash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")?;
    let tampered = SignedLedgerEntry::from_stored_parts(SignedLedgerEntryParts {
        ledger_entry_id: entry.ledger_entry_id().clone(),
        sequence_no: entry.sequence_no(),
        entry_type: entry.entry_type(),
        source_event_at: entry.source_event_at().clone(),
        request_id: entry.request_id().clone(),
        source_event_id: entry.source_event_id().cloned(),
        target_secret_id: entry.target_secret_id().cloned(),
        target_secret_version_id: entry.target_secret_version_id().cloned(),
        actor_user_id: entry.actor_user_id().cloned(),
        actor_device_id: entry.actor_device_id().cloned(),
        result: entry.result(),
        error_code: entry.error_code().map(str::to_owned),
        payload: entry.payload().clone(),
        previous_entry_hash: tampered_previous_hash,
        entry_hash: entry.entry_hash(),
        signature: entry.signature(),
        signature_key_version: entry.signature_key_version(),
    })?;

    assert!(matches!(
        verify_ledger_chain(
            &[tampered],
            LedgerChainHead::genesis(),
            std::slice::from_ref(&verification_key)
        ),
        Err(LedgerError::PreviousHashMismatch { sequence_no: 1 })
    ));

    let sequence_gap_entry =
        sample_entry_draft(sample_payload_ordered()?, LedgerSequenceNo::new(2)?)?
            .sign(&signing_key)?;
    assert!(matches!(
        verify_ledger_chain(
            &[sequence_gap_entry],
            LedgerChainHead::genesis(),
            &[verification_key]
        ),
        Err(LedgerError::SequenceGap {
            expected: 1,
            actual: 2
        })
    ));

    Ok(())
}

#[test]
fn ledger_signature_key_version_mismatch_and_unknown_key_are_rejected() -> TestResult {
    let signing_key = sample_signing_key(1)?;
    let public_key_bytes = signing_key.verification_key().as_bytes();
    let mismatched_key = LedgerVerifyingKey::from_public_key_bytes(
        LedgerSignatureKeyVersion::new(2)?,
        &public_key_bytes,
    )?;
    let entry = sample_entry_draft(sample_payload_ordered()?, LedgerSequenceNo::new(1)?)?
        .sign(&signing_key)?;

    assert!(matches!(
        entry.verify_signature(&mismatched_key),
        Err(LedgerError::SignatureKeyVersionMismatch {
            expected: 1,
            actual: 2
        })
    ));
    assert!(matches!(
        verify_ledger_chain(&[entry], LedgerChainHead::genesis(), &[]),
        Err(LedgerError::UnknownSignatureKey { key_version: 1, .. })
    ));

    Ok(())
}

#[test]
fn ledger_signature_verification_fails_with_different_public_key() -> TestResult {
    let signing_key = sample_signing_key(1)?;
    let different_signing_key = sample_signing_key_with_seed(1, &[7u8; 32])?;
    let different_verification_key = different_signing_key.verification_key();
    let entry = sample_entry_draft(sample_payload_ordered()?, LedgerSequenceNo::new(1)?)?
        .sign(&signing_key)?;

    assert!(matches!(
        entry.verify_signature(&different_verification_key),
        Err(LedgerError::SignatureInvalid { .. })
    ));

    Ok(())
}

#[test]
fn ledger_key_rotation_keeps_old_signatures_verifiable_with_old_public_key() -> TestResult {
    let old_signing_key = sample_signing_key_with_seed(1, &[9u8; 32])?;
    let new_signing_key = sample_signing_key_with_seed(2, &[7u8; 32])?;
    let old_entry = sample_entry_draft_with_signature_key_version(
        sample_payload_ordered()?,
        LedgerSequenceNo::new(1)?,
        LedgerHash::genesis(),
        LedgerSignatureKeyVersion::new(1)?,
    )?
    .sign(&old_signing_key)?;
    let new_entry = sample_entry_draft_with_signature_key_version(
        sample_payload_ordered()?,
        LedgerSequenceNo::new(2)?,
        old_entry.entry_hash(),
        LedgerSignatureKeyVersion::new(2)?,
    )?
    .sign(&new_signing_key)?;
    let old_verification_key = old_signing_key.verification_key();
    let new_verification_key = new_signing_key.verification_key();

    let head = verify_ledger_chain(
        &[old_entry.clone(), new_entry],
        LedgerChainHead::genesis(),
        &[old_verification_key, new_verification_key.clone()],
    )?;

    assert_eq!(head.last_sequence_no(), 2);
    assert!(matches!(
        verify_ledger_chain(
            &[old_entry],
            LedgerChainHead::genesis(),
            &[new_verification_key]
        ),
        Err(LedgerError::UnknownSignatureKey { key_version: 1, .. })
    ));

    Ok(())
}

#[test]
fn ledger_payload_debug_redacts_contents() -> TestResult {
    let payload = sample_payload_ordered()?;
    let payload_debug = format!("{payload:?}");

    assert!(payload_debug.contains("<redacted>"));
    assert!(!payload_debug.contains("confidential"));
    assert!(!payload_debug.contains("xchacha20-poly1305"));

    Ok(())
}

#[test]
fn ledger_signing_key_debug_redacts_key_material() -> TestResult {
    let signing_key = sample_signing_key(1)?;
    let key_debug = format!("{signing_key:?}");

    assert!(key_debug.contains("<redacted>"));
    assert!(!key_debug.contains("090909"));

    Ok(())
}

fn sample_signed_entry(
    payload: LedgerPayload,
    sequence_no: LedgerSequenceNo,
) -> Result<SignedLedgerEntry, LedgerError> {
    sample_entry_draft(payload, sequence_no)?.sign(&sample_signing_key(1)?)
}

fn sample_entry_draft(
    payload: LedgerPayload,
    sequence_no: LedgerSequenceNo,
) -> Result<LedgerEntryDraft, LedgerError> {
    sample_entry_draft_with_previous_hash(payload, sequence_no, LedgerHash::genesis())
}

fn sample_entry_draft_with_previous_hash(
    payload: LedgerPayload,
    sequence_no: LedgerSequenceNo,
    previous_entry_hash: LedgerHash,
) -> Result<LedgerEntryDraft, LedgerError> {
    sample_entry_draft_with_signature_key_version(
        payload,
        sequence_no,
        previous_entry_hash,
        LedgerSignatureKeyVersion::new(1)?,
    )
}

fn sample_entry_draft_with_signature_key_version(
    payload: LedgerPayload,
    sequence_no: LedgerSequenceNo,
    previous_entry_hash: LedgerHash,
    signature_key_version: LedgerSignatureKeyVersion,
) -> Result<LedgerEntryDraft, LedgerError> {
    LedgerEntryDraft::new(LedgerEntryDraftParts {
        ledger_entry_id: LedgerEntryId::parse("22222222-2222-4222-8222-222222222222")?,
        sequence_no,
        entry_type: LedgerEntryType::SecretCreated,
        source_event_at: SourceEventAt::parse("2026-04-08T12:00:00Z").map_err(|_| {
            LedgerError::InvalidPayloadField {
                key: "source_event_at".to_owned(),
                expected: "a canonical UTC RFC3339 timestamp",
            }
        })?,
        request_id: RequestId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").map_err(|_| {
            LedgerError::InvalidUuid {
                field: "request_id",
            }
        })?,
        source_event_id: None,
        target_secret_id: Some(
            SecretId::parse("550e8400-e29b-41d4-a716-446655440000").map_err(|_| {
                LedgerError::InvalidUuid {
                    field: "target_secret_id",
                }
            })?,
        ),
        target_secret_version_id: Some(LedgerTargetSecretVersionId::parse(
            "11111111-2222-4333-8444-555555555555",
        )?),
        actor_user_id: Some(
            OwnerUserId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").map_err(|_| {
                LedgerError::InvalidUuid {
                    field: "actor_user_id",
                }
            })?,
        ),
        actor_device_id: Some(
            DeviceId::new("sbc-device-1").map_err(|_| LedgerError::InvalidActorDeviceId)?,
        ),
        result: LedgerResult::Success,
        error_code: None,
        payload,
        previous_entry_hash,
        signature_key_version,
    })
}

fn sample_payload_ordered() -> Result<LedgerPayload, LedgerError> {
    LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "algorithm": "xchacha20-poly1305",
            "classification": "confidential",
            "key_version": 1,
            "version": 1
        }),
    )
}

fn sample_payload_reordered() -> Result<LedgerPayload, LedgerError> {
    LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "version": 1,
            "key_version": 1,
            "classification": "confidential",
            "algorithm": "xchacha20-poly1305"
        }),
    )
}

fn sample_signing_key(version: u32) -> Result<LedgerSigningKey, LedgerError> {
    sample_signing_key_with_seed(version, &[9u8; 32])
}

fn sample_signing_key_with_seed(
    version: u32,
    seed: &[u8],
) -> Result<LedgerSigningKey, LedgerError> {
    LedgerSigningKey::from_secret_key_bytes(LedgerSignatureKeyVersion::new(version)?, seed)
}

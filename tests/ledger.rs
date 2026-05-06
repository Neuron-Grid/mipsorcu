use mipsorcu::{
    DeviceId, LedgerChainHead, LedgerEntryDraft, LedgerEntryDraftParts, LedgerEntryId,
    LedgerEntryType, LedgerError, LedgerHash, LedgerPayload, LedgerResult, LedgerSequenceNo,
    LedgerSignatureKeyVersion, LedgerSigningKey, LedgerTargetSecretVersionId,
    LedgerVerificationKey, OwnerUserId, RequestId, SecretId, SignedLedgerEntry,
    SignedLedgerEntryParts, SourceEventAt, verify_ledger_chain,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CANONICAL_VECTOR: &str = r#"{"schema":"mipsorcu.ledger_entry.v1","sequence_no":1,"entry_type":"secret_created","source_event_at":"2026-04-08T12:00:00Z","request_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","source_event_id":null,"target_secret_id":"550e8400-e29b-41d4-a716-446655440000","target_secret_version_id":"11111111-2222-4333-8444-555555555555","actor_user_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479","actor_device_id":"sbc-device-1","result":"success","error_code":null,"payload":{"algorithm":"xchacha20-poly1305","classification":"confidential","key_version":1,"version":1},"canonicalization_version":1,"previous_entry_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash_algorithm":"sha-256","signature_algorithm":"ed25519","signature_key_version":1}"#;
const CANONICAL_VECTOR_HASH: &str =
    "8d63bba7d0c4b972f0134df8ffad728330897312bb556ddbea27ff708294a93b";

#[test]
fn canonical_payload_matches_fixed_vector_and_is_stable() -> TestResult {
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
fn same_meaning_uuid_and_payload_order_produce_same_canonical_payload() -> TestResult {
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
fn payload_key_order_does_not_change_hash() -> TestResult {
    let ordered = sample_signed_entry(sample_payload_ordered()?, LedgerSequenceNo::new(1)?)?;
    let reordered = sample_signed_entry(sample_payload_reordered()?, LedgerSequenceNo::new(1)?)?;

    assert_eq!(ordered.entry_hash(), reordered.entry_hash());

    Ok(())
}

#[test]
fn payload_rejects_unknown_forbidden_and_nested_values() -> TestResult {
    let unknown = LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "algorithm": "xchacha20-poly1305",
            "unexpected": 1
        }),
    );
    assert!(matches!(
        unknown,
        Err(LedgerError::UnknownPayloadKey { .. })
    ));

    let forbidden = LedgerPayload::new(
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
        forbidden,
        Err(LedgerError::ForbiddenPayloadKey { .. })
    ));

    let nested = LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "algorithm": { "value": "xchacha20-poly1305" },
            "classification": "confidential",
            "key_version": 1,
            "version": 1
        }),
    );
    assert!(matches!(
        nested,
        Err(LedgerError::PayloadValueMustBeScalar { .. })
    ));

    Ok(())
}

#[test]
fn signature_verifies_and_chain_verification_accepts_valid_entry() -> TestResult {
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
fn payload_tampering_makes_signature_verification_fail() -> TestResult {
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
        Err(LedgerError::SignatureInvalid)
    ));

    Ok(())
}

#[test]
fn previous_hash_tampering_and_sequence_gap_are_detected() -> TestResult {
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
fn signature_key_version_mismatch_and_unknown_key_are_rejected() -> TestResult {
    let signing_key = sample_signing_key(1)?;
    let public_key_bytes = signing_key.verification_key().as_bytes();
    let mismatched_key = LedgerVerificationKey::from_public_key_bytes(
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
        Err(LedgerError::UnknownSignatureKey { key_version: 1 })
    ));

    Ok(())
}

#[test]
fn debug_output_redacts_payload_and_signing_key_material() -> TestResult {
    let payload = sample_payload_ordered()?;
    let signing_key = sample_signing_key(1)?;
    let payload_debug = format!("{payload:?}");
    let key_debug = format!("{signing_key:?}");

    assert!(payload_debug.contains("<redacted>"));
    assert!(!payload_debug.contains("confidential"));
    assert!(!payload_debug.contains("xchacha20-poly1305"));
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
        previous_entry_hash: LedgerHash::genesis(),
        signature_key_version: LedgerSignatureKeyVersion::new(1)?,
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
    LedgerSigningKey::from_secret_key_bytes(LedgerSignatureKeyVersion::new(version)?, &[9u8; 32])
}

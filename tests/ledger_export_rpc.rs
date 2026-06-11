use mipsorcu::ledger::{
    LedgerEntryDraft, LedgerEntryDraftParts, LedgerEntryId, LedgerEntryType, LedgerError,
    LedgerHash, LedgerPayload, LedgerResult, LedgerSequenceNo, LedgerSignatureKeyVersion,
    LedgerSigningKey, LedgerTargetSecretVersionId, SignedLedgerEntry,
};
use mipsorcu::server::supabase::{
    ExportLedgerError, LedgerVerificationMaterialRow, SupabaseRpcError,
    classify_export_ledger_error,
};
use mipsorcu::types::{DeviceId, OwnerUserId, SecretId};
use mipsorcu::{RequestId, SourceEventAt};
use serde_json::json;

// Real ed25519 test keypair so signatures are cryptographically valid
const TEST_SECRET_KEY_BYTES: [u8; 32] = [
    0x98, 0x3b, 0x6e, 0x5f, 0x0f, 0x8a, 0xa1, 0x56, 0x2e, 0x5a, 0x4e, 0x7b, 0x9f, 0x0d, 0x2b, 0x7f,
    0x8c, 0x3a, 0x4d, 0x7e, 0x9f, 0xa2, 0xc1, 0x5d, 0x6b, 0x8e, 0x3f, 0xa2, 0xc1, 0x5d, 0x6b, 0x8e,
];

fn test_ledger_signing_key() -> LedgerSigningKey {
    LedgerSigningKey::from_secret_key_bytes(
        LedgerSignatureKeyVersion::new(1).expect("valid key version"),
        &TEST_SECRET_KEY_BYTES,
    )
    .expect("valid signing key")
}

fn test_signed_ledger_entry() -> (SignedLedgerEntry, [u8; 32]) {
    let signing_key = test_ledger_signing_key();
    let verification_key = signing_key.verification_key();
    let public_key_bytes = verification_key.as_bytes();

    let payload = LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "algorithm": "xchacha20-poly1305",
            "classification": "confidential",
            "key_version": 1,
            "version": 1
        }),
    )
    .expect("valid payload");

    let draft = LedgerEntryDraft::new(LedgerEntryDraftParts {
        ledger_entry_id: LedgerEntryId::parse("22222222-2222-4222-8222-222222222222")
            .expect("valid ledger entry id"),
        sequence_no: LedgerSequenceNo::new(1).expect("valid sequence no"),
        entry_type: LedgerEntryType::SecretCreated,
        source_event_at: SourceEventAt::parse("2026-04-08T12:00:00Z")
            .expect("valid source_event_at"),
        request_id: RequestId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            .expect("valid request id"),
        source_event_id: None,
        target_secret_id: Some(
            SecretId::parse("550e8400-e29b-41d4-a716-446655440000").expect("valid secret id"),
        ),
        target_secret_version_id: Some(
            LedgerTargetSecretVersionId::parse("11111111-2222-4333-8444-555555555555")
                .expect("valid version id"),
        ),
        actor_user_id: Some(
            OwnerUserId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("valid user id"),
        ),
        actor_device_id: Some(DeviceId::new("test-device").expect("valid device id")),
        result: LedgerResult::Success,
        error_code: None,
        payload,
        previous_entry_hash: LedgerHash::genesis(),
        signature_key_version: LedgerSignatureKeyVersion::new(1).expect("valid key version"),
    })
    .expect("valid draft");

    let signed = draft.sign(&signing_key).expect("valid signature");
    (signed, public_key_bytes)
}

fn make_dto_row(
    signed: &SignedLedgerEntry,
    public_key_bytes: &[u8; 32],
    pk_status: Option<&str>,
) -> LedgerVerificationMaterialRow {
    use mipsorcu::ledger::{
        LEDGER_CANONICALIZATION_VERSION_V1, LEDGER_HASH_ALGORITHM_SHA3_256,
        LEDGER_SIGNATURE_ALGORITHM_ED25519,
    };

    let pk_key_version = pk_status.map(|_| 1i32);
    let pk_public_key = pk_status.map(|_| format!("\\x{}", hex::encode(public_key_bytes)));
    let pk_algorithm = pk_status.map(|_| "ed25519".to_owned());
    let pk_status = pk_status.map(str::to_owned);

    LedgerVerificationMaterialRow {
        ledger_entry_id: signed.ledger_entry_id().clone(),
        sequence_no: signed.sequence_no(),
        entry_hash: signed.entry_hash(),
        previous_entry_hash: signed.previous_entry_hash(),
        signature: signed.signature(),
        signature_key_version: signed.signature_key_version(),
        entry_type: signed.entry_type().as_str().to_owned(),
        source_event_at: signed.source_event_at().as_str().to_owned(),
        request_id: signed.request_id().as_canonical_string(),
        source_event_id: signed
            .source_event_id()
            .map(|event_id| event_id.as_canonical_string()),
        target_secret_id: signed
            .target_secret_id()
            .map(|secret_id| secret_id.as_canonical_string()),
        target_secret_version_id: signed
            .target_secret_version_id()
            .map(|version_id| version_id.as_canonical_string()),
        actor_user_id: signed
            .actor_user_id()
            .map(|user_id| user_id.as_canonical_string()),
        actor_device_id: signed
            .actor_device_id()
            .map(|device_id| device_id.as_str().to_owned()),
        result: signed.result().as_str().to_owned(),
        error_code: signed.error_code().map(str::to_owned),
        payload: signed.payload().as_value(),
        canonicalization_version: LEDGER_CANONICALIZATION_VERSION_V1 as i32,
        hash_algorithm: LEDGER_HASH_ALGORITHM_SHA3_256.to_owned(),
        signature_algorithm: LEDGER_SIGNATURE_ALGORITHM_ED25519.to_owned(),
        pk_key_version,
        pk_public_key,
        pk_algorithm,
        pk_status,
    }
}

// ---- restoration tests ----

#[test]
fn restore_signed_ledger_entry_from_export_row() {
    let (signed, public_key_bytes) = test_signed_ledger_entry();
    let row = make_dto_row(&signed, &public_key_bytes, Some("active"));

    let restored = row
        .try_restore_signed_ledger_entry()
        .expect("should restore signed ledger entry");

    // Core verification fields must match
    assert_eq!(restored.sequence_no(), signed.sequence_no());
    assert_eq!(restored.entry_hash(), signed.entry_hash());
    assert_eq!(restored.previous_entry_hash(), signed.previous_entry_hash());
    assert_eq!(restored.signature(), signed.signature());
    assert_eq!(
        restored.signature_key_version(),
        signed.signature_key_version()
    );
    assert_eq!(restored.entry_type(), signed.entry_type());
}

#[test]
fn restore_active_verifying_key() {
    let (signed, public_key_bytes) = test_signed_ledger_entry();
    let row = make_dto_row(&signed, &public_key_bytes, Some("active"));

    let key = row
        .try_restore_verifying_key()
        .expect("should restore key")
        .expect("key should be present");

    assert_eq!(key.key_version().get(), 1);
    assert_eq!(key.as_bytes(), public_key_bytes);

    // Key must be usable for signature verification via SignedLedgerEntry::verify_signature
    signed
        .verify_signature(&key)
        .expect("signature should verify against restored key");
}

#[test]
fn restore_retired_verifying_key() {
    let (signed, public_key_bytes) = test_signed_ledger_entry();
    let row = make_dto_row(&signed, &public_key_bytes, Some("retired"));

    let key = row
        .try_restore_verifying_key()
        .expect("should restore key")
        .expect("key should be present");

    assert_eq!(key.key_version().get(), 1);
    assert_eq!(key.as_bytes(), public_key_bytes);

    // Retired key must still be usable for verification via SignedLedgerEntry::verify_signature
    signed
        .verify_signature(&key)
        .expect("signature should verify against retired key");
}

#[test]
fn restore_created_verifying_key_for_lifecycle_entries() {
    let (signed, public_key_bytes) = test_signed_ledger_entry();
    let row = make_dto_row(&signed, &public_key_bytes, Some("created"));

    let key = row
        .try_restore_verifying_key()
        .expect("should restore key")
        .expect("key should be present");

    assert_eq!(key.key_version().get(), 1);
    assert_eq!(key.as_bytes(), public_key_bytes);
}

#[test]
fn detect_missing_public_key() {
    let (signed, public_key_bytes) = test_signed_ledger_entry();
    let row = make_dto_row(&signed, &public_key_bytes, None);

    let result = row
        .try_restore_verifying_key()
        .expect("should not error on missing key");

    assert!(
        result.is_none(),
        "missing key should produce None (caller should map to UnknownSignatureKey)"
    );
}

#[test]
fn detect_key_version_mismatch() {
    let (signed, public_key_bytes) = test_signed_ledger_entry();
    let mut row = make_dto_row(&signed, &public_key_bytes, Some("active"));
    // Override pk_key_version to not match signature_key_version
    row.pk_key_version = Some(99);

    let result = row.try_restore_verifying_key();
    assert!(
        matches!(result, Err(LedgerError::SignatureKeyVersionMismatch { .. })),
        "expected SignatureKeyVersionMismatch, got {result:?}"
    );
}

#[test]
fn reject_negative_public_key_version_before_mismatch() {
    let (signed, public_key_bytes) = test_signed_ledger_entry();
    let mut row = make_dto_row(&signed, &public_key_bytes, Some("active"));
    row.pk_key_version = Some(-1);

    let result = row.try_restore_verifying_key();
    assert!(
        matches!(
            result,
            Err(LedgerError::InvalidPositiveInteger {
                field: "signature_key_version"
            })
        ),
        "expected InvalidPositiveInteger for negative pk_key_version, got {result:?}"
    );
}

#[test]
fn detect_invalid_bytea_public_key_encoding() {
    let (signed, _public_key_bytes) = test_signed_ledger_entry();
    let row = LedgerVerificationMaterialRow {
        pk_key_version: Some(1),
        pk_public_key: Some("not-bytea-hex".to_owned()),
        pk_algorithm: Some("ed25519".to_owned()),
        pk_status: Some("active".to_owned()),
        ..make_dto_row(&signed, &[0u8; 32], Some("active"))
    };

    let result = row.try_restore_verifying_key();
    assert!(
        matches!(result, Err(LedgerError::InvalidVerificationKey)),
        "expected InvalidVerificationKey for invalid bytea, got {result:?}"
    );
}

#[test]
fn detect_invalid_bytea_public_key_hex() {
    let (signed, _public_key_bytes) = test_signed_ledger_entry();
    let row = LedgerVerificationMaterialRow {
        pk_key_version: Some(1),
        pk_public_key: Some("\\xzzzz".to_owned()), // invalid hex
        pk_algorithm: Some("ed25519".to_owned()),
        pk_status: Some("active".to_owned()),
        ..make_dto_row(&signed, &[0u8; 32], Some("active"))
    };

    let result = row.try_restore_verifying_key();
    assert!(
        matches!(result, Err(LedgerError::InvalidVerificationKey)),
        "expected InvalidVerificationKey for bad hex, got {result:?}"
    );
}

#[test]
fn reject_non_ed25519_algorithm() {
    let (signed, public_key_bytes) = test_signed_ledger_entry();
    let mut row = make_dto_row(&signed, &public_key_bytes, Some("active"));
    row.pk_algorithm = Some("ecdsa-p256".to_owned());

    let result = row.try_restore_verifying_key();
    assert!(
        matches!(result, Err(LedgerError::InvalidVerificationKey)),
        "expected InvalidVerificationKey for non-ed25519 algorithm, got {result:?}"
    );
}

#[test]
fn reject_unknown_key_status() {
    let (signed, public_key_bytes) = test_signed_ledger_entry();
    let mut row = make_dto_row(&signed, &public_key_bytes, Some("active"));
    row.pk_status = Some("revoked".to_owned());

    let result = row.try_restore_verifying_key();
    assert!(
        matches!(result, Err(LedgerError::InvalidVerificationKey)),
        "expected InvalidVerificationKey for unknown status, got {result:?}"
    );
}

#[test]
fn reject_wrong_length_public_key() {
    let (signed, _public_key_bytes) = test_signed_ledger_entry();
    let row = LedgerVerificationMaterialRow {
        pk_key_version: Some(1),
        pk_public_key: Some(format!("\\x{}", hex::encode([0u8; 16]))), // 16 bytes, not 32
        pk_algorithm: Some("ed25519".to_owned()),
        pk_status: Some("active".to_owned()),
        ..make_dto_row(&signed, &[0u8; 32], Some("active"))
    };

    let result = row.try_restore_verifying_key();
    assert!(
        matches!(
            result,
            Err(LedgerError::InvalidVerificationKeyLength { actual: 16 })
        ),
        "expected InvalidVerificationKeyLength, got {result:?}"
    );
}

#[test]
fn tampered_previous_entry_hash_is_preserved_for_chain_verification() {
    let (signed, public_key_bytes) = test_signed_ledger_entry();
    // Tamper with previous_entry_hash — verify_ledger_chain would later
    // detect this as a previous_hash mismatch.
    let mut row = make_dto_row(&signed, &public_key_bytes, Some("active"));
    let tampered_prev = LedgerHash::from_bytes(&[0xffu8; 32]).expect("valid hash");
    row.previous_entry_hash = tampered_prev;

    let restored = row
        .try_restore_signed_ledger_entry()
        .expect("should restore entry");

    // The tampered previous_entry_hash propagates into the restored entry
    assert_eq!(restored.previous_entry_hash(), tampered_prev);
    assert_ne!(
        restored.previous_entry_hash(),
        signed.previous_entry_hash(),
        "previous_entry_hash should reflect tampering"
    );
    // entry_hash is preserved as-is from the DB row
    assert_eq!(restored.entry_hash(), signed.entry_hash());
}

// ---- error classification tests ----

#[test]
fn export_ledger_error_classification_invalid_rpc_input() {
    let body = r#"{"hint":"invalid_rpc_input: bad sequence range"}"#.to_owned();
    let error = SupabaseRpcError::NonSuccessStatus { status: 400, body };

    assert_eq!(
        classify_export_ledger_error(&error),
        ExportLedgerError::InvalidRpcInput
    );
    assert_eq!(
        classify_export_ledger_error(&error).as_error_code(),
        "ledger_export_invalid_rpc_input"
    );
}

#[test]
fn export_ledger_error_classification_fallbacks_to_export_failed() {
    let body = r#"{"message":"database connection timed out"}"#.to_owned();
    let error = SupabaseRpcError::NonSuccessStatus { status: 500, body };

    assert_eq!(
        classify_export_ledger_error(&error),
        ExportLedgerError::ExportFailed
    );
    assert_eq!(
        classify_export_ledger_error(&error).as_error_code(),
        "ledger_export_failed"
    );
}

#[test]
fn export_ledger_error_does_not_expose_body() {
    let body = r#"{"hint":"invalid_rpc_input with secret upstream state"}"#.to_owned();
    let error = SupabaseRpcError::NonSuccessStatus { status: 400, body };
    let classification = classify_export_ledger_error(&error);

    assert_eq!(
        classification.as_error_code(),
        "ledger_export_invalid_rpc_input"
    );
    // Error Debug/Display must not leak body contents
    assert!(!format!("{error:?}").contains("secret upstream state"));
    assert!(!error.to_string().contains("secret upstream state"));
}

use std::error::Error;

use mipsorcu::server::dto::RotateSecretRequest;
use mipsorcu::server::handlers::testing;
use mipsorcu::server::supabase::{SecretReadJoin, SecretVersionReadRow};
use mipsorcu::{
    AuditAction, AuditEventId, AuditMetadata, AuditResult, ENCRYPTED_DATA_KEY_LENGTH, OwnerUserId,
    RequestId, SecretId,
};
use serde_json::json;

const SECRET_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const AUDIT_EVENT_ID: &str = "11111111-1111-4111-8111-111111111111";
const REQUEST_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const CREATED_AT: &str = "2026-04-08T12:00:00Z";

type TestResult<T> = Result<T, Box<dyn Error>>;

fn valid_row() -> SecretVersionReadRow {
    SecretVersionReadRow {
        id: "650e8400-e29b-41d4-a716-446655440000".to_owned(),
        secret_id: SECRET_ID.to_owned(),
        version: 1,
        ciphertext: "\\x01".to_owned(),
        encrypted_data_key: format!("\\x01{}", "00".repeat(72)),
        key_version: 1,
        algorithm: mipsorcu::ALGORITHM_XCHACHA20_POLY1305.to_owned(),
        classification: "confidential".to_owned(),
        nonce_or_iv: format!("\\x{}", "00".repeat(24)),
        aad_context: json!({
            "aad_version": 1,
            "secret_id": SECRET_ID,
            "version": 1,
            "owner_user_id": OWNER_USER_ID,
            "classification": "confidential",
            "created_at": CREATED_AT,
        }),
        created_by_user_id: OWNER_USER_ID.to_owned(),
        created_at: CREATED_AT.to_owned(),
        secrets: SecretReadJoin {
            current_version_id: "650e8400-e29b-41d4-a716-446655440000".to_owned(),
            owner_user_id: OWNER_USER_ID.to_owned(),
            classification: "confidential".to_owned(),
        },
    }
}

#[test]
fn failure_audit_event_allows_attempted_secret_without_fk_target() -> TestResult<()> {
    let request_id = RequestId::parse(REQUEST_ID)?;
    let actor_user_id = OwnerUserId::parse(OWNER_USER_ID)?;
    let secret_id = SecretId::parse(SECRET_ID)?;
    let metadata_json = AuditMetadata::empty().with_attempted_secret_id(&secret_id)?;

    let event = testing::build_failure_audit_event(
        AuditEventId::parse(AUDIT_EVENT_ID)?,
        &request_id,
        Some(&actor_user_id),
        None,
        AuditAction::EncryptCreate,
        metadata_json,
    )?;

    assert!(event.target_secret_id().is_none());
    assert_eq!(
        event.metadata_json().as_value()["attempted_secret_id"],
        SECRET_ID
    );
    assert_eq!(event.action(), AuditAction::EncryptCreate);
    assert_eq!(event.result(), AuditResult::Failure);

    Ok(())
}

#[test]
fn failure_audit_event_keeps_existing_secret_target_for_other_failures() -> TestResult<()> {
    let request_id = RequestId::parse(REQUEST_ID)?;
    let actor_user_id = OwnerUserId::parse(OWNER_USER_ID)?;
    let target_secret_id = SecretId::parse(SECRET_ID)?;

    let event = testing::build_failure_audit_event(
        AuditEventId::parse(AUDIT_EVENT_ID)?,
        &request_id,
        Some(&actor_user_id),
        Some(&target_secret_id),
        AuditAction::Decrypt,
        AuditMetadata::empty(),
    )?;

    assert_eq!(
        event.target_secret_id().map(SecretId::as_canonical_string),
        Some(SECRET_ID.to_owned())
    );
    assert_eq!(event.metadata_json().as_value(), &serde_json::json!({}));

    Ok(())
}

#[test]
fn parse_decrypt_row_accepts_valid_supabase_row() {
    let parsed = testing::parse_decrypt_row(valid_row()).expect("valid row should parse");

    assert_eq!(parsed.secret_id().as_canonical_string(), SECRET_ID);
    assert_eq!(parsed.version().get(), 1);
    assert_eq!(parsed.key_version().get(), 1);
    assert_eq!(parsed.nonce_or_iv().as_bytes().len(), 24);
    assert_eq!(parsed.ciphertext().as_bytes(), &[1]);
}

#[test]
fn parsed_row_builds_current_secret_version_state_for_rotation() {
    let parsed = testing::parse_decrypt_row(valid_row()).expect("valid row should parse");
    let current = parsed.into_current_secret_version_state();

    assert_eq!(current.secret_id().as_canonical_string(), SECRET_ID);
    assert_eq!(current.current_version().get(), 1);
    assert_eq!(current.owner_user_id().as_canonical_string(), OWNER_USER_ID);
    assert_eq!(current.classification().as_str(), "confidential");
    assert_eq!(current.key_version().get(), 1);
    assert_eq!(
        current.encrypted_data_key().as_bytes().len(),
        ENCRYPTED_DATA_KEY_LENGTH
    );
    assert_eq!(current.encrypted_data_key().version(), 1);
}

#[test]
fn select_single_current_secret_version_row_returns_only_current_row() {
    let current = valid_row();
    let mut old = valid_row();
    old.id = "750e8400-e29b-41d4-a716-446655440000".to_owned();
    old.version = 0;

    let selected = testing::select_single_current_secret_version_row(vec![old, current])
        .expect("one current row should be selected");

    assert_eq!(selected.id, "650e8400-e29b-41d4-a716-446655440000");
    assert_eq!(selected.version, 1);
}

#[test]
fn select_single_current_secret_version_row_maps_no_current_row_to_not_found() {
    let mut old = valid_row();
    old.id = "750e8400-e29b-41d4-a716-446655440000".to_owned();

    assert!(matches!(
        testing::select_single_current_secret_version_row(vec![old]),
        Err(mipsorcu::server::errors::ApiError::NotFound(message)) if message == "secret not found"
    ));
}

#[test]
fn select_single_current_secret_version_row_rejects_multiple_current_rows() {
    let first = valid_row();
    let second = valid_row();

    assert!(matches!(
        testing::select_single_current_secret_version_row(vec![first, second]),
        Err(mipsorcu::server::errors::ApiError::InternalInvariantViolation(_))
    ));
}

#[test]
fn parse_decrypt_row_rejects_invalid_lengths_and_metadata() {
    let mut bad_nonce = valid_row();
    bad_nonce.nonce_or_iv = "\\x00".to_owned();
    assert!(matches!(
        testing::parse_decrypt_row(bad_nonce),
        Err(mipsorcu::server::errors::ApiError::DbIntegrityViolation(_))
    ));

    let mut empty_ciphertext = valid_row();
    empty_ciphertext.ciphertext = "\\x".to_owned();
    assert!(matches!(
        testing::parse_decrypt_row(empty_ciphertext),
        Err(mipsorcu::server::errors::ApiError::DbIntegrityViolation(_))
    ));

    let mut owner_mismatch = valid_row();
    owner_mismatch.created_by_user_id = "f47ac10b-58cc-4372-a567-0e02b2c3d480".to_owned();
    assert!(matches!(
        testing::parse_decrypt_row(owner_mismatch),
        Err(mipsorcu::server::errors::ApiError::DbIntegrityViolation(_))
    ));

    let mut bad_algorithm = valid_row();
    bad_algorithm.algorithm = "chacha20-poly1305".to_owned();
    assert!(matches!(
        testing::parse_decrypt_row(bad_algorithm),
        Err(mipsorcu::server::errors::ApiError::DbIntegrityViolation(_))
    ));

    let mut non_current = valid_row();
    non_current.secrets.current_version_id = "750e8400-e29b-41d4-a716-446655440000".to_owned();
    assert!(matches!(
        testing::parse_decrypt_row(non_current),
        Err(mipsorcu::server::errors::ApiError::DbIntegrityViolation(_))
    ));

    let mut classification_mismatch = valid_row();
    classification_mismatch.classification = "restricted".to_owned();
    assert!(matches!(
        testing::parse_decrypt_row(classification_mismatch),
        Err(mipsorcu::server::errors::ApiError::DbIntegrityViolation(_))
    ));

    let mut bad_encrypted_data_key = valid_row();
    bad_encrypted_data_key.encrypted_data_key = "\\x01".to_owned();
    assert!(matches!(
        testing::parse_decrypt_row(bad_encrypted_data_key),
        Err(mipsorcu::server::errors::ApiError::DbIntegrityViolation(_))
    ));
}

#[test]
fn validate_rotate_secret_request_rejects_invalid_device_id_and_plaintext() {
    let invalid_device_id = RotateSecretRequest {
        device_id: "   ".to_owned(),
        plaintext: "00".to_owned(),
    };
    assert!(matches!(
        testing::validate_rotate_secret_request(invalid_device_id),
        Err(mipsorcu::server::errors::ApiError::BadRequest(_))
    ));

    let invalid_plaintext = RotateSecretRequest {
        device_id: "sbc-device-1".to_owned(),
        plaintext: "not hex".to_owned(),
    };
    assert!(matches!(
        testing::validate_rotate_secret_request(invalid_plaintext),
        Err(mipsorcu::server::errors::ApiError::BadRequest(_))
    ));
}

#[test]
fn decode_bytea_requires_postgres_hex_prefix() {
    assert_eq!(
        testing::decode_bytea("\\x0a0b").expect("bytea should decode"),
        vec![10, 11]
    );
    assert!(matches!(
        testing::decode_bytea("0a0b"),
        Err(mipsorcu::server::errors::ApiError::DecryptFailed)
    ));
    assert!(matches!(
        testing::decode_bytea("\\xzz"),
        Err(mipsorcu::server::errors::ApiError::DecryptFailed)
    ));
}

#[test]
fn parse_write_response_version_rejects_non_positive_values() {
    assert_eq!(
        testing::parse_write_response_version(1).expect("valid version"),
        1
    );
    assert!(matches!(
        testing::parse_write_response_version(0),
        Err(mipsorcu::server::errors::ApiError::InternalInvariantViolation(_))
    ));
    assert!(matches!(
        testing::parse_write_response_version(-1),
        Err(mipsorcu::server::errors::ApiError::InternalInvariantViolation(_))
    ));
}

use mipsorcu::server::dto::{CreateSecretRequest, RotateSecretRequest};
use serde_json::{Value, json};

const SECRET_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

#[test]
fn create_and_rotate_request_dto_require_plaintext_hex() {
    let create = serde_json::from_value::<CreateSecretRequest>(json!({
        "classification": "confidential",
        "device_id": "sbc-device-1",
        "plaintext": "00"
    }));
    let rotate = serde_json::from_value::<RotateSecretRequest>(json!({
        "device_id": "sbc-device-1",
        "plaintext": "00"
    }));

    assert!(create.is_err());
    assert!(rotate.is_err());
}

#[test]
fn decrypt_secret_response_serializes_plaintext_hex_and_encoding() {
    let response =
        mipsorcu::server::dto::DecryptSecretResponse::new(SECRET_ID.to_owned(), 3, b"dummy secret");

    let value = serde_json::to_value(response).expect("response should serialize");

    assert_eq!(value["secret_id"], Value::String(SECRET_ID.to_owned()));
    assert_eq!(value["version"], Value::from(3));
    assert_eq!(
        value["plaintext_hex"],
        Value::String("64756d6d7920736563726574".to_owned())
    );
    assert_eq!(value["encoding"], Value::String("hex".to_owned()));
}

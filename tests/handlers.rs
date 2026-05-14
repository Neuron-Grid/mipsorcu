use mipsorcu::server::dto::{
    CreateSecretAliasRequest, CreateSecretAliasResponse, CreateSecretRequest, RotateSecretRequest,
};
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

#[test]
fn create_secret_alias_request_rejects_unknown_fields() {
    let request = serde_json::from_value::<CreateSecretAliasRequest>(json!({
        "alias": "prod-api",
        "secret_id": SECRET_ID
    }));

    assert!(request.is_err());
}

#[test]
fn create_secret_alias_response_serializes_public_contract() {
    let response = CreateSecretAliasResponse {
        secret_id: SECRET_ID.to_owned(),
        alias: "Prod.API_1".to_owned(),
        alias_normalized: "prod.api_1".to_owned(),
    };

    let value = serde_json::to_value(response).expect("response should serialize");

    assert_eq!(value["secret_id"], Value::String(SECRET_ID.to_owned()));
    assert_eq!(value["alias"], Value::String("Prod.API_1".to_owned()));
    assert_eq!(
        value["alias_normalized"],
        Value::String("prod.api_1".to_owned())
    );
}

#[test]
fn secret_alias_validation_normalizes_and_rejects_uuid_values() {
    let alias = mipsorcu::SecretAlias::new("  Prod.API_1  ").expect("alias should parse");
    let normalized = alias.normalized();
    assert_eq!(alias.as_str(), "Prod.API_1");
    assert_eq!(normalized.as_str(), "prod.api_1");

    assert!(mipsorcu::SecretAlias::new("bad alias").is_err());
    assert!(mipsorcu::SecretAlias::new(&"a".repeat(129)).is_err());
    assert!(mipsorcu::SecretAlias::new(SECRET_ID).is_err());
}

#[test]
fn secret_ref_preserves_uuid_path_and_accepts_alias_path() {
    let by_id = mipsorcu::SecretRef::parse(SECRET_ID).expect("uuid secret ref should parse");
    let by_alias = mipsorcu::SecretRef::parse("Prod.API_1").expect("alias secret ref should parse");

    match by_id {
        mipsorcu::SecretRef::Id(secret_id) => {
            assert_eq!(secret_id.as_canonical_string(), SECRET_ID);
        }
        mipsorcu::SecretRef::Alias(_) => panic!("uuid secret_ref must stay an id"),
    }

    match by_alias {
        mipsorcu::SecretRef::Alias(alias_normalized) => {
            assert_eq!(alias_normalized.as_str(), "prod.api_1");
        }
        mipsorcu::SecretRef::Id(_) => panic!("alias secret_ref must stay an alias"),
    }
}

#[test]
fn alias_debug_does_not_expose_alias_value() {
    let alias = mipsorcu::SecretAlias::new("prod-secret").expect("alias should parse");
    let rendered = format!("{alias:?}");

    assert!(rendered.contains("SecretAlias"));
    assert!(!rendered.contains("prod-secret"));
}

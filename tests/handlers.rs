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
        secret_alias_id: "750e8400-e29b-41d4-a716-446655440000".to_owned(),
        secret_id: SECRET_ID.to_owned(),
    };

    let value = serde_json::to_value(response).expect("response should serialize");

    assert_eq!(
        value["secret_alias_id"],
        Value::String("750e8400-e29b-41d4-a716-446655440000".to_owned())
    );
    assert_eq!(value["secret_id"], Value::String(SECRET_ID.to_owned()));
    assert!(value.get("alias").is_none());
    assert!(value.get("alias_normalized").is_none());
}

#[test]
fn normalized_alias_validation_trims_and_rejects_invalid_values() {
    let alias = mipsorcu::NormalizedAlias::parse("  Prod_API-1  ").expect("alias should parse");
    assert_eq!(alias.as_str(), "Prod_API-1");

    assert!(mipsorcu::NormalizedAlias::parse("bad alias").is_err());
    assert!(mipsorcu::NormalizedAlias::parse(&"a".repeat(129)).is_err());
}

#[test]
fn secret_ref_preserves_uuid_path_and_accepts_alias_path() {
    let by_id = mipsorcu::SecretRef::parse(SECRET_ID).expect("uuid secret ref should parse");
    let by_alias = mipsorcu::SecretRef::parse("Prod_API-1").expect("alias secret ref should parse");

    match by_id {
        mipsorcu::SecretRef::Id(secret_id) => {
            assert_eq!(secret_id.as_canonical_string(), SECRET_ID);
        }
        mipsorcu::SecretRef::Alias(_) => panic!("uuid secret_ref must stay an id"),
    }

    match by_alias {
        mipsorcu::SecretRef::Alias(alias) => {
            assert_eq!(alias.as_str(), "Prod_API-1");
        }
        mipsorcu::SecretRef::Id(_) => panic!("alias secret_ref must stay an alias"),
    }
}

#[test]
fn alias_debug_does_not_expose_alias_value() {
    let alias = mipsorcu::NormalizedAlias::parse("prod-secret").expect("alias should parse");
    let rendered = format!("{alias:?}");

    assert!(rendered.contains("NormalizedAlias"));
    assert!(!rendered.contains("prod-secret"));
}

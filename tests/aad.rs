use std::fmt;

use mipsorcu::aad::AAD_VERSION_V1;
use mipsorcu::{AadError, AadV1};
use proptest::prelude::*;
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::{Builder, Uuid};

#[derive(Debug, Clone)]
struct AadInput {
    secret_id: Uuid,
    version: u32,
    owner_user_id: Uuid,
    classification: String,
    created_at: OffsetDateTime,
}

impl AadInput {
    fn to_aad(&self) -> Result<AadV1, AadError> {
        AadV1::parse(
            &self.secret_id.hyphenated().to_string(),
            self.version,
            &self.owner_user_id.hyphenated().to_string(),
            &self.classification,
            &self.created_at_rfc3339()?,
        )
    }

    fn created_at_rfc3339(&self) -> Result<String, AadError> {
        self.created_at
            .format(&Rfc3339)
            .map_err(|error| AadError::SerializationFailed(error.to_string()))
    }
}

fn test_case_error(error: impl fmt::Display) -> proptest::test_runner::TestCaseError {
    proptest::test_runner::TestCaseError::fail(error.to_string())
}

fn uuid_strategy() -> impl Strategy<Value = Uuid> {
    any::<[u8; 16]>().prop_map(Uuid::from_bytes)
}

fn secret_id_strategy() -> impl Strategy<Value = Uuid> {
    any::<[u8; 16]>().prop_map(|bytes| Builder::from_random_bytes(bytes).into_uuid())
}

fn classification_strategy() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::char::range('a', 'z'), 1..32)
        .prop_map(|chars| chars.into_iter().collect())
}

fn timestamp_strategy() -> impl Strategy<Value = OffsetDateTime> {
    (0i64..4_102_444_800i64).prop_filter_map("valid unix timestamp", |seconds| {
        OffsetDateTime::from_unix_timestamp(seconds).ok()
    })
}

fn aad_input_strategy() -> impl Strategy<Value = AadInput> {
    (
        secret_id_strategy(),
        1u32..=1_000_000u32,
        uuid_strategy(),
        classification_strategy(),
        timestamp_strategy(),
    )
        .prop_map(
            |(secret_id, version, owner_user_id, classification, created_at)| AadInput {
                secret_id,
                version,
                owner_user_id,
                classification,
                created_at,
            },
        )
}

#[test]
fn canonical_json_uses_alphabetical_keys_without_extra_whitespace() -> Result<(), AadError> {
    let aad = AadV1::parse(
        "550e8400-e29b-41d4-a716-446655440000",
        3,
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "confidential",
        "2026-04-08T12:00:00Z",
    )?;

    let canonical = aad.canonical_json()?;
    let expected = r#"{"aad_version":1,"classification":"confidential","created_at":"2026-04-08T12:00:00Z","owner_user_id":"f47ac10b-58cc-4372-a567-0e02b2c3d479","secret_id":"550e8400-e29b-41d4-a716-446655440000","version":3}"#;

    assert_eq!(canonical, expected);

    Ok(())
}

#[test]
fn non_utc_timestamp_is_rejected() {
    let result = AadV1::parse(
        "550e8400-e29b-41d4-a716-446655440000",
        1,
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "confidential",
        "2026-04-08T21:00:00+09:00",
    );

    assert!(matches!(result, Err(AadError::InvalidTimestamp { .. })));
}

#[test]
fn secret_id_must_be_uuid_v4() {
    let result = AadV1::parse(
        "550e8400-e29b-11d4-a716-446655440000",
        1,
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "confidential",
        "2026-04-08T12:00:00Z",
    );

    assert!(matches!(
        result,
        Err(AadError::InvalidUuidVersion {
            field: "secret_id",
            ..
        })
    ));
}

#[test]
fn stored_context_rejects_unexpected_fields() -> Result<(), AadError> {
    let aad = AadV1::parse(
        "550e8400-e29b-41d4-a716-446655440000",
        1,
        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        "confidential",
        "2026-04-08T12:00:00Z",
    )?;
    let mut context = aad.to_stored_context()?;
    context
        .as_object_mut()
        .ok_or(AadError::ExpectedJsonObject)?
        .insert("unexpected".to_owned(), Value::String("value".to_owned()));

    let result = AadV1::from_stored_context(&context);

    assert!(matches!(
        result,
        Err(AadError::UnexpectedField { field }) if field == "unexpected"
    ));

    Ok(())
}

proptest! {
    #[test]
    fn aad_normalization_is_stable(input in aad_input_strategy()) {
        let aad = input.to_aad().map_err(test_case_error)?;
        let first = aad.canonical_bytes().map_err(test_case_error)?;
        let second = aad.canonical_bytes().map_err(test_case_error)?;

        prop_assert_eq!(first, second);
    }

    #[test]
    fn aad_normalization_is_order_independent(input in aad_input_strategy()) {
        #[derive(Serialize)]
        struct ReverseOrderContext<'a> {
            version: u32,
            secret_id: &'a str,
            owner_user_id: &'a str,
            created_at: &'a str,
            classification: &'a str,
            aad_version: u8,
        }

        let created_at = input.created_at_rfc3339().map_err(test_case_error)?;
        let shuffled_json = serde_json::to_string(&ReverseOrderContext {
            version: input.version,
            secret_id: &input.secret_id.hyphenated().to_string(),
            owner_user_id: &input.owner_user_id.hyphenated().to_string(),
            created_at: &created_at,
            classification: &input.classification,
            aad_version: AAD_VERSION_V1,
        }).map_err(test_case_error)?;

        let shuffled_value: Value = serde_json::from_str(&shuffled_json).map_err(test_case_error)?;
        let restored = AadV1::from_stored_context(&shuffled_value)
            .and_then(|restored| restored.canonical_bytes())
            .map_err(test_case_error)?;

        let canonical = input.to_aad()
            .and_then(|aad| aad.canonical_bytes())
            .map_err(test_case_error)?;

        prop_assert_eq!(restored, canonical);
    }

    #[test]
    fn uuid_variants_are_normalized(uuid in secret_id_strategy(), owner_uuid in uuid_strategy()) {
        let secret_variant = uuid.simple().to_string().to_uppercase();
        let owner_variant = owner_uuid.simple().to_string().to_uppercase();

        let aad = AadV1::parse(
            &secret_variant,
            1,
            &owner_variant,
            "confidential",
            "2026-04-08T12:00:00Z",
        ).map_err(test_case_error)?;

        let stored = aad.to_stored_context().map_err(test_case_error)?;
        let secret_id = stored.get("secret_id")
            .and_then(Value::as_str)
            .ok_or_else(|| test_case_error("secret_id must exist in stored context"))?;
        let owner_user_id = stored.get("owner_user_id")
            .and_then(Value::as_str)
            .ok_or_else(|| test_case_error("owner_user_id must exist in stored context"))?;

        prop_assert_eq!(secret_id, uuid.hyphenated().to_string());
        prop_assert_eq!(owner_user_id, owner_uuid.hyphenated().to_string());
    }

    #[test]
    fn timestamp_variants_are_normalized(created_at in timestamp_strategy()) {
        let canonical = created_at.format(&Rfc3339).map_err(test_case_error)?;
        let base = canonical.trim_end_matches('Z');
        let plus_zero = format!("{base}+00:00");
        let utc = format!("{base}UTC");

        let from_plus_zero = AadV1::parse(
            "550e8400-e29b-41d4-a716-446655440000",
            1,
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "confidential",
            &plus_zero,
        ).map_err(test_case_error)?;
        let from_utc = AadV1::parse(
            "550e8400-e29b-41d4-a716-446655440000",
            1,
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "confidential",
            &utc,
        ).map_err(test_case_error)?;

        let plus_zero_created_at = from_plus_zero.to_stored_context()
            .map_err(test_case_error)?
            .get("created_at")
            .and_then(Value::as_str)
            .ok_or_else(|| test_case_error("created_at must exist in stored context"))?
            .to_owned();
        let utc_created_at = from_utc.to_stored_context()
            .map_err(test_case_error)?
            .get("created_at")
            .and_then(Value::as_str)
            .ok_or_else(|| test_case_error("created_at must exist in stored context"))?
            .to_owned();

        prop_assert_eq!(plus_zero_created_at.as_str(), canonical.as_str());
        prop_assert_eq!(utc_created_at.as_str(), canonical.as_str());
    }

    #[test]
    fn aad_round_trip_from_stored_context_preserves_bytes(input in aad_input_strategy()) {
        let aad = input.to_aad().map_err(test_case_error)?;
        let stored = aad.to_stored_context().map_err(test_case_error)?;
        let restored = AadV1::from_stored_context(&stored)
            .and_then(|restored| restored.canonical_bytes())
            .map_err(test_case_error)?;
        let canonical = aad.canonical_bytes().map_err(test_case_error)?;

        prop_assert_eq!(restored, canonical);
    }
}

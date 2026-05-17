use mipsorcu::{AliasInputError, NormalizedAlias};
use proptest::prelude::*;

#[test]
fn parse_accepts_typical_alias() {
    assert!(NormalizedAlias::parse("github-api").is_ok());
    assert!(NormalizedAlias::parse("GitHub_API_v2").is_ok());
    assert!(NormalizedAlias::parse("a").is_ok());
}

#[test]
fn parse_trims_leading_and_trailing_whitespace_then_validates() {
    let result = NormalizedAlias::parse("  github-api  ");
    let parsed = result.expect("trimmed valid alias should parse");

    assert_eq!(parsed.as_str(), "github-api");
}

#[test]
fn parse_rejects_empty_and_whitespace_only() {
    assert!(matches!(
        NormalizedAlias::parse(""),
        Err(AliasInputError::Empty)
    ));
    assert!(matches!(
        NormalizedAlias::parse("   "),
        Err(AliasInputError::Empty)
    ));
    assert!(matches!(
        NormalizedAlias::parse("\t\n"),
        Err(AliasInputError::Empty)
    ));
}

#[test]
fn parse_rejects_full_width_space() {
    let result = NormalizedAlias::parse("alias　name");

    assert!(matches!(
        result,
        Err(AliasInputError::DisallowedCharacter { .. })
    ));
}

#[test]
fn parse_rejects_disallowed_punctuation() {
    for input in [
        "alias.name",
        "alias/name",
        "alias,name",
        "alias name",
        "alias@name",
    ] {
        assert!(matches!(
            NormalizedAlias::parse(input),
            Err(AliasInputError::DisallowedCharacter { .. })
        ));
    }
}

#[test]
fn parse_rejects_emoji() {
    let result = NormalizedAlias::parse("alias-name-🔐");

    assert!(matches!(
        result,
        Err(AliasInputError::DisallowedCharacter { .. })
    ));
}

#[test]
fn parse_enforces_maximum_length() {
    let max_input = "a".repeat(128);
    assert!(NormalizedAlias::parse(&max_input).is_ok());

    let over_input = "a".repeat(129);
    assert!(matches!(
        NormalizedAlias::parse(&over_input),
        Err(AliasInputError::TooLong {
            actual: 129,
            max: 128
        })
    ));
}

#[test]
fn disallowed_character_position_is_byte_index() {
    let result = NormalizedAlias::parse("alias　name");

    assert!(matches!(
        result,
        Err(AliasInputError::DisallowedCharacter { position: 5 })
    ));
}

#[test]
fn debug_output_does_not_expose_alias_content() {
    let alias = NormalizedAlias::parse("secret-alias-name").expect("valid alias");
    let output = format!("{alias:?}");

    assert!(!output.contains("secret-alias-name"));
    assert!(output.contains("len"));
    assert!(output.contains("<redacted>"));
}

#[test]
fn error_messages_do_not_expose_alias_content() {
    let error = NormalizedAlias::parse("alias with space").expect_err("invalid alias should fail");
    let output = error.to_string();

    assert!(!output.contains("alias with space"));
}

proptest! {
    #[test]
    fn parse_accepts_any_valid_alias(alias in "[A-Za-z0-9_\\-]{1,128}") {
        prop_assert!(NormalizedAlias::parse(&alias).is_ok());
    }

    #[test]
    fn parse_is_idempotent_for_valid_input(alias in "[A-Za-z0-9_\\-]{1,128}") {
        let first = NormalizedAlias::parse(&alias).expect("generated alias must be valid");
        let second = NormalizedAlias::parse(first.as_str()).expect("normalized alias must stay valid");

        prop_assert_eq!(first.as_str(), second.as_str());
    }
}

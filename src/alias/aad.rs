use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::AadError;
use crate::types::{KeyVersion, OwnerUserId, SecretAliasId, SecretId};

pub const ALIAS_AAD_VERSION_V1: u8 = 1;
const ALIAS_AAD_V1_FIELDS: &[&str] = &[
    "aad_version",
    "alias_key_version",
    "owner_user_id",
    "secret_alias_id",
    "secret_id",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasAadV1 {
    secret_alias_id: SecretAliasId,
    secret_id: SecretId,
    owner_user_id: OwnerUserId,
    alias_key_version: KeyVersion,
}

impl AliasAadV1 {
    pub fn new(
        secret_alias_id: SecretAliasId,
        secret_id: SecretId,
        owner_user_id: OwnerUserId,
        alias_key_version: KeyVersion,
    ) -> Self {
        Self {
            secret_alias_id,
            secret_id,
            owner_user_id,
            alias_key_version,
        }
    }

    pub fn from_stored_context(context: &Value) -> Result<Self, AadError> {
        let object = context.as_object().ok_or(AadError::ExpectedJsonObject)?;
        validate_alias_aad_v1_field_set(object)?;
        let aad_version = parse_aad_version(required_value(object, "aad_version")?)?;

        if aad_version != ALIAS_AAD_VERSION_V1 {
            return Err(AadError::UnsupportedAadVersion {
                value: aad_version.to_string(),
            });
        }

        let secret_alias_id = parse_required_string(object, "secret_alias_id")?;
        let secret_id = parse_required_string(object, "secret_id")?;
        let owner_user_id = parse_required_string(object, "owner_user_id")?;
        let alias_key_version = parse_required_positive_integer(object, "alias_key_version")?;

        Ok(Self::new(
            SecretAliasId::parse(&secret_alias_id)?,
            SecretId::parse(&secret_id)?,
            OwnerUserId::parse(&owner_user_id)?,
            KeyVersion::new(alias_key_version).map_err(|_| AadError::InvalidPositiveInteger {
                field: "alias_key_version",
                value: alias_key_version.to_string(),
            })?,
        ))
    }

    pub fn canonical_json(&self) -> Result<String, AadError> {
        let owner_user_id = self.owner_user_id.as_canonical_string();
        let secret_alias_id = self.secret_alias_id.as_canonical_string();
        let secret_id = self.secret_id.as_canonical_string();
        let canonical = CanonicalAliasAad {
            aad_version: ALIAS_AAD_VERSION_V1,
            alias_key_version: self.alias_key_version.get(),
            owner_user_id: &owner_user_id,
            secret_alias_id: &secret_alias_id,
            secret_id: &secret_id,
        };

        serde_json::to_string(&canonical)
            .map_err(|error| AadError::SerializationFailed(error.to_string()))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AadError> {
        self.canonical_json().map(String::into_bytes)
    }

    pub fn to_stored_context(&self) -> Result<Value, AadError> {
        let canonical = self.canonical_json()?;
        serde_json::from_str(&canonical)
            .map_err(|error| AadError::SerializationFailed(error.to_string()))
    }
}

#[derive(Serialize)]
struct CanonicalAliasAad<'a> {
    aad_version: u8,
    alias_key_version: u32,
    owner_user_id: &'a str,
    secret_alias_id: &'a str,
    secret_id: &'a str,
}

fn required_value<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Value, AadError> {
    object.get(field).ok_or(AadError::MissingField { field })
}

fn validate_alias_aad_v1_field_set(object: &Map<String, Value>) -> Result<(), AadError> {
    for field in ALIAS_AAD_V1_FIELDS {
        required_value(object, field)?;
    }

    if let Some(field) = object
        .keys()
        .find(|key| !ALIAS_AAD_V1_FIELDS.contains(&key.as_str()))
    {
        return Err(AadError::UnexpectedField {
            field: field.to_owned(),
        });
    }

    Ok(())
}

fn parse_required_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<String, AadError> {
    let value = required_value(object, field)?;

    value
        .as_str()
        .map(str::to_owned)
        .ok_or(AadError::InvalidFieldType {
            field,
            expected: "a string",
        })
}

fn parse_required_positive_integer(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<u32, AadError> {
    let value = required_value(object, field)?;
    parse_positive_integer(value, field)
}

fn parse_positive_integer(value: &Value, field: &'static str) -> Result<u32, AadError> {
    if let Value::Number(number) = value {
        let parsed = number
            .as_u64()
            .ok_or_else(|| AadError::InvalidPositiveInteger {
                field,
                value: number.to_string(),
            })?;
        let parsed = u32::try_from(parsed).map_err(|_| AadError::InvalidPositiveInteger {
            field,
            value: number.to_string(),
        })?;

        if parsed == 0 {
            return Err(AadError::InvalidPositiveInteger {
                field,
                value: number.to_string(),
            });
        }

        return Ok(parsed);
    }

    Err(AadError::InvalidFieldType {
        field,
        expected: "a positive integer",
    })
}

fn parse_aad_version(value: &Value) -> Result<u8, AadError> {
    let field = "aad_version";

    if let Value::Number(number) = value {
        let parsed = number
            .as_u64()
            .and_then(|number| u8::try_from(number).ok())
            .ok_or_else(|| AadError::UnsupportedAadVersion {
                value: number.to_string(),
            })?;

        if parsed == ALIAS_AAD_VERSION_V1 {
            return Ok(parsed);
        }

        return Err(AadError::UnsupportedAadVersion {
            value: number.to_string(),
        });
    }

    Err(AadError::InvalidFieldType {
        field,
        expected: "the integer 1",
    })
}

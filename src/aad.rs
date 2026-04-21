use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::error::AadError;
use crate::types::{Classification, CreatedAt, OwnerUserId, SecretId, SecretVersion};

pub const AAD_VERSION_V1: u8 = 1;
const AAD_V1_FIELDS: &[&str] = &[
    "aad_version",
    "classification",
    "created_at",
    "owner_user_id",
    "secret_id",
    "version",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AadV1 {
    secret_id: SecretId,
    version: SecretVersion,
    owner_user_id: OwnerUserId,
    classification: Classification,
    created_at: CreatedAt,
}

impl AadV1 {
    pub fn new(
        secret_id: SecretId,
        version: SecretVersion,
        owner_user_id: OwnerUserId,
        classification: Classification,
        created_at: CreatedAt,
    ) -> Self {
        Self {
            secret_id,
            version,
            owner_user_id,
            classification,
            created_at,
        }
    }

    pub fn parse(
        secret_id: &str,
        version: u32,
        owner_user_id: &str,
        classification: &str,
        created_at: &str,
    ) -> Result<Self, AadError> {
        Ok(Self::new(
            SecretId::parse(secret_id)?,
            SecretVersion::new(version)?,
            OwnerUserId::parse(owner_user_id)?,
            Classification::new(classification)?,
            CreatedAt::parse(created_at)?,
        ))
    }

    pub fn from_stored_context(context: &Value) -> Result<Self, AadError> {
        let object = context.as_object().ok_or(AadError::ExpectedJsonObject)?;
        validate_aad_v1_field_set(object)?;
        let aad_version = parse_aad_version(required_value(object, "aad_version")?)?;

        if aad_version != AAD_VERSION_V1 {
            return Err(AadError::UnsupportedAadVersion {
                value: aad_version.to_string(),
            });
        }

        let secret_id = parse_required_string(object, "secret_id")?;
        let version = parse_required_positive_integer(object, "version")?;
        let owner_user_id = parse_required_string(object, "owner_user_id")?;
        let classification = parse_required_string(object, "classification")?;
        let created_at = parse_required_string(object, "created_at")?;

        Self::parse(
            &secret_id,
            version,
            &owner_user_id,
            &classification,
            &created_at,
        )
    }

    pub fn from_row_metadata(
        secret_id: SecretId,
        version: SecretVersion,
        owner_user_id: OwnerUserId,
        classification: Classification,
        created_at: CreatedAt,
    ) -> Self {
        Self::new(
            secret_id,
            version,
            owner_user_id,
            classification,
            created_at,
        )
    }

    pub fn owner_user_id(&self) -> &OwnerUserId {
        &self.owner_user_id
    }

    pub fn canonical_json(&self) -> Result<String, AadError> {
        let created_at = self.created_at.as_rfc3339_utc()?;
        let owner_user_id = self.owner_user_id.as_canonical_string();
        let secret_id = self.secret_id.as_canonical_string();
        let canonical = CanonicalAad {
            aad_version: AAD_VERSION_V1,
            classification: self.classification.as_str(),
            created_at: &created_at,
            owner_user_id: &owner_user_id,
            secret_id: &secret_id,
            version: self.version.get(),
        };

        serde_json::to_string(&canonical)
            .map_err(|error| AadError::SerializationFailed(error.to_string()))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AadError> {
        self.canonical_json().map(String::into_bytes)
    }

    pub fn to_stored_context(&self) -> Result<Value, AadError> {
        Ok(json!({
            "aad_version": AAD_VERSION_V1,
            "secret_id": self.secret_id.as_canonical_string(),
            "version": self.version.get(),
            "owner_user_id": self.owner_user_id.as_canonical_string(),
            "classification": self.classification.as_str(),
            "created_at": self.created_at.as_rfc3339_utc()?,
        }))
    }
}

#[derive(Serialize)]
struct CanonicalAad<'a> {
    aad_version: u8,
    classification: &'a str,
    created_at: &'a str,
    owner_user_id: &'a str,
    secret_id: &'a str,
    version: u32,
}

fn required_value<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Value, AadError> {
    object.get(field).ok_or(AadError::MissingField { field })
}

fn validate_aad_v1_field_set(object: &Map<String, Value>) -> Result<(), AadError> {
    for field in AAD_V1_FIELDS {
        required_value(object, field)?;
    }

    if let Some(field) = object
        .keys()
        .find(|key| !AAD_V1_FIELDS.contains(&key.as_str()))
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
    if let Some(number) = value.as_u64() {
        let parsed = u32::try_from(number).map_err(|_| AadError::InvalidPositiveInteger {
            field,
            value: number.to_string(),
        })?;

        return SecretVersion::new(parsed).map(SecretVersion::get);
    }

    if let Some(text) = value.as_str() {
        let parsed = text
            .parse::<u32>()
            .map_err(|_| AadError::InvalidPositiveInteger {
                field,
                value: text.to_owned(),
            })?;

        return SecretVersion::new(parsed).map(SecretVersion::get);
    }

    Err(AadError::InvalidFieldType {
        field,
        expected: "a positive integer",
    })
}

fn parse_aad_version(value: &Value) -> Result<u8, AadError> {
    let field = "aad_version";

    if let Some(number) = value.as_u64() {
        return u8::try_from(number).map_err(|_| AadError::UnsupportedAadVersion {
            value: number.to_string(),
        });
    }

    if let Some(text) = value.as_str() {
        return text.parse::<u8>().map_err(|_| AadError::InvalidFieldType {
            field,
            expected: "the integer 1",
        });
    }

    Err(AadError::InvalidFieldType {
        field,
        expected: "the integer 1",
    })
}

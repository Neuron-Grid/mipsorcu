use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::NormalizedAlias;
use crate::server::dto::{CreateSecretAliasRequest, CreateSecretRequest, RotateSecretRequest};
use crate::server::errors::ApiError;
use crate::types::{
    Classification, CreatedAt, DeviceId, Plaintext, SecretAliasId, SecretId, SecretRef,
};

#[derive(Debug)]
pub(super) struct ParsedCreateSecretRequest {
    pub(super) classification: Classification,
    pub(super) device_id: DeviceId,
    pub(super) plaintext: Plaintext,
    pub(super) created_at: CreatedAt,
}

#[derive(Debug)]
pub(super) struct ParsedRotateSecretRequest {
    pub(super) device_id: DeviceId,
    pub(super) plaintext: Plaintext,
    pub(super) created_at: CreatedAt,
}

#[derive(Debug)]
pub(super) struct ParsedCreateSecretAliasRequest {
    pub(super) alias: NormalizedAlias,
}

pub(super) fn parse_create_secret_request(
    body: CreateSecretRequest,
) -> Result<ParsedCreateSecretRequest, ApiError> {
    Ok(ParsedCreateSecretRequest {
        classification: parse_classification(&body.classification)?,
        device_id: parse_device_id(&body.device_id)?,
        plaintext: parse_hex_plaintext(&body.plaintext_hex)?,
        created_at: current_created_at()?,
    })
}

pub(super) fn parse_rotate_secret_request(
    body: RotateSecretRequest,
) -> Result<ParsedRotateSecretRequest, ApiError> {
    Ok(ParsedRotateSecretRequest {
        device_id: parse_device_id(&body.device_id)?,
        plaintext: parse_hex_plaintext(&body.plaintext_hex)?,
        created_at: current_created_at()?,
    })
}

pub(super) fn parse_create_secret_alias_request(
    body: CreateSecretAliasRequest,
) -> Result<ParsedCreateSecretAliasRequest, ApiError> {
    Ok(ParsedCreateSecretAliasRequest {
        alias: parse_secret_alias(&body.alias)?,
    })
}

pub(super) fn parse_secret_ref(value: &str) -> Result<SecretRef, ApiError> {
    SecretRef::parse(value).map_err(|error| ApiError::BadRequest(error.to_string()))
}

pub(super) fn parse_secret_id(value: &str) -> Result<SecretId, ApiError> {
    SecretId::parse(value.trim()).map_err(|error| ApiError::BadRequest(error.to_string()))
}

pub(super) fn parse_secret_alias_id(value: &str) -> Result<SecretAliasId, ApiError> {
    SecretAliasId::parse(value.trim()).map_err(|error| ApiError::BadRequest(error.to_string()))
}

fn parse_classification(value: &str) -> Result<Classification, ApiError> {
    Classification::new(value).map_err(|error| ApiError::BadRequest(error.to_string()))
}

fn parse_device_id(value: &str) -> Result<DeviceId, ApiError> {
    DeviceId::new(value).map_err(|error| ApiError::BadRequest(error.to_string()))
}

pub(super) fn parse_secret_alias(value: &str) -> Result<NormalizedAlias, ApiError> {
    NormalizedAlias::parse(value).map_err(|error| ApiError::BadRequest(error.to_string()))
}

fn parse_hex_plaintext(value: &str) -> Result<Plaintext, ApiError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ApiError::BadRequest(
            "invalid plaintext_hex encoding: must be lowercase hex with even length".to_owned(),
        ));
    }

    hex::decode(value)
        .map(Plaintext::new)
        .map_err(|error| ApiError::BadRequest(format!("invalid plaintext_hex encoding: {error}")))
}

fn current_created_at() -> Result<CreatedAt, ApiError> {
    let rfc3339 = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| ApiError::InternalError(error.to_string()))?;

    CreatedAt::parse(&rfc3339).map_err(|error| ApiError::InternalError(error.to_string()))
}

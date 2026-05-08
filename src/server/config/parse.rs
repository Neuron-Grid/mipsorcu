use super::error::ConfigError;

pub(super) fn parse_positive_u64_config(
    value: Option<String>,
    name: &'static str,
    default_value: u64,
) -> Result<u64, ConfigError> {
    let Some(value) = value else {
        return Ok(default_value);
    };

    let parsed = value
        .parse::<u64>()
        .map_err(|error| ConfigError::InvalidValue {
            name,
            reason: error.to_string(),
        })?;

    if parsed == 0 {
        return Err(ConfigError::InvalidValue {
            name,
            reason: "value must be greater than zero".to_owned(),
        });
    }

    Ok(parsed)
}

pub(super) fn parse_non_negative_u64_config(
    value: Option<String>,
    name: &'static str,
    default_value: u64,
) -> Result<u64, ConfigError> {
    let Some(value) = value else {
        return Ok(default_value);
    };

    value
        .parse::<u64>()
        .map_err(|error| ConfigError::InvalidValue {
            name,
            reason: error.to_string(),
        })
}

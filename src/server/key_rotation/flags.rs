use crate::types::KeyVersion;

use super::KeyRotationCliError;

pub(super) fn parse_key_version_flag(
    args: &[String],
    flag: &'static str,
) -> Result<KeyVersion, KeyRotationCliError> {
    let value = parse_required_flag(args, flag)?;
    let parsed = value
        .parse::<u32>()
        .map_err(|_| KeyRotationCliError::Usage(format!("{flag} must be a positive integer")))?;

    KeyVersion::new(parsed)
        .map_err(|_| KeyRotationCliError::Usage(format!("{flag} must be a positive integer")))
}

pub(super) fn parse_positive_u32_flag(
    args: &[String],
    flag: &'static str,
) -> Result<u32, KeyRotationCliError> {
    let value = parse_required_flag(args, flag)?;
    let parsed = value
        .parse::<u32>()
        .map_err(|_| KeyRotationCliError::Usage(format!("{flag} must be a positive integer")))?;

    if parsed == 0 {
        return Err(KeyRotationCliError::Usage(format!(
            "{flag} must be a positive integer"
        )));
    }

    Ok(parsed)
}

pub(super) fn parse_required_flag<'a>(
    args: &'a [String],
    flag: &'static str,
) -> Result<&'a str, KeyRotationCliError> {
    let mut index = 0;
    let mut found = None;

    while index < args.len() {
        let current = args[index].as_str();
        if !current.starts_with("--") {
            return Err(KeyRotationCliError::Usage(super::usage()));
        }

        let value = args
            .get(index + 1)
            .ok_or_else(|| KeyRotationCliError::Usage(format!("{current} requires a value")))?;
        if value.starts_with("--") {
            return Err(KeyRotationCliError::Usage(format!(
                "{current} requires a value"
            )));
        }

        if current == flag {
            if found.is_some() {
                return Err(KeyRotationCliError::Usage(format!(
                    "{flag} must be provided once"
                )));
            }
            found = Some(value.as_str());
        }

        index += 2;
    }

    found.ok_or_else(|| KeyRotationCliError::Usage(format!("missing required flag {flag}")))
}

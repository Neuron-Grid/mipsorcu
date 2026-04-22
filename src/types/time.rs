use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use crate::error::AadError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CreatedAt(OffsetDateTime);

impl CreatedAt {
    pub fn parse(value: &str) -> Result<Self, AadError> {
        let normalized_value = rewrite_utc_suffix(value);
        let parsed = OffsetDateTime::parse(&normalized_value, &Rfc3339).map_err(|_| {
            AadError::InvalidTimestamp {
                field: "created_at",
                value: value.to_owned(),
            }
        })?;

        if parsed.offset() != UtcOffset::UTC {
            return Err(AadError::InvalidTimestamp {
                field: "created_at",
                value: value.to_owned(),
            });
        }

        Ok(Self(parsed.to_offset(UtcOffset::UTC)))
    }

    pub fn as_rfc3339_utc(&self) -> Result<String, AadError> {
        self.0
            .format(&Rfc3339)
            .map_err(|error| AadError::SerializationFailed(error.to_string()))
    }
}

fn rewrite_utc_suffix(value: &str) -> String {
    let trimmed = value.trim();
    let upper = trimmed.to_ascii_uppercase();

    if upper.ends_with(" UTC") {
        let prefix = &trimmed[..trimmed.len() - 4];
        return format!("{prefix}Z");
    }

    if upper.ends_with("UTC") {
        let prefix = &trimmed[..trimmed.len() - 3];
        return format!("{prefix}Z");
    }

    trimmed.to_owned()
}

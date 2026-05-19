use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use crate::error::AadError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CreatedAt(OffsetDateTime);

impl CreatedAt {
    pub fn now_utc() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    pub fn parse(value: &str) -> Result<Self, AadError> {
        parse_utc_rfc3339(value, "created_at").map(Self)
    }

    pub fn as_rfc3339_utc(&self) -> Result<String, AadError> {
        format_utc_rfc3339(self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceEventAt(String);

impl SourceEventAt {
    pub fn now_utc() -> Result<Self, AadError> {
        format_utc_rfc3339(OffsetDateTime::now_utc()).map(Self)
    }

    pub fn parse(value: &str) -> Result<Self, AadError> {
        if !value.ends_with('Z') {
            return Err(AadError::InvalidTimestamp {
                field: "source_event_at",
                value: value.to_owned(),
            });
        }

        let parsed =
            OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AadError::InvalidTimestamp {
                field: "source_event_at",
                value: value.to_owned(),
            })?;

        if parsed.offset() != UtcOffset::UTC {
            return Err(AadError::InvalidTimestamp {
                field: "source_event_at",
                value: value.to_owned(),
            });
        }

        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn parse_utc_rfc3339(value: &str, field: &'static str) -> Result<OffsetDateTime, AadError> {
    let normalized_value = rewrite_utc_suffix(value);
    let parsed = OffsetDateTime::parse(&normalized_value, &Rfc3339).map_err(|_| {
        AadError::InvalidTimestamp {
            field,
            value: value.to_owned(),
        }
    })?;

    if parsed.offset() != UtcOffset::UTC {
        return Err(AadError::InvalidTimestamp {
            field,
            value: value.to_owned(),
        });
    }

    Ok(parsed.to_offset(UtcOffset::UTC))
}

fn format_utc_rfc3339(value: OffsetDateTime) -> Result<String, AadError> {
    value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|error| AadError::SerializationFailed(error.to_string()))
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

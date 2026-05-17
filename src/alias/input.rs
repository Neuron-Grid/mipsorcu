use std::fmt;

use super::error::AliasInputError;

pub const ALIAS_MAX_LENGTH: usize = 128;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NormalizedAlias(String);

impl NormalizedAlias {
    pub fn parse(value: &str) -> Result<Self, AliasInputError> {
        let trimmed = value.trim();

        if trimmed.is_empty() {
            return Err(AliasInputError::Empty);
        }

        if trimmed.len() > ALIAS_MAX_LENGTH {
            return Err(AliasInputError::TooLong {
                actual: trimmed.len(),
                max: ALIAS_MAX_LENGTH,
            });
        }

        for (position, byte) in trimmed.bytes().enumerate() {
            if !is_allowed_byte(byte) {
                return Err(AliasInputError::DisallowedCharacter { position });
            }
        }

        Ok(Self(trimmed.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for NormalizedAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NormalizedAlias")
            .field("len", &self.0.len())
            .field("contents", &"<redacted>")
            .finish()
    }
}

fn is_allowed_byte(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

pub type AliasInput = NormalizedAlias;

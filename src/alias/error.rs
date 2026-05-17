use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasInputError {
    Empty,
    TooLong { actual: usize, max: usize },
    DisallowedCharacter { position: usize },
}

impl fmt::Display for AliasInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(formatter, "alias must not be empty or whitespace only"),
            Self::TooLong { actual, max } => write!(
                formatter,
                "alias must be at most {max} characters: actual {actual}"
            ),
            Self::DisallowedCharacter { position } => write!(
                formatter,
                "alias contains disallowed character at position {position}"
            ),
        }
    }
}

impl std::error::Error for AliasInputError {}

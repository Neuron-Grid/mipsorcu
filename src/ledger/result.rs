use super::error::LedgerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LedgerResult {
    Success,
    Failure,
}

impl LedgerResult {
    pub fn parse(value: &str) -> Result<Self, LedgerError> {
        match value {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            _ => Err(LedgerError::UnknownResult {
                value: value.to_owned(),
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

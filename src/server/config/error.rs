use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum ConfigError {
    MissingVar { name: &'static str },
    InvalidValue { name: &'static str, reason: String },
    DotenvLoad { path: PathBuf, reason: String },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVar { name } => {
                write!(
                    formatter,
                    "required environment variable is not set: {name}"
                )
            }
            Self::InvalidValue { name, reason } => {
                write!(
                    formatter,
                    "environment variable {name} has an invalid value: {reason}"
                )
            }
            Self::DotenvLoad { path, reason } => {
                write!(
                    formatter,
                    "failed to load dotenv file {}: {reason}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

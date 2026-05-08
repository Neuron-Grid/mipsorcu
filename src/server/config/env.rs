use std::collections::HashMap;
use std::fs;
use std::path::Path;

use super::error::ConfigError;

#[doc(hidden)]
pub type DotenvVars = HashMap<String, String>;

pub(super) fn current_process_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

pub(super) fn required_var<F>(
    name: &'static str,
    dotenv: &DotenvVars,
    get_process_var: &F,
) -> Result<String, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let value = get_process_var(name)
        .or_else(|| dotenv.get(name).cloned())
        .ok_or(ConfigError::MissingVar { name })?;
    if value.trim().is_empty() {
        return Err(ConfigError::InvalidValue {
            name,
            reason: "value must not be empty".to_owned(),
        });
    }
    Ok(value)
}

pub(super) fn optional_var<F>(
    name: &str,
    dotenv: &DotenvVars,
    get_process_var: &F,
) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    match get_process_var(name) {
        Some(value) if !value.trim().is_empty() => Some(value),
        Some(_) => None,
        None => dotenv
            .get(name)
            .cloned()
            .filter(|value| !value.trim().is_empty()),
    }
}

pub(super) fn load_dotenv_file(path: &Path) -> Result<DotenvVars, ConfigError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DotenvVars::new());
        }
        Err(error) => {
            return Err(ConfigError::DotenvLoad {
                path: path.to_path_buf(),
                reason: error.to_string(),
            });
        }
    };

    parse_dotenv_contents(&contents, path)
}

#[doc(hidden)]
pub fn parse_dotenv_contents(contents: &str, path: &Path) -> Result<DotenvVars, ConfigError> {
    let mut dotenv = DotenvVars::new();

    for (index, line) in contents.lines().enumerate() {
        let Some((name, value)) = parse_dotenv_line(line, path, index + 1)? else {
            continue;
        };
        dotenv.insert(name, value);
    }

    Ok(dotenv)
}

fn parse_dotenv_line(
    line: &str,
    path: &Path,
    line_number: usize,
) -> Result<Option<(String, String)>, ConfigError> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    let binding = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    let Some((name, raw_value)) = binding.split_once('=') else {
        return Err(dotenv_parse_error(
            path,
            line_number,
            "line must contain `=`".to_owned(),
        ));
    };

    let name = name.trim();
    if !is_valid_dotenv_key(name) {
        return Err(dotenv_parse_error(
            path,
            line_number,
            format!("invalid key `{name}`"),
        ));
    }

    let value = parse_dotenv_value(raw_value.trim(), path, line_number)?;
    Ok(Some((name.to_owned(), value)))
}

fn parse_dotenv_value(
    raw_value: &str,
    path: &Path,
    line_number: usize,
) -> Result<String, ConfigError> {
    if raw_value.starts_with('"') {
        if raw_value.len() < 2 || !raw_value.ends_with('"') {
            return Err(dotenv_parse_error(
                path,
                line_number,
                "double-quoted value must terminate on the same line".to_owned(),
            ));
        }

        return parse_double_quoted_dotenv_value(
            &raw_value[1..raw_value.len() - 1],
            path,
            line_number,
        );
    }

    if raw_value.starts_with('\'') {
        if raw_value.len() < 2 || !raw_value.ends_with('\'') {
            return Err(dotenv_parse_error(
                path,
                line_number,
                "single-quoted value must terminate on the same line".to_owned(),
            ));
        }

        return Ok(raw_value[1..raw_value.len() - 1].to_owned());
    }

    Ok(raw_value.to_owned())
}

fn parse_double_quoted_dotenv_value(
    raw_value: &str,
    path: &Path,
    line_number: usize,
) -> Result<String, ConfigError> {
    let mut value = String::with_capacity(raw_value.len());
    let mut chars = raw_value.chars();

    while let Some(character) = chars.next() {
        if character != '\\' {
            value.push(character);
            continue;
        }

        let Some(escaped) = chars.next() else {
            return Err(dotenv_parse_error(
                path,
                line_number,
                "unterminated escape sequence".to_owned(),
            ));
        };

        match escaped {
            '\\' => value.push('\\'),
            '"' => value.push('"'),
            'n' => value.push('\n'),
            'r' => value.push('\r'),
            't' => value.push('\t'),
            _ => {
                return Err(dotenv_parse_error(
                    path,
                    line_number,
                    format!("unsupported escape sequence `\\{escaped}`"),
                ));
            }
        }
    }

    Ok(value)
}

fn is_valid_dotenv_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }

    chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn dotenv_parse_error(path: &Path, line_number: usize, reason: String) -> ConfigError {
    ConfigError::DotenvLoad {
        path: path.to_path_buf(),
        reason: format!("line {line_number}: {reason}"),
    }
}

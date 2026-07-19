//! SQL function-definition discovery used by cutoff parity hard gates.

mod alter_rename;
mod drop;

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::PathBuf;

use alter_rename::parse_alter_function_rename;
use drop::parse_drop_function;

use super::migrations::MigrationFile;

/// A dollar-quoted SQL body and its absolute source ranges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DollarQuotedBody {
    /// Dollar delimiter, such as `$$` or `$function$`.
    pub delimiter: String,
    /// Range including the opening and closing delimiters.
    pub quoted_range: Range<usize>,
    /// Range containing only the body text.
    pub body_range: Range<usize>,
}

impl DollarQuotedBody {
    /// Returns the body text after verifying that the stored range still fits.
    pub fn text<'a>(&self, sql: &'a str) -> Result<&'a str, String> {
        sql.get(self.body_range.clone()).ok_or_else(|| {
            format!(
                "dollar-quoted body range {:?} does not fit SQL source of {} bytes",
                self.body_range,
                sql.len()
            )
        })
    }
}

/// One CREATE FUNCTION declaration identified by canonical input-argument types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionDefinition {
    /// Canonical `schema.name(type,...)` identity.
    pub identity: String,
    /// Migration carrier path.
    pub path: PathBuf,
    /// Migration carrier basename.
    pub migration_basename: String,
    /// Migration carrier timestamp/version prefix.
    pub migration_timestamp: String,
    /// Position of the carrier in the lexicographically ordered chain.
    pub migration_ordinal: usize,
    /// Byte offset of `CREATE` in the carrier.
    pub start: usize,
    /// Complete CREATE FUNCTION statement range through its semicolon.
    pub statement_range: Range<usize>,
    /// Dollar-quoted body metadata.
    pub dollar_quoted_body: DollarQuotedBody,
    /// Owned body text for candidate-independent assertions.
    pub body: String,
}

/// One decoded single-quoted literal and its byte range including quote marks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlQuotedLiteral {
    /// SQL literal value after decoding doubled single quotes.
    pub value: String,
    /// Absolute range including the opening and closing single quotes.
    pub range: Range<usize>,
}

enum FunctionEvent {
    Create(FunctionDefinition),
    Drop(Vec<String>),
    Rename { source: String, target: String },
}

/// Returns every effective CREATE FUNCTION declaration in one migration.
pub fn definitions_in_migration(
    migration: &MigrationFile,
) -> Result<Vec<FunctionDefinition>, String> {
    Ok(function_events_in_migration(migration)?
        .into_iter()
        .filter_map(|event| match event {
            FunctionEvent::Create(definition) => Some(definition),
            FunctionEvent::Drop(_) | FunctionEvent::Rename { .. } => None,
        })
        .collect())
}

fn function_events_in_migration(migration: &MigrationFile) -> Result<Vec<FunctionEvent>, String> {
    let sql = migration.sql.as_str();
    let bytes = sql.as_bytes();
    let mut events = Vec::new();
    let mut index = 0usize;

    while index < bytes.len() {
        if starts_line_comment(bytes, index) {
            index = skip_line_comment(bytes, index);
            continue;
        }
        if starts_block_comment(bytes, index) {
            index = skip_block_comment(bytes, index)?;
            continue;
        }
        if bytes[index] == b'\'' {
            index = skip_single_quoted(sql, index)?.0;
            continue;
        }
        if bytes[index] == b'"' {
            index = skip_double_quoted(bytes, index)?;
            continue;
        }
        if bytes[index] == b'$'
            && let Some(body) = dollar_quote_at(sql, index)?
        {
            index = body.quoted_range.end;
            continue;
        }
        if is_word_start(bytes[index]) {
            let word_end = consume_word(bytes, index);
            if ascii_word_eq(&bytes[index..word_end], b"create")
                && let Some(definition) = parse_create_function(migration, index, word_end)?
            {
                index = definition.statement_range.end;
                events.push(FunctionEvent::Create(definition));
                continue;
            }
            if ascii_word_eq(&bytes[index..word_end], b"drop")
                && let Some((identities, statement_end)) = parse_drop_function(migration, word_end)?
            {
                index = statement_end;
                events.push(FunctionEvent::Drop(identities));
                continue;
            }
            if ascii_word_eq(&bytes[index..word_end], b"alter")
                && let Some((source, target, statement_end)) =
                    parse_alter_function_rename(migration, word_end)?
            {
                index = statement_end;
                events.push(FunctionEvent::Rename { source, target });
                continue;
            }
            index = word_end;
            continue;
        }
        index += 1;
    }

    Ok(events)
}

/// Returns all function declarations in migration execution order.
pub fn all_definitions(migrations: &[MigrationFile]) -> Result<Vec<FunctionDefinition>, String> {
    let mut definitions = Vec::new();
    for migration in migrations {
        definitions.extend(definitions_in_migration(migration)?);
    }
    Ok(definitions)
}

/// Returns the final effective function state after CREATE, DROP, and RENAME events.
pub fn effective_definitions(
    migrations: &[MigrationFile],
) -> Result<Vec<FunctionDefinition>, String> {
    Ok(effective_definition_state(migrations)?
        .into_values()
        .collect())
}

/// Finds the latest effective definition for one canonical identity.
pub fn latest_definition(
    migrations: &[MigrationFile],
    expected_identity: &str,
) -> Result<FunctionDefinition, String> {
    let expected = canonicalize_expected_identity(expected_identity)?;
    effective_definition_state(migrations)?
        .remove(&expected)
        .ok_or_else(|| {
            format!(
                "explicit candidate migration chain does not define canonical function {expected}"
            )
        })
}

fn effective_definition_state(
    migrations: &[MigrationFile],
) -> Result<BTreeMap<String, FunctionDefinition>, String> {
    let mut state = BTreeMap::new();
    for migration in migrations {
        for event in function_events_in_migration(migration)? {
            match event {
                FunctionEvent::Create(definition) => {
                    state.insert(definition.identity.clone(), definition);
                }
                FunctionEvent::Drop(identities) => {
                    for identity in identities {
                        state.remove(&identity);
                    }
                }
                FunctionEvent::Rename { source, target } => {
                    let mut definition = state.remove(&source).ok_or_else(|| {
                        format!(
                            "ALTER FUNCTION RENAME source {source} is not defined before the event in {}",
                            migration.path.display()
                        )
                    })?;
                    if source == target || state.contains_key(&target) {
                        return Err(format!(
                            "ALTER FUNCTION RENAME target {target} conflicts with effective function state in {}",
                            migration.path.display()
                        ));
                    }
                    definition.identity.clone_from(&target);
                    state.insert(target, definition);
                }
            }
        }
    }
    Ok(state)
}

/// Locates every dollar-quoted region outside comments and quoted strings.
pub fn dollar_quoted_ranges(sql: &str) -> Result<Vec<DollarQuotedBody>, String> {
    let bytes = sql.as_bytes();
    let mut ranges = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if starts_line_comment(bytes, index) {
            index = skip_line_comment(bytes, index);
        } else if starts_block_comment(bytes, index) {
            index = skip_block_comment(bytes, index)?;
        } else if bytes[index] == b'\'' {
            index = skip_single_quoted(sql, index)?.0;
        } else if bytes[index] == b'"' {
            index = skip_double_quoted(bytes, index)?;
        } else if bytes[index] == b'$' {
            if let Some(body) = dollar_quote_at(sql, index)? {
                index = body.quoted_range.end;
                ranges.push(body);
            } else {
                index += 1;
            }
        } else {
            index += 1;
        }
    }
    Ok(ranges)
}

/// Locates the first dollar-quoted body after `search_from`.
pub fn dollar_quoted_body(sql: &str, search_from: usize) -> Result<DollarQuotedBody, String> {
    if !sql.is_char_boundary(search_from) {
        return Err(format!(
            "dollar-quoted body search offset {search_from} is not a UTF-8 boundary"
        ));
    }
    let bytes = sql.as_bytes();
    let mut index = search_from;
    while index < bytes.len() {
        if starts_line_comment(bytes, index) {
            index = skip_line_comment(bytes, index);
        } else if starts_block_comment(bytes, index) {
            index = skip_block_comment(bytes, index)?;
        } else if bytes[index] == b'\'' {
            index = skip_single_quoted(sql, index)?.0;
        } else if bytes[index] == b'"' {
            index = skip_double_quoted(bytes, index)?;
        } else if bytes[index] == b'$' {
            if let Some(body) = dollar_quote_at(sql, index)? {
                return Ok(body);
            }
            index += 1;
        } else if bytes[index] == b';' {
            return Err("CREATE FUNCTION ended before a dollar-quoted body was found".to_owned());
        } else {
            index += 1;
        }
    }
    Err("CREATE FUNCTION must contain a closed dollar-quoted body".to_owned())
}

/// Extracts decoded single-quoted literals outside comments and nested dollar strings.
pub fn quoted_literals(sql: &str) -> Result<Vec<SqlQuotedLiteral>, String> {
    let bytes = sql.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if starts_line_comment(bytes, index) {
            index = skip_line_comment(bytes, index);
        } else if starts_block_comment(bytes, index) {
            index = skip_block_comment(bytes, index)?;
        } else if bytes[index] == b'"' {
            index = skip_double_quoted(bytes, index)?;
        } else if bytes[index] == b'$' {
            if let Some(body) = dollar_quote_at(sql, index)? {
                index = body.quoted_range.end;
            } else {
                index += 1;
            }
        } else if bytes[index] == b'\'' {
            let (end, value) = skip_single_quoted(sql, index)?;
            literals.push(SqlQuotedLiteral {
                value,
                range: index..end,
            });
            index = end;
        } else {
            index += 1;
        }
    }
    Ok(literals)
}

fn parse_create_function(
    migration: &MigrationFile,
    create_start: usize,
    after_create: usize,
) -> Result<Option<FunctionDefinition>, String> {
    let sql = migration.sql.as_str();
    let bytes = sql.as_bytes();
    let mut cursor = Cursor::new(sql, after_create);
    cursor.skip_trivia()?;
    if cursor.consume_word_if("or") {
        cursor.skip_trivia()?;
        if !cursor.consume_word_if("replace") {
            return Ok(None);
        }
        cursor.skip_trivia()?;
    }
    if !cursor.consume_word_if("function") {
        return Ok(None);
    }
    cursor.skip_trivia()?;

    let schema = cursor.read_identifier()?;
    cursor.skip_trivia()?;
    if cursor.current_byte() != Some(b'.') {
        return Err(format!(
            "CREATE FUNCTION in {} must use a schema-qualified name",
            migration.path.display()
        ));
    }
    cursor.advance_one();
    cursor.skip_trivia()?;
    let function_name = cursor.read_identifier()?;
    cursor.skip_trivia()?;
    let arguments_open = cursor.position;
    if cursor.current_byte() != Some(b'(') {
        return Err(format!(
            "CREATE FUNCTION {schema}.{function_name} in {} lacks an argument list",
            migration.path.display()
        ));
    }
    let arguments_close = matching_parenthesis(sql, arguments_open)?;
    let arguments = sql
        .get(arguments_open + 1..arguments_close)
        .ok_or_else(|| {
            format!(
                "CREATE FUNCTION argument range is invalid in {}",
                migration.path.display()
            )
        })?;
    let argument_types = canonical_argument_types(arguments)?;
    let identity = format!("{schema}.{function_name}({})", argument_types.join(","));
    let body = dollar_quoted_body(sql, arguments_close + 1)?;
    let body_text = body.text(sql)?.to_owned();
    let statement_end = find_statement_end(bytes, body.quoted_range.end)?;

    Ok(Some(FunctionDefinition {
        identity,
        path: migration.path.clone(),
        migration_basename: migration.basename.clone(),
        migration_timestamp: migration.timestamp.clone(),
        migration_ordinal: migration.ordinal,
        start: create_start,
        statement_range: create_start..statement_end,
        dollar_quoted_body: body,
        body: body_text,
    }))
}

fn canonicalize_expected_identity(identity: &str) -> Result<String, String> {
    if identity.trim() != identity || identity.is_empty() {
        return Err(format!(
            "canonical function identity {identity:?} must be non-empty without surrounding whitespace"
        ));
    }
    let open = identity.find('(').ok_or_else(|| {
        format!("canonical function identity {identity:?} lacks an argument list")
    })?;
    if !identity.ends_with(')') {
        return Err(format!(
            "canonical function identity {identity:?} must end with ')'"
        ));
    }
    let qualified = identity[..open].trim();
    let (schema, function_name) = qualified.split_once('.').ok_or_else(|| {
        format!("canonical function identity {identity:?} must be schema-qualified")
    })?;
    if schema.is_empty() || function_name.is_empty() || function_name.contains('.') {
        return Err(format!(
            "canonical function identity {identity:?} has an invalid qualified name"
        ));
    }
    let arguments = &identity[open + 1..identity.len() - 1];
    let argument_types = if arguments.trim().is_empty() {
        Vec::new()
    } else {
        split_top_level(arguments, b',')?
            .into_iter()
            .map(canonicalize_type)
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(format!(
        "{}.{}({})",
        canonicalize_identifier(schema)?,
        canonicalize_identifier(function_name)?,
        argument_types.join(",")
    ))
}

fn canonical_argument_types(arguments: &str) -> Result<Vec<String>, String> {
    if arguments.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut types = Vec::new();
    for raw_argument in split_top_level(arguments, b',')? {
        let without_default = strip_argument_default(raw_argument)?;
        let argument = without_default.trim();
        if argument.is_empty() {
            return Err("CREATE FUNCTION contains an empty argument declaration".to_owned());
        }
        let (mode, after_mode) = strip_argument_mode(argument);
        if mode == Some("out") {
            continue;
        }
        let argument = after_mode.trim();
        let (first, rest) = split_first_component(argument)?;
        let rest = rest.trim();
        let continues_type = matches!(rest.as_bytes().first(), Some(b'.' | b'[' | b'('));
        let type_source = if rest.is_empty() || begins_with_type_keyword(first) || continues_type {
            argument
        } else {
            rest
        };
        types.push(canonicalize_type(type_source)?);
    }
    Ok(types)
}

fn strip_argument_default(argument: &str) -> Result<&str, String> {
    let bytes = argument.as_bytes();
    let mut index = 0usize;
    let mut depth = 0usize;
    while index < bytes.len() {
        if starts_line_comment(bytes, index) {
            index = skip_line_comment(bytes, index);
        } else if starts_block_comment(bytes, index) {
            index = skip_block_comment(bytes, index)?;
        } else if bytes[index] == b'\'' {
            index = skip_single_quoted(argument, index)?.0;
        } else if bytes[index] == b'"' {
            index = skip_double_quoted(bytes, index)?;
        } else if bytes[index] == b'$' {
            if let Some(body) = dollar_quote_at(argument, index)? {
                index = body.quoted_range.end;
            } else {
                index += 1;
            }
        } else if bytes[index] == b'(' || bytes[index] == b'[' {
            depth += 1;
            index += 1;
        } else if bytes[index] == b')' || bytes[index] == b']' {
            depth = depth.checked_sub(1).ok_or_else(|| {
                "argument declaration has an unmatched closing delimiter".to_owned()
            })?;
            index += 1;
        } else if depth == 0 && bytes[index] == b'=' {
            return Ok(&argument[..index]);
        } else if depth == 0 && is_word_start(bytes[index]) {
            let end = consume_word(bytes, index);
            if ascii_word_eq(&bytes[index..end], b"default") {
                return Ok(&argument[..index]);
            }
            index = end;
        } else {
            index += 1;
        }
    }
    if depth != 0 {
        return Err("argument declaration has an unmatched opening delimiter".to_owned());
    }
    Ok(argument)
}

fn strip_argument_mode(argument: &str) -> (Option<&str>, &str) {
    for mode in ["inout", "variadic", "out", "in"] {
        if let Some(rest) = strip_ascii_word_prefix(argument, mode) {
            return (Some(mode), rest);
        }
    }
    (None, argument)
}

fn split_first_component(argument: &str) -> Result<(&str, &str), String> {
    let bytes = argument.as_bytes();
    if bytes.first() == Some(&b'"') {
        let end = skip_double_quoted(bytes, 0)?;
        return Ok((&argument[..end], &argument[end..]));
    }
    if bytes.first().is_none_or(|byte| !is_word_start(*byte)) {
        return Err(format!(
            "function argument declaration {argument:?} must start with an identifier or type"
        ));
    }
    let end = consume_word(bytes, 0);
    Ok((&argument[..end], &argument[end..]))
}

fn begins_with_type_keyword(component: &str) -> bool {
    matches!(
        component.to_ascii_lowercase().as_str(),
        "bigint"
            | "bigserial"
            | "bit"
            | "boolean"
            | "box"
            | "bytea"
            | "character"
            | "cidr"
            | "date"
            | "decimal"
            | "double"
            | "inet"
            | "integer"
            | "interval"
            | "json"
            | "jsonb"
            | "macaddr"
            | "money"
            | "numeric"
            | "real"
            | "record"
            | "smallint"
            | "smallserial"
            | "serial"
            | "text"
            | "time"
            | "timestamp"
            | "uuid"
            | "varchar"
            | "void"
            | "xml"
    )
}

fn canonicalize_type(raw_type: &str) -> Result<String, String> {
    let trimmed = raw_type.trim();
    if trimmed.is_empty() {
        return Err("function argument type must not be empty".to_owned());
    }
    if trimmed.contains('"') || trimmed.contains('\'') || trimmed.contains(';') {
        return Err(format!(
            "function argument type {trimmed:?} uses unsupported quoting or statement syntax"
        ));
    }
    let mut canonical = String::with_capacity(trimmed.len());
    let mut pending_space = false;
    for character in trimmed.chars() {
        if character.is_whitespace() {
            pending_space = true;
            continue;
        }
        let punctuation = matches!(character, '.' | ',' | '(' | ')' | '[' | ']');
        if pending_space
            && !canonical.is_empty()
            && !punctuation
            && !matches!(canonical.chars().last(), Some('.' | '(' | '[' | ','))
        {
            canonical.push(' ');
        }
        if punctuation && canonical.ends_with(' ') {
            canonical.pop();
        }
        canonical.push(character.to_ascii_lowercase());
        pending_space = false;
    }
    Ok(canonical)
}

fn canonicalize_identifier(identifier: &str) -> Result<String, String> {
    let bytes = identifier.as_bytes();
    if bytes.first() == Some(&b'"') {
        if skip_double_quoted(bytes, 0)? != bytes.len() {
            return Err(format!(
                "quoted identifier {identifier:?} has trailing data"
            ));
        }
        return Ok(identifier.to_owned());
    }
    if bytes.first().is_none_or(|byte| !is_word_start(*byte))
        || consume_word(bytes, 0) != bytes.len()
    {
        return Err(format!(
            "identifier {identifier:?} is not canonical SQL syntax"
        ));
    }
    Ok(identifier.to_ascii_lowercase())
}

fn split_top_level(source: &str, separator: u8) -> Result<Vec<&str>, String> {
    let bytes = source.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut depth = 0usize;
    while index < bytes.len() {
        if starts_line_comment(bytes, index) {
            index = skip_line_comment(bytes, index);
        } else if starts_block_comment(bytes, index) {
            index = skip_block_comment(bytes, index)?;
        } else if bytes[index] == b'\'' {
            index = skip_single_quoted(source, index)?.0;
        } else if bytes[index] == b'"' {
            index = skip_double_quoted(bytes, index)?;
        } else if bytes[index] == b'$' {
            if let Some(body) = dollar_quote_at(source, index)? {
                index = body.quoted_range.end;
            } else {
                index += 1;
            }
        } else if matches!(bytes[index], b'(' | b'[') {
            depth += 1;
            index += 1;
        } else if matches!(bytes[index], b')' | b']') {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| "SQL fragment has an unmatched closing delimiter".to_owned())?;
            index += 1;
        } else if depth == 0 && bytes[index] == separator {
            parts.push(&source[start..index]);
            start = index + 1;
            index += 1;
        } else {
            index += 1;
        }
    }
    if depth != 0 {
        return Err("SQL fragment has an unmatched opening delimiter".to_owned());
    }
    parts.push(&source[start..]);
    Ok(parts)
}

fn matching_parenthesis(sql: &str, open: usize) -> Result<usize, String> {
    let bytes = sql.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return Err(format!("byte offset {open} is not an opening parenthesis"));
    }
    let mut depth = 0usize;
    let mut index = open;
    while index < bytes.len() {
        if starts_line_comment(bytes, index) {
            index = skip_line_comment(bytes, index);
        } else if starts_block_comment(bytes, index) {
            index = skip_block_comment(bytes, index)?;
        } else if bytes[index] == b'\'' {
            index = skip_single_quoted(sql, index)?.0;
        } else if bytes[index] == b'"' {
            index = skip_double_quoted(bytes, index)?;
        } else if bytes[index] == b'$' {
            if let Some(body) = dollar_quote_at(sql, index)? {
                index = body.quoted_range.end;
            } else {
                index += 1;
            }
        } else if bytes[index] == b'(' {
            depth += 1;
            index += 1;
        } else if bytes[index] == b')' {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| "function argument list has an unmatched ')'".to_owned())?;
            if depth == 0 {
                return Ok(index);
            }
            index += 1;
        } else {
            index += 1;
        }
    }
    Err("function argument list has an unmatched '('".to_owned())
}

fn find_statement_end(bytes: &[u8], after_body: usize) -> Result<usize, String> {
    let mut index = after_body;
    while index < bytes.len() {
        if starts_line_comment(bytes, index) {
            index = skip_line_comment(bytes, index);
        } else if starts_block_comment(bytes, index) {
            index = skip_block_comment(bytes, index)?;
        } else if bytes[index] == b';' {
            return Ok(index + 1);
        } else {
            index += 1;
        }
    }
    Err("CREATE FUNCTION dollar-quoted body must be followed by a semicolon".to_owned())
}

fn dollar_quote_at(sql: &str, start: usize) -> Result<Option<DollarQuotedBody>, String> {
    let bytes = sql.as_bytes();
    if bytes.get(start) != Some(&b'$') {
        return Ok(None);
    }
    let mut delimiter_end = start + 1;
    while delimiter_end < bytes.len()
        && (bytes[delimiter_end].is_ascii_alphanumeric() || bytes[delimiter_end] == b'_')
    {
        delimiter_end += 1;
    }
    if bytes.get(delimiter_end) != Some(&b'$') {
        return Ok(None);
    }
    if delimiter_end > start + 1 && !matches!(bytes[start + 1], b'a'..=b'z' | b'A'..=b'Z' | b'_') {
        return Ok(None);
    }
    let delimiter_bytes = &bytes[start..=delimiter_end];
    let content_start = delimiter_end + 1;
    let close = find_bytes(bytes, content_start, delimiter_bytes).ok_or_else(|| {
        let delimiter = String::from_utf8_lossy(delimiter_bytes);
        format!("unclosed dollar quote {delimiter} at byte {start}")
    })?;
    let quoted_end = close + delimiter_bytes.len();
    let delimiter = sql
        .get(start..content_start)
        .ok_or_else(|| "dollar-quote delimiter is not valid UTF-8 syntax".to_owned())?
        .to_owned();
    Ok(Some(DollarQuotedBody {
        delimiter,
        quoted_range: start..quoted_end,
        body_range: content_start..close,
    }))
}

fn find_bytes(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || from > haystack.len() || needle.len() > haystack.len() {
        return None;
    }
    (from..=haystack.len().saturating_sub(needle.len()))
        .find(|&index| &haystack[index..index + needle.len()] == needle)
}

fn skip_single_quoted(sql: &str, start: usize) -> Result<(usize, String), String> {
    let bytes = sql.as_bytes();
    if bytes.get(start) != Some(&b'\'') {
        return Err(format!("byte offset {start} is not a single quote"));
    }
    let escape_mode = start > 0
        && matches!(bytes[start - 1], b'e' | b'E')
        && (start == 1 || !is_word_continue(bytes[start - 2]));
    let mut value = String::new();
    let mut segment_start = start + 1;
    let mut index = start + 1;
    while index < bytes.len() {
        if escape_mode && bytes[index] == b'\\' {
            let segment = sql
                .get(segment_start..index)
                .ok_or_else(|| "single-quoted literal is not valid UTF-8".to_owned())?;
            value.push_str(segment);
            let escaped = bytes
                .get(index + 1)
                .ok_or_else(|| format!("unterminated escape string literal at byte {start}"))?;
            value.push(char::from(*escaped));
            index += 2;
            segment_start = index;
        } else if bytes[index] == b'\'' {
            if bytes.get(index + 1) == Some(&b'\'') {
                let segment = sql
                    .get(segment_start..index)
                    .ok_or_else(|| "single-quoted literal is not valid UTF-8".to_owned())?;
                value.push_str(segment);
                value.push('\'');
                index += 2;
                segment_start = index;
            } else {
                let segment = sql
                    .get(segment_start..index)
                    .ok_or_else(|| "single-quoted literal is not valid UTF-8".to_owned())?;
                value.push_str(segment);
                return Ok((index + 1, value));
            }
        } else {
            index += 1;
        }
    }
    Err(format!(
        "unterminated single-quoted literal at byte {start}"
    ))
}

fn skip_double_quoted(bytes: &[u8], start: usize) -> Result<usize, String> {
    if bytes.get(start) != Some(&b'"') {
        return Err(format!("byte offset {start} is not a double quote"));
    }
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            if bytes.get(index + 1) == Some(&b'"') {
                index += 2;
            } else {
                return Ok(index + 1);
            }
        } else {
            index += 1;
        }
    }
    Err(format!(
        "unterminated double-quoted identifier at byte {start}"
    ))
}

fn starts_line_comment(bytes: &[u8], index: usize) -> bool {
    bytes.get(index) == Some(&b'-') && bytes.get(index + 1) == Some(&b'-')
}

fn skip_line_comment(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 2;
    while index < bytes.len() && bytes[index] != b'\n' {
        index += 1;
    }
    index
}

fn starts_block_comment(bytes: &[u8], index: usize) -> bool {
    bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'*')
}

fn skip_block_comment(bytes: &[u8], start: usize) -> Result<usize, String> {
    let mut depth = 1usize;
    let mut index = start + 2;
    while index < bytes.len() {
        if starts_block_comment(bytes, index) {
            depth += 1;
            index += 2;
        } else if bytes.get(index) == Some(&b'*') && bytes.get(index + 1) == Some(&b'/') {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| "block comment nesting underflow".to_owned())?;
            index += 2;
            if depth == 0 {
                return Ok(index);
            }
        } else {
            index += 1;
        }
    }
    Err(format!("unterminated block comment at byte {start}"))
}

fn ascii_word_eq(actual: &[u8], expected_lowercase: &[u8]) -> bool {
    actual.len() == expected_lowercase.len()
        && actual
            .iter()
            .zip(expected_lowercase)
            .all(|(actual, expected)| actual.to_ascii_lowercase() == *expected)
}

fn is_word_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_word_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn consume_word(bytes: &[u8], start: usize) -> usize {
    let mut index = start;
    while index < bytes.len() && is_word_continue(bytes[index]) {
        index += 1;
    }
    index
}

fn strip_ascii_word_prefix<'a>(source: &'a str, prefix: &str) -> Option<&'a str> {
    let bytes = source.as_bytes();
    let end = consume_word(bytes, 0);
    ascii_word_eq(&bytes[..end], prefix.as_bytes()).then_some(&source[end..])
}

struct Cursor<'a> {
    sql: &'a str,
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(sql: &'a str, position: usize) -> Self {
        Self { sql, position }
    }

    fn skip_trivia(&mut self) -> Result<(), String> {
        let bytes = self.sql.as_bytes();
        loop {
            while self
                .current_byte()
                .is_some_and(|byte| byte.is_ascii_whitespace())
            {
                self.position += 1;
            }
            if starts_line_comment(bytes, self.position) {
                self.position = skip_line_comment(bytes, self.position);
            } else if starts_block_comment(bytes, self.position) {
                self.position = skip_block_comment(bytes, self.position)?;
            } else {
                return Ok(());
            }
        }
    }

    fn consume_word_if(&mut self, expected_lowercase: &str) -> bool {
        let bytes = self.sql.as_bytes();
        if self.current_byte().is_none_or(|byte| !is_word_start(byte)) {
            return false;
        }
        let end = consume_word(bytes, self.position);
        if ascii_word_eq(&bytes[self.position..end], expected_lowercase.as_bytes()) {
            self.position = end;
            true
        } else {
            false
        }
    }

    fn read_identifier(&mut self) -> Result<String, String> {
        let bytes = self.sql.as_bytes();
        if self.current_byte() == Some(b'"') {
            let end = skip_double_quoted(bytes, self.position)?;
            let identifier = self
                .sql
                .get(self.position..end)
                .ok_or_else(|| "quoted identifier is not valid UTF-8".to_owned())?;
            self.position = end;
            return Ok(identifier.to_owned());
        }
        if self.current_byte().is_none_or(|byte| !is_word_start(byte)) {
            return Err(format!("expected SQL identifier at byte {}", self.position));
        }
        let end = consume_word(bytes, self.position);
        let identifier = self
            .sql
            .get(self.position..end)
            .ok_or_else(|| "identifier is not valid UTF-8".to_owned())?
            .to_ascii_lowercase();
        self.position = end;
        Ok(identifier)
    }

    fn current_byte(&self) -> Option<u8> {
        self.sql.as_bytes().get(self.position).copied()
    }

    fn advance_one(&mut self) {
        self.position += 1;
    }
}

//! Strict `DROP FUNCTION` event parsing for effective-definition tracking.

use super::{Cursor, canonical_argument_types, matching_parenthesis};
use crate::sql_cutoff_parity::migrations::MigrationFile;

pub(super) fn parse_drop_function(
    migration: &MigrationFile,
    after_drop: usize,
) -> Result<Option<(Vec<String>, usize)>, String> {
    let sql = migration.sql.as_str();
    let mut cursor = Cursor::new(sql, after_drop);
    cursor.skip_trivia()?;
    if !cursor.consume_word_if("function") {
        return Ok(None);
    }
    cursor.skip_trivia()?;
    if cursor.consume_word_if("if") {
        cursor.skip_trivia()?;
        if !cursor.consume_word_if("exists") {
            return Err(format!(
                "DROP FUNCTION in {} has IF without EXISTS",
                migration.path.display()
            ));
        }
        cursor.skip_trivia()?;
    }
    let mut identities = Vec::new();
    loop {
        let schema = cursor.read_identifier()?;
        cursor.skip_trivia()?;
        if cursor.current_byte() != Some(b'.') {
            return Err(format!(
                "DROP FUNCTION in {} must use a schema-qualified canonical identity",
                migration.path.display()
            ));
        }
        cursor.advance_one();
        cursor.skip_trivia()?;
        let function_name = cursor.read_identifier()?;
        cursor.skip_trivia()?;
        if cursor.current_byte() != Some(b'(') {
            return Err(format!(
                "DROP FUNCTION {schema}.{function_name} in {} omits argument types and is ambiguous",
                migration.path.display()
            ));
        }
        let close = matching_parenthesis(sql, cursor.position)?;
        let arguments = sql.get(cursor.position + 1..close).ok_or_else(|| {
            format!(
                "DROP FUNCTION argument range is invalid in {}",
                migration.path.display()
            )
        })?;
        identities.push(format!(
            "{schema}.{function_name}({})",
            canonical_argument_types(arguments)?.join(",")
        ));
        cursor.position = close + 1;
        cursor.skip_trivia()?;
        if cursor.current_byte() == Some(b',') {
            cursor.advance_one();
            cursor.skip_trivia()?;
            continue;
        }
        if cursor.consume_word_if("cascade") || cursor.consume_word_if("restrict") {
            cursor.skip_trivia()?;
        }
        if cursor.current_byte() != Some(b';') {
            return Err(format!(
                "DROP FUNCTION in {} has unsupported trailing syntax at byte {}",
                migration.path.display(),
                cursor.position
            ));
        }
        return Ok(Some((identities, cursor.position + 1)));
    }
}

//! Strict `ALTER FUNCTION ... RENAME TO ...` event parsing.

use super::{Cursor, canonical_argument_types, matching_parenthesis};
use crate::sql_cutoff_parity::migrations::MigrationFile;

pub(super) fn parse_alter_function_rename(
    migration: &MigrationFile,
    after_alter: usize,
) -> Result<Option<(String, String, usize)>, String> {
    let sql = migration.sql.as_str();
    let mut cursor = Cursor::new(sql, after_alter);
    cursor.skip_trivia()?;
    if !cursor.consume_word_if("function") {
        return Ok(None);
    }
    cursor.skip_trivia()?;
    if cursor.consume_word_if("if") {
        return Err(format!(
            "ALTER FUNCTION IF EXISTS is unsupported and must fail closed in {}",
            migration.path.display()
        ));
    }

    let schema = cursor.read_identifier()?;
    cursor.skip_trivia()?;
    if cursor.current_byte() != Some(b'.') {
        return Err(format!(
            "ALTER FUNCTION in {} must use a schema-qualified canonical identity",
            migration.path.display()
        ));
    }
    cursor.advance_one();
    cursor.skip_trivia()?;
    let function_name = cursor.read_identifier()?;
    cursor.skip_trivia()?;
    if cursor.current_byte() != Some(b'(') {
        return Err(format!(
            "ALTER FUNCTION {schema}.{function_name} in {} omits argument types and is ambiguous",
            migration.path.display()
        ));
    }
    let close = matching_parenthesis(sql, cursor.position)?;
    let arguments = sql.get(cursor.position + 1..close).ok_or_else(|| {
        format!(
            "ALTER FUNCTION argument range is invalid in {}",
            migration.path.display()
        )
    })?;
    let argument_types = canonical_argument_types(arguments)?.join(",");
    let source = format!("{schema}.{function_name}({argument_types})");
    cursor.position = close + 1;
    cursor.skip_trivia()?;
    if !cursor.consume_word_if("rename") {
        return Ok(None);
    }
    cursor.skip_trivia()?;
    if !cursor.consume_word_if("to") {
        return Err(format!(
            "ALTER FUNCTION RENAME in {} lacks TO",
            migration.path.display()
        ));
    }
    cursor.skip_trivia()?;
    let target_name = cursor.read_identifier()?;
    cursor.skip_trivia()?;
    if cursor.current_byte() != Some(b';') {
        return Err(format!(
            "ALTER FUNCTION RENAME target in {} must be one unqualified name followed by ';'",
            migration.path.display()
        ));
    }
    let target = format!("{schema}.{target_name}({argument_types})");
    Ok(Some((source, target, cursor.position + 1)))
}

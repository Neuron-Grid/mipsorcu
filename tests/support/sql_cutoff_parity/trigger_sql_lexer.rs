//! SQL-aware lexical and control-flow support for trigger vocabulary guards.

use std::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Word,
    SingleQuoted,
    Operator,
    OpenParenthesis,
    CloseParenthesis,
    Semicolon,
    Opaque,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Token {
    kind: TokenKind,
    range: Range<usize>,
}

impl Token {
    fn text<'a>(&self, sql: &'a str) -> Result<&'a str, String> {
        sql.get(self.range.clone())
            .ok_or_else(|| "SQL token byte range does not fit source".to_owned())
    }

    fn is_word(&self, sql: &str, expected: &str) -> Result<bool, String> {
        Ok(self.kind == TokenKind::Word && self.text(sql)?.eq_ignore_ascii_case(expected))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlFrame {
    If { id: usize },
    Case,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveTarget {
    owner_id: usize,
    start: usize,
}

/// Locates exact trigger branches and bounds each branch at its same-level delimiter.
pub(super) fn trigger_branch_ranges(body: &str) -> Result<Vec<Range<usize>>, String> {
    let tokens = significant_tokens(body)?;
    let mut controls = Vec::<ControlFrame>::new();
    let mut branches = Vec::<Range<usize>>::new();
    let mut active = None::<ActiveTarget>;
    let mut next_if_id = 0usize;
    let mut index = 0usize;

    while index < tokens.len() {
        if tokens[index].is_word(body, "end")? {
            if token_is_word(&tokens, index.saturating_add(1), body, "if")? {
                let owner_id = pop_if(&mut controls)?;
                close_target(
                    &mut active,
                    owner_id,
                    tokens[index].range.start,
                    &mut branches,
                )?;
                index = index.saturating_add(2);
                continue;
            }
            if token_is_word(&tokens, index.saturating_add(1), body, "case")? {
                pop_case(&mut controls)?;
                index = index.saturating_add(2);
                continue;
            }
            if controls.last() == Some(&ControlFrame::Case) {
                controls.pop();
            }
            index = index.saturating_add(1);
            continue;
        }

        if tokens[index].is_word(body, "case")? {
            controls.push(ControlFrame::Case);
            index = index.saturating_add(1);
            continue;
        }

        if tokens[index].is_word(body, "elsif")? {
            let owner_id = current_if_id(&controls, "ELSIF")?;
            close_target(
                &mut active,
                owner_id,
                tokens[index].range.start,
                &mut branches,
            )?;
            if exact_trigger_header(&tokens, index, body)? {
                start_target(&mut active, owner_id, tokens[index].range.start)?;
            }
            index = index.saturating_add(1);
            continue;
        }

        if tokens[index].is_word(body, "else")? {
            match controls.last() {
                Some(ControlFrame::If { id }) => {
                    close_target(&mut active, *id, tokens[index].range.start, &mut branches)?;
                }
                Some(ControlFrame::Case) => {}
                None => return Err("unmatched ELSE in trigger owner body".to_owned()),
            }
            index = index.saturating_add(1);
            continue;
        }

        if tokens[index].is_word(body, "if")? {
            let owner_id = next_if_id;
            next_if_id = next_if_id
                .checked_add(1)
                .ok_or_else(|| "IF control identifier overflow".to_owned())?;
            controls.push(ControlFrame::If { id: owner_id });
            if exact_trigger_header(&tokens, index, body)? {
                start_target(&mut active, owner_id, tokens[index].range.start)?;
            }
        }
        index = index.saturating_add(1);
    }

    if !controls.is_empty() || active.is_some() {
        return Err("unclosed or ambiguous IF/CASE control flow in trigger owner body".to_owned());
    }
    Ok(branches)
}

/// Locates effective `NOT IN (<literal-list>)` expressions outside quoted regions.
pub(super) fn effective_not_in_literal_lists(branch: &str) -> Result<Vec<Range<usize>>, String> {
    let tokens = significant_tokens(branch)?;
    let mut lists = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        if !tokens[index].is_word(branch, "not")? {
            index = index.saturating_add(1);
            continue;
        }
        if !token_is_word(&tokens, index.saturating_add(1), branch, "in")? {
            index = index.saturating_add(1);
            continue;
        }
        let open_index = index.saturating_add(2);
        if tokens.get(open_index).map(|token| token.kind) != Some(TokenKind::OpenParenthesis) {
            return Err(
                "effective trigger NOT IN must be followed by a parenthesized literal list"
                    .to_owned(),
            );
        }
        let close_index = matching_parenthesis_token(&tokens, open_index)?;
        let open_end = tokens
            .get(open_index)
            .ok_or_else(|| "NOT IN opening parenthesis token disappeared".to_owned())?
            .range
            .end;
        let close_start = tokens
            .get(close_index)
            .ok_or_else(|| "NOT IN closing parenthesis token disappeared".to_owned())?
            .range
            .start;
        lists.push(open_end..close_start);
        index = close_index.saturating_add(1);
    }
    Ok(lists)
}

fn exact_trigger_header(tokens: &[Token], start: usize, sql: &str) -> Result<bool, String> {
    let branch_keyword = tokens
        .get(start)
        .ok_or_else(|| "trigger branch keyword token disappeared".to_owned())?;
    if !branch_keyword.is_word(sql, "if")? && !branch_keyword.is_word(sql, "elsif")? {
        return Ok(false);
    }
    let Some(v_key) = tokens.get(start.saturating_add(1)) else {
        return Ok(false);
    };
    let Some(equality) = tokens.get(start.saturating_add(2)) else {
        return Ok(false);
    };
    let Some(literal) = tokens.get(start.saturating_add(3)) else {
        return Ok(false);
    };
    let Some(then_keyword) = tokens.get(start.saturating_add(4)) else {
        return Ok(false);
    };
    Ok(v_key.is_word(sql, "v_key")?
        && equality.kind == TokenKind::Operator
        && equality.text(sql)? == "="
        && literal.kind == TokenKind::SingleQuoted
        && literal.text(sql)? == "'trigger'"
        && then_keyword.is_word(sql, "then")?)
}

fn start_target(
    active: &mut Option<ActiveTarget>,
    owner_id: usize,
    start: usize,
) -> Result<(), String> {
    if active.is_some() {
        return Err("nested or overlapping trigger branches are ambiguous".to_owned());
    }
    *active = Some(ActiveTarget { owner_id, start });
    Ok(())
}

fn close_target(
    active: &mut Option<ActiveTarget>,
    owner_id: usize,
    end: usize,
    branches: &mut Vec<Range<usize>>,
) -> Result<(), String> {
    if active
        .as_ref()
        .is_some_and(|target| target.owner_id == owner_id)
    {
        let target = active
            .take()
            .ok_or_else(|| "active trigger branch disappeared while closing".to_owned())?;
        if target.start >= end {
            return Err("trigger branch has an invalid or empty source range".to_owned());
        }
        branches.push(target.start..end);
    }
    Ok(())
}

fn current_if_id(controls: &[ControlFrame], keyword: &str) -> Result<usize, String> {
    match controls.last() {
        Some(ControlFrame::If { id }) => Ok(*id),
        Some(ControlFrame::Case) => Err(format!(
            "{keyword} cannot delimit an IF branch while CASE is the innermost control"
        )),
        None => Err(format!("unmatched {keyword} in trigger owner body")),
    }
}

fn pop_if(controls: &mut Vec<ControlFrame>) -> Result<usize, String> {
    match controls.pop() {
        Some(ControlFrame::If { id }) => Ok(id),
        Some(ControlFrame::Case) => {
            Err("END IF mismatches an open CASE in trigger owner body".to_owned())
        }
        None => Err("unmatched END IF in trigger owner body".to_owned()),
    }
}

fn pop_case(controls: &mut Vec<ControlFrame>) -> Result<(), String> {
    match controls.pop() {
        Some(ControlFrame::Case) => Ok(()),
        Some(ControlFrame::If { .. }) => {
            Err("END CASE mismatches an open IF in trigger owner body".to_owned())
        }
        None => Err("unmatched END CASE in trigger owner body".to_owned()),
    }
}

fn token_is_word(
    tokens: &[Token],
    index: usize,
    sql: &str,
    expected: &str,
) -> Result<bool, String> {
    tokens
        .get(index)
        .map_or(Ok(false), |token| token.is_word(sql, expected))
}

fn matching_parenthesis_token(tokens: &[Token], open: usize) -> Result<usize, String> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token.kind {
            TokenKind::OpenParenthesis => depth = depth.saturating_add(1),
            TokenKind::CloseParenthesis => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| "NOT IN list has an unmatched ')'".to_owned())?;
                if depth == 0 {
                    return Ok(index);
                }
            }
            _ => {}
        }
    }
    Err("NOT IN list has an unmatched '('".to_owned())
}

fn significant_tokens(sql: &str) -> Result<Vec<Token>, String> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index = index.saturating_add(1);
        } else if starts_line_comment(bytes, index) {
            index = skip_line_comment(bytes, index);
        } else if starts_block_comment(bytes, index) {
            index = skip_block_comment(bytes, index)?;
        } else if bytes[index] == b'\'' {
            let end = skip_single_quoted(sql, index)?;
            tokens.push(Token {
                kind: TokenKind::SingleQuoted,
                range: index..end,
            });
            index = end;
        } else if bytes[index] == b'"' {
            let end = skip_double_quoted(bytes, index)?;
            tokens.push(Token {
                kind: TokenKind::Opaque,
                range: index..end,
            });
            index = end;
        } else if bytes[index] == b'$' {
            if let Some(end) = skip_dollar_quoted(sql, index)? {
                tokens.push(Token {
                    kind: TokenKind::Opaque,
                    range: index..end,
                });
                index = end;
            } else {
                tokens.push(single_byte_token(TokenKind::Other, index));
                index = index.saturating_add(1);
            }
        } else if is_word_start(bytes[index]) {
            let end = consume_word(bytes, index);
            tokens.push(Token {
                kind: TokenKind::Word,
                range: index..end,
            });
            index = end;
        } else if is_operator_character(bytes[index]) {
            let end = consume_operator(bytes, index);
            tokens.push(Token {
                kind: TokenKind::Operator,
                range: index..end,
            });
            index = end;
        } else {
            let kind = match bytes[index] {
                b'(' => TokenKind::OpenParenthesis,
                b')' => TokenKind::CloseParenthesis,
                b';' => TokenKind::Semicolon,
                _ => TokenKind::Other,
            };
            tokens.push(single_byte_token(kind, index));
            index = index.saturating_add(1);
        }
    }
    Ok(tokens)
}

fn single_byte_token(kind: TokenKind, start: usize) -> Token {
    Token {
        kind,
        range: start..start.saturating_add(1),
    }
}

fn is_word_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_word_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn consume_word(bytes: &[u8], start: usize) -> usize {
    let mut end = start.saturating_add(1);
    while end < bytes.len() && is_word_continue(bytes[end]) {
        end = end.saturating_add(1);
    }
    end
}

fn is_operator_character(byte: u8) -> bool {
    matches!(
        byte,
        b'+' | b'-'
            | b'*'
            | b'/'
            | b'<'
            | b'>'
            | b'='
            | b'~'
            | b'!'
            | b'@'
            | b'#'
            | b'%'
            | b'^'
            | b'&'
            | b'|'
            | b'`'
            | b'?'
    )
}

fn consume_operator(bytes: &[u8], start: usize) -> usize {
    let mut end = start.saturating_add(1);
    while end < bytes.len()
        && is_operator_character(bytes[end])
        && !starts_line_comment(bytes, end)
        && !starts_block_comment(bytes, end)
    {
        end = end.saturating_add(1);
    }
    end
}

fn starts_line_comment(bytes: &[u8], index: usize) -> bool {
    bytes.get(index..index.saturating_add(2)) == Some(b"--")
}

fn skip_line_comment(bytes: &[u8], start: usize) -> usize {
    bytes
        .get(start..)
        .and_then(|tail| tail.iter().position(|byte| *byte == b'\n'))
        .map_or(bytes.len(), |relative| {
            start.saturating_add(relative).saturating_add(1)
        })
}

fn starts_block_comment(bytes: &[u8], index: usize) -> bool {
    bytes.get(index..index.saturating_add(2)) == Some(b"/*")
}

fn skip_block_comment(bytes: &[u8], start: usize) -> Result<usize, String> {
    let mut depth = 1usize;
    let mut index = start.saturating_add(2);
    while index < bytes.len() {
        if starts_block_comment(bytes, index) {
            depth = depth.saturating_add(1);
            index = index.saturating_add(2);
        } else if bytes.get(index..index.saturating_add(2)) == Some(b"*/") {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| "SQL block comment nesting underflow".to_owned())?;
            index = index.saturating_add(2);
            if depth == 0 {
                return Ok(index);
            }
        } else {
            index = index.saturating_add(1);
        }
    }
    Err(format!("unterminated SQL block comment at byte {start}"))
}

fn skip_single_quoted(sql: &str, start: usize) -> Result<usize, String> {
    let bytes = sql.as_bytes();
    let mut index = start.saturating_add(1);
    while index < bytes.len() {
        if bytes[index] == b'\'' {
            if bytes.get(index.saturating_add(1)) == Some(&b'\'') {
                index = index.saturating_add(2);
            } else {
                return Ok(index.saturating_add(1));
            }
        } else {
            index = index.saturating_add(1);
        }
    }
    Err(format!(
        "unterminated SQL single-quoted literal at byte {start}"
    ))
}

fn skip_double_quoted(bytes: &[u8], start: usize) -> Result<usize, String> {
    let mut index = start.saturating_add(1);
    while index < bytes.len() {
        if bytes[index] == b'"' {
            if bytes.get(index.saturating_add(1)) == Some(&b'"') {
                index = index.saturating_add(2);
            } else {
                return Ok(index.saturating_add(1));
            }
        } else {
            index = index.saturating_add(1);
        }
    }
    Err(format!(
        "unterminated SQL double-quoted token at byte {start}"
    ))
}

fn skip_dollar_quoted(sql: &str, start: usize) -> Result<Option<usize>, String> {
    let bytes = sql.as_bytes();
    let Some(tag_end_relative) = bytes
        .get(start.saturating_add(1)..)
        .and_then(|tail| tail.iter().position(|byte| *byte == b'$'))
    else {
        return Ok(None);
    };
    let tag_end = start.saturating_add(1).saturating_add(tag_end_relative);
    let tag = bytes
        .get(start.saturating_add(1)..tag_end)
        .ok_or_else(|| "dollar-quote tag range is invalid".to_owned())?;
    if !valid_dollar_tag(tag) {
        return Ok(None);
    }
    let delimiter = sql
        .get(start..tag_end.saturating_add(1))
        .ok_or_else(|| "dollar-quote delimiter range is invalid".to_owned())?;
    let content_start = tag_end.saturating_add(1);
    let relative_close = sql
        .get(content_start..)
        .ok_or_else(|| "dollar-quote content range is invalid".to_owned())?
        .find(delimiter)
        .ok_or_else(|| format!("unterminated SQL dollar quote {delimiter}"))?;
    Ok(Some(
        content_start
            .saturating_add(relative_close)
            .saturating_add(delimiter.len()),
    ))
}

fn valid_dollar_tag(tag: &[u8]) -> bool {
    tag.is_empty()
        || (tag
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            && tag
                .iter()
                .skip(1)
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_'))
}

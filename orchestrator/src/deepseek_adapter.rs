//! Inert DeepSeek Harness CLI specification and installed-version JSONL validation.
//!
//! This module does not start a process, inspect authentication, or select a provider
//! route. Its contract is limited to the installed `@deepseek-ai/dsh-headless`
//! `0.2.1-rc.3` emitter. A future supervisor must independently verify that the
//! selected profile routes only through an authorized service before execution.

use std::fmt;

use serde::Deserialize;
use serde::de::{IgnoredAny, Visitor};
use uuid::Uuid;

use crate::agent::{AgentRequest, AgentRole, AgentStage, Failure};

const MAX_PROMPT_BYTES: usize = 64 * 1024;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_EVENT_BYTES: usize = 32 * 1024;
const MAX_SESSION_ID_BYTES: usize = 64;
// The installed JavaScript emitter sums usage as Number before serializing it.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Command data for a future supervisor; this value is not an execution capability.
pub struct DeepSeekCommand {
    stdin: String,
    request: AgentRequest,
}

impl DeepSeekCommand {
    pub fn program(&self) -> &'static str {
        "dsh"
    }

    /// The task is sent on stdin, so it is not exposed in process arguments.
    /// No `--session-id` is supplied: headless uses a fresh session by default.
    pub fn args(&self) -> [&'static str; 3] {
        ["--profile", "headless", "--json"]
    }

    pub fn stdin(&self) -> &[u8] {
        self.stdin.as_bytes()
    }
}

impl fmt::Debug for DeepSeekCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeepSeekCommand")
            .field("stdin", &"[REDACTED]")
            .finish()
    }
}

fn validate_request(request: AgentRequest) -> Result<(), Failure> {
    if request.task_id.is_nil()
        || request.operation_id.is_nil()
        || request.role != AgentRole::Implementer
        || !matches!(request.stage, AgentStage::Plan | AgentStage::Implement)
        || request.attempt > 3
    {
        return Err(Failure::InvalidInput);
    }
    Ok(())
}

/// Build an inert headless command for an implementer request.
///
/// The selected Harness profile and its provider route are not inspected here.
/// The supervisor must bind the resulting stdout, stderr, and exit status to this
/// single invocation and independently enforce the configured billing boundary.
pub fn command_spec(request: AgentRequest, prompt: &str) -> Result<DeepSeekCommand, Failure> {
    validate_request(request)?;
    if prompt.trim().is_empty() || prompt.len() > MAX_PROMPT_BYTES || prompt.contains('\0') {
        return Err(Failure::InvalidInput);
    }

    Ok(DeepSeekCommand {
        stdin: prompt.to_owned(),
        request,
    })
}

/// A CLI-reported completion, not evidence that the requested work succeeded.
/// Model text, reasoning, and tool contents are discarded by this parser.
#[derive(Eq, PartialEq)]
pub struct DeepSeekResult {
    /// Local correlation only; the supervisor must bind the stream to this invocation.
    pub request: AgentRequest,
    /// UUID suffix of the fresh `session-<uuid>` identity reported by the CLI.
    pub session_id: Uuid,
    /// Provider-reported input tokens summed across all completed steps, bounded to
    /// the PostgreSQL `bigint` range used by task usage accounting.
    pub input_tokens: u64,
    /// Provider-reported output tokens summed across all completed steps, bounded to
    /// the PostgreSQL `bigint` range used by task usage accounting.
    pub output_tokens: u64,
    /// CLI-reported total tokens summed across completed steps, bounded to the
    /// PostgreSQL `bigint` range. This is not inferred from buckets.
    pub model_tokens: u64,
}

impl fmt::Debug for DeepSeekResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeepSeekResult")
            .field("request", &self.request)
            .field("session_id", &"[REDACTED]")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum OutputEvent {
    #[serde(rename = "session")]
    Session {
        #[serde(rename = "sessionId")]
        session_id: String,
        cwd: String,
    },
    #[serde(rename = "status")]
    Status(StatusEvent),
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "thinking")]
    Thinking { text: String },
    #[serde(rename = "tool_call")]
    ToolCall {
        #[serde(rename = "callId")]
        call_id: String,
        tool: String,
        input: IgnoredAny,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        #[serde(rename = "callId")]
        call_id: String,
        status: ToolStatus,
        result: String,
    },
    #[serde(rename = "final")]
    Final { text: String },
    #[serde(rename = "error")]
    Error { message: String },
}

#[derive(Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum StatusEvent {
    TurnStart {
        turn: u64,
    },
    StepStart {
        turn: u64,
        step: u64,
    },
    StepEnd {
        turn: u64,
        step: u64,
        #[serde(default, rename = "usage")]
        usage: Option<Usage>,
    },
    TurnEnd {
        turn: u64,
        reason: serde_json::Value,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ToolStatus {
    Completed,
    Error,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Usage {
    input_tokens: u64,
    output_tokens: u64,
    #[serde(default)]
    total_tokens: OptionalTokenCount,
    #[serde(default)]
    cache_read_tokens: OptionalTokenCount,
    #[serde(default)]
    cache_write_tokens: OptionalTokenCount,
    #[serde(default)]
    reasoning_tokens: OptionalTokenCount,
}

#[derive(Default)]
struct OptionalTokenCount(Option<u64>);

impl<'de> Deserialize<'de> for OptionalTokenCount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TokenCountVisitor;

        impl<'de> Visitor<'de> for TokenCountVisitor {
            type Value = OptionalTokenCount;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a non-negative integer token count")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OptionalTokenCount(Some(value)))
            }
        }

        deserializer.deserialize_u64(TokenCountVisitor)
    }
}

impl Usage {
    fn validate(&self) -> Result<u64, Failure> {
        let values = [
            self.input_tokens,
            self.output_tokens,
            self.total_tokens.0.unwrap_or_default(),
            self.cache_read_tokens.0.unwrap_or_default(),
            self.cache_write_tokens.0.unwrap_or_default(),
            self.reasoning_tokens.0.unwrap_or_default(),
        ];
        if values.into_iter().any(|value| value > MAX_SAFE_INTEGER) {
            return Err(Failure::InvalidInput);
        }
        let reported_total = self.total_tokens.0.ok_or(Failure::Unavailable)?;
        let input_output_total = self
            .input_tokens
            .checked_add(self.output_tokens)
            .ok_or(Failure::InvalidInput)?;
        if reported_total < input_output_total {
            return Err(Failure::InvalidInput);
        }
        Ok(reported_total)
    }
}

fn checked_token_sum(total: u64, step_tokens: u64) -> Result<u64, Failure> {
    total
        .checked_add(step_tokens)
        .filter(|sum| *sum <= i64::MAX as u64)
        .ok_or(Failure::InvalidInput)
}

/// Validate one installed-version `--json` stream without exposing its contents.
///
/// Both a zero process exit and a complete `turn_end`/`final` sequence with reason
/// `completed` are required. Installed headless does not place the terminal reason
/// in its `final` event; the parser therefore requires it in the preceding `status`
/// event. Headless aggregates attempts within each step and omits step usage if that
/// aggregate is incomplete, so every completed step must include `totalTokens`.
/// Any explicit error, cancellation/non-completed reason, incomplete stream, unknown
/// event, or nonzero process exit is a failure.
pub fn parse_jsonl(
    bytes: &[u8],
    command: &DeepSeekCommand,
    exit_success: bool,
) -> Result<DeepSeekResult, Failure> {
    if !exit_success {
        return Err(Failure::Unavailable);
    }
    if bytes.is_empty() || bytes.len() > MAX_OUTPUT_BYTES || !bytes.ends_with(b"\n") {
        return Err(Failure::InvalidInput);
    }

    let mut session_id = None;
    let mut turn_started = false;
    let mut active_turn = None;
    let mut active_step = None;
    let mut next_step = 1_u64;
    let mut completed_steps = 0_u64;
    let mut input_tokens = 0_u64;
    let mut output_tokens = 0_u64;
    let mut model_tokens = 0_u64;
    let mut turn_ended = false;
    let mut final_seen = false;

    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() || line.len() > MAX_EVENT_BYTES {
            return Err(Failure::InvalidInput);
        }
        let event: OutputEvent = serde_json::from_slice(line).map_err(|_| Failure::InvalidInput)?;
        if final_seen {
            return Err(Failure::InvalidSession);
        }

        match event {
            OutputEvent::Session {
                session_id: raw_id,
                cwd,
            } => {
                if session_id.is_some() || turn_started || raw_id.len() > MAX_SESSION_ID_BYTES {
                    return Err(Failure::InvalidSession);
                }
                let uuid = raw_id
                    .strip_prefix("session-")
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .filter(|value| !value.is_nil())
                    .ok_or(Failure::InvalidSession)?;
                if cwd.is_empty() {
                    return Err(Failure::InvalidInput);
                }
                session_id = Some(uuid);
            }
            OutputEvent::Status(status) => {
                if session_id.is_none() || turn_ended {
                    return Err(Failure::InvalidSession);
                }
                match status {
                    StatusEvent::TurnStart { turn } => {
                        if turn_started || turn == 0 {
                            return Err(Failure::InvalidSession);
                        }
                        turn_started = true;
                        active_turn = Some(turn);
                    }
                    StatusEvent::StepStart { turn, step } => {
                        if active_turn != Some(turn) || active_step.is_some() || step != next_step {
                            return Err(Failure::InvalidSession);
                        }
                        active_step = Some(step);
                    }
                    StatusEvent::StepEnd { turn, step, usage } => {
                        if active_turn != Some(turn) || active_step != Some(step) {
                            return Err(Failure::InvalidSession);
                        }
                        let usage = usage.ok_or(Failure::Unavailable)?;
                        let step_model_tokens = usage.validate()?;
                        input_tokens = checked_token_sum(input_tokens, usage.input_tokens)?;
                        output_tokens = checked_token_sum(output_tokens, usage.output_tokens)?;
                        model_tokens = checked_token_sum(model_tokens, step_model_tokens)?;
                        completed_steps = completed_steps
                            .checked_add(1)
                            .ok_or(Failure::InvalidInput)?;
                        next_step = next_step.checked_add(1).ok_or(Failure::InvalidInput)?;
                        active_step = None;
                    }
                    StatusEvent::TurnEnd { turn, reason } => {
                        if active_turn != Some(turn)
                            || active_step.is_some()
                            || completed_steps == 0
                        {
                            return Err(Failure::InvalidSession);
                        }
                        let completed = reason
                            .as_object()
                            .and_then(|value| value.get("kind"))
                            .and_then(serde_json::Value::as_str)
                            == Some("completed");
                        if !completed {
                            return Err(Failure::Unavailable);
                        }
                        turn_ended = true;
                    }
                }
            }
            OutputEvent::Text { text } | OutputEvent::Thinking { text } => {
                let _ = text;
                if !turn_started || turn_ended {
                    return Err(Failure::InvalidSession);
                }
            }
            OutputEvent::ToolCall {
                call_id,
                tool,
                input,
            } => {
                let _ = (call_id, tool, input);
                if !turn_started || turn_ended {
                    return Err(Failure::InvalidSession);
                }
            }
            OutputEvent::ToolResult {
                call_id,
                status,
                result,
            } => {
                let _ = (call_id, result);
                if !turn_started || turn_ended {
                    return Err(Failure::InvalidSession);
                }
                if matches!(status, ToolStatus::Error) {
                    // A completed tool error is not itself a failed agent run, but
                    // it is never treated as evidence of success by this adapter.
                    continue;
                }
            }
            OutputEvent::Final { text } => {
                let _ = text;
                if !turn_ended {
                    return Err(Failure::InvalidSession);
                }
                final_seen = true;
            }
            OutputEvent::Error { message } => {
                let _ = message;
                return Err(Failure::Unavailable);
            }
        }
    }

    if !turn_started || !turn_ended || !final_seen {
        return Err(Failure::Unavailable);
    }
    Ok(DeepSeekResult {
        request: command.request,
        session_id: session_id.ok_or(Failure::InvalidSession)?,
        input_tokens,
        output_tokens,
        model_tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AgentRequest {
        AgentRequest {
            task_id: Uuid::from_u128(1),
            operation_id: Uuid::from_u128(2),
            stage: AgentStage::Implement,
            role: AgentRole::Implementer,
            attempt: 0,
        }
    }

    fn command() -> DeepSeekCommand {
        command_spec(request(), "do the task").expect("valid command")
    }

    fn completed_stream() -> Vec<u8> {
        concat!(
            "{\"type\":\"session\",\"sessionId\":\"session-00000000-0000-0000-0000-000000000003\",\"cwd\":\"/workspace\"}\n",
            "{\"type\":\"status\",\"phase\":\"turn_start\",\"turn\":1}\n",
            "{\"type\":\"status\",\"phase\":\"step_start\",\"turn\":1,\"step\":1}\n",
            "{\"type\":\"text\",\"text\":\"SECRET assistant content\"}\n",
            "{\"type\":\"tool_call\",\"callId\":\"call-1\",\"tool\":\"bash\",\"input\":{\"secret\":\"SECRET tool input\"}}\n",
            "{\"type\":\"tool_result\",\"callId\":\"call-1\",\"status\":\"completed\",\"result\":\"SECRET tool result\"}\n",
            "{\"type\":\"status\",\"phase\":\"step_end\",\"turn\":1,\"step\":1,\"usage\":{\"inputTokens\":1,\"outputTokens\":2,\"totalTokens\":3}}\n",
            "{\"type\":\"status\",\"phase\":\"turn_end\",\"turn\":1,\"reason\":{\"kind\":\"completed\"}}\n",
            "{\"type\":\"final\",\"text\":\"SECRET final content\"}\n",
        )
        .as_bytes()
        .to_vec()
    }

    #[test]
    fn command_is_inert_stdin_mode_without_resume_id() {
        let command = command_spec(request(), "private task text").expect("valid command");
        assert_eq!(command.program(), "dsh");
        assert_eq!(command.args(), ["--profile", "headless", "--json"]);
        assert_eq!(command.stdin(), b"private task text");
        assert!(!format!("{command:?}").contains("private task text"));
    }

    #[test]
    fn command_rejects_invalid_role_stage_and_prompt() {
        let mut invalid = request();
        invalid.role = AgentRole::Reviewer;
        assert_eq!(
            command_spec(invalid, "task").err(),
            Some(Failure::InvalidInput)
        );

        let mut invalid = request();
        invalid.stage = AgentStage::Review;
        assert_eq!(
            command_spec(invalid, "task").err(),
            Some(Failure::InvalidInput)
        );
        assert_eq!(
            command_spec(request(), "  ").err(),
            Some(Failure::InvalidInput)
        );
    }

    #[test]
    fn accepts_only_a_complete_successful_installed_jsonl_run() {
        let result = parse_jsonl(&completed_stream(), &command(), true).expect("success stream");
        assert_eq!(result.session_id, Uuid::from_u128(3));
        assert_eq!(result.request, request());
        assert_eq!(result.input_tokens, 1);
        assert_eq!(result.output_tokens, 2);
        assert_eq!(result.model_tokens, 3);
        let debug = format!("{result:?}");
        assert!(!debug.contains("SECRET"));
        assert!(!debug.contains(&result.session_id.to_string()));
    }

    #[test]
    fn sums_all_step_usage_including_retry_aggregates() {
        let stream = String::from_utf8(completed_stream())
            .expect("fixture is UTF-8")
            .replace(
                "{\"type\":\"status\",\"phase\":\"turn_end\",\"turn\":1",
                concat!(
                    "{\"type\":\"status\",\"phase\":\"step_start\",\"turn\":1,\"step\":2}\n",
                    "{\"type\":\"status\",\"phase\":\"step_end\",\"turn\":1,\"step\":2,\"usage\":{\"inputTokens\":4,\"outputTokens\":5,\"cacheReadTokens\":2,\"cacheWriteTokens\":3,\"totalTokens\":20}}\n",
                    "{\"type\":\"status\",\"phase\":\"turn_end\",\"turn\":1"
                ),
            );
        let result = parse_jsonl(stream.as_bytes(), &command(), true).expect("complete usage");
        assert_eq!(result.input_tokens, 5);
        assert_eq!(result.output_tokens, 7);
        assert_eq!(result.model_tokens, 23);
    }

    #[test]
    fn rejects_missing_incomplete_and_out_of_range_usage() {
        let base = String::from_utf8(completed_stream()).expect("fixture is UTF-8");
        for usage in [
            "",
            ",\"usage\":{\"inputTokens\":1}",
            ",\"usage\":{\"inputTokens\":1,\"outputTokens\":2}",
            ",\"usage\":{\"inputTokens\":-1,\"outputTokens\":1}",
            ",\"usage\":{\"inputTokens\":1.0,\"outputTokens\":1}",
            ",\"usage\":{\"inputTokens\":18446744073709551616,\"outputTokens\":1}",
            ",\"usage\":{\"inputTokens\":1,\"outputTokens\":1,\"totalTokens\":2,\"unknown\":2}",
            ",\"usage\":{\"inputTokens\":1,\"outputTokens\":1,\"totalTokens\":1}",
            ",\"usage\":{\"inputTokens\":1,\"inputTokens\":1,\"outputTokens\":1,\"totalTokens\":2}",
            ",\"usage\":{\"inputTokens\":1,\"outputTokens\":1,\"totalTokens\":null}",
            ",\"usage\":{\"inputTokens\":9007199254740992,\"outputTokens\":1,\"totalTokens\":9007199254740993}",
        ] {
            let mut line =
                "{\"type\":\"status\",\"phase\":\"step_end\",\"turn\":1,\"step\":1}".to_owned();
            line.push_str(usage);
            line.push('}');
            let stream = base.replace(
                "{\"type\":\"status\",\"phase\":\"step_end\",\"turn\":1,\"step\":1,\"usage\":{\"inputTokens\":1,\"outputTokens\":2,\"totalTokens\":3}}",
                &line,
            );
            let result = parse_jsonl(stream.as_bytes(), &command(), true);
            assert!(result.is_err(), "accepted invalid usage fixture: {line}");
        }
    }

    #[test]
    fn rejects_duplicate_misordered_and_skipped_steps() {
        let base = String::from_utf8(completed_stream()).expect("fixture is UTF-8");
        let duplicate_start = base.replace(
            "{\"type\":\"status\",\"phase\":\"step_end\"",
            concat!(
                "{\"type\":\"status\",\"phase\":\"step_start\",\"turn\":1,\"step\":1}\n",
                "{\"type\":\"status\",\"phase\":\"step_end\""
            ),
        );
        let out_of_order = base.replace(
            "\"phase\":\"step_start\",\"turn\":1,\"step\":1",
            "\"phase\":\"step_start\",\"turn\":1,\"step\":2",
        );
        let missing_end = base.replace(
            "{\"type\":\"status\",\"phase\":\"step_end\",\"turn\":1,\"step\":1,\"usage\":{\"inputTokens\":1,\"outputTokens\":2,\"totalTokens\":3}}\n",
            "",
        );
        let duplicate_end = base.replace(
            "{\"type\":\"status\",\"phase\":\"turn_end\",\"turn\":1",
            concat!(
                "{\"type\":\"status\",\"phase\":\"step_end\",\"turn\":1,\"step\":1,\"usage\":{\"inputTokens\":1,\"outputTokens\":2,\"totalTokens\":3}}\n",
                "{\"type\":\"status\",\"phase\":\"turn_end\",\"turn\":1"
            ),
        );
        let skipped_step = base.replace(
            "{\"type\":\"status\",\"phase\":\"turn_end\",\"turn\":1",
            concat!(
                "{\"type\":\"status\",\"phase\":\"step_start\",\"turn\":1,\"step\":3}\n",
                "{\"type\":\"status\",\"phase\":\"step_end\",\"turn\":1,\"step\":3,\"usage\":{\"inputTokens\":1,\"outputTokens\":1,\"totalTokens\":2}}\n",
                "{\"type\":\"status\",\"phase\":\"turn_end\",\"turn\":1"
            ),
        );
        for stream in [
            duplicate_start,
            duplicate_end,
            out_of_order,
            skipped_step,
            missing_end,
        ] {
            assert!(parse_jsonl(stream.as_bytes(), &command(), true).is_err());
        }
    }

    #[test]
    fn rejects_usage_sums_beyond_database_bigint() {
        for (input_tokens, output_tokens) in [(MAX_SAFE_INTEGER, 0), (0, MAX_SAFE_INTEGER), (0, 0)]
        {
            let mut stream = String::from(concat!(
                "{\"type\":\"session\",\"sessionId\":\"session-00000000-0000-0000-0000-000000000003\",\"cwd\":\"/workspace\"}\n",
                "{\"type\":\"status\",\"phase\":\"turn_start\",\"turn\":1}\n"
            ));
            for step in 1..=1025_u64 {
                stream.push_str(&format!(
                    "{{\"type\":\"status\",\"phase\":\"step_start\",\"turn\":1,\"step\":{step}}}\n{{\"type\":\"status\",\"phase\":\"step_end\",\"turn\":1,\"step\":{step},\"usage\":{{\"inputTokens\":{input_tokens},\"outputTokens\":{output_tokens},\"totalTokens\":{MAX_SAFE_INTEGER}}}}}\n"
                ));
            }
            stream.push_str(concat!(
                "{\"type\":\"status\",\"phase\":\"turn_end\",\"turn\":1,\"reason\":{\"kind\":\"completed\"}}\n",
                "{\"type\":\"final\",\"text\":\"completed\"}\n"
            ));
            assert!(stream.len() < MAX_OUTPUT_BYTES);
            assert_eq!(
                parse_jsonl(stream.as_bytes(), &command(), true).err(),
                Some(Failure::InvalidInput)
            );
        }
    }

    #[test]
    fn rejects_explicit_error_events_and_error_terminal_reason() {
        let explicit_error = "{\"type\":\"error\",\"message\":\"SECRET auth detail\"}\n";
        assert_eq!(
            parse_jsonl(explicit_error.as_bytes(), &command(), true).err(),
            Some(Failure::Unavailable)
        );

        let terminal = b"\"kind\":\"completed\"";
        let error_reason = completed_stream()
            .windows(terminal.len())
            .position(|v| v == terminal)
            .unwrap()
            + b"\"kind\":\"".len();
        let mut stream = completed_stream();
        stream.splice(
            error_reason..error_reason + b"completed".len(),
            b"error".iter().copied(),
        );
        assert_eq!(
            parse_jsonl(&stream, &command(), true).err(),
            Some(Failure::Unavailable)
        );
    }

    #[test]
    fn rejects_aborted_or_other_noncompleted_runs() {
        let mut stream = completed_stream();
        let terminal = b"\"kind\":\"completed\"";
        let index = stream
            .windows(terminal.len())
            .position(|value| value == terminal)
            .expect("terminal reason")
            + b"\"kind\":\"".len();
        stream.splice(
            index..index + b"completed".len(),
            b"aborted".iter().copied(),
        );
        assert_eq!(
            parse_jsonl(&stream, &command(), true).err(),
            Some(Failure::Unavailable)
        );
    }

    #[test]
    fn rejects_terminal_event_for_a_different_turn() {
        let stream = String::from_utf8(completed_stream()).unwrap().replace(
            "\"phase\":\"turn_end\",\"turn\":1",
            "\"phase\":\"turn_end\",\"turn\":2",
        );
        assert_eq!(
            parse_jsonl(stream.as_bytes(), &command(), true).err(),
            Some(Failure::InvalidSession)
        );
    }

    #[test]
    fn rejects_nonzero_exit_missing_final_duplicate_final_and_bad_json() {
        assert_eq!(
            parse_jsonl(&completed_stream(), &command(), false).err(),
            Some(Failure::Unavailable)
        );

        let mut missing_final = completed_stream();
        let start = missing_final
            .windows(b"{\"type\":\"final\"".len())
            .position(|value| value == b"{\"type\":\"final\"")
            .expect("final event");
        missing_final.truncate(start);
        assert_eq!(
            parse_jsonl(&missing_final, &command(), true).err(),
            Some(Failure::Unavailable)
        );

        let mut duplicate_final = completed_stream();
        duplicate_final.extend_from_slice(b"{\"type\":\"final\",\"text\":\"another\"}\n");
        assert_eq!(
            parse_jsonl(&duplicate_final, &command(), true).err(),
            Some(Failure::InvalidSession)
        );
        assert_eq!(
            parse_jsonl(b"{not-json}\n", &command(), true).err(),
            Some(Failure::InvalidInput)
        );
    }

    #[test]
    fn rejects_oversized_output_lines_and_unknown_master_only_fields() {
        let oversized = vec![b'a'; MAX_OUTPUT_BYTES + 1];
        assert_eq!(
            parse_jsonl(&oversized, &command(), true).err(),
            Some(Failure::InvalidInput)
        );

        let mut stream = completed_stream();
        let final_start = stream
            .windows(b"{\"type\":\"final\"".len())
            .position(|value| value == b"{\"type\":\"final\"")
            .expect("final event");
        let final_end = stream[final_start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|length| final_start + length)
            .expect("line terminator");
        stream.splice(
            final_end..final_end,
            b",\"reason\":{\"kind\":\"completed\"},\"sessionId\":\"session-00000000-0000-0000-0000-000000000003\""
                .iter()
                .copied(),
        );
        assert_eq!(
            parse_jsonl(&stream, &command(), true).err(),
            Some(Failure::InvalidInput)
        );
    }
}

//! Claude Code CLI command specification and result validation only.
//!
//! This module never starts a process or checks authentication/billing. In particular,
//! the caller must not treat a command spec as proof that subscription auth is selected.
//! Structured findings are retained only in memory and are never serialized here.

use std::fmt;

use serde::{Deserialize, de::SeqAccess, de::Visitor};
use uuid::Uuid;

use crate::agent::{AgentRequest, AgentRole, AgentStage, Failure, Outcome};

const MAX_PROMPT_BYTES: usize = 64 * 1024;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_FINDINGS: usize = 32;
const MAX_FINDING_BYTES: usize = 2048;
const MAX_FINDINGS_BYTES: usize = 32 * 1024;
const OUTPUT_SCHEMA: &str = r#"{"type":"object","properties":{"task_id":{"type":"string"},"operation_id":{"type":"string"},"invocation_id":{"type":"string"},"outcome":{"type":"string","enum":["approved","changes_requested"]},"findings":{"type":"array","items":{"type":"string","maxLength":2048},"maxItems":32}},"required":["task_id","operation_id","invocation_id","outcome","findings"],"additionalProperties":false}"#;

/// Inert command data for a future trusted supervisor. It is not an execution capability.
pub struct ClaudeCommand {
    stdin: String,
    request: AgentRequest,
    invocation_id: Uuid,
    session_id: String,
}

impl ClaudeCommand {
    pub fn program(&self) -> &'static str {
        "claude"
    }

    pub fn args(&self) -> Vec<&str> {
        vec![
            "-p",
            "--restricted",
            "--safe-mode",
            "--no-session-persistence",
            "--session-id",
            &self.session_id,
            "--strict-mcp-config",
            "--permission-mode",
            "plan",
            "--tools",
            "Read,Grep,Glob",
            "--output-format",
            "json",
            "--json-schema",
            OUTPUT_SCHEMA,
        ]
    }

    pub fn schema(&self) -> &'static str {
        OUTPUT_SCHEMA
    }

    pub fn stdin(&self) -> &[u8] {
        self.stdin.as_bytes()
    }

    #[cfg(test)]
    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    #[cfg(test)]
    pub(crate) fn invocation_id(&self) -> Uuid {
        self.invocation_id
    }
}

impl fmt::Debug for ClaudeCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaudeCommand")
            .field("stdin", &"[REDACTED]")
            .finish()
    }
}

fn validate_request(request: AgentRequest) -> Result<(), Failure> {
    if request.task_id.is_nil()
        || request.operation_id.is_nil()
        || request.role != AgentRole::Reviewer
        || request.stage != AgentStage::Review
        || request.attempt > 3
    {
        return Err(Failure::InvalidInput);
    }
    Ok(())
}

/// Builds an inert command specification. A future supervisor must independently
/// authorize and inspect the prompt before sending any of it to a provider.
pub fn command_spec(request: AgentRequest, prompt: &str) -> Result<ClaudeCommand, Failure> {
    validate_request(request)?;
    if prompt.trim().is_empty() || prompt.len() > MAX_PROMPT_BYTES || prompt.contains('\0') {
        return Err(Failure::InvalidInput);
    }
    let invocation_id = Uuid::new_v4();
    let stdin = format!(
        "Task ID: {}\nOperation ID: {}\nInvocation ID: {invocation_id}\nRole: reviewer\nStage: review\nAttempt: {}\nReturn the task ID, operation ID, invocation ID, review outcome, and bounded natural-language findings matching the JSON schema. Include at least one non-empty finding for changes_requested and no findings for approved.\n\n{prompt}",
        request.task_id, request.operation_id, request.attempt
    );
    if stdin.len() > MAX_PROMPT_BYTES {
        return Err(Failure::InvalidInput);
    }
    Ok(ClaudeCommand {
        stdin,
        request,
        invocation_id,
        session_id: Uuid::new_v4().to_string(),
    })
}

#[derive(Eq, PartialEq)]
pub struct ClaudeResult {
    /// Correlation only: `--no-session-persistence` sessions cannot be resumed.
    pub session_id: Uuid,
    pub outcome: Outcome,
    review_request: AgentRequest,
    findings: Vec<String>,
}

impl ClaudeResult {
    /// Returns untrusted findings retained in memory. They can contain secrets;
    /// callers must not log or persist them, or forward them without authorization
    /// and an independently established confidentiality boundary.
    pub fn findings(&self) -> &[String] {
        &self.findings
    }

    pub(crate) fn review_request(&self) -> AgentRequest {
        self.review_request
    }
}

impl fmt::Debug for ClaudeResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaudeResult")
            .field("session_id", &self.session_id)
            .field("outcome", &self.outcome)
            .field("findings", &"[REDACTED]")
            .finish()
    }
}

struct BoundedFindings(Vec<String>);

impl<'de> Deserialize<'de> for BoundedFindings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FindingsVisitor;

        impl<'de> Visitor<'de> for FindingsVisitor {
            type Value = BoundedFindings;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded array of non-empty review findings")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut findings = Vec::new();
                let mut total_bytes = 0usize;
                loop {
                    if findings.len() == MAX_FINDINGS {
                        if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                            return Err(serde::de::Error::custom("too many findings"));
                        }
                        break;
                    }
                    let Some(finding) = seq.next_element::<String>()? else {
                        break;
                    };
                    if finding.trim().is_empty()
                        || finding.contains('\0')
                        || finding.len() > MAX_FINDING_BYTES
                    {
                        return Err(serde::de::Error::custom("invalid finding"));
                    }
                    total_bytes = total_bytes
                        .checked_add(finding.len())
                        .filter(|total| *total <= MAX_FINDINGS_BYTES)
                        .ok_or_else(|| serde::de::Error::custom("findings too large"))?;
                    findings.push(finding);
                }
                Ok(BoundedFindings(findings))
            }
        }

        deserializer.deserialize_seq(FindingsVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuredOutcome {
    task_id: String,
    operation_id: String,
    invocation_id: String,
    outcome: String,
    findings: BoundedFindings,
}

fn validate_findings(findings: &[String], outcome: Outcome) -> Result<(), Failure> {
    if (outcome == Outcome::Approved && !findings.is_empty())
        || (outcome == Outcome::ChangesRequested && findings.is_empty())
    {
        return Err(Failure::InvalidInput);
    }
    Ok(())
}

#[derive(Deserialize)]
struct JsonEnvelope {
    #[serde(rename = "type")]
    kind: String,
    subtype: String,
    is_error: bool,
    session_id: String,
    structured_output: Option<StructuredOutcome>,
}

/// Validate the documented `--output-format json --json-schema` envelope without
/// retaining unstructured CLI/model text.
pub fn parse_json(
    bytes: &[u8],
    command: &ClaudeCommand,
    exit_success: bool,
) -> Result<ClaudeResult, Failure> {
    validate_request(command.request)?;
    if !exit_success {
        return Err(Failure::Unavailable);
    }
    if bytes.is_empty() || bytes.len() > MAX_OUTPUT_BYTES {
        return Err(Failure::InvalidInput);
    }
    let envelope: JsonEnvelope =
        serde_json::from_slice(bytes).map_err(|_| Failure::InvalidInput)?;
    if envelope.kind != "result" || envelope.subtype != "success" || envelope.is_error {
        return Err(Failure::Unavailable);
    }
    let session_id = Uuid::parse_str(&envelope.session_id).map_err(|_| Failure::InvalidSession)?;
    if session_id.is_nil() || envelope.session_id != command.session_id {
        return Err(Failure::InvalidSession);
    }
    let output = envelope.structured_output.ok_or(Failure::InvalidSession)?;
    if Uuid::parse_str(&output.task_id).ok() != Some(command.request.task_id)
        || Uuid::parse_str(&output.operation_id).ok() != Some(command.request.operation_id)
        || Uuid::parse_str(&output.invocation_id).ok() != Some(command.invocation_id)
    {
        return Err(Failure::InvalidSession);
    }
    let outcome = match output.outcome.as_str() {
        "approved" => Outcome::Approved,
        "changes_requested" => Outcome::ChangesRequested,
        _ => return Err(Failure::InvalidInput),
    };
    validate_findings(&output.findings.0, outcome)?;
    Ok(ClaudeResult {
        session_id,
        outcome,
        review_request: command.request,
        findings: output.findings.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> AgentRequest {
        AgentRequest {
            task_id: Uuid::from_u128(1),
            operation_id: Uuid::from_u128(2),
            stage: AgentStage::Review,
            role: AgentRole::Reviewer,
            attempt: 0,
        }
    }

    fn output_with_findings(command: &ClaudeCommand, outcome: &str, findings: &[&str]) -> Vec<u8> {
        serde_json::json!({
            "type": "result",
            "subtype": "success",
            "is_error": false,
            "session_id": command.session_id,
            "total_cost_usd": 1.0,
            "structured_output": {
                "task_id": command.request.task_id.to_string(),
                "operation_id": command.request.operation_id.to_string(),
                "invocation_id": command.invocation_id.to_string(),
                "outcome": outcome,
                "findings": findings
            },
            "result": "sensitive free-form result"
        })
        .to_string()
        .into_bytes()
    }

    fn output(command: &ClaudeCommand, outcome: &str) -> Vec<u8> {
        let findings = if outcome == "changes_requested" {
            vec!["Review finding: validate the input before use."]
        } else {
            vec![]
        };
        output_with_findings(command, outcome, &findings)
    }

    #[test]
    fn command_spec_uses_documented_print_and_schema_modes_without_secrets_in_debug() {
        let command = command_spec(request(), "private review input").unwrap();
        let args = command.args();
        assert_eq!(command.program(), "claude");
        assert!(args.contains(&"-p"));
        assert!(args.contains(&"--restricted"));
        assert!(args.contains(&"--safe-mode"));
        assert!(args.contains(&"--no-session-persistence"));
        assert!(args.contains(&"--strict-mcp-config"));
        assert!(args.contains(&"--permission-mode"));
        assert!(args.contains(&"plan"));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--tools", "Read,Grep,Glob"])
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--output-format", "json"])
        );
        assert!(!args.contains(&"--bare"));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--json-schema", command.schema()])
        );
        assert!(serde_json::from_str::<serde_json::Value>(command.schema()).is_ok());
        assert!(
            std::str::from_utf8(command.stdin())
                .unwrap()
                .contains("private review input")
        );
        assert!(!format!("{command:?}").contains("private review input"));
    }

    #[test]
    fn parses_only_correlated_structured_review_outcomes() {
        let command = command_spec(request(), "review input").unwrap();
        for (outcome, expected) in [
            ("approved", Outcome::Approved),
            ("changes_requested", Outcome::ChangesRequested),
        ] {
            let result = parse_json(&output(&command, outcome), &command, true).unwrap();
            assert_eq!(result.session_id.to_string(), command.session_id);
            assert_eq!(result.outcome, expected);
            if expected == Outcome::ChangesRequested {
                assert_eq!(
                    result.findings(),
                    ["Review finding: validate the input before use."]
                );
            } else {
                assert!(result.findings().is_empty());
            }
            assert!(!format!("{result:?}").contains("Review finding"));
            assert!(!format!("{result:?}").contains("sensitive free-form result"));
        }

        let mut wrong =
            serde_json::from_slice::<serde_json::Value>(&output(&command, "approved")).unwrap();
        wrong["structured_output"]["invocation_id"] = Uuid::from_u128(99).to_string().into();
        assert_eq!(
            parse_json(&wrong.to_string().into_bytes(), &command, true),
            Err(Failure::InvalidSession)
        );
    }

    #[test]
    fn rejects_findings_that_violate_outcome_or_memory_bounds() {
        let command = command_spec(request(), "review input").unwrap();
        let invalid_findings: Vec<Vec<String>> = vec![
            vec![],
            vec!["  \n".to_owned()],
            vec!["bad\0finding".to_owned()],
            vec!["x".repeat(MAX_FINDING_BYTES + 1)],
            vec!["💥".repeat(MAX_FINDING_BYTES / 4 + 1)],
            (0..=MAX_FINDINGS).map(|_| "finding".to_owned()).collect(),
            (0..=MAX_FINDINGS_BYTES / MAX_FINDING_BYTES)
                .map(|_| "x".repeat(MAX_FINDING_BYTES))
                .collect(),
        ];
        for findings in invalid_findings {
            let references: Vec<&str> = findings.iter().map(String::as_str).collect();
            assert_eq!(
                parse_json(
                    &output_with_findings(&command, "changes_requested", &references),
                    &command,
                    true
                ),
                Err(Failure::InvalidInput)
            );
        }

        assert_eq!(
            parse_json(
                &output_with_findings(&command, "approved", &["unexpected finding"]),
                &command,
                true
            ),
            Err(Failure::InvalidInput)
        );

        let mut missing_findings =
            serde_json::from_slice::<serde_json::Value>(&output(&command, "approved")).unwrap();
        missing_findings["structured_output"]
            .as_object_mut()
            .unwrap()
            .remove("findings");
        assert_eq!(
            parse_json(&missing_findings.to_string().into_bytes(), &command, true),
            Err(Failure::InvalidInput)
        );
    }

    #[test]
    fn rejects_high_density_findings_during_deserialization() {
        let command = command_spec(request(), "review input").unwrap();
        let findings = vec!["x"; 10_000];
        let bytes = output_with_findings(&command, "changes_requested", &findings);
        assert!(bytes.len() < MAX_OUTPUT_BYTES);
        assert_eq!(
            parse_json(&bytes, &command, true),
            Err(Failure::InvalidInput)
        );
    }

    #[test]
    fn rejects_cli_errors_missing_structured_output_and_invalid_outcomes() {
        let command = command_spec(request(), "review input").unwrap();
        assert_eq!(
            parse_json(&output(&command, "approved"), &command, false),
            Err(Failure::Unavailable)
        );
        let mut error =
            serde_json::from_slice::<serde_json::Value>(&output(&command, "approved")).unwrap();
        error["is_error"] = true.into();
        assert_eq!(
            parse_json(&error.to_string().into_bytes(), &command, true),
            Err(Failure::Unavailable)
        );
        error["is_error"] = false.into();
        error["session_id"] = "not-a-session-id".into();
        assert_eq!(
            parse_json(&error.to_string().into_bytes(), &command, true),
            Err(Failure::InvalidSession)
        );
        error["session_id"] = Uuid::nil().to_string().into();
        assert_eq!(
            parse_json(&error.to_string().into_bytes(), &command, true),
            Err(Failure::InvalidSession)
        );
        error["session_id"] = Uuid::new_v4().to_string().into();
        assert_eq!(
            parse_json(&error.to_string().into_bytes(), &command, true),
            Err(Failure::InvalidSession)
        );
        error["session_id"] = command.session_id.clone().into();
        error.as_object_mut().unwrap().remove("structured_output");
        assert_eq!(
            parse_json(&error.to_string().into_bytes(), &command, true),
            Err(Failure::InvalidSession)
        );
        assert_eq!(
            parse_json(&output(&command, "uncertain"), &command, true),
            Err(Failure::InvalidInput)
        );
        assert!(parse_json(&[b'x'; MAX_OUTPUT_BYTES + 1], &command, true).is_err());
    }

    #[test]
    fn rejects_requests_outside_the_independent_review_role() {
        assert!(command_spec(request(), "review input").is_ok());
        assert!(
            command_spec(
                AgentRequest {
                    stage: AgentStage::Implement,
                    ..request()
                },
                "x"
            )
            .is_err()
        );
        assert!(
            command_spec(
                AgentRequest {
                    role: AgentRole::Implementer,
                    ..request()
                },
                "x"
            )
            .is_err()
        );
        assert!(command_spec(request(), "\0").is_err());
    }
}

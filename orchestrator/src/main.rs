use std::{env, ffi::OsString, path::PathBuf, process::ExitCode, time::Duration};

use mipsorcu_orchestrator::{
    github::{GitHubAdapter, GitHubError},
    mock,
    policy::PolicyBundle,
    postgres::TaskStore,
};
use uuid::Uuid;

#[tokio::main]
async fn main() -> ExitCode {
    let result = match utf8_args(env::args_os().skip(1)) {
        Ok(args) => run(args).await,
        Err(message) => Err(message.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn utf8_args(args: impl IntoIterator<Item = OsString>) -> Result<Vec<String>, &'static str> {
    args.into_iter()
        .map(|arg| {
            arg.into_string()
                .map_err(|_| "arguments must be valid UTF-8")
        })
        .collect()
}

async fn run(args: Vec<String>) -> Result<(), String> {
    match args.as_slice() {
        [] => {
            print_help();
            Ok(())
        }
        [arg] if arg == "--help" || arg == "help" => {
            print_help();
            Ok(())
        }
        [arg] if arg == "demo" => mock::run_demo().await,
        [command, task_id] if command == "status" => status(task_id).await,
        [command, policy_path, issue_number, operation_id, expected_branch, expected_head_sha]
            if command == "observe-candidate" =>
        {
            let args = CandidateArgs::parse(
                policy_path,
                issue_number,
                operation_id,
                expected_branch,
                expected_head_sha,
            )?;
            observe_candidate(args).await
        }
        [command] if command == "observe-candidate" => Err(
            "usage: observe-candidate <policy-file> <issue-number> <operation-uuid> <expected-branch> <expected-head-sha>".into(),
        ),
        [command, ..] if matches!(command.as_str(), "enqueue" | "run" | "resume") => Err(format!(
            "{command} is unavailable: trusted policy and fresh GitHub verification are not wired to a production worker"
        )),
        _ => Err("unsupported command; run `mipsorcu-orchestrator --help`".into()),
    }
}

fn print_help() {
    println!(
        "mipsorcu-orchestrator\n\nUsage:\n  mipsorcu-orchestrator --help\n  mipsorcu-orchestrator demo\n  mipsorcu-orchestrator status <task-uuid>\n  mipsorcu-orchestrator observe-candidate <policy-file> <issue-number> <operation-uuid> <expected-branch> <expected-head-sha>\n\nCommands:\n  demo          Run the mock-only crash/replay/resume flow through simulated merge to COMPLETED.\n  status <id>   Show an explicitly unverified PostgreSQL task snapshot.\n  observe-candidate  Read-only candidate lookup using an operator-controlled policy file and ORCHESTRATOR_GITHUB_TOKEN. Protect the policy file and choose its path as the operator; the loader does not verify ownership or access permissions. This reports an observation only, not verified CI or approvals and not authorization for operation completion, retry, or merge.\n  enqueue/run/resume are unavailable until trusted policy, fresh GitHub reads, workspace isolation, and a production worker are connected.\n\nThe demo uses in-memory state and does not call PostgreSQL, GitHub, Git, the filesystem, or a model. Its merge is simulated and does not change a repository. status reads ORCHESTRATOR_DATABASE_URL from the environment."
    );
}

struct CandidateArgs<'a> {
    policy_path: &'a str,
    issue_number: u64,
    operation_id: Uuid,
    expected_branch: &'a str,
    expected_head_sha: &'a str,
}

impl<'a> CandidateArgs<'a> {
    fn parse(
        policy_path: &'a str,
        issue_number: &str,
        operation_id: &str,
        expected_branch: &'a str,
        expected_head_sha: &'a str,
    ) -> Result<Self, String> {
        let issue_number = issue_number
            .parse::<u64>()
            .ok()
            .filter(|number| *number != 0)
            .ok_or_else(|| "issue number must be a positive integer".to_owned())?;
        let operation_id = Uuid::parse_str(operation_id)
            .ok()
            .filter(|id| !id.is_nil())
            .ok_or_else(|| "operation id must be a non-nil UUID".to_owned())?;

        Ok(Self {
            policy_path,
            issue_number,
            operation_id,
            expected_branch,
            expected_head_sha,
        })
    }
}

async fn observe_candidate(args: CandidateArgs<'_>) -> Result<(), String> {
    let token = env::var("ORCHESTRATOR_GITHUB_TOKEN")
        .map_err(|_| "ORCHESTRATOR_GITHUB_TOKEN is required".to_owned())?;
    if token.trim().is_empty() {
        return Err("ORCHESTRATOR_GITHUB_TOKEN must not be empty".into());
    }
    let policy_path = PathBuf::from(args.policy_path);
    let policy = tokio::task::spawn_blocking(move || PolicyBundle::load(&policy_path))
        .await
        .map_err(|_| "policy loader task failed".to_owned())?
        .map_err(|_| "could not load the operator policy file".to_owned())?;
    let adapter =
        GitHubAdapter::new(policy.github_policy().clone(), &token).map_err(map_candidate_error)?;
    let request = adapter.observe_pull_request_candidate(
        args.issue_number,
        args.operation_id,
        &policy.task_policy().base_sha,
        args.expected_branch,
        args.expected_head_sha,
    );
    let candidate = tokio::time::timeout(Duration::from_secs(30), request)
        .await
        .map_err(|_| {
            "candidate observation timed out; operation completion, retry, and merge are not authorized"
                .to_owned()
        })?
        .map_err(map_candidate_error)?;

    println!("candidate_pull_request: #{candidate}");
    println!(
        "observation only: CI and approvals were not verified; this does not authorize operation completion, retry, or merge"
    );
    Ok(())
}

fn map_candidate_error(error: GitHubError) -> String {
    match error {
        GitHubError::PullCandidateNotFound => "no matching candidate was observed; this does not prove create failure or authorize operation completion, retry, or merge".into(),
        GitHubError::AmbiguousPullCandidate => "multiple matching candidates were observed; operation completion, retry, and merge are not authorized".into(),
        GitHubError::InvalidTaskReference => "candidate inputs are invalid".into(),
        GitHubError::InvalidPolicy => "operator policy is invalid".into(),
        _ => "candidate observation failed; operation completion, retry, and merge are not authorized".into(),
    }
}

async fn status(task_id: &str) -> Result<(), String> {
    let task_id = Uuid::parse_str(task_id).map_err(|_| "task id must be a UUID".to_owned())?;
    let database_url = env::var("ORCHESTRATOR_DATABASE_URL")
        .map_err(|_| "ORCHESTRATOR_DATABASE_URL is required".to_owned())?;
    let store = TaskStore::connect(&database_url)
        .await
        .map_err(|_| "could not connect to orchestrator database".to_owned())?;
    let task = store
        .get(task_id)
        .await
        .map_err(|_| "could not read a valid task record".to_owned())?;
    println!("verification: database snapshot only; GitHub and trusted policy not rechecked");
    println!("task_id: {}", task.task_id);
    println!("issue: #{}", task.issue_number);
    println!("state: {:?}", task.state);
    println!("base_sha: {}", task.base_sha);
    println!("head_sha: {}", task.head_sha.as_deref().unwrap_or("unset"));
    println!("attempts: {}", task.attempts);
    println!(
        "assignee: {}",
        task.assignee.as_deref().unwrap_or("unset").escape_debug()
    );
    println!("validation_passed_db_claim: {}", task.validation_passed);
    println!(
        "pull_request: {}",
        task.pull_request
            .map_or_else(|| "unset".to_owned(), |n| format!("#{n}"))
    );
    println!(
        "checkpoint: {}",
        task.checkpoint
            .map_or_else(|| "unset".to_owned(), |s| format!("{s:?}"))
    );
    println!("elapsed_seconds: {}", task.elapsed.as_secs());
    println!("model_tokens: {}", task.model_tokens);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CandidateArgs, map_candidate_error, utf8_args};
    use mipsorcu_orchestrator::github::GitHubError;
    use std::ffi::OsString;
    use uuid::Uuid;

    #[test]
    fn candidate_arguments_reject_zero_issue_before_setup() {
        assert_eq!(
            CandidateArgs::parse(
                "policy.json",
                "0",
                "00000000-0000-0000-0000-000000000001",
                "codex/issue-7-op-00000000-0000-0000-0000-000000000001",
                &"a".repeat(40),
            )
            .err()
            .as_deref(),
            Some("issue number must be a positive integer")
        );
    }

    #[test]
    fn candidate_arguments_reject_nil_operation_before_setup() {
        assert_eq!(
            CandidateArgs::parse(
                "policy.json",
                "7",
                "00000000-0000-0000-0000-000000000000",
                "codex/issue-7-op-00000000-0000-0000-0000-000000000001",
                &"a".repeat(40),
            )
            .err()
            .as_deref(),
            Some("operation id must be a non-nil UUID")
        );
    }

    #[test]
    fn candidate_arguments_parse_issue_and_non_nil_operation_uuid() {
        let operation_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("fixture UUID is valid");
        let expected_head_sha = "a".repeat(40);
        let parsed = CandidateArgs::parse(
            "policy.json",
            "7",
            "00000000-0000-0000-0000-000000000001",
            "codex/issue-7-op-00000000-0000-0000-0000-000000000001",
            &expected_head_sha,
        )
        .expect("valid CLI values parse");
        assert_eq!(parsed.issue_number, 7);
        assert_eq!(parsed.operation_id, operation_id);
    }

    #[test]
    fn candidate_error_mapping_is_static_and_distinguishes_no_candidate() {
        assert_eq!(
            map_candidate_error(GitHubError::PullCandidateNotFound),
            "no matching candidate was observed; this does not prove create failure or authorize operation completion, retry, or merge"
        );
        assert_eq!(
            map_candidate_error(GitHubError::Unavailable),
            "candidate observation failed; operation completion, retry, and merge are not authorized"
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_argument_returns_static_error_without_exposing_input() {
        use std::os::unix::ffi::OsStringExt;

        let invalid_argument = OsString::from_vec(vec![0xff, b's', b'e', b'c', b'r', b'e', b't']);
        assert_eq!(
            utf8_args([invalid_argument]),
            Err("arguments must be valid UTF-8")
        );
    }
}

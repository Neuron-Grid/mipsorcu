use std::{env, process::ExitCode};

use mipsorcu_orchestrator::{mock, postgres::TaskStore};
use uuid::Uuid;

#[tokio::main]
async fn main() -> ExitCode {
    match run(env::args().skip(1).collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
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
        [command, ..] if matches!(command.as_str(), "enqueue" | "run" | "resume") => Err(format!(
            "{command} is unavailable: trusted policy and fresh GitHub verification are not wired to a production worker"
        )),
        _ => Err("unsupported command; run `mipsorcu-orchestrator --help`".into()),
    }
}

fn print_help() {
    println!(
        "mipsorcu-orchestrator\n\nUsage:\n  mipsorcu-orchestrator --help\n  mipsorcu-orchestrator demo\n  mipsorcu-orchestrator status <task-uuid>\n\nCommands:\n  demo          Run a mock-only state, crash/replay, and resume demonstration.\n  status <id>   Show an explicitly unverified PostgreSQL task snapshot.\n  enqueue/run/resume are unavailable until trusted policy, fresh GitHub reads, workspace isolation, and a production worker are connected.\n\nstatus reads ORCHESTRATOR_DATABASE_URL from the environment. No merge or model command is implemented."
    );
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
    println!("assignee: {}", task.assignee.as_deref().unwrap_or("unset"));
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

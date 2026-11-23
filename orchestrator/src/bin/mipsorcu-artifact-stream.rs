use std::{
    env,
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

use mipsorcu_orchestrator::artifact_receiver::write_artifact_stream;
use uuid::Uuid;

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(task_id) = arguments.next() else {
        return usage_error();
    };
    let Some(operation_id) = arguments.next() else {
        return usage_error();
    };
    let Some(base_commit) = arguments.next() else {
        return usage_error();
    };
    let Some(worktree) = arguments.next() else {
        return usage_error();
    };
    if arguments.next().is_some() {
        return usage_error();
    }

    let (Some(task_id), Some(operation_id), Ok(base_commit)) = (
        task_id
            .to_str()
            .and_then(|value| Uuid::parse_str(value).ok()),
        operation_id
            .to_str()
            .and_then(|value| Uuid::parse_str(value).ok()),
        base_commit.into_string().map_err(|_| ()),
    ) else {
        return usage_error();
    };

    let stdout = io::stdout();
    let mut output = stdout.lock();
    match write_artifact_stream(
        task_id,
        operation_id,
        &base_commit,
        Path::new(&worktree),
        &mut output,
    )
    .and_then(|()| {
        output
            .flush()
            .map_err(|_| mipsorcu_orchestrator::artifact_receiver::ArtifactError::Io)
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            let _ = writeln!(io::stderr().lock(), "artifact transfer failed");
            ExitCode::FAILURE
        }
    }
}

fn usage_error() -> ExitCode {
    let _ = writeln!(io::stderr().lock(), "invalid artifact transfer arguments");
    ExitCode::FAILURE
}

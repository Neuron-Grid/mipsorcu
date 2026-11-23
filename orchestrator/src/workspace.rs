use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRequest {
    pub task_id: String,
    pub base_sha: String,
    pub repo: PathBuf,
    pub workspace_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePlan {
    pub repo: PathBuf,
    pub path: PathBuf,
    pub base_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceError {
    InvalidTaskId,
    InvalidSha,
    InvalidRoot,
    RepoMismatch,
    StaleBase,
    PathExists,
    GitUnavailable,
    WorktreeRejected,
    DirtyWorkspace,
    GitTimeout,
    GitOutputLimit,
}

impl WorkspaceRequest {
    /// Validate workspace inputs against a trusted, existing repository and its current HEAD.
    /// This function performs read-only Git queries and does not create the planned directory.
    pub fn plan(&self) -> Result<WorkspacePlan, WorkspaceError> {
        if !valid_task_id(&self.task_id) {
            return Err(WorkspaceError::InvalidTaskId);
        }
        if !valid_sha(&self.base_sha) {
            return Err(WorkspaceError::InvalidSha);
        }

        let repo = fs::canonicalize(&self.repo).map_err(|_| WorkspaceError::InvalidRoot)?;
        let root =
            fs::canonicalize(&self.workspace_root).map_err(|_| WorkspaceError::InvalidRoot)?;
        if !repo.is_dir() || !root.is_dir() || repo.starts_with(&root) || root.starts_with(&repo) {
            return Err(WorkspaceError::InvalidRoot);
        }

        let git_root = git_output(
            &repo,
            [OsStr::new("rev-parse"), OsStr::new("--show-toplevel")],
        )?;
        let git_root = PathBuf::from(git_root.trim());
        let git_root = fs::canonicalize(git_root).map_err(|_| WorkspaceError::RepoMismatch)?;
        if git_root != repo {
            return Err(WorkspaceError::RepoMismatch);
        }

        let head = git_output(&repo, [OsStr::new("rev-parse"), OsStr::new("HEAD")])?;
        if !head.trim().eq_ignore_ascii_case(&self.base_sha) {
            return Err(WorkspaceError::StaleBase);
        }

        let path = root.join(&self.task_id);
        if fs::symlink_metadata(&path).is_ok() {
            return Err(WorkspaceError::PathExists);
        }

        Ok(WorkspacePlan {
            repo,
            path,
            base_sha: self.base_sha.to_ascii_lowercase(),
        })
    }

    /// Create this task's detached worktree after the caller verifies its durable lease
    /// and trusted-policy authorization. Git receives arguments directly, without a shell.
    pub fn create(&self) -> Result<WorkspacePlan, WorkspaceError> {
        let plan = self.plan()?;
        let output = run_git(
            &plan.repo,
            [
                OsStr::new("worktree"),
                OsStr::new("add"),
                OsStr::new("--detach"),
                plan.path.as_os_str(),
                OsStr::new(&plan.base_sha),
            ],
        )?;
        if !output.status.success() {
            return Err(WorkspaceError::WorktreeRejected);
        }
        self.resume(&plan, &plan.base_sha)?;
        Ok(plan)
    }

    /// Validate a saved worktree checkpoint before reuse. Any staged, untracked, ignored,
    /// or modified file causes rejection; callers also revalidate GitHub state and policy.
    pub fn resume(
        &self,
        plan: &WorkspacePlan,
        expected_head_sha: &str,
    ) -> Result<(), WorkspaceError> {
        if !valid_task_id(&self.task_id)
            || !valid_sha(expected_head_sha)
            || plan.repo != fs::canonicalize(&self.repo).map_err(|_| WorkspaceError::InvalidRoot)?
            || plan.path
                != fs::canonicalize(&self.workspace_root)
                    .map_err(|_| WorkspaceError::InvalidRoot)?
                    .join(&self.task_id)
            || plan.base_sha != self.base_sha.to_ascii_lowercase()
        {
            return Err(WorkspaceError::InvalidRoot);
        }
        observe_worktree(&plan.repo, &plan.path, expected_head_sha).map(|_| ())
    }
}

/// Independently observe a registered task worktree before an external operation such as
/// opening a pull request. The caller supplies the trusted repository, task path, and
/// checkpoint SHA; the returned SHA is the clean local HEAD observed at call time.
pub fn observe_worktree(
    repo: &Path,
    path: &Path,
    expected_head_sha: &str,
) -> Result<String, WorkspaceError> {
    if !valid_sha(expected_head_sha) {
        return Err(WorkspaceError::InvalidSha);
    }
    observe_worktree_inner(repo, path, Some(expected_head_sha))
}

/// Observe a registered, clean task worktree when its expected head is not checkpointed yet.
pub fn observe_worktree_head(repo: &Path, path: &Path) -> Result<String, WorkspaceError> {
    observe_worktree_inner(repo, path, None)
}

fn observe_worktree_inner(
    repo: &Path,
    path: &Path,
    expected_head_sha: Option<&str>,
) -> Result<String, WorkspaceError> {
    let repo = fs::canonicalize(repo).map_err(|_| WorkspaceError::InvalidRoot)?;
    let path = fs::canonicalize(path).map_err(|_| WorkspaceError::InvalidRoot)?;
    if !repo.is_dir() || !path.is_dir() || path == repo || path.starts_with(&repo) {
        return Err(WorkspaceError::InvalidRoot);
    }
    let main_root = git_output(
        &repo,
        [OsStr::new("rev-parse"), OsStr::new("--show-toplevel")],
    )?;
    if fs::canonicalize(main_root.trim()).map_err(|_| WorkspaceError::RepoMismatch)? != repo {
        return Err(WorkspaceError::RepoMismatch);
    }

    let root = git_output(
        &path,
        [OsStr::new("rev-parse"), OsStr::new("--show-toplevel")],
    )?;
    if fs::canonicalize(root.trim()).map_err(|_| WorkspaceError::RepoMismatch)? != path
        || git_common_dir(&path)? != git_common_dir(&repo)?
    {
        return Err(WorkspaceError::RepoMismatch);
    }

    let registered = git_output(
        &repo,
        [
            OsStr::new("worktree"),
            OsStr::new("list"),
            OsStr::new("--porcelain"),
        ],
    )?;
    if !registered.lines().any(|line| {
        line.strip_prefix("worktree ")
            .and_then(|registered_path| fs::canonicalize(registered_path).ok())
            .is_some_and(|registered_path| registered_path == path)
    }) {
        return Err(WorkspaceError::RepoMismatch);
    }

    let head = git_output(&path, [OsStr::new("rev-parse"), OsStr::new("HEAD")])?;
    let head = head.trim();
    if expected_head_sha.is_some_and(|expected| !head.eq_ignore_ascii_case(expected)) {
        return Err(WorkspaceError::StaleBase);
    }
    if !is_clean_status(&git_status(&path)?) {
        return Err(WorkspaceError::DirtyWorkspace);
    }
    Ok(head.to_ascii_lowercase())
}

fn git_status(repo: &Path) -> Result<String, WorkspaceError> {
    let output = run_git(
        repo,
        [
            OsStr::new("status"),
            OsStr::new("--porcelain=v1"),
            OsStr::new("--untracked-files=all"),
            OsStr::new("--ignored=matching"),
            OsStr::new("--ignore-submodules=none"),
        ],
    )?;
    if !output.status.success() {
        return Err(WorkspaceError::RepoMismatch);
    }
    String::from_utf8(output.stdout).map_err(|_| WorkspaceError::RepoMismatch)
}

fn is_clean_status(status: &str) -> bool {
    status.is_empty()
}

fn git_common_dir(repo: &Path) -> Result<PathBuf, WorkspaceError> {
    let common = git_output(
        repo,
        [OsStr::new("rev-parse"), OsStr::new("--git-common-dir")],
    )?;
    let common = PathBuf::from(common.trim());
    fs::canonicalize(if common.is_absolute() {
        common
    } else {
        repo.join(common)
    })
    .map_err(|_| WorkspaceError::RepoMismatch)
}

fn git_output<const N: usize>(repo: &Path, args: [&OsStr; N]) -> Result<String, WorkspaceError> {
    let output = run_git(repo, args)?;
    if !output.status.success() {
        return Err(WorkspaceError::RepoMismatch);
    }
    String::from_utf8(output.stdout).map_err(|_| WorkspaceError::RepoMismatch)
}

const GIT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_GIT_OUTPUT: usize = 256 * 1024;
const MAX_GIT_READERS: usize = 16;
static ACTIVE_GIT_READERS: AtomicUsize = AtomicUsize::new(0);

fn run_git<const N: usize>(repo: &Path, args: [&OsStr; N]) -> Result<Output, WorkspaceError> {
    let mut command = Command::new("git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .arg("--no-optional-locks")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("core.untrackedCache=false")
        .arg("-c")
        .arg("core.hooksPath=/mipsorcu-disabled-hooks")
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_git_command(command)
}

fn run_git_command(mut command: Command) -> Result<Output, WorkspaceError> {
    // shortcut: other platforms may leak pipe descriptors, use an isolated helper before enabling them.
    if !cfg!(target_os = "linux") {
        return Err(WorkspaceError::GitUnavailable);
    }
    reserve_git_readers()?;
    #[cfg(unix)]
    command.process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            ACTIVE_GIT_READERS.fetch_sub(2, Ordering::AcqRel);
            return Err(WorkspaceError::GitUnavailable);
        }
    };
    let Some(stdout) = child.stdout.take() else {
        ACTIVE_GIT_READERS.fetch_sub(2, Ordering::AcqRel);
        stop_git(&mut child);
        return Err(WorkspaceError::GitUnavailable);
    };
    let Some(stderr) = child.stderr.take() else {
        ACTIVE_GIT_READERS.fetch_sub(2, Ordering::AcqRel);
        stop_git(&mut child);
        return Err(WorkspaceError::GitUnavailable);
    };
    let stdout_reader = match thread::Builder::new()
        .name("orchestrator-git-stdout".to_owned())
        .spawn(move || {
            let _slot = GitReaderSlot;
            read_bounded(stdout)
        }) {
        Ok(reader) => reader,
        Err(_) => {
            ACTIVE_GIT_READERS.fetch_sub(2, Ordering::AcqRel);
            stop_git(&mut child);
            return Err(WorkspaceError::GitUnavailable);
        }
    };
    let stderr_reader = match thread::Builder::new()
        .name("orchestrator-git-stderr".to_owned())
        .spawn(move || {
            let _slot = GitReaderSlot;
            read_bounded(stderr)
        }) {
        Ok(reader) => reader,
        Err(_) => {
            ACTIVE_GIT_READERS.fetch_sub(1, Ordering::AcqRel);
            stop_git(&mut child);
            return Err(WorkspaceError::GitUnavailable);
        }
    };

    let deadline = Instant::now() + GIT_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(_) => {
                stop_git(&mut child);
                return Err(WorkspaceError::GitUnavailable);
            }
        }
        if Instant::now() >= deadline {
            stop_git(&mut child);
            return Err(WorkspaceError::GitTimeout);
        }
        thread::sleep(Duration::from_millis(10));
    };

    while !stdout_reader.is_finished() || !stderr_reader.is_finished() {
        if Instant::now() >= deadline {
            // The reaped process-group ID can already refer to an unrelated process.
            return Err(WorkspaceError::GitTimeout);
        }
        thread::sleep(Duration::from_millis(10));
    }

    let (stdout, stdout_limited) = stdout_reader
        .join()
        .map_err(|_| WorkspaceError::GitUnavailable)?
        .map_err(|_| WorkspaceError::GitUnavailable)?;
    let (stderr, stderr_limited) = stderr_reader
        .join()
        .map_err(|_| WorkspaceError::GitUnavailable)?
        .map_err(|_| WorkspaceError::GitUnavailable)?;
    if stdout_limited || stderr_limited {
        return Err(WorkspaceError::GitOutputLimit);
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

struct GitReaderSlot;

impl Drop for GitReaderSlot {
    fn drop(&mut self) {
        ACTIVE_GIT_READERS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn reserve_git_readers() -> Result<(), WorkspaceError> {
    loop {
        let active = ACTIVE_GIT_READERS.load(Ordering::Acquire);
        let reserved = active
            .checked_add(2)
            .filter(|reserved| *reserved <= MAX_GIT_READERS)
            .ok_or(WorkspaceError::GitUnavailable)?;
        if ACTIVE_GIT_READERS
            .compare_exchange_weak(active, reserved, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Ok(());
        }
    }
}

fn stop_git(child: &mut std::process::Child) {
    let process_group = child.id();
    let _ = child.kill();
    stop_process_group(process_group);
    let _ = child.wait();
}

#[cfg(unix)]
fn stop_process_group(process_group: u32) {
    let process_group = format!("-{process_group}");
    let _ = Command::new("/bin/kill")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .arg("-KILL")
        .arg(process_group)
        .status();
}

#[cfg(not(unix))]
fn stop_process_group(_: u32) {}

fn read_bounded(mut reader: impl Read) -> io::Result<(Vec<u8>, bool)> {
    let mut output = Vec::with_capacity(MAX_GIT_OUTPUT);
    let mut buffer = [0_u8; 8192];
    let mut exceeded = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok((output, exceeded));
        }
        let remaining = MAX_GIT_OUTPUT.saturating_sub(output.len());
        output.extend_from_slice(&buffer[..count.min(remaining)]);
        exceeded |= count > remaining;
    }
}

fn valid_task_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn valid_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::WorkspaceRequest;
    use super::{
        MAX_GIT_OUTPUT, WorkspaceError, is_clean_status, read_bounded, valid_sha, valid_task_id,
    };
    #[cfg(not(target_os = "linux"))]
    use std::ffi::OsStr;
    #[cfg(not(target_os = "linux"))]
    use std::path::Path;
    #[cfg(target_os = "linux")]
    use std::path::PathBuf;

    #[test]
    fn accepts_only_uuid_task_ids_and_full_git_object_ids() {
        assert!(valid_task_id("01234567-89ab-cdef-0123-456789abcdef"));
        assert!(!valid_task_id("../main"));
        assert!(valid_sha(&"a".repeat(40)));
        assert!(!valid_sha("deadbeef"));
    }

    #[test]
    fn refuses_staged_tracked_untracked_and_ignored_changes_on_resume() {
        assert!(is_clean_status(""));
        assert!(!is_clean_status(" M src/main.rs\n"));
        assert!(!is_clean_status("A  src/main.rs\n"));
        assert!(!is_clean_status("?? notes.txt\n"));
        assert!(!is_clean_status("!! build/cache.bin\n"));
    }

    #[test]
    fn drains_git_output_but_fails_when_the_capture_limit_is_exceeded() {
        let input = vec![b'x'; MAX_GIT_OUTPUT + 1];
        let (captured, exceeded) = read_bounded(std::io::Cursor::new(input)).unwrap();
        assert_eq!(captured.len(), MAX_GIT_OUTPUT);
        assert!(exceeded);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refuses_a_base_sha_that_does_not_match_repository_head() {
        let request = WorkspaceRequest {
            task_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
            base_sha: "0".repeat(40),
            repo: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".."),
            workspace_root: std::env::temp_dir(),
        };
        assert_eq!(request.plan(), Err(WorkspaceError::StaleBase));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn captures_subprocess_output_on_linux() {
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", "printf 'synthetic output'"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let output = super::run_git_command(command).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"synthetic output");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn refuses_git_before_spawning_on_unsupported_platform() {
        assert!(matches!(
            super::run_git(Path::new("/missing"), [OsStr::new("--version")]),
            Err(WorkspaceError::GitUnavailable)
        ));
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .arg("--list")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        assert!(matches!(
            super::run_git_command(command),
            Err(WorkspaceError::GitUnavailable)
        ));
    }
}

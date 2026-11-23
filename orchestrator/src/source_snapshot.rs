//! Read-only Git object materialization without exposing Git metadata.
//!
//! The caller must provide a private, trusted parent directory (mode 0700 on Unix)
//! that no agent can access, and must stop every child before cleanup. Permissions alone
//! do not isolate processes running under the same user ID.

use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::{
    os::{
        fd::OwnedFd,
        unix::{ffi::OsStringExt, net::UnixStream, process::CommandExt},
    },
    process::Child,
};

use uuid::Uuid;

const MAX_TREE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_FILES: usize = 10_000;
pub(crate) const MAX_PATH_BYTES: usize = 4_096;
pub(crate) const MAX_PATH_COMPONENTS: usize = 128;
pub(crate) const MAX_TOTAL_PATH_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(unix)]
type DirectoryIdentity = (u64, u64);
#[cfg(not(unix))]
type DirectoryIdentity = ();

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotError {
    InvalidTaskId,
    InvalidCommit,
    InvalidPath,
    InvalidTree,
    InvalidBlob,
    UnsupportedEntry,
    LimitExceeded,
    InvalidRepository,
    UntrustedParent,
    PathExists,
    GitUnavailable,
    GitTimeout,
    UnsupportedPlatform,
    Io,
    CleanupFailed,
    RootChanged,
}

#[derive(Debug, Eq, PartialEq)]
struct SnapshotFile {
    path: PathBuf,
    oid: String,
    executable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObjectFormat {
    Sha1,
    Sha256,
}

impl ObjectFormat {
    fn parse(bytes: &[u8]) -> Result<Self, SnapshotError> {
        match bytes
            .strip_suffix(b"\n")
            .ok_or(SnapshotError::InvalidRepository)?
        {
            b"sha1" => Ok(Self::Sha1),
            b"sha256" => Ok(Self::Sha256),
            _ => Err(SnapshotError::InvalidRepository),
        }
    }

    fn oid_bytes(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

pub(crate) struct PathTrie {
    nodes: Vec<PathNode>,
    children: BTreeMap<(usize, String), usize>,
}

impl Default for PathTrie {
    fn default() -> Self {
        Self {
            nodes: vec![PathNode::default()],
            children: BTreeMap::new(),
        }
    }
}

#[derive(Default)]
struct PathNode {
    component: String,
    file: bool,
    directory: bool,
}

impl PathTrie {
    pub(crate) fn insert_file(&mut self, path: &str) -> Result<(), SnapshotError> {
        let mut parent = 0;
        let mut components = path.split('/').peekable();
        while let Some(component) = components.next() {
            let final_component = components.peek().is_none();
            let normalized = component.to_ascii_lowercase();
            let key = (parent, normalized);
            let node = if let Some(node) = self.children.get(&key).copied() {
                if self.nodes[node].component != component {
                    return Err(SnapshotError::InvalidTree);
                }
                node
            } else {
                let node = self.nodes.len();
                self.nodes.push(PathNode {
                    component: component.to_owned(),
                    ..PathNode::default()
                });
                self.children.insert(key, node);
                node
            };
            if self.nodes[node].file || (final_component && self.nodes[node].directory) {
                return Err(SnapshotError::InvalidTree);
            }
            if final_component {
                self.nodes[node].file = true;
            } else {
                self.nodes[node].directory = true;
            }
            parent = node;
        }
        Ok(())
    }

    pub(crate) fn insert_directory(&mut self, path: &str) -> Result<(), SnapshotError> {
        let mut parent = 0;
        for component in path.split('/') {
            let key = (parent, component.to_ascii_lowercase());
            let node = if let Some(node) = self.children.get(&key).copied() {
                if self.nodes[node].component != component || self.nodes[node].file {
                    return Err(SnapshotError::InvalidTree);
                }
                node
            } else {
                let node = self.nodes.len();
                self.nodes.push(PathNode {
                    component: component.to_owned(),
                    ..PathNode::default()
                });
                self.children.insert(key, node);
                node
            };
            self.nodes[node].directory = true;
            parent = node;
        }
        Ok(())
    }
}

/// A source-only tree. It has no `.git` directory and does not follow Git filters.
/// Call `cleanup` only after every process with access to this tree has stopped.
/// These synchronous operations can block; async callers should run them through
/// their runtime's blocking-work facility (for example, Tokio `spawn_blocking`).
pub struct SourceSnapshot {
    path: PathBuf,
    commit_sha: String,
    task_id: Uuid,
    identity: DirectoryIdentity,
    parent_identity: DirectoryIdentity,
}

impl SourceSnapshot {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn commit_sha(&self) -> &str {
        &self.commit_sha
    }

    pub fn task_id(&self) -> Uuid {
        self.task_id
    }

    pub(crate) fn verify_identity(&self) -> Result<(), SnapshotError> {
        let metadata = fs::symlink_metadata(&self.path).map_err(|_| SnapshotError::RootChanged)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(SnapshotError::RootChanged);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if (metadata.dev(), metadata.ino()) != self.identity {
                return Err(SnapshotError::RootChanged);
            }
        }
        let parent = self.path.parent().ok_or(SnapshotError::RootChanged)?;
        if directory_identity(parent).map_err(|_| SnapshotError::RootChanged)?
            != self.parent_identity
        {
            return Err(SnapshotError::RootChanged);
        }
        Ok(())
    }

    /// Remove only the directory created for this snapshot.
    /// Async callers should run this synchronous operation through their runtime's
    /// blocking-work facility (for example, Tokio `spawn_blocking`).
    pub fn cleanup(self) -> Result<(), SnapshotError> {
        self.verify_identity()?;
        remove_owned_root(&self.path, self.identity).map_err(|_| SnapshotError::CleanupFailed)
    }
}

/// Materialize tracked regular files from an exact commit object. This omits all
/// worktree changes, refs, hooks, config, attributes, and shared Git metadata.
///
/// The caller must ensure the parent is trusted and remains exclusively controlled
/// until cleanup; mode 0700 does not protect it from another process with the same UID.
/// Blob bytes are rehashed by Git without filters or object writes and compared
/// against the object IDs from the commit tree before the snapshot is returned.
/// Git execution uses nonblocking parent-side I/O and process-group termination. A
/// descendant that escapes that group may continue running; use OS-level containment
/// if terminating arbitrary descendants is required. If the direct child has already
/// exited, the old process-group ID is not signaled because the ID may have been reused.
/// The timeout is not a strict bound.
/// Blob contents are copied unchanged and are not scanned for secrets. Check the
/// snapshot before exposing it to an agent, and stop all access before calling cleanup.
/// This synchronous operation can block; async callers should use their runtime's
/// blocking-work facility (for example, Tokio `spawn_blocking`).
/// Linux is required until descriptor creation is atomic on other platforms.
pub fn create_snapshot(
    repo: &Path,
    trusted_parent: &Path,
    task_id: Uuid,
    commit_sha: &str,
) -> Result<SourceSnapshot, SnapshotError> {
    // shortcut: non-Linux descriptor creation may race, use an isolated helper before enabling it.
    if !cfg!(target_os = "linux") {
        return Err(SnapshotError::UnsupportedPlatform);
    }
    if task_id.is_nil() {
        return Err(SnapshotError::InvalidTaskId);
    }
    if !valid_oid(commit_sha) {
        return Err(SnapshotError::InvalidCommit);
    }
    let repo = fs::canonicalize(repo).map_err(|_| SnapshotError::InvalidRepository)?;
    let parent = fs::canonicalize(trusted_parent).map_err(|_| SnapshotError::UntrustedParent)?;
    if !repo.is_dir() || !parent.is_dir() || repo.starts_with(&parent) || parent.starts_with(&repo)
    {
        return Err(SnapshotError::UntrustedParent);
    }
    validate_private_parent(&parent)?;
    let parent_identity =
        directory_identity(&parent).map_err(|_| SnapshotError::UntrustedParent)?;
    let root_output = git(&repo, &["rev-parse", "--show-toplevel"], None, 8 * 1024)?;
    let reported_root = std::str::from_utf8(&root_output)
        .map_err(|_| SnapshotError::InvalidRepository)?
        .trim();
    if Path::new(reported_root) != repo {
        return Err(SnapshotError::InvalidRepository);
    }

    let resolved = git(
        &repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{commit_sha}^{{commit}}"),
        ],
        None,
        128,
    )?;
    let resolved = std::str::from_utf8(&resolved)
        .map_err(|_| SnapshotError::InvalidCommit)?
        .trim()
        .to_ascii_lowercase();
    if resolved != commit_sha.to_ascii_lowercase() {
        return Err(SnapshotError::InvalidCommit);
    }

    let git_dir = git(&repo, &["rev-parse", "--absolute-git-dir"], None, 8 * 1024)?;
    let git_dir =
        fs::canonicalize(parse_git_dir(&git_dir)?).map_err(|_| SnapshotError::InvalidRepository)?;
    if !git_dir.is_dir() {
        return Err(SnapshotError::InvalidRepository);
    }
    let object_format = ObjectFormat::parse(&git(
        &repo,
        &["rev-parse", "--show-object-format"],
        None,
        128,
    )?)?;
    if resolved.len() != object_format.oid_bytes() {
        return Err(SnapshotError::InvalidCommit);
    }

    let tree = git(
        &repo,
        &["ls-tree", "-r", "-z", "--full-tree", &resolved],
        None,
        MAX_TREE_BYTES,
    )?;
    let files = parse_tree(&tree)?;
    if files
        .iter()
        .any(|file| file.oid.len() != object_format.oid_bytes())
    {
        return Err(SnapshotError::InvalidTree);
    }
    let input = files
        .iter()
        .map(|file| format!("{}\n", file.oid))
        .collect::<String>()
        .into_bytes();
    let blobs = git(
        &repo,
        &["cat-file", "--batch"],
        Some(input),
        MAX_TOTAL_BYTES + MAX_FILES * 128,
    )?;
    let contents = parse_blobs(&blobs, &files)?;

    let path = parent.join(task_id.to_string());
    let mut builder = DirBuilder::new();
    set_new_directory_mode(&mut builder);
    builder.create(&path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            SnapshotError::PathExists
        } else {
            SnapshotError::Io
        }
    })?;
    let identity = directory_identity(&path).map_err(|_| SnapshotError::CleanupFailed)?;
    if set_directory_mode(&path).is_err() {
        cleanup_failed_snapshot(&path, identity, &parent, parent_identity)
            .map_err(|_| SnapshotError::CleanupFailed)?;
        return Err(SnapshotError::Io);
    }
    let materialized = write_snapshot(&path, &files, &contents)
        .and_then(|()| verify_snapshot_root(&path, identity, &parent, parent_identity))
        .and_then(|()| {
            if files.is_empty() {
                return Ok(());
            }
            let input = hash_object_paths(&files)?;
            let output = git_with_dir(
                &path,
                &git_dir,
                &["hash-object", "--no-filters", "--stdin-paths"],
                Some(input),
                MAX_FILES * (64 + 1),
            )?;
            verify_hash_object_output(&output, &files, object_format)
        })
        .and_then(|()| verify_snapshot_root(&path, identity, &parent, parent_identity));
    if let Err(error) = materialized {
        cleanup_failed_snapshot(&path, identity, &parent, parent_identity)?;
        return Err(error);
    }
    Ok(SourceSnapshot {
        path,
        commit_sha: resolved,
        task_id,
        identity,
        parent_identity,
    })
}

fn parse_git_dir(bytes: &[u8]) -> Result<PathBuf, SnapshotError> {
    let value = bytes
        .strip_suffix(b"\n")
        .filter(|value| !value.is_empty() && !value.contains(&0))
        .ok_or(SnapshotError::InvalidRepository)?;
    #[cfg(unix)]
    let path = PathBuf::from(std::ffi::OsString::from_vec(value.to_vec()));
    #[cfg(not(unix))]
    let path =
        PathBuf::from(std::str::from_utf8(value).map_err(|_| SnapshotError::InvalidRepository)?);
    if !path.is_absolute() {
        return Err(SnapshotError::InvalidRepository);
    }
    Ok(path)
}

fn hash_object_paths(files: &[SnapshotFile]) -> Result<Vec<u8>, SnapshotError> {
    let mut input = Vec::new();
    for file in files {
        let path = file.path.to_str().ok_or(SnapshotError::InvalidPath)?;
        validate_tree_path(path.as_bytes())?;
        input.extend_from_slice(b"./");
        input.extend_from_slice(path.as_bytes());
        input.push(b'\n');
    }
    Ok(input)
}

fn verify_hash_object_output(
    output: &[u8],
    files: &[SnapshotFile],
    object_format: ObjectFormat,
) -> Result<(), SnapshotError> {
    if files.is_empty() {
        return if output.is_empty() {
            Ok(())
        } else {
            Err(SnapshotError::InvalidBlob)
        };
    }
    let lines = output
        .strip_suffix(b"\n")
        .ok_or(SnapshotError::InvalidBlob)?
        .split(|byte| *byte == b'\n');
    let mut lines = lines;
    for file in files {
        let actual = lines.next().ok_or(SnapshotError::InvalidBlob)?;
        if actual.len() != object_format.oid_bytes()
            || !actual.iter().all(u8::is_ascii_hexdigit)
            || !actual.eq_ignore_ascii_case(file.oid.as_bytes())
        {
            return Err(SnapshotError::InvalidBlob);
        }
    }
    if lines.next().is_some() {
        return Err(SnapshotError::InvalidBlob);
    }
    Ok(())
}

fn verify_snapshot_root(
    path: &Path,
    identity: DirectoryIdentity,
    parent: &Path,
    parent_identity: DirectoryIdentity,
) -> Result<(), SnapshotError> {
    if directory_identity(parent).map_err(|_| SnapshotError::RootChanged)? != parent_identity
        || directory_identity(path).map_err(|_| SnapshotError::RootChanged)? != identity
    {
        return Err(SnapshotError::RootChanged);
    }
    Ok(())
}

fn cleanup_failed_snapshot(
    path: &Path,
    identity: DirectoryIdentity,
    parent: &Path,
    parent_identity: DirectoryIdentity,
) -> Result<(), SnapshotError> {
    verify_snapshot_root(path, identity, parent, parent_identity)?;
    remove_owned_root(path, identity)
}

fn parse_tree(bytes: &[u8]) -> Result<Vec<SnapshotFile>, SnapshotError> {
    if bytes.len() > MAX_TREE_BYTES {
        return Err(SnapshotError::LimitExceeded);
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    let mut paths = PathTrie::default();
    let mut total_path_bytes = 0usize;
    if !bytes.is_empty() && bytes.last() != Some(&0) {
        return Err(SnapshotError::InvalidTree);
    }
    let records = if bytes.is_empty() {
        &[][..]
    } else {
        &bytes[..bytes.len() - 1]
    };
    for record in records.split(|byte| *byte == 0) {
        if record.is_empty() {
            return Err(SnapshotError::InvalidTree);
        }
        if files.len() >= MAX_FILES {
            return Err(SnapshotError::LimitExceeded);
        }
        let separator = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(SnapshotError::InvalidTree)?;
        let (header, path_bytes) = (&record[..separator], &record[separator + 1..]);
        total_path_bytes = total_path_bytes
            .checked_add(path_bytes.len())
            .ok_or(SnapshotError::LimitExceeded)?;
        if path_bytes.len() > MAX_PATH_BYTES || total_path_bytes > MAX_TOTAL_PATH_BYTES {
            return Err(SnapshotError::LimitExceeded);
        }
        let mut fields = header.split(|byte| *byte == b' ');
        let mode = fields.next().ok_or(SnapshotError::InvalidTree)?;
        let kind = fields.next().ok_or(SnapshotError::InvalidTree)?;
        let oid = fields.next().ok_or(SnapshotError::InvalidTree)?;
        if fields.next().is_some()
            || !valid_oid(std::str::from_utf8(oid).map_err(|_| SnapshotError::InvalidTree)?)
        {
            return Err(SnapshotError::InvalidTree);
        }
        let executable = match (mode, kind) {
            (b"100644", b"blob") => false,
            (b"100755", b"blob") => true,
            (b"120000", _) | (b"160000", _) => return Err(SnapshotError::UnsupportedEntry),
            _ => return Err(SnapshotError::UnsupportedEntry),
        };
        validate_tree_path(path_bytes)?;
        let path_text = std::str::from_utf8(path_bytes).map_err(|_| SnapshotError::InvalidPath)?;
        let path = PathBuf::from(path_text);
        paths.insert_file(path_text)?;
        files.push(SnapshotFile {
            path,
            oid: std::str::from_utf8(oid)
                .map_err(|_| SnapshotError::InvalidTree)?
                .to_owned(),
            executable,
        });
    }
    Ok(files)
}

pub(crate) fn validate_tree_path(path: &[u8]) -> Result<(), SnapshotError> {
    if path.is_empty() || path[0] == b'/' || path.contains(&b'\\') || path.contains(&b':') {
        return Err(SnapshotError::InvalidPath);
    }
    if path.split(|byte| *byte == b'/').count() > MAX_PATH_COMPONENTS {
        return Err(SnapshotError::InvalidPath);
    }
    std::str::from_utf8(path).map_err(|_| SnapshotError::InvalidPath)?;
    for component in path.split(|byte| *byte == b'/') {
        if component.is_empty()
            || component == b"."
            || component == b".."
            || component.eq_ignore_ascii_case(b".git")
            || component.eq_ignore_ascii_case(b".hg")
            || component.eq_ignore_ascii_case(b".svn")
            || component.iter().any(|byte| *byte < 0x20 || *byte == 0x7f)
            || component.ends_with(b".")
            || component.ends_with(b" ")
            || component.iter().any(|byte| !byte.is_ascii())
        {
            return Err(SnapshotError::InvalidPath);
        }
    }
    Ok(())
}

fn parse_blobs(bytes: &[u8], files: &[SnapshotFile]) -> Result<Vec<Vec<u8>>, SnapshotError> {
    if bytes.len() > MAX_TOTAL_BYTES + MAX_FILES * 128 {
        return Err(SnapshotError::LimitExceeded);
    }
    let mut cursor = 0usize;
    let mut total = 0usize;
    let mut result = Vec::with_capacity(files.len());
    for file in files {
        let header_end = bytes[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or(SnapshotError::InvalidBlob)?
            + cursor;
        let header = &bytes[cursor..header_end];
        cursor = header_end + 1;
        let mut parts = header.split(|byte| *byte == b' ');
        let oid = parts.next().ok_or(SnapshotError::InvalidBlob)?;
        let kind = parts.next().ok_or(SnapshotError::InvalidBlob)?;
        let length = parts.next().ok_or(SnapshotError::InvalidBlob)?;
        if parts.next().is_some() || oid != file.oid.as_bytes() || kind != b"blob" {
            return Err(SnapshotError::InvalidBlob);
        }
        let length = std::str::from_utf8(length)
            .map_err(|_| SnapshotError::InvalidBlob)?
            .parse::<usize>()
            .map_err(|_| SnapshotError::InvalidBlob)?;
        total = total
            .checked_add(length)
            .ok_or(SnapshotError::LimitExceeded)?;
        let end = cursor
            .checked_add(length)
            .ok_or(SnapshotError::LimitExceeded)?;
        if length > MAX_FILE_BYTES
            || total > MAX_TOTAL_BYTES
            || end >= bytes.len()
            || bytes[end] != b'\n'
        {
            return Err(SnapshotError::LimitExceeded);
        }
        result.push(bytes[cursor..end].to_vec());
        cursor = end + 1;
    }
    if cursor != bytes.len() {
        return Err(SnapshotError::InvalidBlob);
    }
    Ok(result)
}

fn write_snapshot(
    root: &Path,
    files: &[SnapshotFile],
    contents: &[Vec<u8>],
) -> Result<(), SnapshotError> {
    if files.len() != contents.len() {
        return Err(SnapshotError::InvalidBlob);
    }
    for (entry, content) in files.iter().zip(contents) {
        let parent = entry.path.parent().ok_or(SnapshotError::InvalidPath)?;
        let mut current = root.to_path_buf();
        for component in parent.components() {
            current.push(component);
            if !current.exists() {
                fs::create_dir(&current).map_err(|_| SnapshotError::Io)?;
                set_directory_mode(&current)?;
            }
            let metadata = fs::symlink_metadata(&current).map_err(|_| SnapshotError::Io)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(SnapshotError::InvalidPath);
            }
        }
        let target = root.join(&entry.path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        set_file_mode(&mut options, entry.executable);
        let mut output = options.open(target).map_err(|_| SnapshotError::Io)?;
        output.write_all(content).map_err(|_| SnapshotError::Io)?;
    }
    Ok(())
}

#[cfg(unix)]
fn git(
    repo: &Path,
    args: &[&str],
    input: Option<Vec<u8>>,
    limit: usize,
) -> Result<Vec<u8>, SnapshotError> {
    git_with_optional_dir(repo, None, args, input, limit)
}

#[cfg(unix)]
fn git_with_dir(
    repo: &Path,
    git_dir: &Path,
    args: &[&str],
    input: Option<Vec<u8>>,
    limit: usize,
) -> Result<Vec<u8>, SnapshotError> {
    git_with_optional_dir(repo, Some(git_dir), args, input, limit)
}

#[cfg(unix)]
fn git_with_optional_dir(
    repo: &Path,
    git_dir: Option<&Path>,
    args: &[&str],
    input: Option<Vec<u8>>,
    limit: usize,
) -> Result<Vec<u8>, SnapshotError> {
    let mut command = Command::new("git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .arg("--no-pager")
        .arg("--no-lazy-fetch")
        .arg("--no-replace-objects")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("core.untrackedCache=false")
        .arg("-c")
        .arg("core.hooksPath=/dev/null");
    if let Some(git_dir) = git_dir {
        command.arg("--git-dir").arg(git_dir);
    }
    command.arg("-C").arg(repo).args(args);
    run_git_command(command, input, limit, GIT_TIMEOUT)
}

#[cfg(not(unix))]
fn git(_: &Path, _: &[&str], _: Option<Vec<u8>>, _: usize) -> Result<Vec<u8>, SnapshotError> {
    Err(SnapshotError::UntrustedParent)
}

#[cfg(not(unix))]
fn git_with_dir(
    _: &Path,
    _: &Path,
    _: &[&str],
    _: Option<Vec<u8>>,
    _: usize,
) -> Result<Vec<u8>, SnapshotError> {
    Err(SnapshotError::UntrustedParent)
}

#[cfg(not(unix))]
fn git_with_optional_dir(
    _: &Path,
    _: Option<&Path>,
    _: &[&str],
    _: Option<Vec<u8>>,
    _: usize,
) -> Result<Vec<u8>, SnapshotError> {
    Err(SnapshotError::UntrustedParent)
}

#[cfg(unix)]
fn run_git_command(
    mut command: Command,
    input: Option<Vec<u8>>,
    limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, SnapshotError> {
    let (mut stdout, child_stdout) =
        UnixStream::pair().map_err(|_| SnapshotError::GitUnavailable)?;
    let (mut stderr, child_stderr) =
        UnixStream::pair().map_err(|_| SnapshotError::GitUnavailable)?;
    stdout
        .set_nonblocking(true)
        .map_err(|_| SnapshotError::GitUnavailable)?;
    stderr
        .set_nonblocking(true)
        .map_err(|_| SnapshotError::GitUnavailable)?;

    let (mut stdin, child_stdin) = if input.is_some() {
        let (parent, child) = UnixStream::pair().map_err(|_| SnapshotError::GitUnavailable)?;
        parent
            .set_nonblocking(true)
            .map_err(|_| SnapshotError::GitUnavailable)?;
        (Some(parent), Some(child))
    } else {
        (None, None)
    };
    command
        .stdin(match child_stdin {
            Some(stream) => Stdio::from(OwnedFd::from(stream)),
            None => Stdio::null(),
        })
        .stdout(Stdio::from(OwnedFd::from(child_stdout)))
        .stderr(Stdio::from(OwnedFd::from(child_stderr)))
        .process_group(0);
    let mut child = command.spawn().map_err(|_| SnapshotError::GitUnavailable)?;
    drop(command);
    let process_group = child.id();
    let deadline = Instant::now() + timeout;
    let input = input.unwrap_or_default();
    let mut input_offset = 0usize;
    let mut writer_failed = false;
    let mut output = Vec::with_capacity(limit.min(64 * 1024));
    let mut exceeded = false;
    let mut output_eof = false;
    let mut error_eof = false;
    let mut status = None;
    let mut buffer = [0u8; 64 * 1024];
    let mut consecutive_idle_polls = 0u8;

    loop {
        if Instant::now() >= deadline {
            if status.is_none() {
                stop_git(&mut child, process_group);
            }
            return Err(SnapshotError::GitTimeout);
        }

        let mut progressed = false;
        let mut close_stdin = false;
        if let Some(stream) = stdin.as_mut() {
            if input_offset == input.len() {
                close_stdin = true;
                progressed = true;
            } else {
                match stream.write(&input[input_offset..]) {
                    Ok(0) => {
                        writer_failed = true;
                        close_stdin = true;
                        progressed = true;
                    }
                    Ok(count) => {
                        input_offset += count;
                        progressed = true;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        writer_failed = true;
                        close_stdin = true;
                        progressed = true;
                    }
                }
            }
        }
        if close_stdin {
            stdin = None;
        }

        if !output_eof {
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    output_eof = true;
                    progressed = true;
                }
                Ok(count) => {
                    let remaining = limit.saturating_sub(output.len());
                    output.extend_from_slice(&buffer[..count.min(remaining)]);
                    exceeded |= count > remaining;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    if status.is_none() {
                        stop_git(&mut child, process_group);
                    }
                    return Err(SnapshotError::GitUnavailable);
                }
            }
        }
        if !error_eof {
            match stderr.read(&mut buffer) {
                Ok(0) => {
                    error_eof = true;
                    progressed = true;
                }
                Ok(_) => progressed = true,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    if status.is_none() {
                        stop_git(&mut child, process_group);
                    }
                    return Err(SnapshotError::GitUnavailable);
                }
            }
        }

        if status.is_none() {
            match child.try_wait() {
                Ok(Some(child_status)) => {
                    status = Some(child_status);
                    progressed = true;
                }
                Ok(None) => {}
                Err(_) => {
                    if status.is_none() {
                        stop_git(&mut child, process_group);
                    }
                    return Err(SnapshotError::GitUnavailable);
                }
            }
        }
        if status.is_some() && output_eof && error_eof && stdin.is_none() {
            break;
        }
        if !progressed {
            if consecutive_idle_polls < 4 {
                thread::yield_now();
                consecutive_idle_polls += 1;
            } else {
                thread::sleep(Duration::from_millis(1));
                consecutive_idle_polls = 0;
            }
        } else {
            consecutive_idle_polls = 0;
        }
    }

    let status = status.ok_or(SnapshotError::GitUnavailable)?;
    if writer_failed {
        return Err(SnapshotError::GitUnavailable);
    }
    if exceeded {
        return Err(SnapshotError::LimitExceeded);
    }
    if !status.success() {
        return Err(SnapshotError::GitUnavailable);
    }
    Ok(output)
}

#[cfg(unix)]
fn stop_git(child: &mut Child, process_group: u32) {
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

fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(unix)]
fn validate_private_parent(path: &Path) -> Result<(), SnapshotError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path).map_err(|_| SnapshotError::UntrustedParent)?;
    if metadata.file_type().is_symlink() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(SnapshotError::UntrustedParent);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_parent(_: &Path) -> Result<(), SnapshotError> {
    Err(SnapshotError::UntrustedParent)
}

fn set_directory_mode(path: &Path) -> Result<(), SnapshotError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| SnapshotError::Io)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(SnapshotError::UntrustedParent)
    }
}

fn set_new_directory_mode(builder: &mut DirBuilder) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    #[cfg(not(unix))]
    {
        let _ = builder;
    }
}

#[cfg(unix)]
fn remove_owned_root(path: &Path, identity: DirectoryIdentity) -> Result<(), SnapshotError> {
    if directory_identity(path)? != identity {
        return Err(SnapshotError::RootChanged);
    }
    fs::remove_dir_all(path).map_err(|_| SnapshotError::CleanupFailed)
}

#[cfg(not(unix))]
fn remove_owned_root(_: &Path, _: DirectoryIdentity) -> Result<(), SnapshotError> {
    Err(SnapshotError::UntrustedParent)
}

fn set_file_mode(options: &mut OpenOptions, executable: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if executable { 0o700 } else { 0o600 });
    }
    #[cfg(not(unix))]
    {
        let _ = (options, executable);
    }
}

#[cfg(unix)]
fn directory_identity(path: &Path) -> Result<DirectoryIdentity, SnapshotError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path).map_err(|_| SnapshotError::Io)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn directory_identity(_: &Path) -> Result<DirectoryIdentity, SnapshotError> {
    Err(SnapshotError::UntrustedParent)
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn synthetic_snapshot(
    path: PathBuf,
    task_id: Uuid,
    commit_sha: &str,
) -> Result<SourceSnapshot, SnapshotError> {
    if task_id.is_nil() {
        return Err(SnapshotError::InvalidTaskId);
    }
    if !valid_oid(commit_sha) {
        return Err(SnapshotError::InvalidCommit);
    }
    let path = fs::canonicalize(path).map_err(|_| SnapshotError::UntrustedParent)?;
    let metadata = fs::symlink_metadata(&path).map_err(|_| SnapshotError::UntrustedParent)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SnapshotError::UntrustedParent);
    }
    let parent = path.parent().ok_or(SnapshotError::UntrustedParent)?;
    Ok(SourceSnapshot {
        parent_identity: directory_identity(parent)?,
        identity: directory_identity(&path)?,
        path,
        task_id,
        commit_sha: commit_sha.to_ascii_lowercase(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_relative_paths_and_rejects_metadata_or_escape_names() {
        for invalid in [
            b"../outside".as_slice(),
            b"/absolute",
            b"a//b",
            b"a/./b",
            b"a/../b",
            b"a/new\nline",
            b".git/config",
            b"a/.GIT/config",
            b"a\\b",
            b"C:/escape",
            "src/日本語.rs".as_bytes(),
        ] {
            assert_eq!(validate_tree_path(invalid), Err(SnapshotError::InvalidPath));
        }
        assert!(validate_tree_path(b"src/main.rs").is_ok());
        assert_eq!(
            validate_tree_path(format!("{}file", "a/".repeat(MAX_PATH_COMPONENTS)).as_bytes()),
            Err(SnapshotError::InvalidPath)
        );
    }

    #[test]
    fn accepts_an_empty_commit_tree() {
        assert_eq!(parse_tree(&[]), Ok(Vec::new()));
    }

    #[test]
    fn parses_only_regular_blob_entries_and_rejects_duplicates() {
        let oid = "a".repeat(40);
        let tree = format!("100644 blob {oid}\tsrc/main.rs\0");
        let files = parse_tree(tree.as_bytes()).unwrap();
        assert_eq!(files.len(), 1);
        assert!(!files[0].executable);
        for mode in ["120000 blob", "160000 commit"] {
            let tree = format!("{mode} {oid}\tlink\0");
            assert_eq!(
                parse_tree(tree.as_bytes()),
                Err(SnapshotError::UnsupportedEntry)
            );
        }
        let duplicate = format!("100644 blob {oid}\ta\0{} blob {oid}\ta\0", "100644");
        assert_eq!(
            parse_tree(duplicate.as_bytes()),
            Err(SnapshotError::InvalidTree)
        );
        assert_eq!(
            parse_tree(format!("100644 blob {oid}\ta").as_bytes()),
            Err(SnapshotError::InvalidTree)
        );
        for conflicting in [
            format!("100644 blob {oid}\ta\0{} blob {oid}\ta/b\0", "100644"),
            format!("100644 blob {oid}\ta/b\0{} blob {oid}\ta\0", "100644"),
            format!(
                "100644 blob {oid}\tA/file\0{} blob {oid}\ta/other\0",
                "100644"
            ),
        ] {
            assert_eq!(
                parse_tree(conflicting.as_bytes()),
                Err(SnapshotError::InvalidTree)
            );
        }
        let mut paths = PathTrie::default();
        assert!(paths.insert_file("src/main.rs").is_ok());
        assert!(paths.insert_file("src/lib.rs").is_ok());
        assert_eq!(
            paths.insert_file("SRC/other.rs"),
            Err(SnapshotError::InvalidTree)
        );
    }

    #[test]
    fn parses_batch_framing_and_enforces_blob_limits() {
        let file = SnapshotFile {
            path: PathBuf::from("a"),
            oid: "a".repeat(40),
            executable: false,
        };
        assert_eq!(
            parse_blobs(
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa blob 3\nabc\n",
                &[file]
            ),
            Ok(vec![b"abc".to_vec()])
        );
        let file = SnapshotFile {
            path: PathBuf::from("a"),
            oid: "a".repeat(40),
            executable: false,
        };
        assert!(
            parse_blobs(
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa blob 3\nab\n",
                &[file]
            )
            .is_err()
        );
    }

    #[test]
    fn verifies_fixed_hash_object_vectors_and_rejects_mismatch_or_bad_output() {
        let sha1_file = SnapshotFile {
            path: PathBuf::from("a file"),
            oid: "f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f".to_owned(),
            executable: false,
        };
        assert_eq!(
            hash_object_paths(std::slice::from_ref(&sha1_file)).unwrap(),
            b"./a file\n"
        );
        let option_like_file = SnapshotFile {
            path: PathBuf::from("-option like"),
            oid: sha1_file.oid.clone(),
            executable: false,
        };
        assert_eq!(
            hash_object_paths(&[option_like_file]).unwrap(),
            b"./-option like\n"
        );
        assert_eq!(
            verify_hash_object_output(
                b"f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f\n",
                std::slice::from_ref(&sha1_file),
                ObjectFormat::Sha1,
            ),
            Ok(())
        );
        assert_eq!(
            verify_hash_object_output(
                b"f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7e\n",
                std::slice::from_ref(&sha1_file),
                ObjectFormat::Sha1,
            ),
            Err(SnapshotError::InvalidBlob)
        );
        assert_eq!(
            verify_hash_object_output(
                b"f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f\nextra\n",
                std::slice::from_ref(&sha1_file),
                ObjectFormat::Sha1,
            ),
            Err(SnapshotError::InvalidBlob)
        );

        let sha256_file = SnapshotFile {
            path: PathBuf::from("empty"),
            oid: "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813".to_owned(),
            executable: false,
        };
        assert_eq!(
            verify_hash_object_output(
                b"473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813\n",
                &[sha256_file],
                ObjectFormat::Sha256,
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_ambiguous_git_dir_output_and_object_format() {
        assert_eq!(
            parse_git_dir(b"/repo/.git\n"),
            Ok(PathBuf::from("/repo/.git"))
        );
        assert_eq!(
            parse_git_dir(b"/repo/with\nnewline/.git\n"),
            Ok(PathBuf::from("/repo/with\nnewline/.git"))
        );
        assert_eq!(
            parse_git_dir(b"/repo/\xff/.git\n"),
            Ok(PathBuf::from(std::ffi::OsString::from_vec(
                b"/repo/\xff/.git".to_vec()
            )))
        );
        assert_eq!(
            parse_git_dir(b"/repo/.git\0bad\n"),
            Err(SnapshotError::InvalidRepository)
        );
        assert_eq!(ObjectFormat::parse(b"sha1\n"), Ok(ObjectFormat::Sha1));
        assert_eq!(ObjectFormat::parse(b"sha256\n"), Ok(ObjectFormat::Sha256));
        assert_eq!(
            ObjectFormat::parse(b"sha1\nsha256\n"),
            Err(SnapshotError::InvalidRepository)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hashes_synthetic_files_without_writing_git_objects() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("mipsorcu-hash-test-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(root.join("a file"), b"abc").unwrap();
        fs::write(root.join("-other"), b"abc").unwrap();
        let expected = "f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f";
        let files = ["a file", "-other"].map(|path| SnapshotFile {
            path: PathBuf::from(path),
            oid: expected.to_owned(),
            executable: false,
        });
        let hash_files = || {
            git(
                &root,
                &["hash-object", "--no-filters", "--stdin-paths"],
                Some(hash_object_paths(&files).unwrap()),
                MAX_FILES * (64 + 1),
            )
            .unwrap()
        };
        assert_eq!(
            verify_hash_object_output(&hash_files(), &files, ObjectFormat::Sha1),
            Ok(())
        );
        fs::write(root.join("-other"), b"changed").unwrap();
        assert_eq!(
            verify_hash_object_output(&hash_files(), &files, ObjectFormat::Sha1),
            Err(SnapshotError::InvalidBlob)
        );
        assert!(!root.join(".git").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn snapshots_existing_head_without_git_metadata_and_cleans_only_its_root() {
        use std::os::unix::fs::PermissionsExt;
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
        let repo = fs::canonicalize(repo).unwrap();
        let sha =
            String::from_utf8(git(&repo, &["rev-parse", "HEAD"], None, 128).unwrap()).unwrap();
        let parent =
            std::env::temp_dir().join(format!("mipsorcu-snapshot-test-{}", Uuid::new_v4()));
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let snapshot = create_snapshot(&repo, &parent, Uuid::new_v4(), sha.trim()).unwrap();
        assert_eq!(snapshot.commit_sha(), sha.trim());
        assert!(!snapshot.path().join(".git").exists());
        let object = format!("{}:orchestrator/src/lib.rs", sha.trim());
        let committed = git(&repo, &["show", &object], None, 256 * 1024).unwrap();
        assert_eq!(
            fs::read(snapshot.path().join("orchestrator/src/lib.rs")).unwrap(),
            committed
        );
        let root = snapshot.path().to_path_buf();
        snapshot.cleanup().unwrap();
        assert!(!root.exists());
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn rejects_unsupported_platform_before_accessing_repository() {
        assert!(matches!(
            create_snapshot(
                Path::new("/missing"),
                Path::new("/missing"),
                Uuid::nil(),
                ""
            ),
            Err(SnapshotError::UnsupportedPlatform)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn escaped_fd_holder_helper() {
        let Ok(mode) = std::env::var("MIPSORCU_SNAPSHOT_FD_HOLDER_MODE") else {
            return;
        };
        if mode == "large-output" {
            let output = vec![b'x'; 8 * 1024 * 1024];
            std::io::stdout().lock().write_all(&output).unwrap();
            std::io::stderr()
                .lock()
                .write_all(&vec![b'e'; 2 * 1024 * 1024])
                .unwrap();
        } else if mode == "stdin-echo" {
            let mut input = Vec::new();
            std::io::stdin().lock().read_to_end(&mut input).unwrap();
            std::io::stdout().lock().write_all(&input).unwrap();
        } else if mode == "silent" {
            thread::sleep(Duration::from_secs(30));
        } else if mode == "holder" || mode == "parent" {
            let marker =
                PathBuf::from(std::env::var_os("MIPSORCU_SNAPSHOT_FD_HOLDER_MARKER").unwrap());
            if mode == "holder" {
                fs::write(&marker, "holding").unwrap();
                thread::sleep(Duration::from_secs(2));
                fs::remove_file(marker).unwrap();
            } else {
                let mut holder = Command::new(std::env::current_exe().unwrap());
                holder
                    .args([
                        "--exact",
                        "source_snapshot::tests::escaped_fd_holder_helper",
                        "--nocapture",
                    ])
                    .env("MIPSORCU_SNAPSHOT_FD_HOLDER_MODE", "holder")
                    .env("MIPSORCU_SNAPSHOT_FD_HOLDER_MARKER", &marker)
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .process_group(0);
                let mut child = holder.spawn().unwrap();
                let deadline = Instant::now() + Duration::from_secs(3);
                while !marker.exists() && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(5));
                }
                assert!(marker.exists(), "escaped child did not publish its marker");
                child.wait().unwrap();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn nonblocking_stdio_returns_when_escaped_child_holds_descriptors() {
        let marker = std::env::temp_dir().join(format!(
            "mipsorcu-snapshot-fd-holder-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "source_snapshot::tests::escaped_fd_holder_helper",
                "--nocapture",
            ])
            .env("MIPSORCU_SNAPSHOT_FD_HOLDER_MODE", "parent")
            .env("MIPSORCU_SNAPSHOT_FD_HOLDER_MARKER", &marker);

        let started = Instant::now();
        assert_eq!(
            run_git_command(command, None, 1024, Duration::from_millis(750)),
            Err(SnapshotError::GitTimeout)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            marker.exists(),
            "the escaped child should still hold its descriptors when the runner returns"
        );
        let cleanup_deadline = Instant::now() + Duration::from_secs(4);
        while marker.exists() && Instant::now() < cleanup_deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!marker.exists(), "the helper should clean itself up");
    }

    #[cfg(unix)]
    #[test]
    fn nonblocking_stdio_drains_large_stdout_and_stderr_before_timeout() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "source_snapshot::tests::escaped_fd_holder_helper",
                "--nocapture",
            ])
            .env("MIPSORCU_SNAPSHOT_FD_HOLDER_MODE", "large-output");
        let started = Instant::now();
        let output = run_git_command(command, None, 9 * 1024 * 1024, Duration::from_secs(3))
            .expect("large output should be fully drained before the deadline");
        assert!(output.len() >= 8 * 1024 * 1024);
        assert!(
            output
                .windows(64)
                .any(|window| window.iter().all(|byte| *byte == b'x'))
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[cfg(unix)]
    #[test]
    fn nonblocking_stdio_delivers_large_stdin_without_partial_write_loss() {
        let input = (0..2 * 1024 * 1024)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "source_snapshot::tests::escaped_fd_holder_helper",
                "--nocapture",
            ])
            .env("MIPSORCU_SNAPSHOT_FD_HOLDER_MODE", "stdin-echo");
        let output = run_git_command(
            command,
            Some(input.clone()),
            input.len() + 64 * 1024,
            Duration::from_secs(3),
        )
        .expect("large stdin should be fully consumed and echoed");
        assert!(
            output.windows(input.len()).any(|window| window == input),
            "child output should contain the complete input sequence"
        );
    }

    #[cfg(unix)]
    #[test]
    fn nonblocking_stdio_times_out_when_child_is_silent() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "source_snapshot::tests::escaped_fd_holder_helper",
                "--nocapture",
            ])
            .env("MIPSORCU_SNAPSHOT_FD_HOLDER_MODE", "silent");
        let started = Instant::now();
        assert_eq!(
            run_git_command(command, None, 1024, Duration::from_millis(250)),
            Err(SnapshotError::GitTimeout)
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}

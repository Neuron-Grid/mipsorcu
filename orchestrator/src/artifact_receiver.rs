//! Bounded transfer of an untrusted worktree result into private staging.
//!
//! The producer emits a complete worktree snapshot. The receiver compares it with
//! the trusted `SourceSnapshot`, stores files with mode 0600 in a new operation
//! directory, and returns a digest-checked handle. This is not an execution
//! authority or a same-user isolation boundary.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

use crate::source_snapshot::{
    MAX_FILE_BYTES, MAX_FILES, MAX_PATH_BYTES, MAX_TOTAL_BYTES, MAX_TOTAL_PATH_BYTES, PathTrie,
    SnapshotError, SourceSnapshot, validate_tree_path,
};

const MAGIC: &[u8; 8] = b"MIPART01";
const MAX_ARCHIVE_BYTES: usize = MAX_TOTAL_BYTES + MAX_FILES * (MAX_PATH_BYTES + 24) + 104;
const MAX_RECORD_HEADER: usize = 16;
const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
// Bound directory path expansion separately from files, whose source limits do
// not account for inferred ancestors or manifest copies.
const MAX_DIRECTORY_ENTRIES: usize = MAX_MANIFEST_BYTES / 256;
const MAX_DIRECTORY_PATH_BYTES: usize = MAX_MANIFEST_BYTES;
const MANIFEST_NAME: &str = ".mipsorcu-artifact-manifest.json";
const MANIFEST_HASH_NAME: &str = ".mipsorcu-artifact-manifest.sha3";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactError {
    UnsupportedPlatform,
    InvalidIdentity,
    InvalidStream,
    InvalidPath,
    InvalidTree,
    LimitExceeded,
    UnsafeParent,
    UnsafeSnapshot,
    PathExists,
    CleanupFailed,
    Io,
    Changed,
    ManifestInvalid,
    FileMissing,
    Incomplete,
}

impl From<SnapshotError> for ArtifactError {
    fn from(error: SnapshotError) -> Self {
        match error {
            SnapshotError::InvalidPath => Self::InvalidPath,
            SnapshotError::InvalidTree | SnapshotError::UnsupportedEntry => Self::InvalidTree,
            SnapshotError::LimitExceeded => Self::LimitExceeded,
            SnapshotError::RootChanged => Self::Changed,
            _ => Self::UnsafeSnapshot,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactChange {
    Added,
    Modified,
    Unchanged,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEntry {
    pub path: String,
    pub change: ArtifactChange,
    pub sha3_256: Option<String>,
    pub size: u64,
    pub executable: bool,
    pub directory: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEntry {
    pub path: String,
    pub sha3_256: Option<String>,
    pub size: u64,
    pub executable: bool,
    pub directory: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    pub format_version: u8,
    pub task_id: String,
    pub operation_id: String,
    pub base_commit: String,
    pub staging_root_device: u64,
    pub staging_root_inode: u64,
    pub base_entries: Vec<SnapshotEntry>,
    pub entries: Vec<ArtifactEntry>,
}

/// Verified staging handle. It exposes only files listed in its internally
/// generated manifest and rechecks identity, type, link count, size, and digest.
pub struct StagedArtifacts {
    root: PathBuf,
    root_identity: (u64, u64),
    data_root: PathBuf,
    data_root_identity: (u64, u64),
    parent: PathBuf,
    parent_identity: (u64, u64),
    owner_uid: u32,
    manifest: ArtifactManifest,
}

impl StagedArtifacts {
    pub fn manifest(&self) -> &ArtifactManifest {
        &self.manifest
    }

    /// Removes this operation's staging after all users of it have stopped.
    /// The operator must keep the parent private, including from same-user processes.
    pub fn cleanup(self) -> Result<(), ArtifactError> {
        self.verify_roots()?;
        fs::remove_dir_all(&self.root).map_err(|_| ArtifactError::CleanupFailed)?;
        File::open(&self.parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ArtifactError::CleanupFailed)
    }

    pub fn read_file(&self, relative_path: &str) -> Result<Vec<u8>, ArtifactError> {
        self.verify_roots()?;
        let entry = self
            .manifest
            .entries
            .iter()
            .find(|entry| entry.path == relative_path && !entry.directory)
            .ok_or(ArtifactError::FileMissing)?;
        if entry.change == ArtifactChange::Deleted {
            return Err(ArtifactError::FileMissing);
        }
        validate_tree_path(relative_path.as_bytes()).map_err(ArtifactError::from)?;
        let path = self.data_root.join(relative_path);
        let before = fs::symlink_metadata(&path).map_err(|_| ArtifactError::FileMissing)?;
        validate_staged_file(&before, entry.size)?;
        let file = open_nofollow(&path)?;
        let opened = file.metadata().map_err(|_| ArtifactError::Io)?;
        validate_staged_file(&opened, entry.size)?;
        if identity(&before) != identity(&opened) {
            return Err(ArtifactError::Changed);
        }
        let size = usize::try_from(entry.size).map_err(|_| ArtifactError::LimitExceeded)?;
        let mut bytes = Vec::with_capacity(size);
        file.take(entry.size.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| ArtifactError::Io)?;
        if bytes.len() != size || hash_hex(&bytes) != entry.sha3_256.as_deref().unwrap_or("") {
            return Err(ArtifactError::Changed);
        }
        let after = fs::symlink_metadata(&path).map_err(|_| ArtifactError::Changed)?;
        if identity(&after) != identity(&opened) {
            return Err(ArtifactError::Changed);
        }
        self.verify_roots()?;
        Ok(bytes)
    }

    fn verify_roots(&self) -> Result<(), ArtifactError> {
        verify_private_directory(&self.parent, self.parent_identity, self.owner_uid)?;
        verify_private_directory(&self.root, self.root_identity, self.owner_uid)?;
        verify_private_directory(&self.data_root, self.data_root_identity, self.owner_uid)
    }
}

/// Create the specified stream from a stopped task worktree. Task, operation,
/// and base revision are untrusted producer fields; the receiver compares them
/// with the trusted `SourceSnapshot`. The complete file set is read before bytes
/// are written. The caller must stop all writers first; metadata checks detect
/// ordinary concurrent changes but do not prove quiescence. `.git` and other
/// metadata paths are rejected.
pub fn write_artifact_stream(
    task_id: Uuid,
    operation_id: Uuid,
    base_commit: &str,
    worktree: &Path,
    output: &mut impl Write,
) -> Result<(), ArtifactError> {
    if !cfg!(target_os = "linux") {
        return Err(ArtifactError::UnsupportedPlatform);
    }
    if task_id.is_nil() || operation_id.is_nil() || !valid_oid(base_commit) {
        return Err(ArtifactError::InvalidIdentity);
    }
    let worktree = canonical_directory(worktree)?;
    let before = directory_meta(&worktree)?;
    let (files, dirs) = read_tree(&worktree)?;
    let after = directory_meta(&worktree)?;
    if before != after {
        return Err(ArtifactError::Changed);
    }
    let file_directories = parent_directories(files.keys().map(String::as_str))?;

    let mut total = 104usize;
    output.write_all(MAGIC).map_err(|_| ArtifactError::Io)?;
    output
        .write_all(task_id.as_bytes())
        .map_err(|_| ArtifactError::Io)?;
    output
        .write_all(operation_id.as_bytes())
        .map_err(|_| ArtifactError::Io)?;
    let mut commit = [0_u8; 64];
    let oid = base_commit.to_ascii_lowercase();
    commit[..oid.len()].copy_from_slice(oid.as_bytes());
    output.write_all(&commit).map_err(|_| ArtifactError::Io)?;

    let mut entries = files.into_iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    for (path, file) in entries {
        write_record(
            output,
            &mut total,
            1,
            &path,
            if file.executable { 0o755 } else { 0o644 },
            &file.bytes,
        )?;
    }
    for path in dirs {
        let path = path
            .to_str()
            .ok_or(ArtifactError::InvalidPath)?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if !file_directories.contains(&path) {
            write_record(output, &mut total, 2, &path, 0o755, &[])?;
        }
    }
    total = total.checked_add(1).ok_or(ArtifactError::LimitExceeded)?;
    if total > MAX_ARCHIVE_BYTES {
        return Err(ArtifactError::LimitExceeded);
    }
    output.write_all(&[0]).map_err(|_| ArtifactError::Io)
}

/// Receive a complete stream into an operation-specific private directory.
/// All stream framing and limits are checked before the staging path is created.
/// The caller-supplied identity must match both the frame and the trusted snapshot.
pub fn receive_artifacts(
    snapshot: &SourceSnapshot,
    expected_task_id: Uuid,
    operation_id: Uuid,
    trusted_parent: &Path,
    input: &mut impl Read,
) -> Result<StagedArtifacts, ArtifactError> {
    if !cfg!(target_os = "linux") {
        return Err(ArtifactError::UnsupportedPlatform);
    }
    if expected_task_id.is_nil() || operation_id.is_nil() || snapshot.task_id() != expected_task_id
    {
        return Err(ArtifactError::InvalidIdentity);
    }
    snapshot.verify_identity()?;
    let parent = canonical_directory(trusted_parent)?;
    let parent_id = directory_meta(&parent)?;
    use std::os::unix::fs::MetadataExt;
    let owner_uid = fs::symlink_metadata(&parent)
        .map_err(|_| ArtifactError::UnsafeParent)?
        .uid();
    if owner_uid != effective_uid()? {
        return Err(ArtifactError::UnsafeParent);
    }
    verify_private_directory(&parent, parent_id, owner_uid)?;
    let frame = read_frame(input)?;
    if frame.task_id != expected_task_id
        || frame.operation_id != operation_id
        || frame.base_commit != snapshot.commit_sha().to_ascii_lowercase()
    {
        return Err(ArtifactError::InvalidIdentity);
    }
    let (baseline, baseline_dirs) = read_tree(snapshot.path())?;
    let mut manifest = compare_trees(
        expected_task_id,
        operation_id,
        snapshot.commit_sha(),
        &baseline,
        &baseline_dirs,
        &frame.entries,
    )?;
    snapshot.verify_identity()?;
    verify_private_directory(&parent, parent_id, owner_uid)?;

    let root = parent.join(format!("{}-{}", expected_task_id, operation_id));
    create_private_directory(&root)?;
    let root_id = directory_meta(&root)?;
    manifest.staging_root_device = root_id.0;
    manifest.staging_root_inode = root_id.1;
    if let Err(error) = write_staging(&root, &frame.entries, &manifest) {
        if directory_meta(&root).ok() != Some(root_id)
            || verify_private_directory(&parent, parent_id, owner_uid).is_err()
            || fs::remove_dir_all(&root).is_err()
        {
            return Err(ArtifactError::CleanupFailed);
        }
        return Err(error);
    }
    let data_root = root.join("data");
    let data_root_id = directory_meta(&data_root)?;
    verify_private_directory(&parent, parent_id, owner_uid)?;
    verify_private_directory(&root, root_id, owner_uid)?;
    verify_private_directory(&data_root, data_root_id, owner_uid)?;
    Ok(StagedArtifacts {
        root,
        root_identity: root_id,
        data_root,
        data_root_identity: data_root_id,
        parent,
        parent_identity: parent_id,
        owner_uid,
        manifest,
    })
}

/// Reopen a completed staging operation after process restart. This verifies the
/// persisted completion record against the trusted source snapshot and every
/// staged path and byte. Snapshot SHA3 values are local tree-integrity evidence;
/// reopening does not repeat Git object verification and is not execution proof,
/// successful execution evidence, or authorization for another transfer.
pub fn reopen_artifacts(
    snapshot: &SourceSnapshot,
    expected_task_id: Uuid,
    operation_id: Uuid,
    trusted_parent: &Path,
) -> Result<StagedArtifacts, ArtifactError> {
    if !cfg!(target_os = "linux") {
        return Err(ArtifactError::UnsupportedPlatform);
    }
    if expected_task_id.is_nil() || operation_id.is_nil() || snapshot.task_id() != expected_task_id
    {
        return Err(ArtifactError::InvalidIdentity);
    }
    snapshot.verify_identity()?;
    let parent = canonical_directory(trusted_parent)?;
    let parent_identity = directory_meta(&parent)?;
    let owner_uid = effective_uid()?;
    verify_private_directory(&parent, parent_identity, owner_uid)?;

    let root = parent.join(format!("{}-{}", expected_task_id, operation_id));
    let root_identity = directory_meta(&root).map_err(|_| ArtifactError::Incomplete)?;
    verify_private_directory(&root, root_identity, owner_uid)?;
    let data_root = root.join("data");
    let data_root_identity = directory_meta(&data_root).map_err(|_| ArtifactError::Incomplete)?;
    verify_private_directory(&data_root, data_root_identity, owner_uid)?;
    verify_root_children(&root)?;

    let manifest = read_persisted_manifest(&root, owner_uid)?;
    if manifest.format_version != 1
        || manifest.task_id != expected_task_id.to_string()
        || manifest.operation_id != operation_id.to_string()
        || manifest.base_commit != snapshot.commit_sha().to_ascii_lowercase()
        || manifest.staging_root_device != root_identity.0
        || manifest.staging_root_inode != root_identity.1
    {
        return Err(ArtifactError::InvalidIdentity);
    }

    let (baseline, baseline_dirs) = read_tree(snapshot.path())?;
    let (files, dirs) = read_tree(&data_root)?;
    verify_staged_tree_metadata(&data_root, owner_uid, &files, &dirs)?;
    let mut manifest_entries = BTreeMap::new();
    for entry in &manifest.entries {
        validate_manifest_entry(entry)?;
        if manifest_entries
            .insert(entry.path.as_str(), entry)
            .is_some()
        {
            return Err(ArtifactError::ManifestInvalid);
        }
    }
    let mut received = BTreeMap::new();
    for (path, file) in files {
        let executable = manifest_entries
            .get(path.as_str())
            .filter(|entry| !entry.directory && entry.change != ArtifactChange::Deleted)
            .map(|entry| entry.executable)
            .ok_or(ArtifactError::ManifestInvalid)?;
        received.insert(
            path,
            StreamEntry::File {
                bytes: file.bytes,
                executable,
            },
        );
    }
    for path in dirs {
        let path = path
            .to_str()
            .ok_or(ArtifactError::InvalidPath)?
            .replace(std::path::MAIN_SEPARATOR, "/");
        received.insert(path, StreamEntry::Directory);
    }
    let mut verified = compare_trees(
        expected_task_id,
        operation_id,
        snapshot.commit_sha(),
        &baseline,
        &baseline_dirs,
        &received,
    )?;
    verified.staging_root_device = root_identity.0;
    verified.staging_root_inode = root_identity.1;
    if verified != manifest {
        return Err(ArtifactError::Changed);
    }
    snapshot.verify_identity()?;
    verify_private_directory(&parent, parent_identity, owner_uid)?;
    verify_private_directory(&root, root_identity, owner_uid)?;
    verify_private_directory(&data_root, data_root_identity, owner_uid)?;
    verify_root_children(&root)?;
    Ok(StagedArtifacts {
        root,
        root_identity,
        data_root,
        data_root_identity,
        parent,
        parent_identity,
        owner_uid,
        manifest,
    })
}

struct StreamFrame {
    task_id: Uuid,
    operation_id: Uuid,
    base_commit: String,
    entries: BTreeMap<String, StreamEntry>,
}

#[derive(Clone)]
enum StreamEntry {
    Directory,
    File { bytes: Vec<u8>, executable: bool },
}

struct TreeFile {
    bytes: Vec<u8>,
    executable: bool,
    hash: String,
}

fn parent_directories<'a>(
    paths: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<String>, ArtifactError> {
    let mut directories = BTreeSet::new();
    let mut total_path_bytes = 0usize;
    for path in paths {
        let mut parent = Path::new(path).parent();
        while let Some(directory) = parent.filter(|directory| !directory.as_os_str().is_empty()) {
            let directory = directory
                .to_str()
                .ok_or(ArtifactError::InvalidPath)?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if directories.insert(directory.clone()) {
                total_path_bytes = total_path_bytes
                    .checked_add(directory.len())
                    .ok_or(ArtifactError::LimitExceeded)?;
                if directories.len() > MAX_DIRECTORY_ENTRIES
                    || total_path_bytes > MAX_DIRECTORY_PATH_BYTES
                {
                    return Err(ArtifactError::LimitExceeded);
                }
            }
            parent = parent.and_then(Path::parent);
        }
    }
    Ok(directories)
}

fn read_frame(input: &mut impl Read) -> Result<StreamFrame, ArtifactError> {
    let mut total = 0usize;
    let mut fixed = [0_u8; 104];
    read_exact(input, &mut fixed, &mut total)?;
    if fixed.get(..8) != Some(MAGIC) {
        return Err(ArtifactError::InvalidStream);
    }
    let task_id = Uuid::from_slice(fixed.get(8..24).ok_or(ArtifactError::InvalidStream)?)
        .map_err(|_| ArtifactError::InvalidStream)?;
    let operation_id = Uuid::from_slice(fixed.get(24..40).ok_or(ArtifactError::InvalidStream)?)
        .map_err(|_| ArtifactError::InvalidStream)?;
    let oid_bytes = fixed.get(40..104).ok_or(ArtifactError::InvalidStream)?;
    let oid_end = oid_bytes
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(oid_bytes.len());
    if oid_end != 40 && oid_end != 64
        || oid_bytes[..oid_end].iter().any(|b| !b.is_ascii_hexdigit())
        || oid_bytes[oid_end..].iter().any(|b| *b != 0)
    {
        return Err(ArtifactError::InvalidStream);
    }
    let base_commit = std::str::from_utf8(&oid_bytes[..oid_end])
        .map_err(|_| ArtifactError::InvalidStream)?
        .to_ascii_lowercase();
    let mut entries = BTreeMap::new();
    let mut paths = PathTrie::default();
    let mut total_file_path_bytes = 0usize;
    let mut total_directory_path_bytes = 0usize;
    let mut directory_entries = 0usize;
    let mut file_entries = 0usize;
    let mut total_file_bytes = 0usize;
    loop {
        let kind = read_byte(input, &mut total)?;
        if kind == 0 {
            let mut trailing = [0_u8; 1];
            if input.read(&mut trailing).map_err(|_| ArtifactError::Io)? != 0 {
                return Err(ArtifactError::InvalidStream);
            }
            break;
        }
        let mut header = [0_u8; MAX_RECORD_HEADER];
        read_exact(input, &mut header, &mut total)?;
        let path_len = usize::try_from(u32::from_be_bytes(
            header[..4]
                .try_into()
                .map_err(|_| ArtifactError::InvalidStream)?,
        ))
        .map_err(|_| ArtifactError::LimitExceeded)?;
        let mode = u32::from_be_bytes(
            header[4..8]
                .try_into()
                .map_err(|_| ArtifactError::InvalidStream)?,
        );
        let size = usize::try_from(u64::from_be_bytes(
            header[8..16]
                .try_into()
                .map_err(|_| ArtifactError::InvalidStream)?,
        ))
        .map_err(|_| ArtifactError::LimitExceeded)?;
        // Header is kind + 4-byte path length + 4-byte mode + 8-byte size.
        if path_len == 0 || path_len > MAX_PATH_BYTES || size > MAX_FILE_BYTES {
            return Err(ArtifactError::LimitExceeded);
        }
        let mut path_bytes = vec![0; path_len];
        read_exact(input, &mut path_bytes, &mut total)?;
        validate_tree_path(&path_bytes).map_err(ArtifactError::from)?;
        let path = std::str::from_utf8(&path_bytes)
            .map_err(|_| ArtifactError::InvalidPath)?
            .to_owned();
        let entry = match kind {
            1 if matches!(mode, 0o644 | 0o755) && size <= MAX_FILE_BYTES => {
                total_file_path_bytes = total_file_path_bytes
                    .checked_add(path_len)
                    .ok_or(ArtifactError::LimitExceeded)?;
                file_entries = file_entries
                    .checked_add(1)
                    .ok_or(ArtifactError::LimitExceeded)?;
                if total_file_path_bytes > MAX_TOTAL_PATH_BYTES || file_entries > MAX_FILES {
                    return Err(ArtifactError::LimitExceeded);
                }
                total_file_bytes = total_file_bytes
                    .checked_add(size)
                    .ok_or(ArtifactError::LimitExceeded)?;
                if total_file_bytes > MAX_TOTAL_BYTES {
                    return Err(ArtifactError::LimitExceeded);
                }
                paths.insert_file(&path).map_err(ArtifactError::from)?;
                let mut bytes = vec![0; size];
                read_exact(input, &mut bytes, &mut total)?;
                StreamEntry::File {
                    bytes,
                    executable: mode == 0o755,
                }
            }
            2 if mode == 0o755 && size == 0 => {
                directory_entries = directory_entries
                    .checked_add(1)
                    .ok_or(ArtifactError::LimitExceeded)?;
                total_directory_path_bytes = total_directory_path_bytes
                    .checked_add(path_len)
                    .ok_or(ArtifactError::LimitExceeded)?;
                if directory_entries > MAX_DIRECTORY_ENTRIES
                    || total_directory_path_bytes > MAX_DIRECTORY_PATH_BYTES
                {
                    return Err(ArtifactError::LimitExceeded);
                }
                paths.insert_directory(&path).map_err(ArtifactError::from)?;
                StreamEntry::Directory
            }
            _ => return Err(ArtifactError::InvalidStream),
        };
        if entries.insert(path, entry).is_some() {
            return Err(ArtifactError::InvalidTree);
        }
        if total > MAX_ARCHIVE_BYTES {
            return Err(ArtifactError::LimitExceeded);
        }
    }
    let implicit_directories = parent_directories(entries.keys().map(String::as_str))?;
    for path in implicit_directories {
        if let std::collections::btree_map::Entry::Vacant(slot) = entries.entry(path.clone()) {
            directory_entries = directory_entries
                .checked_add(1)
                .ok_or(ArtifactError::LimitExceeded)?;
            total_directory_path_bytes = total_directory_path_bytes
                .checked_add(path.len())
                .ok_or(ArtifactError::LimitExceeded)?;
            if directory_entries > MAX_DIRECTORY_ENTRIES
                || total_directory_path_bytes > MAX_DIRECTORY_PATH_BYTES
            {
                return Err(ArtifactError::LimitExceeded);
            }
            slot.insert(StreamEntry::Directory);
        }
    }

    Ok(StreamFrame {
        task_id,
        operation_id,
        base_commit,
        entries,
    })
}

fn write_record(
    output: &mut impl Write,
    total: &mut usize,
    kind: u8,
    path: &str,
    mode: u32,
    bytes: &[u8],
) -> Result<(), ArtifactError> {
    let path_bytes = path.as_bytes();
    validate_tree_path(path_bytes).map_err(ArtifactError::from)?;
    let path_len = u32::try_from(path_bytes.len()).map_err(|_| ArtifactError::LimitExceeded)?;
    let size = u64::try_from(bytes.len()).map_err(|_| ArtifactError::LimitExceeded)?;
    let record_size = 17usize
        .checked_add(path_bytes.len())
        .and_then(|n| n.checked_add(bytes.len()))
        .ok_or(ArtifactError::LimitExceeded)?;
    *total = total
        .checked_add(record_size)
        .ok_or(ArtifactError::LimitExceeded)?;
    if *total > MAX_ARCHIVE_BYTES {
        return Err(ArtifactError::LimitExceeded);
    }
    output.write_all(&[kind]).map_err(|_| ArtifactError::Io)?;
    output
        .write_all(&path_len.to_be_bytes())
        .map_err(|_| ArtifactError::Io)?;
    output
        .write_all(&mode.to_be_bytes())
        .map_err(|_| ArtifactError::Io)?;
    output
        .write_all(&size.to_be_bytes())
        .map_err(|_| ArtifactError::Io)?;
    output
        .write_all(path_bytes)
        .map_err(|_| ArtifactError::Io)?;
    output.write_all(bytes).map_err(|_| ArtifactError::Io)?;
    Ok(())
}

fn compare_trees(
    task_id: Uuid,
    operation_id: Uuid,
    base_commit: &str,
    baseline: &BTreeMap<String, TreeFile>,
    baseline_dirs: &[PathBuf],
    received: &BTreeMap<String, StreamEntry>,
) -> Result<ArtifactManifest, ArtifactError> {
    let mut entries = Vec::with_capacity(baseline.len().saturating_add(received.len()));
    let baseline_directories: std::collections::BTreeSet<&Path> =
        baseline_dirs.iter().map(PathBuf::as_path).collect();
    for (path, entry) in received {
        match entry {
            StreamEntry::Directory => entries.push(ArtifactEntry {
                path: path.clone(),
                change: if baseline_directories.contains(Path::new(path)) {
                    ArtifactChange::Unchanged
                } else {
                    ArtifactChange::Added
                },
                sha3_256: None,
                size: 0,
                executable: false,
                directory: true,
            }),
            StreamEntry::File { bytes, executable } => {
                let hash = hash_hex(bytes);
                let prior = baseline.get(path);
                let change = match prior {
                    Some(prior) if prior.hash == hash && prior.executable == *executable => {
                        ArtifactChange::Unchanged
                    }
                    Some(_) => ArtifactChange::Modified,
                    None => ArtifactChange::Added,
                };
                entries.push(ArtifactEntry {
                    path: path.clone(),
                    change,
                    sha3_256: Some(hash),
                    size: bytes.len() as u64,
                    executable: *executable,
                    directory: false,
                });
            }
        }
    }
    for (path, prior) in baseline {
        if !received.contains_key(path) {
            entries.push(ArtifactEntry {
                path: path.clone(),
                change: ArtifactChange::Deleted,
                sha3_256: Some(prior.hash.clone()),
                size: prior.bytes.len() as u64,
                executable: prior.executable,
                directory: false,
            });
        }
    }
    for path in baseline_dirs {
        let path = path
            .to_str()
            .ok_or(ArtifactError::InvalidPath)?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if !received.contains_key(&path) {
            entries.push(ArtifactEntry {
                path,
                change: ArtifactChange::Deleted,
                sha3_256: None,
                size: 0,
                executable: false,
                directory: true,
            });
        }
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let mut base_entries = baseline
        .iter()
        .map(|(path, file)| SnapshotEntry {
            path: path.clone(),
            sha3_256: Some(file.hash.clone()),
            size: file.bytes.len() as u64,
            executable: file.executable,
            directory: false,
        })
        .collect::<Vec<_>>();
    for path in baseline_dirs {
        base_entries.push(SnapshotEntry {
            path: path
                .to_str()
                .ok_or(ArtifactError::InvalidPath)?
                .replace(std::path::MAIN_SEPARATOR, "/"),
            sha3_256: None,
            size: 0,
            executable: false,
            directory: true,
        });
    }
    base_entries.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = ArtifactManifest {
        format_version: 1,
        task_id: task_id.to_string(),
        operation_id: operation_id.to_string(),
        base_commit: base_commit.to_ascii_lowercase(),
        staging_root_device: 0,
        staging_root_inode: 0,
        base_entries,
        entries,
    };
    let json = serde_json::to_vec(&manifest).map_err(|_| ArtifactError::ManifestInvalid)?;
    if json.len() > MAX_MANIFEST_BYTES {
        return Err(ArtifactError::LimitExceeded);
    }
    Ok(manifest)
}

fn validate_manifest_entry(entry: &ArtifactEntry) -> Result<(), ArtifactError> {
    validate_tree_path(entry.path.as_bytes()).map_err(ArtifactError::from)?;
    if entry.directory {
        if entry.sha3_256.is_some() || entry.size != 0 || entry.executable {
            return Err(ArtifactError::ManifestInvalid);
        }
    } else if entry.size > MAX_FILE_BYTES as u64
        || !entry.sha3_256.as_deref().is_some_and(valid_sha3_hex)
    {
        return Err(ArtifactError::ManifestInvalid);
    }
    Ok(())
}

fn valid_sha3_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn write_staging(
    root: &Path,
    entries: &BTreeMap<String, StreamEntry>,
    manifest: &ArtifactManifest,
) -> Result<(), ArtifactError> {
    let data_root = root.join("data");
    create_private_directory(&data_root)?;
    for (path, entry) in entries {
        let full = data_root.join(path);
        let parent = full.parent().ok_or(ArtifactError::InvalidPath)?;
        create_directories(&data_root, parent)?;
        match entry {
            StreamEntry::Directory => create_or_verify_private_directory(&full)?,
            StreamEntry::File { bytes, .. } => {
                let mut file = create_new_private_file(&full)?;
                file.write_all(bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|_| ArtifactError::Io)?;
            }
        }
    }
    sync_directory_tree(&data_root)?;
    let json = serde_json::to_vec(manifest).map_err(|_| ArtifactError::ManifestInvalid)?;
    if json.len() > MAX_MANIFEST_BYTES {
        return Err(ArtifactError::LimitExceeded);
    }
    let temporary_path = root.join(format!("{MANIFEST_NAME}.tmp"));
    let manifest_path = root.join(MANIFEST_NAME);
    let mut file = create_new_private_file(&temporary_path)?;
    file.write_all(&json)
        .and_then(|()| file.sync_all())
        .map_err(|_| ArtifactError::Io)?;
    fs::rename(&temporary_path, &manifest_path).map_err(|_| ArtifactError::Io)?;
    let hash_temporary_path = root.join(format!("{MANIFEST_HASH_NAME}.tmp"));
    let hash_path = root.join(MANIFEST_HASH_NAME);
    let mut hash_file = create_new_private_file(&hash_temporary_path)?;
    hash_file
        .write_all(hash_hex(&json).as_bytes())
        .and_then(|()| hash_file.sync_all())
        .map_err(|_| ArtifactError::Io)?;
    fs::rename(&hash_temporary_path, &hash_path).map_err(|_| ArtifactError::Io)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ArtifactError::Io)?;
    let parent = root.parent().ok_or(ArtifactError::UnsafeParent)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ArtifactError::Io)?;
    Ok(())
}

fn sync_directory_tree(root: &Path) -> Result<(), ArtifactError> {
    for child in fs::read_dir(root).map_err(|_| ArtifactError::Io)? {
        let child = child.map_err(|_| ArtifactError::Io)?;
        let path = child.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| ArtifactError::Io)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            sync_directory_tree(&path)?;
        } else if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(ArtifactError::InvalidTree);
        }
    }
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ArtifactError::Io)
}

fn verify_root_children(root: &Path) -> Result<(), ArtifactError> {
    let mut seen = [false; 3];
    for entry in fs::read_dir(root).map_err(|_| ArtifactError::Incomplete)? {
        let name = entry.map_err(|_| ArtifactError::Io)?.file_name();
        let index = if name == "data" {
            0
        } else if name == MANIFEST_NAME {
            1
        } else if name == MANIFEST_HASH_NAME {
            2
        } else {
            return Err(ArtifactError::Incomplete);
        };
        if std::mem::replace(&mut seen[index], true) {
            return Err(ArtifactError::Incomplete);
        }
    }
    if !seen.into_iter().all(|value| value) {
        return Err(ArtifactError::Incomplete);
    }
    Ok(())
}

fn read_persisted_manifest(root: &Path, owner_uid: u32) -> Result<ArtifactManifest, ArtifactError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let path = root.join(MANIFEST_NAME);
    let before = fs::symlink_metadata(&path).map_err(|_| ArtifactError::Incomplete)?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.uid() != owner_uid
        || before.nlink() != 1
        || before.permissions().mode() & 0o7777 != 0o600
        || before.len() > MAX_MANIFEST_BYTES as u64
    {
        return Err(ArtifactError::ManifestInvalid);
    }
    let file = open_nofollow(&path)?;
    let opened = file.metadata().map_err(|_| ArtifactError::Io)?;
    if identity(&before) != identity(&opened) || opened.len() != before.len() {
        return Err(ArtifactError::Changed);
    }
    let expected_size = usize::try_from(before.len()).map_err(|_| ArtifactError::LimitExceeded)?;
    let mut bytes = Vec::with_capacity(expected_size);
    file.take((MAX_MANIFEST_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ArtifactError::Io)?;
    if bytes.len() != expected_size || bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ArtifactError::ManifestInvalid);
    }
    let after = fs::symlink_metadata(&path).map_err(|_| ArtifactError::Changed)?;
    if identity(&after) != identity(&opened) || after.len() != before.len() {
        return Err(ArtifactError::Changed);
    }
    let hash_path = root.join(MANIFEST_HASH_NAME);
    let hash_metadata = fs::symlink_metadata(&hash_path).map_err(|_| ArtifactError::Incomplete)?;
    if !hash_metadata.is_file()
        || hash_metadata.file_type().is_symlink()
        || hash_metadata.uid() != owner_uid
        || hash_metadata.nlink() != 1
        || hash_metadata.permissions().mode() & 0o7777 != 0o600
        || hash_metadata.len() != 64
    {
        return Err(ArtifactError::ManifestInvalid);
    }
    let hash_file = open_nofollow(&hash_path)?;
    let opened_hash = hash_file.metadata().map_err(|_| ArtifactError::Io)?;
    if identity(&hash_metadata) != identity(&opened_hash) {
        return Err(ArtifactError::Changed);
    }
    let mut expected_hash = Vec::with_capacity(64);
    hash_file
        .take(65)
        .read_to_end(&mut expected_hash)
        .map_err(|_| ArtifactError::Io)?;
    if expected_hash != hash_hex(&bytes).as_bytes() {
        return Err(ArtifactError::Changed);
    }
    let hash_after = fs::symlink_metadata(&hash_path).map_err(|_| ArtifactError::Changed)?;
    if identity(&hash_after) != identity(&opened_hash) || hash_after.len() != 64 {
        return Err(ArtifactError::Changed);
    }
    serde_json::from_slice(&bytes).map_err(|_| ArtifactError::ManifestInvalid)
}

fn verify_staged_tree_metadata(
    root: &Path,
    owner_uid: u32,
    files: &BTreeMap<String, TreeFile>,
    dirs: &[PathBuf],
) -> Result<(), ArtifactError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for path in dirs {
        let metadata = fs::symlink_metadata(root.join(path)).map_err(|_| ArtifactError::Changed)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner_uid
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(ArtifactError::Changed);
        }
    }
    for (path, file) in files {
        let metadata = fs::symlink_metadata(root.join(path)).map_err(|_| ArtifactError::Changed)?;
        validate_staged_file(&metadata, file.bytes.len() as u64)?;
        if metadata.uid() != owner_uid {
            return Err(ArtifactError::Changed);
        }
    }
    Ok(())
}

fn create_directories(root: &Path, directory: &Path) -> Result<(), ArtifactError> {
    use std::os::unix::fs::PermissionsExt;
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| ArtifactError::InvalidPath)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::create_dir(&current) {
            Ok(()) => set_private_dir(&current)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let metadata =
                    fs::symlink_metadata(&current).map_err(|_| ArtifactError::Changed)?;
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.permissions().mode() & 0o7777 != 0o700
                {
                    return Err(ArtifactError::InvalidTree);
                }
            }
            Err(_) => return Err(ArtifactError::Io),
        }
    }
    Ok(())
}

fn read_tree(root: &Path) -> Result<(BTreeMap<String, TreeFile>, Vec<PathBuf>), ArtifactError> {
    let root = canonical_directory(root)?;
    let mut files = BTreeMap::new();
    let mut paths = PathTrie::default();
    let mut dirs = Vec::new();
    let mut budget = WalkBudget::default();
    walk_tree(&root, &root, &mut files, &mut paths, &mut dirs, &mut budget)?;
    dirs.sort();
    Ok((files, dirs))
}

#[derive(Default)]
struct WalkBudget {
    files: usize,
    file_path_bytes: usize,
    directories: usize,
    directory_path_bytes: usize,
    file_bytes: usize,
}

fn walk_tree(
    root: &Path,
    dir: &Path,
    files: &mut BTreeMap<String, TreeFile>,
    paths: &mut PathTrie,
    dirs: &mut Vec<PathBuf>,
    budget: &mut WalkBudget,
) -> Result<(), ArtifactError> {
    use std::os::unix::fs::MetadataExt;
    let before = fs::symlink_metadata(dir).map_err(|_| ArtifactError::Changed)?;
    if !before.is_dir() || before.file_type().is_symlink() {
        return Err(ArtifactError::InvalidTree);
    }
    for child in fs::read_dir(dir).map_err(|_| ArtifactError::Io)? {
        let child = child.map_err(|_| ArtifactError::Io)?;
        let name = child
            .file_name()
            .into_string()
            .map_err(|_| ArtifactError::InvalidPath)?;
        let path = child.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| ArtifactError::InvalidPath)?;
        let relative = relative
            .to_str()
            .ok_or(ArtifactError::InvalidPath)?
            .replace(std::path::MAIN_SEPARATOR, "/");
        validate_tree_path(relative.as_bytes()).map_err(ArtifactError::from)?;
        let metadata = fs::symlink_metadata(&path).map_err(|_| ArtifactError::Changed)?;
        if metadata.file_type().is_symlink() {
            return Err(ArtifactError::InvalidTree);
        }
        if metadata.is_dir() {
            budget.directories = budget
                .directories
                .checked_add(1)
                .ok_or(ArtifactError::LimitExceeded)?;
            budget.directory_path_bytes = budget
                .directory_path_bytes
                .checked_add(relative.len())
                .ok_or(ArtifactError::LimitExceeded)?;
            if budget.directories > MAX_DIRECTORY_ENTRIES
                || budget.directory_path_bytes > MAX_DIRECTORY_PATH_BYTES
            {
                return Err(ArtifactError::LimitExceeded);
            }
            paths
                .insert_directory(&relative)
                .map_err(ArtifactError::from)?;
            dirs.push(PathBuf::from(relative));
            walk_tree(root, &path, files, paths, dirs, budget)?;
        } else if metadata.is_file() {
            budget.files = budget
                .files
                .checked_add(1)
                .ok_or(ArtifactError::LimitExceeded)?;
            budget.file_path_bytes = budget
                .file_path_bytes
                .checked_add(relative.len())
                .ok_or(ArtifactError::LimitExceeded)?;
            if budget.files > MAX_FILES || budget.file_path_bytes > MAX_TOTAL_PATH_BYTES {
                return Err(ArtifactError::LimitExceeded);
            }
            if metadata.len() > MAX_FILE_BYTES as u64 || metadata.nlink() != 1 {
                return Err(ArtifactError::InvalidTree);
            }
            budget.file_bytes = budget
                .file_bytes
                .checked_add(
                    usize::try_from(metadata.len()).map_err(|_| ArtifactError::LimitExceeded)?,
                )
                .ok_or(ArtifactError::LimitExceeded)?;
            if budget.file_bytes > MAX_TOTAL_BYTES {
                return Err(ArtifactError::LimitExceeded);
            }
            paths.insert_file(&relative).map_err(ArtifactError::from)?;
            let file = open_nofollow(&path)?;
            let opened = file.metadata().map_err(|_| ArtifactError::Io)?;
            if !same_file_state(&metadata, &opened) {
                return Err(ArtifactError::Changed);
            }
            let mut bytes = Vec::with_capacity(
                usize::try_from(metadata.len()).map_err(|_| ArtifactError::LimitExceeded)?,
            );
            file.take((MAX_FILE_BYTES as u64) + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ArtifactError::Io)?;
            if bytes.len() != metadata.len() as usize {
                return Err(ArtifactError::Changed);
            }
            let after = fs::symlink_metadata(&path).map_err(|_| ArtifactError::Changed)?;
            if !same_file_state(&opened, &after) {
                return Err(ArtifactError::Changed);
            }
            #[cfg(unix)]
            let executable = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o111 != 0
            };
            #[cfg(not(unix))]
            let executable = false;
            files.insert(
                relative,
                TreeFile {
                    hash: hash_hex(&bytes),
                    bytes,
                    executable,
                },
            );
        } else {
            return Err(ArtifactError::InvalidTree);
        }
        let _ = name;
    }
    let after = fs::symlink_metadata(dir).map_err(|_| ArtifactError::Changed)?;
    if !same_file_state(&before, &after) {
        return Err(ArtifactError::Changed);
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    identity(left) == identity(right)
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn read_exact(
    input: &mut impl Read,
    bytes: &mut [u8],
    total: &mut usize,
) -> Result<(), ArtifactError> {
    *total = total
        .checked_add(bytes.len())
        .ok_or(ArtifactError::LimitExceeded)?;
    if *total > MAX_ARCHIVE_BYTES {
        return Err(ArtifactError::LimitExceeded);
    }
    input
        .read_exact(bytes)
        .map_err(|_| ArtifactError::InvalidStream)
}

fn read_byte(input: &mut impl Read, total: &mut usize) -> Result<u8, ArtifactError> {
    let mut byte = [0];
    read_exact(input, &mut byte, total)?;
    Ok(byte[0])
}

fn hash_hex(bytes: &[u8]) -> String {
    let hash = Sha3_256::digest(bytes);
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn canonical_directory(path: &Path) -> Result<PathBuf, ArtifactError> {
    let before = fs::symlink_metadata(path).map_err(|_| ArtifactError::UnsafeParent)?;
    if before.file_type().is_symlink() || !before.is_dir() {
        return Err(ArtifactError::UnsafeParent);
    }
    let canonical = fs::canonicalize(path).map_err(|_| ArtifactError::UnsafeParent)?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|_| ArtifactError::UnsafeParent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || identity(&metadata) != identity(&before)
    {
        return Err(ArtifactError::UnsafeParent);
    }
    Ok(canonical)
}

fn directory_meta(path: &Path) -> Result<(u64, u64), ArtifactError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path).map_err(|_| ArtifactError::Io)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn effective_uid() -> Result<u32, ArtifactError> {
    use std::process::{Command, Stdio};
    let output = Command::new("/usr/bin/id")
        .arg("-u")
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| ArtifactError::UnsafeParent)?;
    if !output.status.success() || output.stdout.len() > 16 {
        return Err(ArtifactError::UnsafeParent);
    }
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| ArtifactError::UnsafeParent)?
        .trim();
    value.parse().map_err(|_| ArtifactError::UnsafeParent)
}

fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

fn verify_private_directory(
    path: &Path,
    expected: (u64, u64),
    owner_uid: u32,
) -> Result<(), ArtifactError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = fs::symlink_metadata(path).map_err(|_| ArtifactError::Changed)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o7777 != 0o700
        || identity(&metadata) != expected
    {
        return Err(ArtifactError::UnsafeParent);
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), ArtifactError> {
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            ArtifactError::PathExists
        } else {
            ArtifactError::Io
        }
    })?;
    let created_identity = directory_meta(path).map_err(|_| ArtifactError::CleanupFailed)?;
    if let Err(error) = set_private_dir(path) {
        if directory_meta(path).ok() != Some(created_identity) || fs::remove_dir(path).is_err() {
            return Err(ArtifactError::CleanupFailed);
        }
        return Err(error);
    }
    Ok(())
}

fn create_or_verify_private_directory(path: &Path) -> Result<(), ArtifactError> {
    match fs::create_dir(path) {
        Ok(()) => set_private_dir(path),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path).map_err(|_| ArtifactError::Changed)?;
            use std::os::unix::fs::PermissionsExt;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.permissions().mode() & 0o7777 != 0o700
            {
                return Err(ArtifactError::Changed);
            }
            Ok(())
        }
        Err(_) => Err(ArtifactError::Io),
    }
}

fn set_private_dir(path: &Path) -> Result<(), ArtifactError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| ArtifactError::Io)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(ArtifactError::UnsupportedPlatform)
    }
}

fn create_new_private_file(path: &Path) -> Result<File, ArtifactError> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(O_NOFOLLOW);
    options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            ArtifactError::PathExists
        } else {
            ArtifactError::Io
        }
    })
}

fn open_nofollow(path: &Path) -> Result<File, ArtifactError> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(O_NOFOLLOW);
    options.open(path).map_err(|_| ArtifactError::Io)
}

#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0x20000;
#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x100;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const O_NOFOLLOW: i32 = 0;

fn validate_staged_file(metadata: &fs::Metadata, size: u64) -> Result<(), ArtifactError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.len() != size
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ArtifactError::Changed);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
    };

    struct Fixture {
        parent: PathBuf,
        snapshot: SourceSnapshot,
        task_id: Uuid,
    }

    impl Fixture {
        fn new() -> Self {
            let parent = temp_dir("fixture");
            let input = parent.join("input");
            fs::create_dir(&input).unwrap();
            fs::set_permissions(&input, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(input.join("existing.txt"), b"before\n").unwrap();
            fs::write(input.join("deleted.txt"), b"delete me\n").unwrap();
            let executable = input.join("executable.sh");
            fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            let task_id = Uuid::new_v4();
            let snapshot =
                crate::source_snapshot::synthetic_snapshot(input, task_id, &"a".repeat(40))
                    .unwrap();
            Self {
                parent,
                snapshot,
                task_id,
            }
        }

        fn worktree(&self) -> PathBuf {
            let path = self.parent.join("worktree");
            copy_tree(self.snapshot.path(), &path);
            path
        }

        fn staging_parent(&self) -> PathBuf {
            let path = self.parent.join("staging");
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        }

        fn source_path(&self) -> PathBuf {
            self.parent
                .join("restarted-snapshot-parent")
                .join(self.task_id.to_string())
        }

        fn finish(self) {
            self.snapshot.cleanup().unwrap();
            fs::remove_dir_all(self.parent).unwrap();
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("mipsorcu-artifact-{label}-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir(destination).unwrap();
        fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
        for item in fs::read_dir(source).unwrap() {
            let item = item.unwrap();
            let source_path = item.path();
            let destination_path = destination.join(item.file_name());
            let metadata = fs::symlink_metadata(&source_path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                copy_tree(&source_path, &destination_path);
            } else {
                fs::copy(&source_path, &destination_path).unwrap();
                fs::set_permissions(
                    destination_path,
                    fs::Permissions::from_mode(metadata.permissions().mode() & 0o777),
                )
                .unwrap();
            }
        }
    }

    fn change_worktree(path: &Path) {
        fs::write(path.join("existing.txt"), b"after\n").unwrap();
        fs::remove_file(path.join("deleted.txt")).unwrap();
        fs::write(path.join("new.txt"), b"added\n").unwrap();
        fs::write(
            path.join(MANIFEST_NAME),
            b"a legal source path with the manifest name\n",
        )
        .unwrap();
        fs::create_dir(path.join("empty-directory")).unwrap();
    }

    fn entry<'a>(manifest: &'a ArtifactManifest, path: &str) -> &'a ArtifactEntry {
        manifest
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .unwrap()
    }

    fn run_restart_child(
        mode: &str,
        fixture: &Fixture,
        operation_id: Uuid,
        staging: &Path,
        stream_path: &Path,
    ) -> std::process::Output {
        Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .args([
                "--exact",
                "artifact_receiver::tests::artifact_process_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("MIPSORCU_ARTIFACT_FIXTURE_MODE", mode)
            .env("MIPSORCU_ARTIFACT_FIXTURE_SOURCE", fixture.source_path())
            .env("MIPSORCU_ARTIFACT_FIXTURE_STAGING", staging)
            .env("MIPSORCU_ARTIFACT_FIXTURE_STREAM", stream_path)
            .env(
                "MIPSORCU_ARTIFACT_FIXTURE_TASK",
                fixture.task_id.to_string(),
            )
            .env(
                "MIPSORCU_ARTIFACT_FIXTURE_OPERATION",
                operation_id.to_string(),
            )
            .env(
                "MIPSORCU_ARTIFACT_FIXTURE_COMMIT",
                fixture.snapshot.commit_sha(),
            )
            .output()
            .unwrap()
    }

    #[test]
    #[ignore = "invoked as a separate process by the restart durability test"]
    fn artifact_process_fixture() {
        let mode = std::env::var("MIPSORCU_ARTIFACT_FIXTURE_MODE")
            .expect("the isolated restart test must supply a fixture mode");
        let source = PathBuf::from(std::env::var_os("MIPSORCU_ARTIFACT_FIXTURE_SOURCE").unwrap());
        let staging = PathBuf::from(std::env::var_os("MIPSORCU_ARTIFACT_FIXTURE_STAGING").unwrap());
        let stream = PathBuf::from(std::env::var_os("MIPSORCU_ARTIFACT_FIXTURE_STREAM").unwrap());
        let task_id =
            Uuid::parse_str(&std::env::var("MIPSORCU_ARTIFACT_FIXTURE_TASK").unwrap()).unwrap();
        let operation_id =
            Uuid::parse_str(&std::env::var("MIPSORCU_ARTIFACT_FIXTURE_OPERATION").unwrap())
                .unwrap();
        let commit = std::env::var("MIPSORCU_ARTIFACT_FIXTURE_COMMIT").unwrap();
        let snapshot =
            crate::source_snapshot::synthetic_snapshot(source, task_id, &commit).unwrap();
        match mode.as_str() {
            "receive" => {
                let bytes = fs::read(stream).unwrap();
                receive_artifacts(
                    &snapshot,
                    task_id,
                    operation_id,
                    &staging,
                    &mut io::Cursor::new(bytes),
                )
                .unwrap();
            }
            "reopen" => {
                let staged = reopen_artifacts(&snapshot, task_id, operation_id, &staging).unwrap();
                assert_eq!(
                    staged.read_file("nested/inner/result.txt").unwrap(),
                    b"result\n"
                );
                assert_eq!(staged.manifest().operation_id, operation_id.to_string());
            }
            "reject" => {
                assert!(reopen_artifacts(&snapshot, task_id, operation_id, &staging).is_err())
            }
            "incomplete" => assert_eq!(
                reopen_artifacts(&snapshot, task_id, operation_id, &staging).err(),
                Some(ArtifactError::Incomplete)
            ),
            _ => panic!("unknown fixture mode"),
        }
    }

    #[test]
    #[ignore = "requires disposable network-none runner"]
    fn completed_staging_reopens_after_process_restart_and_rejects_tampering() {
        let fixture = Fixture::new();
        let operation_id = Uuid::new_v4();
        let worktree = fixture.worktree();
        fs::create_dir_all(worktree.join("nested/inner")).unwrap();
        fs::write(worktree.join("nested/inner/result.txt"), b"result\n").unwrap();
        let mut stream = Vec::new();
        write_artifact_stream(
            fixture.task_id,
            operation_id,
            fixture.snapshot.commit_sha(),
            &worktree,
            &mut stream,
        )
        .unwrap();
        let staging = fixture.staging_parent();
        fs::create_dir(fixture.parent.join("restarted-snapshot-parent")).unwrap();
        fs::set_permissions(
            fixture.parent.join("restarted-snapshot-parent"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        copy_tree(fixture.snapshot.path(), &fixture.source_path());
        let stream_path = fixture.parent.join("artifact.stream");
        fs::write(&stream_path, stream).unwrap();

        let received = run_restart_child("receive", &fixture, operation_id, &staging, &stream_path);
        assert!(
            received.status.success(),
            "{}",
            String::from_utf8_lossy(&received.stderr)
        );
        let reopened = run_restart_child("reopen", &fixture, operation_id, &staging, &stream_path);
        assert!(
            reopened.status.success(),
            "{}",
            String::from_utf8_lossy(&reopened.stderr)
        );

        fs::write(
            fixture.source_path().join("existing.txt"),
            b"changed baseline\n",
        )
        .unwrap();
        let changed_baseline =
            run_restart_child("reject", &fixture, operation_id, &staging, &stream_path);
        assert!(
            changed_baseline.status.success(),
            "{}",
            String::from_utf8_lossy(&changed_baseline.stderr)
        );
        fs::write(fixture.source_path().join("existing.txt"), b"before\n").unwrap();
        assert!(
            run_restart_child("reopen", &fixture, operation_id, &staging, &stream_path)
                .status
                .success()
        );

        let root = staging.join(format!("{}-{}", fixture.task_id, operation_id));
        fs::write(root.join("data/nested/inner/result.txt"), b"corrupted\n").unwrap();
        let rejected = run_restart_child("reject", &fixture, operation_id, &staging, &stream_path);
        assert!(
            rejected.status.success(),
            "{}",
            String::from_utf8_lossy(&rejected.stderr)
        );

        let extra_operation = Uuid::new_v4();
        let extra_root = staging.join(format!("{}-{}", fixture.task_id, extra_operation));
        let mut extra_stream = Vec::new();
        write_artifact_stream(
            fixture.task_id,
            extra_operation,
            fixture.snapshot.commit_sha(),
            &worktree,
            &mut extra_stream,
        )
        .unwrap();
        let extra_stream_path = fixture.parent.join("extra-artifact.stream");
        fs::write(&extra_stream_path, extra_stream).unwrap();
        let extra_received = run_restart_child(
            "receive",
            &fixture,
            extra_operation,
            &staging,
            &extra_stream_path,
        );
        assert!(
            extra_received.status.success(),
            "{}",
            String::from_utf8_lossy(&extra_received.stderr)
        );
        assert!(
            run_restart_child(
                "reopen",
                &fixture,
                extra_operation,
                &staging,
                &extra_stream_path,
            )
            .status
            .success()
        );
        fs::write(extra_root.join("data/unlisted.txt"), b"extra\n").unwrap();
        let extra_rejected = run_restart_child(
            "reject",
            &fixture,
            extra_operation,
            &staging,
            &extra_stream_path,
        );
        assert!(
            extra_rejected.status.success(),
            "{}",
            String::from_utf8_lossy(&extra_rejected.stderr)
        );

        let incomplete_operation = Uuid::new_v4();
        let incomplete_root = staging.join(format!("{}-{}", fixture.task_id, incomplete_operation));
        fs::create_dir(&incomplete_root).unwrap();
        fs::set_permissions(&incomplete_root, fs::Permissions::from_mode(0o700)).unwrap();
        let incomplete = run_restart_child(
            "incomplete",
            &fixture,
            incomplete_operation,
            &staging,
            &stream_path,
        );
        assert!(
            incomplete.status.success(),
            "{}",
            String::from_utf8_lossy(&incomplete.stderr)
        );
        let mut incomplete_stream = stream_prefix(
            fixture.task_id,
            incomplete_operation,
            fixture.snapshot.commit_sha(),
        );
        incomplete_stream.push(0);
        assert_eq!(
            receive_artifacts(
                &fixture.snapshot,
                fixture.task_id,
                incomplete_operation,
                &staging,
                &mut io::Cursor::new(incomplete_stream),
            )
            .err(),
            Some(ArtifactError::PathExists)
        );

        let manifest_operation = Uuid::new_v4();
        let mut manifest_stream = Vec::new();
        write_artifact_stream(
            fixture.task_id,
            manifest_operation,
            fixture.snapshot.commit_sha(),
            &worktree,
            &mut manifest_stream,
        )
        .unwrap();
        let manifest_stream_path = fixture.parent.join("manifest-artifact.stream");
        fs::write(&manifest_stream_path, manifest_stream).unwrap();
        let manifest_received = run_restart_child(
            "receive",
            &fixture,
            manifest_operation,
            &staging,
            &manifest_stream_path,
        );
        assert!(
            manifest_received.status.success(),
            "{}",
            String::from_utf8_lossy(&manifest_received.stderr)
        );
        assert!(
            run_restart_child(
                "reopen",
                &fixture,
                manifest_operation,
                &staging,
                &manifest_stream_path,
            )
            .status
            .success()
        );
        let manifest_root = staging.join(format!("{}-{}", fixture.task_id, manifest_operation));
        let manifest_path = manifest_root.join(MANIFEST_NAME);
        let mut manifest_bytes = fs::read(&manifest_path).unwrap();
        manifest_bytes[0] ^= 1;
        fs::write(&manifest_path, manifest_bytes).unwrap();
        let manifest_rejected = run_restart_child(
            "reject",
            &fixture,
            manifest_operation,
            &staging,
            &manifest_stream_path,
        );
        assert!(
            manifest_rejected.status.success(),
            "{}",
            String::from_utf8_lossy(&manifest_rejected.stderr)
        );

        fs::remove_dir_all(&staging).unwrap();
        fs::remove_dir_all(worktree).unwrap();
        fixture.finish();
    }

    #[test]
    #[ignore = "requires disposable network-none runner and producer binary"]
    fn producer_binary_round_trips_worktree_into_verified_staging_when_configured() {
        let binary = std::env::var_os("MIPSORCU_ARTIFACT_PRODUCER")
            .expect("MIPSORCU_ARTIFACT_PRODUCER must name the built producer binary");
        let fixture = Fixture::new();
        let operation_id = Uuid::new_v4();
        let worktree = fixture.worktree();
        change_worktree(&worktree);
        let output = Command::new(binary)
            .args([
                fixture.task_id.to_string(),
                operation_id.to_string(),
                fixture.snapshot.commit_sha().to_owned(),
            ])
            .arg(&worktree)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        assert!(!output.stdout.is_empty());

        let staging_parent = fixture.staging_parent();
        let staged = receive_artifacts(
            &fixture.snapshot,
            fixture.task_id,
            operation_id,
            &staging_parent,
            &mut io::Cursor::new(output.stdout),
        )
        .unwrap();
        let manifest = staged.manifest();
        assert_eq!(
            entry(manifest, "existing.txt").change,
            ArtifactChange::Modified
        );
        assert_eq!(
            entry(manifest, "deleted.txt").change,
            ArtifactChange::Deleted
        );
        assert_eq!(entry(manifest, "new.txt").change, ArtifactChange::Added);
        assert!(entry(manifest, "executable.sh").executable);
        assert!(entry(manifest, "empty-directory").directory);
        assert!(staged.data_root.join("empty-directory").is_dir());
        assert_eq!(
            staged.read_file(MANIFEST_NAME).unwrap(),
            b"a legal source path with the manifest name\n"
        );
        assert_eq!(staged.read_file("new.txt").unwrap(), b"added\n");
        let sibling = staging_parent.join("unrelated");
        fs::write(&sibling, b"preserve\n").unwrap();
        let staged_root = staged.root.clone();
        staged.cleanup().unwrap();
        assert!(!staged_root.exists());
        assert_eq!(fs::read(sibling).unwrap(), b"preserve\n");
        fs::remove_dir_all(worktree).unwrap();
        fixture.finish();
    }

    #[test]
    fn producer_and_receiver_allow_many_parent_directories_for_bounded_files() {
        let fixture = Fixture::new();
        let operation_id = Uuid::new_v4();
        let worktree = fixture.worktree();
        let mut last_file = String::new();
        for directory_index in 0..MAX_FILES + 1 {
            fs::create_dir(worktree.join(format!("empty{directory_index:05}"))).unwrap();
        }
        for file_index in 0..100 {
            let file_path = worktree.join(format!("result{file_index:03}.txt"));
            last_file = file_path
                .strip_prefix(&worktree)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            fs::write(file_path, b"bounded file\n").unwrap();
        }

        let mut stream = Vec::new();
        write_artifact_stream(
            fixture.task_id,
            operation_id,
            fixture.snapshot.commit_sha(),
            &worktree,
            &mut stream,
        )
        .unwrap();
        let staging_parent = fixture.staging_parent();
        let staged = receive_artifacts(
            &fixture.snapshot,
            fixture.task_id,
            operation_id,
            &staging_parent,
            &mut io::Cursor::new(stream),
        )
        .unwrap();
        assert_eq!(staged.read_file(&last_file).unwrap(), b"bounded file\n");
        assert_eq!(
            entry(staged.manifest(), &last_file).change,
            ArtifactChange::Added
        );
        assert!(staged.manifest().entries.len() > MAX_FILES);
        assert!(entry(staged.manifest(), "empty10000").directory);
        staged.cleanup().unwrap();
        fs::remove_dir_all(worktree).unwrap();
        fixture.finish();
    }

    #[test]
    fn legacy_leaf_directory_record_infers_ancestors_and_keeps_empty_directory() {
        let fixture = Fixture::new();
        let operation_id = Uuid::new_v4();
        let staging = fixture.staging_parent();
        let mut bytes = stream_prefix(fixture.task_id, operation_id, fixture.snapshot.commit_sha());
        // Old producers may emit only a leaf directory; explicit records remain
        // valid in any order, while missing ancestors are reconstructed.
        append_record(&mut bytes, 2, "empty-parent/empty-leaf", 0o755, b"");
        bytes.push(0);

        let staged = receive_artifacts(
            &fixture.snapshot,
            fixture.task_id,
            operation_id,
            &staging,
            &mut io::Cursor::new(bytes),
        )
        .unwrap();
        assert_eq!(
            entry(staged.manifest(), "empty-parent").change,
            ArtifactChange::Added
        );
        assert_eq!(
            entry(staged.manifest(), "empty-parent/empty-leaf").change,
            ArtifactChange::Added
        );
        assert!(staged.data_root.join("empty-parent/empty-leaf").is_dir());
        staged.cleanup().unwrap();
        fs::remove_dir_all(staging).unwrap();
        fixture.finish();
    }

    #[test]
    fn malformed_or_truncated_streams_do_not_create_staging() {
        let fixture = Fixture::new();
        let operation_id = Uuid::new_v4();
        let staging = fixture.staging_parent();
        let mut path_traversal = Vec::new();
        path_traversal.extend_from_slice(MAGIC);
        path_traversal.extend_from_slice(fixture.task_id.as_bytes());
        path_traversal.extend_from_slice(operation_id.as_bytes());
        let mut commit = [0; 64];
        commit[..40].copy_from_slice(fixture.snapshot.commit_sha().as_bytes());
        path_traversal.extend_from_slice(&commit);
        path_traversal.push(1);
        path_traversal.extend_from_slice(&9_u32.to_be_bytes());
        path_traversal.extend_from_slice(&0o644_u32.to_be_bytes());
        path_traversal.extend_from_slice(&1_u64.to_be_bytes());
        path_traversal.extend_from_slice(b"../escape");
        path_traversal.extend_from_slice(b"x\0");
        assert_eq!(
            receive_artifacts(
                &fixture.snapshot,
                fixture.task_id,
                operation_id,
                &staging,
                &mut io::Cursor::new(path_traversal),
            )
            .err(),
            Some(ArtifactError::InvalidPath)
        );

        let worktree = fixture.worktree();
        change_worktree(&worktree);
        let mut valid = Vec::new();
        write_artifact_stream(
            fixture.task_id,
            operation_id,
            fixture.snapshot.commit_sha(),
            &worktree,
            &mut valid,
        )
        .unwrap();
        valid.pop();
        assert_eq!(
            receive_artifacts(
                &fixture.snapshot,
                fixture.task_id,
                operation_id,
                &staging,
                &mut io::Cursor::new(valid),
            )
            .err(),
            Some(ArtifactError::InvalidStream)
        );
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
        fs::remove_dir_all(staging).unwrap();
        fs::remove_dir_all(worktree).unwrap();
        fixture.finish();
    }

    #[test]
    fn malformed_tree_records_are_rejected_before_staging() {
        let fixture = Fixture::new();
        let staging = fixture.staging_parent();
        let cases: [(&str, &[(u8, &str, u32, &[u8])]); 5] = [
            (
                "duplicate path",
                &[(1, "same", 0o644, b"a"), (1, "same", 0o644, b"b")],
            ),
            (
                "case collision",
                &[(1, "Case", 0o644, b"a"), (1, "case", 0o644, b"b")],
            ),
            (
                "file directory conflict",
                &[(1, "node", 0o644, b"a"), (1, "node/child", 0o644, b"b")],
            ),
            (
                "directory file conflict",
                &[(1, "node/child", 0o644, b"a"), (1, "node", 0o644, b"b")],
            ),
            ("unsupported link kind", &[(3, "link", 0o120000, b"")]),
        ];
        for (label, records) in cases {
            let operation_id = Uuid::new_v4();
            let mut bytes =
                stream_prefix(fixture.task_id, operation_id, fixture.snapshot.commit_sha());
            for (kind, path, mode, content) in records {
                append_record(&mut bytes, *kind, path, *mode, content);
            }
            bytes.push(0);
            let result = receive_artifacts(
                &fixture.snapshot,
                fixture.task_id,
                operation_id,
                &staging,
                &mut io::Cursor::new(bytes),
            );
            assert!(result.is_err(), "accepted malformed case: {label}");
            assert_eq!(
                fs::read_dir(&staging).unwrap().count(),
                0,
                "staging created for {label}"
            );
        }
        fs::remove_dir_all(staging).unwrap();
        fixture.finish();
    }

    #[test]
    fn producer_rejects_hardlinked_files_and_staged_reads_detect_tampering() {
        let fixture = Fixture::new();
        let worktree = fixture.worktree();
        fs::hard_link(worktree.join("existing.txt"), worktree.join("hardlink.txt")).unwrap();
        let mut bytes = Vec::new();
        assert_eq!(
            write_artifact_stream(
                fixture.task_id,
                Uuid::new_v4(),
                fixture.snapshot.commit_sha(),
                &worktree,
                &mut bytes,
            ),
            Err(ArtifactError::InvalidTree)
        );
        assert!(bytes.is_empty());
        fs::remove_file(worktree.join("hardlink.txt")).unwrap();

        let operation_id = Uuid::new_v4();
        let mut stream = Vec::new();
        write_artifact_stream(
            fixture.task_id,
            operation_id,
            fixture.snapshot.commit_sha(),
            &worktree,
            &mut stream,
        )
        .unwrap();
        let staging = fixture.staging_parent();
        let staged = receive_artifacts(
            &fixture.snapshot,
            fixture.task_id,
            operation_id,
            &staging,
            &mut io::Cursor::new(stream),
        )
        .unwrap();
        let staged_file = staged.data_root.join("existing.txt");
        fs::write(&staged_file, b"tampered\n").unwrap();
        assert_eq!(
            staged.read_file("existing.txt"),
            Err(ArtifactError::Changed)
        );
        drop(staged);
        fs::remove_dir_all(staging).unwrap();
        fs::remove_dir_all(worktree).unwrap();
        fixture.finish();
    }

    #[test]
    fn producer_rejects_metadata_paths_and_symlinks_before_emitting() {
        let fixture = Fixture::new();
        let worktree = fixture.worktree();
        fs::create_dir(worktree.join(".git")).unwrap();
        fs::write(worktree.join(".git/config"), b"invalid metadata\n").unwrap();
        let mut stream = Vec::new();
        assert_eq!(
            write_artifact_stream(
                fixture.task_id,
                Uuid::new_v4(),
                fixture.snapshot.commit_sha(),
                &worktree,
                &mut stream,
            ),
            Err(ArtifactError::InvalidPath)
        );
        assert!(stream.is_empty());
        fs::remove_dir_all(worktree.join(".git")).unwrap();
        symlink("/etc/passwd", worktree.join("linked-file")).unwrap();
        assert_eq!(
            write_artifact_stream(
                fixture.task_id,
                Uuid::new_v4(),
                fixture.snapshot.commit_sha(),
                &worktree,
                &mut stream,
            ),
            Err(ArtifactError::InvalidTree)
        );
        assert!(stream.is_empty());
        fs::remove_dir_all(worktree).unwrap();
        fixture.finish();
    }

    fn stream_prefix(task_id: Uuid, operation_id: Uuid, commit: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(task_id.as_bytes());
        bytes.extend_from_slice(operation_id.as_bytes());
        let mut oid = [0; 64];
        oid[..commit.len()].copy_from_slice(commit.as_bytes());
        bytes.extend_from_slice(&oid);
        bytes
    }

    fn append_record(bytes: &mut Vec<u8>, kind: u8, path: &str, mode: u32, content: &[u8]) {
        bytes.push(kind);
        bytes.extend_from_slice(&(path.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&mode.to_be_bytes());
        bytes.extend_from_slice(&(content.len() as u64).to_be_bytes());
        bytes.extend_from_slice(path.as_bytes());
        bytes.extend_from_slice(content);
    }
}

//! Cross-process single-owner lock for a supervisor instance.
//!
//! The operator must create and protect the directory before calling
//! [`acquire`]. This module does not treat process death or a
//! released OS lock as proof that a prior supervisor stopped cleanly.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::{Command, Stdio};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const LOCK_FILE: &str = ".mipsorcu-supervisor.lock";
#[cfg(target_os = "linux")]
const INTENT_FILE: &str = ".mipsorcu-supervisor.intent";
#[cfg(target_os = "linux")]
const INTENT_MAGIC: &[u8; 8] = b"MIPINT01";
#[cfg(target_os = "linux")]
const INTENT_BYTES: usize = 52;
#[cfg(target_os = "linux")]
const BINDING_PREFIX: &str = ".mipsorcu-supervisor.binding-";
#[cfg(target_os = "linux")]
const RESOLVED_PREFIX: &str = ".mipsorcu-supervisor.resolved-";
#[cfg(target_os = "linux")]
const MAX_BINDING_BYTES: u64 = 2048;

/// Durable identity and requested limits for one started container.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorBinding {
    pub intent: SupervisorIntent,
    pub container_id: String,
    pub cgroup_path: String,
    pub cgroup_device: u64,
    pub cgroup_inode: u64,
    pub memory_bytes: u64,
    pub cpu_quota_micros: u64,
    pub cpu_period_micros: u64,
    pub pids_limit: u64,
}

/// Opaque evidence that Docker reported the bound container stopped and the
/// recorded cgroup has no processes. It can only be created inside this crate.
#[cfg(target_os = "linux")]
pub struct VerifiedContainerStop {
    intent: SupervisorIntent,
    container_id: String,
}

/// A held cross-process lock for one supervisor.
///
/// `directory` must be an existing operator-managed directory owned by the
/// current user with mode `0700`. The lock file is persistent and must not be
/// removed or replaced while supervisors may be running. The lock prevents
/// concurrent cooperating processes; it does not defend against a malicious
/// process running as the same user, which can bypass ordinary file access
/// controls.
pub struct SupervisorLock {
    _file: File,
    #[cfg(target_os = "linux")]
    directory: File,
    #[cfg(target_os = "linux")]
    directory_path: PathBuf,
}

/// Non-secret identifiers for one operation whose execution may be ambiguous
/// after a supervisor crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorIntent {
    pub task_id: Uuid,
    pub operation_id: Uuid,
    pub attempt: u32,
    pub fencing_token: u64,
}

/// Safe, path-free failure categories for supervisor lock acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorLockError {
    /// The operator-managed directory failed its ownership or mode checks.
    UnsafeDirectory,
    /// The persistent lock file failed its type, ownership, mode, or identity checks.
    UnsafeLockFile,
    /// Another process currently owns the lock.
    AlreadyHeld,
    /// A previous operation still occupies the single durable intent slot.
    IntentAlreadyExists,
    /// The intent file failed its type, ownership, mode, or identity checks.
    UnsafeIntentFile,
    /// Durable intent recording is supported only on Linux.
    UnsupportedPlatform,
    /// Required intent identifiers or fencing token were invalid.
    InvalidIntent,
    /// The durable intent record is malformed or changed while it was read.
    InvalidIntentRecord,
    /// An operating-system operation failed.
    Io,
}

impl Display for SupervisorLockError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsafeDirectory => {
                "supervisor lock directory is not private and owned by this user"
            }
            Self::UnsafeLockFile => "supervisor lock file is not a safe regular file",
            Self::AlreadyHeld => "another supervisor already holds the lock",
            Self::IntentAlreadyExists => "an unresolved supervisor intent already exists",
            Self::UnsafeIntentFile => "supervisor intent file is not a safe regular file",
            Self::UnsupportedPlatform => "durable supervisor intent is supported only on Linux",
            Self::InvalidIntent => "supervisor intent identifiers are invalid",
            Self::InvalidIntentRecord => "supervisor intent record is invalid",
            Self::Io => "supervisor lock operation failed",
        })
    }
}

impl Error for SupervisorLockError {}

/// Acquires the persistent lock file in an operator-managed private directory.
///
/// The directory must already exist, be owned by the effective user, and have
/// mode `0700`. The lock file is created exclusively when absent; existing
/// files are opened without truncation and validated before and after opening.
/// A nonblocking OS lock is held until this value is dropped. This API neither
/// removes the file nor interprets a released lock as evidence of clean
/// shutdown. Access controls do not protect against hostile same-user processes.
pub fn acquire(directory: &Path) -> Result<SupervisorLock, SupervisorLockError> {
    let uid = current_uid().map_err(|_| SupervisorLockError::Io)?;
    if uid == 0 {
        return Err(SupervisorLockError::UnsafeDirectory);
    }
    let directory_metadata =
        fs::symlink_metadata(directory).map_err(|_| SupervisorLockError::Io)?;
    validate_directory(&directory_metadata, uid)?;

    let lock_path = directory.join(LOCK_FILE);
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&lock_path)
    {
        Ok(file) => {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| SupervisorLockError::Io)?;
            file
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let before = fs::symlink_metadata(&lock_path).map_err(|_| SupervisorLockError::Io)?;
            validate_lock_metadata(&before, uid)?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
                .map_err(|_| SupervisorLockError::Io)?;
            let opened = file.metadata().map_err(|_| SupervisorLockError::Io)?;
            validate_lock_metadata(&opened, uid)?;
            let after = fs::symlink_metadata(&lock_path).map_err(|_| SupervisorLockError::Io)?;
            validate_lock_metadata(&after, uid)?;
            if !same_file(&before, &opened) || !same_file(&opened, &after) {
                return Err(SupervisorLockError::UnsafeLockFile);
            }
            file
        }
        Err(_) => return Err(SupervisorLockError::Io),
    };

    let opened = file.metadata().map_err(|_| SupervisorLockError::Io)?;
    validate_lock_metadata(&opened, uid)?;
    let current = fs::symlink_metadata(&lock_path).map_err(|_| SupervisorLockError::Io)?;
    validate_lock_metadata(&current, uid)?;
    if !same_file(&opened, &current) {
        return Err(SupervisorLockError::UnsafeLockFile);
    }

    match file.try_lock() {
        Ok(()) => {
            #[cfg(target_os = "linux")]
            let (directory, directory_path) = {
                let directory_file = File::open(directory).map_err(|_| SupervisorLockError::Io)?;
                let opened_directory = directory_file
                    .metadata()
                    .map_err(|_| SupervisorLockError::Io)?;
                let current_directory =
                    fs::symlink_metadata(directory).map_err(|_| SupervisorLockError::Io)?;
                if !same_file(&directory_metadata, &opened_directory)
                    || !same_file(&opened_directory, &current_directory)
                {
                    return Err(SupervisorLockError::UnsafeDirectory);
                }
                (directory_file, directory.to_path_buf())
            };
            Ok(SupervisorLock {
                _file: file,
                #[cfg(target_os = "linux")]
                directory,
                #[cfg(target_os = "linux")]
                directory_path,
            })
        }
        Err(TryLockError::WouldBlock) => Err(SupervisorLockError::AlreadyHeld),
        Err(TryLockError::Error(_)) => Err(SupervisorLockError::Io),
    }
}

impl SupervisorLock {
    /// Reads the existing operation intent without removing or resolving it.
    ///
    /// `None` means no marker was found; it does not prove that no process is
    /// running and does not authorize an operation. A malformed marker blocks
    /// recovery. Same-user processes and replacement of trusted parent paths
    /// are outside this mechanism's protection boundary.
    #[cfg(target_os = "linux")]
    pub fn read_intent(&self) -> Result<Option<SupervisorIntent>, SupervisorLockError> {
        let uid = current_uid().map_err(|_| SupervisorLockError::Io)?;
        let directory_opened = self
            .directory
            .metadata()
            .map_err(|_| SupervisorLockError::Io)?;
        let directory_current =
            fs::symlink_metadata(&self.directory_path).map_err(|_| SupervisorLockError::Io)?;
        if !same_file(&directory_opened, &directory_current) {
            return Err(SupervisorLockError::UnsafeDirectory);
        }
        validate_directory(&directory_opened, uid)?;

        let path = self.directory_path.join(INTENT_FILE);
        let before = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(SupervisorLockError::Io),
        };
        validate_intent_metadata(&before, uid)?;
        if before.len() != INTENT_BYTES as u64 {
            return Err(SupervisorLockError::InvalidIntentRecord);
        }

        let mut file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|_| SupervisorLockError::Io)?;
        let opened = file.metadata().map_err(|_| SupervisorLockError::Io)?;
        validate_intent_metadata(&opened, uid)?;
        if !same_file(&before, &opened) {
            return Err(SupervisorLockError::UnsafeIntentFile);
        }

        let mut bytes = [0_u8; INTENT_BYTES];
        file.read_exact(&mut bytes)
            .map_err(|_| SupervisorLockError::InvalidIntentRecord)?;
        let mut trailing = [0_u8; 1];
        if file
            .read(&mut trailing)
            .map_err(|_| SupervisorLockError::Io)?
            != 0
        {
            return Err(SupervisorLockError::InvalidIntentRecord);
        }

        let after = fs::symlink_metadata(&path).map_err(|_| SupervisorLockError::Io)?;
        validate_intent_metadata(&after, uid)?;
        if !same_file(&opened, &after) {
            return Err(SupervisorLockError::UnsafeIntentFile);
        }
        let directory_after =
            fs::symlink_metadata(&self.directory_path).map_err(|_| SupervisorLockError::Io)?;
        if !same_file(&directory_opened, &directory_after) {
            return Err(SupervisorLockError::UnsafeDirectory);
        }

        decode_intent(&bytes).map(Some)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn read_intent(&self) -> Result<Option<SupervisorIntent>, SupervisorLockError> {
        Err(SupervisorLockError::UnsupportedPlatform)
    }

    /// Persists a single operation intent before any child process is started.
    ///
    /// Success means only that the intent record and containing directory were
    /// synced. It does not authorize execution or prove process isolation or
    /// shutdown. Existing records, including partial/corrupt records, remain
    /// blocking across restarts and must not be manually removed as evidence of
    /// clean shutdown. Use a trusted local Linux filesystem; durability across
    /// power loss or storage failure is not established for other filesystems.
    /// Same-user processes and replacement of trusted parent paths are outside
    /// this mechanism's protection boundary.
    #[cfg(target_os = "linux")]
    pub fn persist_intent(&self, intent: SupervisorIntent) -> Result<(), SupervisorLockError> {
        if intent.task_id.is_nil() || intent.operation_id.is_nil() || intent.fencing_token == 0 {
            return Err(SupervisorLockError::InvalidIntent);
        }
        let uid = current_uid().map_err(|_| SupervisorLockError::Io)?;
        let directory_opened = self
            .directory
            .metadata()
            .map_err(|_| SupervisorLockError::Io)?;
        let directory_current =
            fs::symlink_metadata(&self.directory_path).map_err(|_| SupervisorLockError::Io)?;
        if !same_file(&directory_opened, &directory_current) {
            return Err(SupervisorLockError::UnsafeDirectory);
        }
        validate_directory(&directory_opened, uid)?;

        let resolved_path = self.resolved_path(intent.operation_id);
        match fs::symlink_metadata(&resolved_path) {
            Ok(metadata) => {
                validate_intent_metadata(&metadata, uid)?;
                return Err(SupervisorLockError::IntentAlreadyExists);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(SupervisorLockError::Io),
        }

        let path = self.directory_path.join(INTENT_FILE);
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = fs::symlink_metadata(&path).map_err(|_| SupervisorLockError::Io)?;
                validate_intent_metadata(&existing, uid)?;
                return Err(SupervisorLockError::IntentAlreadyExists);
            }
            Err(_) => return Err(SupervisorLockError::Io),
        };

        let opened = file.metadata().map_err(|_| SupervisorLockError::Io)?;
        validate_intent_metadata(&opened, uid)?;
        let current = fs::symlink_metadata(&path).map_err(|_| SupervisorLockError::Io)?;
        validate_intent_metadata(&current, uid)?;
        if !same_file(&opened, &current) {
            return Err(SupervisorLockError::UnsafeIntentFile);
        }

        file.write_all(INTENT_MAGIC)
            .and_then(|()| file.write_all(intent.task_id.as_bytes()))
            .and_then(|()| file.write_all(intent.operation_id.as_bytes()))
            .and_then(|()| file.write_all(&intent.attempt.to_be_bytes()))
            .and_then(|()| file.write_all(&intent.fencing_token.to_be_bytes()))
            .and_then(|()| file.sync_all())
            .map_err(|_| SupervisorLockError::Io)?;
        self.directory
            .sync_all()
            .map_err(|_| SupervisorLockError::Io)?;
        Ok(())
    }

    /// Persists the immutable container/cgroup binding before a bootstrap gate
    /// is opened. Re-recording the identical value is idempotent; replacement
    /// is rejected so a recovered operation cannot point at another container.
    #[cfg(target_os = "linux")]
    pub fn persist_binding(
        &self,
        binding: &SupervisorBinding,
    ) -> Result<(), SupervisorLockError> {
        validate_binding(binding)?;
        if self.read_intent()? != Some(binding.intent) {
            return Err(SupervisorLockError::InvalidIntentRecord);
        }
        let path = self.binding_path(binding.intent.operation_id);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                self.validate_owned_file(&path, &metadata)?;
                let existing = self.read_binding(binding.intent.operation_id)?;
                if existing.as_ref() == Some(binding) {
                    return Ok(());
                }
                Err(SupervisorLockError::InvalidIntentRecord)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let bytes = serde_json::to_vec(binding)
                    .map_err(|_| SupervisorLockError::InvalidIntentRecord)?;
                if bytes.len() > MAX_BINDING_BYTES as usize {
                    return Err(SupervisorLockError::InvalidIntentRecord);
                }
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .map_err(|_| SupervisorLockError::Io)?;
                let opened = file.metadata().map_err(|_| SupervisorLockError::Io)?;
                self.validate_owned_file(&path, &opened)?;
                file.write_all(&bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|_| SupervisorLockError::Io)?;
                self.directory
                    .sync_all()
                    .map_err(|_| SupervisorLockError::Io)
            }
            Err(_) => Err(SupervisorLockError::Io),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn persist_binding(
        &self,
        _binding: &SupervisorBinding,
    ) -> Result<(), SupervisorLockError> {
        Err(SupervisorLockError::UnsupportedPlatform)
    }

    /// Reads the operation's binding without authorizing execution or retry.
    #[cfg(target_os = "linux")]
    pub fn read_binding(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<SupervisorBinding>, SupervisorLockError> {
        if operation_id.is_nil() {
            return Err(SupervisorLockError::InvalidIntent);
        }
        let path = self.binding_path(operation_id);
        let before = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(SupervisorLockError::Io),
        };
        self.validate_owned_file(&path, &before)?;
        if before.len() == 0 || before.len() > MAX_BINDING_BYTES {
            return Err(SupervisorLockError::InvalidIntentRecord);
        }
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|_| SupervisorLockError::Io)?;
        let opened = file.metadata().map_err(|_| SupervisorLockError::Io)?;
        self.validate_owned_file(&path, &opened)?;
        if !same_file(&before, &opened) {
            return Err(SupervisorLockError::UnsafeIntentFile);
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        file.take(MAX_BINDING_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SupervisorLockError::Io)?;
        if bytes.len() as u64 != before.len() || bytes.len() as u64 > MAX_BINDING_BYTES {
            return Err(SupervisorLockError::InvalidIntentRecord);
        }
        let after = fs::symlink_metadata(&path).map_err(|_| SupervisorLockError::Io)?;
        self.validate_owned_file(&path, &after)?;
        if !same_file(&opened, &after) {
            return Err(SupervisorLockError::UnsafeIntentFile);
        }
        let binding: SupervisorBinding = serde_json::from_slice(&bytes)
            .map_err(|_| SupervisorLockError::InvalidIntentRecord)?;
        validate_binding(&binding)?;
        if binding.intent.operation_id != operation_id {
            return Err(SupervisorLockError::InvalidIntentRecord);
        }
        Ok(Some(binding))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn read_binding(
        &self,
        _operation_id: Uuid,
    ) -> Result<Option<SupervisorBinding>, SupervisorLockError> {
        Err(SupervisorLockError::UnsupportedPlatform)
    }

    /// Creates stop evidence only after Docker is observed stopped and the
    /// exact recorded cgroup (including nested cgroups) has no members.
    #[cfg(target_os = "linux")]
    pub(crate) fn verify_container_stopped(
        &self,
        intent: SupervisorIntent,
        binding: &SupervisorBinding,
        docker_state: &crate::docker_preflight::DockerContainerState,
    ) -> Result<VerifiedContainerStop, SupervisorLockError> {
        if docker_state.id() != binding.container_id
            || docker_state.running()
            || self.read_intent()? != Some(intent)
            || self.read_binding(intent.operation_id)?.as_ref() != Some(binding)
            || binding.intent != intent
        {
            return Err(SupervisorLockError::InvalidIntentRecord);
        }
        verify_cgroup_empty(binding)?;
        Ok(VerifiedContainerStop {
            intent,
            container_id: binding.container_id.clone(),
        })
    }

    /// Atomically moves the unresolved marker to a permanent resolved record.
    /// The durable resolved file prevents the same operation from being replayed.
    #[cfg(target_os = "linux")]
    pub(crate) fn resolve_intent(
        &self,
        proof: VerifiedContainerStop,
    ) -> Result<(), SupervisorLockError> {
        let intent = proof.intent;
        let binding = self
            .read_binding(intent.operation_id)?
            .ok_or(SupervisorLockError::InvalidIntentRecord)?;
        if binding.intent != intent || binding.container_id != proof.container_id {
            return Err(SupervisorLockError::InvalidIntentRecord);
        }
        verify_cgroup_empty(&binding)?;
        if self.read_intent()? != Some(intent) {
            return Err(SupervisorLockError::InvalidIntentRecord);
        }
        let active = self
            .directory_path
            .join(INTENT_FILE);
        let resolved = self.resolved_path(intent.operation_id);
        if fs::symlink_metadata(&resolved).is_ok() {
            return Err(SupervisorLockError::IntentAlreadyExists);
        }
        fs::rename(&active, &resolved).map_err(|_| SupervisorLockError::Io)?;
        self.directory
            .sync_all()
            .map_err(|_| SupervisorLockError::Io)
    }

    #[cfg(target_os = "linux")]
    fn binding_path(&self, operation_id: Uuid) -> PathBuf {
        self.directory_path
            .join(format!("{BINDING_PREFIX}{operation_id}"))
    }

    #[cfg(target_os = "linux")]
    fn resolved_path(&self, operation_id: Uuid) -> PathBuf {
        self.directory_path
            .join(format!("{RESOLVED_PREFIX}{operation_id}"))
    }

    #[cfg(target_os = "linux")]
    fn validate_owned_file(
        &self,
        path: &Path,
        metadata: &fs::Metadata,
    ) -> Result<(), SupervisorLockError> {
        let uid = current_uid().map_err(|_| SupervisorLockError::Io)?;
        validate_intent_metadata(metadata, uid)?;
        let directory = self
            .directory
            .metadata()
            .map_err(|_| SupervisorLockError::Io)?;
        let current_directory = fs::symlink_metadata(&self.directory_path)
            .map_err(|_| SupervisorLockError::Io)?;
        if !same_file(&directory, &current_directory) {
            return Err(SupervisorLockError::UnsafeDirectory);
        }
        let current = fs::symlink_metadata(path).map_err(|_| SupervisorLockError::Io)?;
        validate_intent_metadata(&current, uid)?;
        if !same_file(metadata, &current) {
            return Err(SupervisorLockError::UnsafeIntentFile);
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn persist_intent(&self, _intent: SupervisorIntent) -> Result<(), SupervisorLockError> {
        Err(SupervisorLockError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
fn validate_binding(binding: &SupervisorBinding) -> Result<(), SupervisorLockError> {
    use std::path::Component;

    let cgroup = Path::new(&binding.cgroup_path);
    if binding.intent.task_id.is_nil()
        || binding.intent.operation_id.is_nil()
        || binding.intent.fencing_token == 0
        || binding.container_id.len() != 64
        || !binding
            .container_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || !cgroup.is_absolute()
        || cgroup.components().any(|component| {
            matches!(component, Component::ParentDir | Component::CurDir | Component::Prefix(_))
        })
        || !binding.cgroup_path.contains(&binding.container_id)
        || binding.cgroup_device == 0
        || binding.cgroup_inode == 0
        || binding.memory_bytes == 0
        || binding.cpu_quota_micros == 0
        || binding.cpu_period_micros == 0
        || binding.pids_limit == 0
    {
        return Err(SupervisorLockError::InvalidIntentRecord);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_cgroup_empty(binding: &SupervisorBinding) -> Result<(), SupervisorLockError> {
    use std::os::unix::fs::MetadataExt;
    const CGROUP_ROOT: &str = "/sys/fs/cgroup";
    const MAX_NESTED_CGROUPS: usize = 4096;

    validate_binding(binding)?;
    let relative = Path::new(&binding.cgroup_path)
        .strip_prefix("/")
        .map_err(|_| SupervisorLockError::InvalidIntentRecord)?;
    let root = Path::new(CGROUP_ROOT).join(relative);
    let metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        // A cgroup directory can only be removed by the kernel after it becomes
        // empty; the pre-start device/inode binding prevents path reuse proof.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(SupervisorLockError::Io),
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.dev() != binding.cgroup_device
        || metadata.ino() != binding.cgroup_inode
    {
        return Err(SupervisorLockError::InvalidIntentRecord);
    }

    let mut pending = vec![root];
    let mut visited = 0usize;
    while let Some(directory) = pending.pop() {
        visited = visited
            .checked_add(1)
            .filter(|count| *count <= MAX_NESTED_CGROUPS)
            .ok_or(SupervisorLockError::InvalidIntentRecord)?;
        let current = fs::symlink_metadata(&directory).map_err(|_| SupervisorLockError::Io)?;
        if !current.is_dir() || current.file_type().is_symlink() {
            return Err(SupervisorLockError::InvalidIntentRecord);
        }
        let processes = fs::read_to_string(directory.join("cgroup.procs"))
            .map_err(|_| SupervisorLockError::Io)?;
        if processes.lines().any(|line| !line.trim().is_empty()) {
            return Err(SupervisorLockError::InvalidIntentRecord);
        }
        let events = fs::read_to_string(directory.join("cgroup.events"))
            .map_err(|_| SupervisorLockError::Io)?;
        let populated = events.lines().find_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            (fields.next() == Some("populated")).then(|| fields.next())
        });
        if populated.flatten() != Some("0") {
            return Err(SupervisorLockError::InvalidIntentRecord);
        }
        for entry in fs::read_dir(&directory).map_err(|_| SupervisorLockError::Io)? {
            let entry = entry.map_err(|_| SupervisorLockError::Io)?;
            let child_meta = fs::symlink_metadata(entry.path()).map_err(|_| SupervisorLockError::Io)?;
            if child_meta.is_dir() && !child_meta.file_type().is_symlink() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn decode_intent(bytes: &[u8; INTENT_BYTES]) -> Result<SupervisorIntent, SupervisorLockError> {
    if bytes.get(..INTENT_MAGIC.len()) != Some(INTENT_MAGIC) {
        return Err(SupervisorLockError::InvalidIntentRecord);
    }
    let task_id = Uuid::from_slice(
        bytes
            .get(8..24)
            .ok_or(SupervisorLockError::InvalidIntentRecord)?,
    )
    .map_err(|_| SupervisorLockError::InvalidIntentRecord)?;
    let operation_id = Uuid::from_slice(
        bytes
            .get(24..40)
            .ok_or(SupervisorLockError::InvalidIntentRecord)?,
    )
    .map_err(|_| SupervisorLockError::InvalidIntentRecord)?;
    let attempt = u32::from_be_bytes(
        bytes
            .get(40..44)
            .ok_or(SupervisorLockError::InvalidIntentRecord)?
            .try_into()
            .map_err(|_| SupervisorLockError::InvalidIntentRecord)?,
    );
    let fencing_token = u64::from_be_bytes(
        bytes
            .get(44..52)
            .ok_or(SupervisorLockError::InvalidIntentRecord)?
            .try_into()
            .map_err(|_| SupervisorLockError::InvalidIntentRecord)?,
    );
    if task_id.is_nil() || operation_id.is_nil() || fencing_token == 0 {
        return Err(SupervisorLockError::InvalidIntentRecord);
    }
    Ok(SupervisorIntent {
        task_id,
        operation_id,
        attempt,
        fencing_token,
    })
}

fn current_uid() -> io::Result<u32> {
    let output = Command::new("/usr/bin/id")
        .arg("-u")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("uid lookup failed"));
    }
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| io::Error::other("uid lookup failed"))?
        .trim_end_matches('\n');
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(io::Error::other("uid lookup failed"));
    }
    value
        .parse::<u32>()
        .map_err(|_| io::Error::other("uid lookup failed"))
}

fn validate_directory(metadata: &fs::Metadata, uid: u32) -> Result<(), SupervisorLockError> {
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7777 != 0o700 {
        return Err(SupervisorLockError::UnsafeDirectory);
    }
    Ok(())
}

fn validate_lock_metadata(metadata: &fs::Metadata, uid: u32) -> Result<(), SupervisorLockError> {
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(SupervisorLockError::UnsafeLockFile);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_intent_metadata(metadata: &fs::Metadata, uid: u32) -> Result<(), SupervisorLockError> {
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(SupervisorLockError::UnsafeIntentFile);
    }
    Ok(())
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
    const TEST_DIR_ENV: &str = "MIPSORCU_SUPERVISOR_LOCK_TEST_DIR";
    const TEST_MODE_ENV: &str = "MIPSORCU_SUPERVISOR_LOCK_TEST_MODE";

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let root = std::env::temp_dir();
            for _ in 0..64 {
                let ticks = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_nanos());
                let path = root.join(format!(
                    "mipsorcu-lock-test-{}-{ticks}-{}",
                    std::process::id(),
                    NEXT_DIR.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("temporary directory creation failed: {error}"),
                }
            }
            panic!("could not allocate a unique temporary directory")
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct ChildGuard(std::process::Child);

    impl ChildGuard {
        fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
            self.0.try_wait()
        }

        fn kill(&mut self) -> io::Result<()> {
            self.0.kill()
        }

        fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
            self.0.wait()
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }

    fn create_lock_file(path: &Path, mode: u32) {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .expect("test lock file creation failed");
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("test lock file chmod failed");
    }

    fn run_child(directory: &Path, mode: &str) -> std::process::Child {
        Command::new(std::env::current_exe().expect("test executable path missing"))
            .args(["lock_child_process", "--nocapture"])
            .env(TEST_DIR_ENV, directory)
            .env(TEST_MODE_ENV, mode)
            .stderr(Stdio::null())
            .spawn()
            .expect("child test process failed to start")
    }

    #[test]
    fn lock_child_process() {
        let Ok(directory) = std::env::var(TEST_DIR_ENV) else {
            return;
        };
        let path = Path::new(&directory);
        match std::env::var(TEST_MODE_ENV).as_deref() {
            Ok("hold") => {
                let _lock = acquire(path).expect("child could not acquire lock");
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path.join("holder-ready"))
                    .expect("child could not signal readiness");
                loop {
                    std::thread::park();
                }
            }
            Ok("intent-hold") => {
                let lock = acquire(path).expect("child could not acquire lock");
                lock.persist_intent(SupervisorIntent {
                    task_id: Uuid::from_u128(1),
                    operation_id: Uuid::from_u128(2),
                    attempt: 1,
                    fencing_token: 3,
                })
                .expect("child could not persist intent");
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path.join("holder-ready"))
                    .expect("child could not signal readiness");
                loop {
                    std::thread::park();
                }
            }
            Ok("contend") => {
                assert_eq!(acquire(path).err(), Some(SupervisorLockError::AlreadyHeld))
            }
            _ => panic!("invalid child test mode"),
        }
    }

    #[test]
    fn acquires_once_and_releases_when_dropped() {
        let directory = TempDir::new();
        let lock = acquire(directory.path()).expect("first acquire failed");
        assert_eq!(
            acquire(directory.path()).err(),
            Some(SupervisorLockError::AlreadyHeld)
        );
        drop(lock);
        let _lock = acquire(directory.path()).expect("reacquire after drop failed");
        assert!(directory.path().join(LOCK_FILE).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn persisted_intent_remains_single_slot_after_process_kill() {
        let directory = TempDir::new();
        let mut holder = ChildGuard(run_child(directory.path(), "intent-hold"));
        let ready = directory.path().join("holder-ready");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ready.exists() && std::time::Instant::now() < deadline {
            if holder
                .try_wait()
                .expect("checking child process failed")
                .is_some()
            {
                panic!("child process exited before persisting intent");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(ready.exists(), "child did not persist intent in time");

        holder
            .kill()
            .expect("could not stop intent holder test process");
        assert!(!holder.wait().expect("waiting for holder failed").success());

        let lock = acquire(directory.path()).expect("lock was not released after child death");
        assert_eq!(
            lock.read_intent().expect("intent read failed"),
            Some(SupervisorIntent {
                task_id: Uuid::from_u128(1),
                operation_id: Uuid::from_u128(2),
                attempt: 1,
                fencing_token: 3,
            })
        );
        assert_eq!(
            lock.persist_intent(SupervisorIntent {
                task_id: Uuid::from_u128(1),
                operation_id: Uuid::from_u128(2),
                attempt: 1,
                fencing_token: 3,
            }),
            Err(SupervisorLockError::IntentAlreadyExists)
        );
        assert_eq!(
            lock.persist_intent(SupervisorIntent {
                task_id: Uuid::from_u128(4),
                operation_id: Uuid::from_u128(5),
                attempt: 0,
                fencing_token: 6,
            }),
            Err(SupervisorLockError::IntentAlreadyExists)
        );
        assert_eq!(
            fs::metadata(directory.path().join(INTENT_FILE))
                .unwrap()
                .len(),
            52
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_symlinked_or_preexisting_intent_without_overwriting() {
        let directory = TempDir::new();
        let target = directory.path().join("target");
        fs::write(&target, b"keep").expect("test target write failed");
        let lock = acquire(directory.path()).expect("lock acquisition failed");
        symlink(&target, directory.path().join(INTENT_FILE))
            .expect("intent symlink creation failed");
        assert_eq!(
            lock.persist_intent(SupervisorIntent {
                task_id: Uuid::from_u128(1),
                operation_id: Uuid::from_u128(2),
                attempt: 0,
                fencing_token: 1,
            }),
            Err(SupervisorLockError::UnsafeIntentFile)
        );
        assert_eq!(fs::read(target).unwrap(), b"keep");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_invalid_intent_before_creating_the_marker() {
        let directory = TempDir::new();
        let lock = acquire(directory.path()).expect("lock acquisition failed");
        assert_eq!(
            lock.persist_intent(SupervisorIntent {
                task_id: Uuid::nil(),
                operation_id: Uuid::from_u128(2),
                attempt: 0,
                fencing_token: 0,
            }),
            Err(SupervisorLockError::InvalidIntent)
        );
        assert!(!directory.path().join(INTENT_FILE).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_intent_rejects_malformed_and_oversized_records() {
        let mut valid = Vec::from(*INTENT_MAGIC);
        valid.extend_from_slice(Uuid::from_u128(1).as_bytes());
        valid.extend_from_slice(Uuid::from_u128(2).as_bytes());
        valid.extend_from_slice(&1_u32.to_be_bytes());
        valid.extend_from_slice(&3_u64.to_be_bytes());
        assert_eq!(valid.len(), INTENT_BYTES);

        let mut bad_magic = valid.clone();
        bad_magic[0] = b'X';
        let mut nil_task = valid.clone();
        nil_task[8..24].fill(0);
        let mut zero_fence = valid.clone();
        zero_fence[44..52].fill(0);
        let mut oversized = valid.clone();
        oversized.push(0);

        for bytes in [bad_magic, nil_task, zero_fence, vec![0; 4], oversized] {
            let directory = TempDir::new();
            let path = directory.path().join(INTENT_FILE);
            fs::write(&path, bytes).expect("test intent write failed");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("test intent chmod failed");
            let lock = acquire(directory.path()).expect("lock acquisition failed");
            assert_eq!(
                lock.read_intent(),
                Err(SupervisorLockError::InvalidIntentRecord)
            );
            assert!(path.exists(), "read must not remove an unresolved marker");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_intent_returns_none_without_authorizing_or_mutating_directory() {
        let directory = TempDir::new();
        let lock = acquire(directory.path()).expect("lock acquisition failed");
        assert_eq!(lock.read_intent(), Ok(None));
        assert!(!directory.path().join(INTENT_FILE).exists());
    }

    #[test]
    fn serializes_processes_and_releases_after_process_death() {
        let directory = TempDir::new();
        let mut holder = ChildGuard(run_child(directory.path(), "hold"));
        let ready = directory.path().join("holder-ready");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ready.exists() && std::time::Instant::now() < deadline {
            if holder
                .try_wait()
                .expect("checking child process failed")
                .is_some()
            {
                panic!("child process exited before acquiring the lock");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            ready.exists(),
            "child process did not acquire the lock in time"
        );

        let mut contender = ChildGuard(run_child(directory.path(), "contend"));
        assert!(
            contender
                .wait()
                .expect("waiting for contender failed")
                .success()
        );
        holder
            .kill()
            .expect("could not stop lock holder test process");
        assert!(!holder.wait().expect("waiting for holder failed").success());
        let _lock = acquire(directory.path()).expect("lock was not released after process death");
    }

    #[test]
    fn rejects_symlinks_and_permissive_files() {
        let directory = TempDir::new();
        let target = directory.path().join("target");
        create_lock_file(&target, 0o600);
        let link_dir = TempDir::new();
        symlink(&target, link_dir.path().join(LOCK_FILE)).expect("symlink creation failed");
        assert_eq!(
            acquire(link_dir.path()).err(),
            Some(SupervisorLockError::UnsafeLockFile)
        );

        let permissive_dir = TempDir::new();
        create_lock_file(&permissive_dir.path().join(LOCK_FILE), 0o644);
        assert_eq!(
            acquire(permissive_dir.path()).err(),
            Some(SupervisorLockError::UnsafeLockFile)
        );

        let permissive_directory = TempDir::new();
        fs::set_permissions(
            permissive_directory.path(),
            fs::Permissions::from_mode(0o755),
        )
        .expect("test directory chmod failed");
        assert_eq!(
            acquire(permissive_directory.path()).err(),
            Some(SupervisorLockError::UnsafeDirectory)
        );
    }

    #[test]
    fn rejects_wrong_owner_and_hard_links() {
        let directory = TempDir::new();
        let metadata = fs::metadata(directory.path()).expect("test metadata missing");
        assert_eq!(
            validate_directory(&metadata, metadata.uid().wrapping_add(1)),
            Err(SupervisorLockError::UnsafeDirectory)
        );

        let file = directory.path().join(LOCK_FILE);
        create_lock_file(&file, 0o600);
        fs::hard_link(&file, directory.path().join("second-link"))
            .expect("test hard link creation failed");
        assert_eq!(
            acquire(directory.path()).err(),
            Some(SupervisorLockError::UnsafeLockFile)
        );
    }
}

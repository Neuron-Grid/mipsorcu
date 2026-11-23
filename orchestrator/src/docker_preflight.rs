//! Read-only preflight for an operator-selected rootless Docker daemon.
//!
//! This checks daemon-reported capabilities only. It does not prove that cgroup
//! controllers are delegated or that resource limits are enforced.

use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use serde::Deserialize;
#[cfg(target_os = "linux")]
use serde::{
    Deserializer,
    de::{MapAccess, Visitor},
};
#[cfg(target_os = "linux")]
use std::fmt;

use crate::supervisor_lock::SupervisorIntent;

const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_INFO_BYTES: usize = 128 * 1024;
#[cfg(target_os = "linux")]
const MAX_CONTAINER_INSPECT_BYTES: usize = 128 * 1024;
#[cfg(target_os = "linux")]
const MAX_CONTAINER_LIST_BYTES: usize = 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_INTENT_CONTAINERS: usize = 100;
pub const INTENT_TASK_LABEL: &str = "io.mipsorcu.supervisor.task-id";
pub const INTENT_OPERATION_LABEL: &str = "io.mipsorcu.supervisor.operation-id";
pub const INTENT_ATTEMPT_LABEL: &str = "io.mipsorcu.supervisor.attempt";
pub const INTENT_FENCING_LABEL: &str = "io.mipsorcu.supervisor.fencing-token";
const DOCKER_INFO_FORMAT: &str = concat!(
    "{\"OSType\":{{json .OSType}},",
    "\"SecurityOptions\":{{json .SecurityOptions}},",
    "\"CgroupDriver\":{{json .CgroupDriver}},",
    "\"CgroupVersion\":{{json .CgroupVersion}},",
    "\"MemoryLimit\":{{json .MemoryLimit}},",
    "\"PidsLimit\":{{json .PidsLimit}},",
    "\"CPUCfsPeriod\":{{json .CPUCfsPeriod}},",
    "\"CPUCfsQuota\":{{json .CPUCfsQuota}}}"
);
static PREFLIGHT_RUNNING: AtomicBool = AtomicBool::new(false);

/// A non-sensitive classification for failures in the Docker preflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerPreflightError {
    InvalidSocket,
    InvalidBinary,
    AlreadyRunning,
    UnsupportedPlatform,
    SpawnFailed,
    Timeout,
    OutputLimit,
    Io,
    CommandFailed,
    InvalidInfo,
    TerminationUnconfirmed,
    /// The requested container could not be observed; its state is ambiguous.
    ContainerUnknown,
    /// The daemon's inspect response did not match the requested container.
    ContainerMismatch,
    /// The requested container ID was not a full lowercase hexadecimal ID.
    InvalidContainerId,
    /// The supplied durable operation identity was invalid.
    InvalidIntent,
    /// More than one container matched the durable operation identity.
    AmbiguousIntentContainers,
}

/// Minimal read-only container state returned by Docker inspect.
///
/// `running` follows Docker's `State.Running` field (which also remains true for
/// paused containers). This observation is not proof that every process
/// associated with a prior operation has stopped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerContainerState {
    id: String,
    running: bool,
}

impl DockerContainerState {
    /// Full container ID returned by inspect after the requested ID matched.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Docker's `State.Running` observation. This is not descendant-stop proof.
    pub(crate) fn running(&self) -> bool {
        self.running
    }
}

/// Lists the single container observation associated with an unresolved intent.
///
/// `None` means only that this daemon returned no matching container twice. It
/// does not prove that a container does not exist, that a process stopped, or
/// that an operation may be retried. Any ambiguity fails closed.
pub async fn observe_docker_intent(
    daemon_socket: &Path,
    intent: &SupervisorIntent,
) -> Result<Option<DockerContainerState>, DockerPreflightError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (daemon_socket, intent);
        Err(DockerPreflightError::UnsupportedPlatform)
    }
    #[cfg(target_os = "linux")]
    {
        observe_docker_intent_linux(daemon_socket, intent).await
    }
}

/// Build the exact user-label set used to associate a container with an intent.
/// It is metadata only and does not authorize starting, stopping, or replaying it.
pub fn docker_intent_labels(
    intent: &SupervisorIntent,
) -> Result<BTreeMap<String, String>, DockerPreflightError> {
    validate_intent(intent)?;
    Ok([
        (INTENT_TASK_LABEL.to_owned(), intent.task_id.to_string()),
        (
            INTENT_OPERATION_LABEL.to_owned(),
            intent.operation_id.to_string(),
        ),
        (INTENT_ATTEMPT_LABEL.to_owned(), intent.attempt.to_string()),
        (
            INTENT_FENCING_LABEL.to_owned(),
            intent.fencing_token.to_string(),
        ),
    ]
    .into_iter()
    .collect())
}

fn validate_intent(intent: &SupervisorIntent) -> Result<(), DockerPreflightError> {
    if intent.task_id.is_nil()
        || intent.operation_id.is_nil()
        || intent.attempt > 3
        || intent.fencing_token == 0
    {
        return Err(DockerPreflightError::InvalidIntent);
    }
    Ok(())
}

#[derive(Deserialize)]
struct DaemonInfo {
    #[serde(rename = "OSType")]
    os_type: String,
    #[serde(rename = "SecurityOptions")]
    security_options: Vec<String>,
    #[serde(rename = "CgroupDriver")]
    cgroup_driver: String,
    #[serde(rename = "CgroupVersion")]
    cgroup_version: String,
    #[serde(rename = "MemoryLimit")]
    memory_limit: bool,
    #[serde(rename = "PidsLimit")]
    pids_limit: bool,
    #[serde(rename = "CPUCfsPeriod")]
    cpu_cfs_period: bool,
    #[serde(rename = "CPUCfsQuota")]
    cpu_cfs_quota: bool,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
struct DockerApiInfo {
    #[serde(rename = "OSType")]
    os_type: String,
    #[serde(rename = "SecurityOptions")]
    security_options: Vec<String>,
    #[serde(rename = "CgroupDriver")]
    cgroup_driver: String,
    #[serde(rename = "CgroupVersion")]
    cgroup_version: String,
    #[serde(rename = "MemoryLimit")]
    memory_limit: bool,
    #[serde(rename = "PidsLimit")]
    pids_limit: bool,
    #[serde(rename = "CpuCfsPeriod")]
    cpu_cfs_period: bool,
    #[serde(rename = "CpuCfsQuota")]
    cpu_cfs_quota: bool,
}

/// Synchronously checks one explicitly selected Docker CLI and Unix daemon socket.
/// The caller must keep the trusted CLI, its ancestors, the socket, and its ancestor
/// directories stable through this check and any later operation, and reuse that same
/// trusted target for later daemon calls. This check does not authenticate the daemon,
/// prove process-tree termination, or inspect effective cgroup limits. An ambiguous
/// I/O, timeout, or output-limit failure permanently closes this process's preflight gate;
/// after a process restart, the caller must independently establish that the earlier CLI
/// process tree stopped before retrying.
/// Only Linux is supported: on other Unix platforms the socket-pair descriptors may
/// be inherited by concurrently spawned processes before close-on-exec is set.
pub fn check_rootless_docker(
    docker_binary: &Path,
    daemon_socket: &Path,
) -> Result<(), DockerPreflightError> {
    if !cfg!(target_os = "linux") {
        return Err(DockerPreflightError::UnsupportedPlatform);
    }
    if PREFLIGHT_RUNNING
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(DockerPreflightError::AlreadyRunning);
    }
    let permit = PreflightPermit;

    validate_docker_binary(docker_binary)?;
    validate_socket(daemon_socket)?;

    #[cfg(unix)]
    {
        run_info(docker_binary, daemon_socket, permit)
    }
    #[cfg(not(unix))]
    {
        let _ = (docker_binary, daemon_socket, permit);
        Err(DockerPreflightError::UnsupportedPlatform)
    }
}

/// Checks one explicitly selected rootless Docker daemon through its Unix socket.
/// Only Linux is supported. The socket and its parent directories must remain
/// operator-controlled through this check and later use of the same target.
/// This checks daemon reports only; it does not authenticate the daemon, prove
/// effective cgroup limits, or authorize a container to run. Since this request
/// only reads data and starts no CLI, cancelling it releases the shared gate.
pub async fn check_rootless_docker_socket(
    daemon_socket: &Path,
) -> Result<(), DockerPreflightError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = daemon_socket;
        Err(DockerPreflightError::UnsupportedPlatform)
    }
    #[cfg(target_os = "linux")]
    {
        check_rootless_docker_socket_linux(daemon_socket).await
    }
}

/// Reads a container's identity and running flag from an explicitly selected
/// Docker Unix socket. Requires a complete 64-character hexadecimal ID and
/// never follows redirects or retries. The result is an observation only: it
/// does not authenticate the daemon, prove rootless isolation or resource
/// enforcement, authorize execution, or prove that a process tree stopped.
pub async fn inspect_docker_container(
    daemon_socket: &Path,
    container_id: &str,
) -> Result<DockerContainerState, DockerPreflightError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (daemon_socket, container_id);
        Err(DockerPreflightError::UnsupportedPlatform)
    }
    #[cfg(target_os = "linux")]
    {
        inspect_docker_container_linux(daemon_socket, container_id).await
    }
}

#[cfg(target_os = "linux")]
async fn observe_docker_intent_linux(
    daemon_socket: &Path,
    intent: &SupervisorIntent,
) -> Result<Option<DockerContainerState>, DockerPreflightError> {
    validate_intent(intent)?;
    if PREFLIGHT_RUNNING
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(DockerPreflightError::AlreadyRunning);
    }
    let _permit = PreflightPermit;
    validate_socket(daemon_socket)?;

    let first = list_intent_containers(daemon_socket, intent).await?;
    let state = match first.as_slice() {
        [] => None,
        [container] => {
            let inspected = inspect_intent_container(daemon_socket, &container.id, intent).await?;
            if inspected.id != container.id
                || inspected.labels != container.labels
                || inspected.status != container.status
            {
                return Err(DockerPreflightError::ContainerMismatch);
            }
            Some(DockerContainerState {
                id: inspected.id,
                running: inspected.running,
            })
        }
        _ => return Err(DockerPreflightError::AmbiguousIntentContainers),
    };

    let final_list = list_intent_containers(daemon_socket, intent).await?;
    if first != final_list {
        return Err(DockerPreflightError::ContainerMismatch);
    }
    Ok(state)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct IntentContainer {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Labels", deserialize_with = "deserialize_unique_labels")]
    labels: BTreeMap<String, String>,
    #[serde(rename = "State")]
    status: String,
}

#[cfg(target_os = "linux")]
async fn list_intent_containers(
    daemon_socket: &Path,
    intent: &SupervisorIntent,
) -> Result<Vec<IntentContainer>, DockerPreflightError> {
    let expected = docker_intent_labels(intent)?;
    let filters = serde_json::json!({
        "label": [format!("{}={}", INTENT_OPERATION_LABEL, intent.operation_id)]
    });
    let mut url = reqwest::Url::parse("http://localhost/containers/json")
        .map_err(|_| DockerPreflightError::InvalidInfo)?;
    url.query_pairs_mut()
        .append_pair("all", "1")
        .append_pair("filters", &filters.to_string());
    let path = url
        .query()
        .map(|query| format!("{}?{query}", url.path()))
        .ok_or(DockerPreflightError::InvalidInfo)?;
    let (status, body) = docker_api_get(
        daemon_socket,
        &path,
        MAX_CONTAINER_LIST_BYTES,
        DockerPreflightError::InvalidInfo,
    )
    .await?;
    if status != reqwest::StatusCode::OK {
        return Err(DockerPreflightError::CommandFailed);
    }
    let containers: Vec<IntentContainer> =
        serde_json::from_slice(&body).map_err(|_| DockerPreflightError::InvalidInfo)?;
    if containers.len() > MAX_INTENT_CONTAINERS {
        return Err(DockerPreflightError::OutputLimit);
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut validated = Vec::with_capacity(containers.len());
    for container in containers {
        if !valid_container_id(&container.id) || !ids.insert(container.id.clone()) {
            return Err(DockerPreflightError::ContainerMismatch);
        }
        if !matches!(
            container.status.as_str(),
            "created" | "restarting" | "running" | "paused" | "exited" | "dead" | "removing"
        ) {
            return Err(DockerPreflightError::ContainerMismatch);
        }
        if !contains_intent_labels(&container.labels, &expected) {
            return Err(DockerPreflightError::ContainerMismatch);
        }
        validated.push(container);
    }
    Ok(validated)
}

#[cfg(target_os = "linux")]
fn valid_container_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(target_os = "linux")]
fn contains_intent_labels(
    labels: &BTreeMap<String, String>,
    intent_labels: &BTreeMap<String, String>,
) -> bool {
    intent_labels
        .iter()
        .all(|(key, value)| labels.get(key) == Some(value))
}

#[cfg(target_os = "linux")]
fn deserialize_unique_labels<'de, D>(deserializer: D) -> Result<BTreeMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct UniqueLabels;

    impl<'de> Visitor<'de> for UniqueLabels {
        type Value = BTreeMap<String, String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map with unique string labels")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut labels = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                if labels.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate label"));
                }
            }
            Ok(labels)
        }
    }

    deserializer.deserialize_map(UniqueLabels)
}

#[cfg(target_os = "linux")]
async fn inspect_intent_container(
    daemon_socket: &Path,
    container_id: &str,
    intent: &SupervisorIntent,
) -> Result<InspectedIntentContainer, DockerPreflightError> {
    let (status, body) = docker_api_get(
        daemon_socket,
        &format!("/containers/{container_id}/json"),
        MAX_CONTAINER_INSPECT_BYTES,
        DockerPreflightError::InvalidInfo,
    )
    .await?;
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(DockerPreflightError::ContainerUnknown);
    }
    if status != reqwest::StatusCode::OK {
        return Err(DockerPreflightError::CommandFailed);
    }
    let inspect: IntentContainerInspect =
        serde_json::from_slice(&body).map_err(|_| DockerPreflightError::InvalidInfo)?;
    let expected = docker_intent_labels(intent)?;
    if !valid_container_id(&inspect.id)
        || inspect.id != container_id
        || !contains_intent_labels(&inspect.config.labels, &expected)
        || inspect.state.status.is_empty()
    {
        return Err(DockerPreflightError::ContainerMismatch);
    }
    Ok(InspectedIntentContainer {
        id: inspect.id,
        labels: inspect.config.labels,
        running: inspect.state.running,
        status: inspect.state.status,
    })
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
struct IntentContainerInspect {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Config")]
    config: IntentContainerConfig,
    #[serde(rename = "State")]
    state: IntentContainerInspectState,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
struct IntentContainerConfig {
    #[serde(rename = "Labels", deserialize_with = "deserialize_unique_labels")]
    labels: BTreeMap<String, String>,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
struct IntentContainerInspectState {
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "Status")]
    status: String,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct InspectedIntentContainer {
    id: String,
    labels: BTreeMap<String, String>,
    running: bool,
    status: String,
}

#[cfg(target_os = "linux")]
async fn inspect_docker_container_linux(
    daemon_socket: &Path,
    container_id: &str,
) -> Result<DockerContainerState, DockerPreflightError> {
    if container_id.len() != 64
        || !container_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DockerPreflightError::InvalidContainerId);
    }
    if PREFLIGHT_RUNNING
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(DockerPreflightError::AlreadyRunning);
    }
    let _permit = PreflightPermit;
    validate_socket(daemon_socket)?;

    let (status, body) = docker_api_get(
        daemon_socket,
        &format!("/containers/{container_id}/json"),
        MAX_CONTAINER_INSPECT_BYTES,
        DockerPreflightError::InvalidInfo,
    )
    .await?;
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(DockerPreflightError::ContainerUnknown);
    }
    if status != reqwest::StatusCode::OK {
        return Err(DockerPreflightError::CommandFailed);
    }
    let inspect: ContainerInspect =
        serde_json::from_slice(&body).map_err(|_| DockerPreflightError::InvalidInfo)?;
    if inspect.id != container_id {
        return Err(DockerPreflightError::ContainerMismatch);
    }
    Ok(DockerContainerState {
        id: inspect.id,
        running: inspect.state.running,
    })
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
struct ContainerInspect {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "State")]
    state: ContainerInspectState,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
struct ContainerInspectState {
    #[serde(rename = "Running")]
    running: bool,
}

#[cfg(target_os = "linux")]
async fn docker_api_get(
    daemon_socket: &Path,
    path: &str,
    max_body_bytes: usize,
    malformed_length: DockerPreflightError,
) -> Result<(reqwest::StatusCode, Vec<u8>), DockerPreflightError> {
    use reqwest::{
        Client,
        header::{ACCEPT, CONTENT_LENGTH},
        redirect::Policy,
        retry,
    };

    let client = Client::builder()
        .http1_only()
        .redirect(Policy::none())
        .retry(retry::never())
        .connect_timeout(PREFLIGHT_TIMEOUT)
        .timeout(PREFLIGHT_TIMEOUT)
        .unix_socket(daemon_socket)
        .no_proxy()
        .build()
        .map_err(|_| DockerPreflightError::Io)?;
    let url = format!("http://localhost{path}");
    let request = async {
        let mut response = client
            .get(url)
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(map_reqwest_error)?;
        let status = response.status();
        if status != reqwest::StatusCode::OK {
            return Ok((status, Vec::new()));
        }
        if let Some(content_length) = response.headers().get(CONTENT_LENGTH) {
            let content_length = content_length
                .to_str()
                .map_err(|_| malformed_length)?
                .parse::<u64>()
                .map_err(|_| malformed_length)?;
            if content_length > max_body_bytes as u64 {
                return Err(DockerPreflightError::OutputLimit);
            }
        }
        let mut body = Vec::with_capacity(max_body_bytes.min(16 * 1024));
        while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
            if chunk.len() > max_body_bytes.saturating_sub(body.len()) {
                return Err(DockerPreflightError::OutputLimit);
            }
            body.extend_from_slice(&chunk);
        }
        Ok((status, body))
    };
    tokio::time::timeout(PREFLIGHT_TIMEOUT, request)
        .await
        .map_err(|_| DockerPreflightError::Timeout)?
}

#[cfg(target_os = "linux")]
async fn check_rootless_docker_socket_linux(
    daemon_socket: &Path,
) -> Result<(), DockerPreflightError> {
    if PREFLIGHT_RUNNING
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(DockerPreflightError::AlreadyRunning);
    }
    let _permit = PreflightPermit;
    validate_socket(daemon_socket)?;

    let (status, body) = docker_api_get(
        daemon_socket,
        "/info",
        MAX_INFO_BYTES,
        DockerPreflightError::Io,
    )
    .await?;
    if status != reqwest::StatusCode::OK {
        return Err(DockerPreflightError::CommandFailed);
    }
    parse_api_info(&body)
}

#[cfg(target_os = "linux")]
fn map_reqwest_error(error: reqwest::Error) -> DockerPreflightError {
    if error.is_timeout() {
        DockerPreflightError::Timeout
    } else {
        DockerPreflightError::Io
    }
}

struct PreflightPermit;

impl Drop for PreflightPermit {
    fn drop(&mut self) {
        PREFLIGHT_RUNNING.store(false, Ordering::Release);
    }
}

fn validate_docker_binary(path: &Path) -> Result<(), DockerPreflightError> {
    if !path.is_absolute() {
        return Err(DockerPreflightError::InvalidBinary);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| DockerPreflightError::InvalidBinary)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DockerPreflightError::InvalidBinary);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(DockerPreflightError::InvalidBinary);
        }
    }
    Ok(())
}

fn validate_socket(path: &Path) -> Result<(), DockerPreflightError> {
    if !path.is_absolute() {
        return Err(DockerPreflightError::InvalidSocket);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let metadata =
            fs::symlink_metadata(path).map_err(|_| DockerPreflightError::InvalidSocket)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            return Err(DockerPreflightError::InvalidSocket);
        }
        if path
            .to_str()
            .is_none_or(|value| value.contains(['\0', '\n', '\r']))
        {
            return Err(DockerPreflightError::InvalidSocket);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(DockerPreflightError::UnsupportedPlatform)
    }
}

fn parse_info(json: &[u8]) -> Result<(), DockerPreflightError> {
    let info: DaemonInfo =
        serde_json::from_slice(json).map_err(|_| DockerPreflightError::InvalidInfo)?;
    validate_info(info)
}

#[cfg(target_os = "linux")]
fn parse_api_info(json: &[u8]) -> Result<(), DockerPreflightError> {
    let api_info: DockerApiInfo =
        serde_json::from_slice(json).map_err(|_| DockerPreflightError::InvalidInfo)?;
    validate_info(DaemonInfo {
        os_type: api_info.os_type,
        security_options: api_info.security_options,
        cgroup_driver: api_info.cgroup_driver,
        cgroup_version: api_info.cgroup_version,
        memory_limit: api_info.memory_limit,
        pids_limit: api_info.pids_limit,
        cpu_cfs_period: api_info.cpu_cfs_period,
        cpu_cfs_quota: api_info.cpu_cfs_quota,
    })
}

fn validate_info(info: DaemonInfo) -> Result<(), DockerPreflightError> {
    let rootless = info
        .security_options
        .iter()
        .any(|option| option == "name=rootless");
    if info.os_type == "linux"
        && rootless
        && info.cgroup_driver == "systemd"
        && info.cgroup_version == "2"
        && info.memory_limit
        && info.pids_limit
        && info.cpu_cfs_period
        && info.cpu_cfs_quota
    {
        Ok(())
    } else {
        Err(DockerPreflightError::InvalidInfo)
    }
}

#[cfg(unix)]
fn run_info(
    docker_binary: &Path,
    daemon_socket: &Path,
    permit: PreflightPermit,
) -> Result<(), DockerPreflightError> {
    use std::os::{fd::OwnedFd, unix::net::UnixStream};

    let socket = daemon_socket
        .to_str()
        .ok_or(DockerPreflightError::InvalidSocket)?;
    let (mut stdout, child_stdout) = UnixStream::pair().map_err(|_| DockerPreflightError::Io)?;
    let (mut stderr, child_stderr) = UnixStream::pair().map_err(|_| DockerPreflightError::Io)?;
    stdout
        .set_nonblocking(true)
        .map_err(|_| DockerPreflightError::Io)?;
    stderr
        .set_nonblocking(true)
        .map_err(|_| DockerPreflightError::Io)?;

    let mut command = Command::new(docker_binary);
    // A non-directory config path keeps Docker from loading ambient credentials or contexts.
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(child_stdout)))
        .stderr(Stdio::from(OwnedFd::from(child_stderr)))
        .arg("--config")
        .arg("/dev/null")
        .arg("--host")
        .arg(format!("unix://{socket}"))
        .arg("info")
        .arg("--format")
        .arg(DOCKER_INFO_FORMAT);
    let mut child = command
        .spawn()
        .map_err(|_| DockerPreflightError::SpawnFailed)?;
    drop(command);

    let result = drain_child(&mut child, &mut stdout, &mut stderr);
    if matches!(
        &result,
        Err(DockerPreflightError::Timeout
            | DockerPreflightError::OutputLimit
            | DockerPreflightError::Io
            | DockerPreflightError::TerminationUnconfirmed)
    ) {
        // Reaping the CLI does not prove that descendants released its pipes or stopped.
        std::mem::forget(permit);
    } else {
        drop(permit);
    }
    let (status, output) = result?;
    if !status.success() {
        return Err(DockerPreflightError::CommandFailed);
    }
    parse_info(&output)
}

#[cfg(unix)]
fn drain_child(
    child: &mut Child,
    stdout: &mut std::os::unix::net::UnixStream,
    stderr: &mut std::os::unix::net::UnixStream,
) -> Result<(std::process::ExitStatus, Vec<u8>), DockerPreflightError> {
    let deadline = Instant::now() + PREFLIGHT_TIMEOUT;
    let mut output = Vec::with_capacity(MAX_INFO_BYTES.min(16 * 1024));
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut status = None;
    let mut buffer = [0u8; 8 * 1024];

    loop {
        if Instant::now() >= deadline {
            stop_child(child)?;
            return Err(DockerPreflightError::Timeout);
        }

        let mut progressed = false;
        if !stdout_eof {
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    stdout_eof = true;
                    progressed = true;
                }
                Ok(count) => {
                    if count > MAX_INFO_BYTES.saturating_sub(output.len()) {
                        stop_child(child)?;
                        return Err(DockerPreflightError::OutputLimit);
                    }
                    output.extend_from_slice(&buffer[..count]);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    stop_child(child)?;
                    return Err(DockerPreflightError::Io);
                }
            }
        }
        if !stderr_eof {
            match stderr.read(&mut buffer) {
                Ok(0) => {
                    stderr_eof = true;
                    progressed = true;
                }
                Ok(_) => progressed = true,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    stop_child(child)?;
                    return Err(DockerPreflightError::Io);
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
                    stop_child(child)?;
                    return Err(DockerPreflightError::Io);
                }
            }
        }
        if status.is_some() && stdout_eof && stderr_eof {
            return status
                .map(|status| (status, output))
                .ok_or(DockerPreflightError::Io);
        }
        if !progressed {
            thread::sleep(Duration::from_millis(2));
        }
    }
}

#[cfg(unix)]
fn stop_child(child: &mut Child) -> Result<(), DockerPreflightError> {
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            _ => return Err(DockerPreflightError::TerminationUnconfirmed),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs,
        os::unix::{fs::symlink, net::UnixListener},
        path::{Path, PathBuf},
    };

    #[cfg(target_os = "linux")]
    use std::{
        io::{BufRead, BufReader, Write},
        process::{Command, Stdio},
        sync::{Arc, atomic::AtomicBool},
        thread,
        time::{Duration, Instant},
    };

    #[cfg(target_os = "linux")]
    use super::parse_api_info;
    use super::{
        DockerPreflightError, check_rootless_docker, check_rootless_docker_socket, parse_info,
        validate_socket,
    };

    const GOOD_INFO: &str = r#"{"OSType":"linux","SecurityOptions":["name=seccomp","name=rootless"],"CgroupDriver":"systemd","CgroupVersion":"2","MemoryLimit":true,"PidsLimit":true,"CPUCfsPeriod":true,"CPUCfsQuota":true}"#;
    #[cfg(target_os = "linux")]
    const GOOD_API_INFO: &str = r#"{"OSType":"linux","SecurityOptions":["name=seccomp","name=rootless"],"CgroupDriver":"systemd","CgroupVersion":"2","MemoryLimit":true,"PidsLimit":true,"CpuCfsPeriod":true,"CpuCfsQuota":true}"#;
    #[cfg(target_os = "linux")]
    const EXPECTED_INFO_FORMAT: &str = r#"{"OSType":{{json .OSType}},"SecurityOptions":{{json .SecurityOptions}},"CgroupDriver":{{json .CgroupDriver}},"CgroupVersion":{{json .CgroupVersion}},"MemoryLimit":{{json .MemoryLimit}},"PidsLimit":{{json .PidsLimit}},"CPUCfsPeriod":{{json .CPUCfsPeriod}},"CPUCfsQuota":{{json .CPUCfsQuota}}}"#;
    #[cfg(target_os = "linux")]
    const CHILD_CASE_ENV: &str = "MIPSORCU_PREFLIGHT_TEST_CHILD";

    fn temp_path(name: &str) -> PathBuf {
        PathBuf::from("/tmp").join(format!("mpf-{name}-{}", uuid::Uuid::new_v4()))
    }

    #[cfg(target_os = "linux")]
    fn socket_http_fixture(
        response: Vec<u8>,
        response_delay: Duration,
    ) -> (
        PathBuf,
        Arc<AtomicBool>,
        thread::JoinHandle<(String, Vec<String>, usize)>,
    ) {
        let socket = temp_path("http-fixture");
        let listener = UnixListener::bind(&socket).unwrap();
        let received = Arc::new(AtomicBool::new(false));
        let received_by_server = received.clone();
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut headers = Vec::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                headers.push(line.trim_end().to_owned());
            }
            drop(reader);
            received_by_server.store(true, std::sync::atomic::Ordering::Release);
            thread::sleep(response_delay);
            let _ = stream.write_all(&response);
            drop(stream);

            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_millis(200);
            let mut extra_requests = 0;
            while Instant::now() < deadline {
                match listener.accept() {
                    Ok((stream, _)) => {
                        extra_requests += 1;
                        drop(stream);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            (request_line, headers, extra_requests)
        });
        (socket, received, thread)
    }

    #[cfg(target_os = "linux")]
    fn http_response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut response =
            format!("HTTP/1.1 {status}\r\n{headers}Connection: close\r\n\r\n").into_bytes();
        response.extend_from_slice(body);
        response
    }

    #[cfg(target_os = "linux")]
    fn socket_http_sequence_fixture(
        responses: Vec<(String, String)>,
    ) -> (PathBuf, thread::JoinHandle<Vec<String>>) {
        let socket = temp_path("http-sequence");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let thread = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let deadline = Instant::now() + Duration::from_secs(5);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "fake daemon request timed out");
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("fake daemon accept failed: {error}"),
                    }
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some(length) = line.to_ascii_lowercase().strip_prefix("content-length:")
                    {
                        content_length = length.trim().parse().unwrap();
                    }
                }
                let mut request_body = vec![0; content_length];
                std::io::Read::read_exact(&mut reader, &mut request_body).unwrap();
                requests.push(request_line.trim_end().to_owned());
                stream
                    .write_all(&http_response(
                        &status,
                        &format!(
                            "Content-Type: application/json\r\nContent-Length: {}\r\n",
                            body.len()
                        ),
                        body.as_bytes(),
                    ))
                    .unwrap();
            }
            requests
        });
        (socket, thread)
    }

    #[cfg(target_os = "linux")]
    fn run_socket_preflight_case(case: &str) {
        if case == "socket-gate" {
            super::PREFLIGHT_RUNNING.store(true, std::sync::atomic::Ordering::Release);
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(check_rootless_docker_socket(Path::new("/missing/socket")));
            assert_eq!(result, Err(DockerPreflightError::AlreadyRunning));
            return;
        }

        let (response, delay, expected) = match case {
            "socket-valid" => {
                let body = GOOD_API_INFO.as_bytes();
                (
                    http_response(
                        "200 OK",
                        &format!(
                            "Content-Type: application/json\r\nContent-Length: {}\r\n",
                            body.len()
                        ),
                        body,
                    ),
                    Duration::ZERO,
                    Ok(()),
                )
            }
            "socket-invalid" => (
                http_response(
                    "200 OK",
                    "Content-Type: application/json\r\nContent-Length: 8\r\n",
                    b"not json",
                ),
                Duration::ZERO,
                Err(DockerPreflightError::InvalidInfo),
            ),
            "socket-redirect" => (
                http_response(
                    "302 Found",
                    "Location: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\n",
                    b"",
                ),
                Duration::ZERO,
                Err(DockerPreflightError::CommandFailed),
            ),
            "socket-content-length-limit" => (
                http_response(
                    "200 OK",
                    &format!(
                        "Content-Type: application/json\r\nContent-Length: {}\r\n",
                        super::MAX_INFO_BYTES + 1
                    ),
                    b"",
                ),
                Duration::ZERO,
                Err(DockerPreflightError::OutputLimit),
            ),
            "socket-stream-limit" => {
                let body = vec![b'x'; super::MAX_INFO_BYTES + 1];
                let mut response =
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                        .to_vec();
                for chunk in body.chunks(16 * 1024) {
                    response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                    response.extend_from_slice(chunk);
                    response.extend_from_slice(b"\r\n");
                }
                response.extend_from_slice(b"0\r\n\r\n");
                (
                    response,
                    Duration::ZERO,
                    Err(DockerPreflightError::OutputLimit),
                )
            }
            "socket-timeout" => {
                let body = GOOD_INFO.as_bytes();
                (
                    http_response(
                        "200 OK",
                        &format!(
                            "Content-Type: application/json\r\nContent-Length: {}\r\n",
                            body.len()
                        ),
                        body,
                    ),
                    super::PREFLIGHT_TIMEOUT + Duration::from_millis(100),
                    Err(DockerPreflightError::Timeout),
                )
            }
            "socket-cancel" => {
                let body = GOOD_API_INFO.as_bytes();
                (
                    http_response(
                        "200 OK",
                        &format!("Content-Length: {}\r\n", body.len()),
                        body,
                    ),
                    Duration::from_secs(3),
                    Err(DockerPreflightError::Timeout),
                )
            }
            _ => panic!("unknown socket preflight case"),
        };

        let (socket, received, server) = socket_http_fixture(response, delay);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            if case == "socket-cancel" {
                let socket_for_task = socket.clone();
                let pending =
                    tokio::spawn(
                        async move { check_rootless_docker_socket(&socket_for_task).await },
                    );
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !received.load(std::sync::atomic::Ordering::Acquire) {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .expect("fake daemon must receive the request before cancellation");
                pending.abort();
                assert!(pending.await.unwrap_err().is_cancelled());
                assert_eq!(
                    check_rootless_docker_socket(Path::new("/missing/socket")).await,
                    Err(DockerPreflightError::InvalidSocket)
                );
                Err(DockerPreflightError::Timeout)
            } else {
                check_rootless_docker_socket(&socket).await
            }
        });
        let (request_line, headers, extra_requests) = server.join().unwrap();
        fs::remove_file(socket).unwrap();

        assert_eq!(result, expected);
        assert_eq!(request_line, "GET /info HTTP/1.1\r\n");
        assert!(
            headers
                .iter()
                .any(|header| header.eq_ignore_ascii_case("host: localhost"))
        );
        assert!(
            !headers
                .iter()
                .any(|header| header.to_ascii_lowercase().starts_with("authorization:"))
        );
        assert!(!headers.iter().any(|header| {
            header
                .to_ascii_lowercase()
                .starts_with("proxy-authorization:")
        }));
        assert_eq!(extra_requests, 0);
    }

    #[cfg(target_os = "linux")]
    fn run_cli_fixture(socket: &Path, script_body: &str) -> Result<(), DockerPreflightError> {
        use std::os::unix::fs::PermissionsExt;

        let binary = temp_path("docker-fixture");
        let expected_socket = socket.to_str().unwrap();
        let script = format!(
            "#!/bin/sh\n[ \"$#\" -eq 7 ] || exit 91\n[ \"$1\" = '--config' ] || exit 92\n[ \"$2\" = '/dev/null' ] || exit 93\n[ \"$3\" = '--host' ] || exit 94\n[ \"$4\" = 'unix://{expected_socket}' ] || exit 95\n[ \"$5\" = 'info' ] || exit 96\n[ \"$6\" = '--format' ] || exit 97\n[ \"$7\" = '{EXPECTED_INFO_FORMAT}' ] || exit 98\n[ \"${{DOCKER_HOST+x}}\" != x ] || exit 99\n[ \"${{DOCKER_CONTEXT+x}}\" != x ] || exit 100\n[ \"${{DOCKER_CONFIG+x}}\" != x ] || exit 101\n[ \"${{HTTP_PROXY+x}}\" != x ] || exit 102\n[ \"${{HTTPS_PROXY+x}}\" != x ] || exit 103\n{script_body}\n"
        );
        fs::write(&binary, script).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let result = check_rootless_docker(&binary, socket);
        fs::remove_file(binary).unwrap();
        result
    }

    #[test]
    fn accepts_daemon_info_with_required_rootless_and_cgroup_capabilities() {
        assert_eq!(parse_info(GOOD_INFO.as_bytes()), Ok(()));
    }

    #[test]
    fn rejects_missing_rootless_capability_and_partial_or_cpu_disabled_info() {
        let no_rootless = GOOD_INFO.replace(",\"name=rootless\"", "");
        assert_eq!(
            parse_info(no_rootless.as_bytes()),
            Err(DockerPreflightError::InvalidInfo)
        );

        let partial = r#"{"OSType":"linux","SecurityOptions":["name=rootless"],"CgroupDriver":"systemd","CgroupVersion":"2","MemoryLimit":true}"#;
        assert_eq!(
            parse_info(partial.as_bytes()),
            Err(DockerPreflightError::InvalidInfo)
        );

        let cpu_disabled = GOOD_INFO.replace("\"CPUCfsQuota\":true", "\"CPUCfsQuota\":false");
        assert_eq!(
            parse_info(cpu_disabled.as_bytes()),
            Err(DockerPreflightError::InvalidInfo)
        );
    }

    #[test]
    fn rejects_malformed_info() {
        assert_eq!(
            parse_info(b"not json"),
            Err(DockerPreflightError::InvalidInfo)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_cli_and_engine_api_info_with_distinct_cpu_field_names() {
        assert_eq!(parse_info(GOOD_INFO.as_bytes()), Ok(()));
        assert_eq!(parse_api_info(GOOD_API_INFO.as_bytes()), Ok(()));
        assert_eq!(
            parse_info(GOOD_API_INFO.as_bytes()),
            Err(DockerPreflightError::InvalidInfo)
        );
        assert_eq!(
            parse_api_info(GOOD_INFO.as_bytes()),
            Err(DockerPreflightError::InvalidInfo)
        );
    }

    #[test]
    fn rejects_relative_regular_file_and_symlink_socket_paths() {
        assert_eq!(
            validate_socket(Path::new("relative.sock")),
            Err(DockerPreflightError::InvalidSocket)
        );

        let file = temp_path("file");
        fs::write(&file, b"fixture").unwrap();
        assert_eq!(
            validate_socket(&file),
            Err(DockerPreflightError::InvalidSocket)
        );
        let link = temp_path("symlink");
        symlink(&file, &link).unwrap();
        assert_eq!(
            validate_socket(&link),
            Err(DockerPreflightError::InvalidSocket)
        );
        fs::remove_file(link).unwrap();
        fs::remove_file(file).unwrap();
    }

    #[test]
    fn accepts_only_an_existing_unix_socket() {
        let socket = temp_path("socket");
        let listener = UnixListener::bind(&socket).unwrap();
        assert_eq!(validate_socket(&socket), Ok(()));
        drop(listener);
        fs::remove_file(socket).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn invokes_explicit_cli_with_clean_environment_and_accepts_synthetic_response() {
        let socket = temp_path("fixture-socket");
        let listener = UnixListener::bind(&socket).unwrap();
        let result = run_cli_fixture(&socket, &format!("printf '%s\\n' '{GOOD_INFO}'"));
        drop(listener);
        fs::remove_file(socket).unwrap();
        assert_eq!(result, Ok(()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_preflight_uses_one_fixed_get_without_auth_and_accepts_valid_info() {
        run_isolated_child("socket-valid");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_preflight_rejects_invalid_info_and_redirect() {
        run_isolated_child("socket-invalid");
        run_isolated_child("socket-redirect");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_preflight_bounds_content_length_and_streamed_body() {
        run_isolated_child("socket-content-length-limit");
        run_isolated_child("socket-stream-limit");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_preflight_times_out_when_daemon_delays_response() {
        run_isolated_child("socket-timeout");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_preflight_cancellation_releases_the_gate() {
        run_isolated_child("socket-cancel");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_preflight_respects_the_existing_closed_gate() {
        run_isolated_child("socket-gate");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn container_inspect_reads_only_matching_id_and_running_state() {
        run_isolated_child("socket-inspect-running");
        run_isolated_child("socket-inspect-stopped");
        run_isolated_child("socket-inspect-mismatch");
        run_isolated_child("socket-inspect-invalid");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn container_inspect_rejects_ambiguous_or_unbounded_responses() {
        run_isolated_child("socket-inspect-not-found");
        run_isolated_child("socket-inspect-redirect");
        run_isolated_child("socket-inspect-large");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn intent_observation_requires_one_stable_matching_container() {
        run_isolated_child("socket-intent-one");
        run_isolated_child("socket-intent-zero");
        run_isolated_child("socket-intent-race");
        run_isolated_child("socket-intent-multiple");
        run_isolated_child("socket-intent-duplicate-id");
        run_isolated_child("socket-intent-duplicate-label");
        run_isolated_child("socket-intent-missing-labels");
        run_isolated_child("socket-intent-invalid-labels");
        run_isolated_child("socket-intent-invalid-id");
        run_isolated_child("socket-intent-http-error");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn intent_labels_reject_invalid_identity_before_socket_access() {
        use crate::supervisor_lock::SupervisorIntent;
        use uuid::Uuid;

        let valid = SupervisorIntent {
            task_id: Uuid::from_u128(1),
            operation_id: Uuid::from_u128(2),
            attempt: 0,
            fencing_token: 1,
        };
        assert_eq!(super::docker_intent_labels(&valid).unwrap().len(), 4);
        for invalid in [
            SupervisorIntent {
                task_id: Uuid::nil(),
                ..valid
            },
            SupervisorIntent {
                operation_id: Uuid::nil(),
                ..valid
            },
            SupervisorIntent {
                attempt: 4,
                ..valid
            },
            SupervisorIntent {
                fencing_token: 0,
                ..valid
            },
        ] {
            assert_eq!(
                super::observe_docker_intent(Path::new("/missing/socket"), &invalid).await,
                Err(DockerPreflightError::InvalidIntent)
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn container_inspect_rejects_noncanonical_id_before_socket_access() {
        assert_eq!(
            super::inspect_docker_container(Path::new("/missing/socket"), "../../etc/passwd").await,
            Err(DockerPreflightError::InvalidContainerId)
        );
    }

    #[cfg(target_os = "linux")]
    fn run_socket_inspect_case(case: &str) {
        use super::{DockerContainerState, inspect_docker_container};

        const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let (status, body, expected) = match case {
            "socket-inspect-running" => (
                "200 OK",
                format!(r#"{{"Id":"{ID}","State":{{"Running":true,"Status":"paused"}}}}"#),
                Ok(DockerContainerState {
                    id: ID.to_owned(),
                    running: true,
                }),
            ),
            "socket-inspect-stopped" => (
                "200 OK",
                format!(r#"{{"Id":"{ID}","State":{{"Running":false,"Status":"exited"}}}}"#),
                Ok(DockerContainerState {
                    id: ID.to_owned(),
                    running: false,
                }),
            ),
            "socket-inspect-mismatch" => (
                "200 OK",
                format!(
                    r#"{{"Id":"{}","State":{{"Running":false}}}}"#,
                    "b".repeat(64)
                ),
                Err(DockerPreflightError::ContainerMismatch),
            ),
            "socket-inspect-invalid" => (
                "200 OK",
                r#"{"Id":"bad","State":{}}"#.to_owned(),
                Err(DockerPreflightError::InvalidInfo),
            ),
            "socket-inspect-not-found" => (
                "404 Not Found",
                "{}".to_owned(),
                Err(DockerPreflightError::ContainerUnknown),
            ),
            "socket-inspect-redirect" => (
                "302 Found",
                String::new(),
                Err(DockerPreflightError::CommandFailed),
            ),
            "socket-inspect-large" => (
                "200 OK",
                "x".repeat(128 * 1024 + 1),
                Err(DockerPreflightError::OutputLimit),
            ),
            _ => panic!("unknown inspect fixture case"),
        };
        let headers = format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
        let (socket, _, server) = socket_http_fixture(
            http_response(status, &headers, body.as_bytes()),
            Duration::ZERO,
        );
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(inspect_docker_container(&socket, ID));
        let (request_line, headers, extra_requests) = server.join().unwrap();
        fs::remove_file(socket).unwrap();
        assert_eq!(result, expected);
        assert_eq!(
            request_line,
            format!("GET /containers/{ID}/json HTTP/1.1\r\n")
        );
        assert!(
            !headers
                .iter()
                .any(|header| header.to_ascii_lowercase().starts_with("authorization:"))
        );
        assert_eq!(extra_requests, 0);
    }

    #[cfg(target_os = "linux")]
    fn run_socket_intent_case(case: &str) {
        use super::{INTENT_FENCING_LABEL, INTENT_OPERATION_LABEL, observe_docker_intent};
        use crate::supervisor_lock::SupervisorIntent;
        use uuid::Uuid;

        const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let intent = SupervisorIntent {
            task_id: Uuid::from_u128(1),
            operation_id: Uuid::from_u128(2),
            attempt: 1,
            fencing_token: 3,
        };
        let labels = serde_json::to_value(super::docker_intent_labels(&intent).unwrap()).unwrap();
        let list_entry = |id: &str, labels: &serde_json::Value| {
            serde_json::json!({
                "Id": id,
                "Labels": labels,
                "State": "exited",
            })
        };
        let list = |entries: Vec<serde_json::Value>| serde_json::to_string(&entries).unwrap();
        let inspect = |id: &str, labels: &serde_json::Value| {
            serde_json::json!({
                "Id": id,
                "Config": { "Labels": labels },
                "State": { "Running": false, "Status": "exited" },
            })
            .to_string()
        };
        let ok = "200 OK".to_owned();
        let responses = match case {
            "socket-intent-one" => {
                let mut labels_with_image = labels.clone();
                labels_with_image["org.opencontainers.image.version"] = serde_json::json!("test");
                vec![
                    (ok.clone(), list(vec![list_entry(ID, &labels_with_image)])),
                    (ok.clone(), inspect(ID, &labels_with_image)),
                    (ok.clone(), list(vec![list_entry(ID, &labels_with_image)])),
                ]
            }
            "socket-intent-zero" => vec![
                (ok.clone(), list(Vec::new())),
                (ok.clone(), list(Vec::new())),
            ],
            "socket-intent-race" => vec![
                (ok.clone(), list(Vec::new())),
                (ok.clone(), list(vec![list_entry(ID, &labels)])),
            ],
            "socket-intent-multiple" => vec![(
                ok.clone(),
                list(vec![
                    list_entry(ID, &labels),
                    list_entry(&"b".repeat(64), &labels),
                ]),
            )],
            "socket-intent-duplicate-id" => vec![(
                ok.clone(),
                list(vec![list_entry(ID, &labels), list_entry(ID, &labels)]),
            )],
            "socket-intent-duplicate-label" => vec![(
                ok.clone(),
                format!(
                    r#"[{{"Id":"{ID}","Labels":{{"{INTENT_OPERATION_LABEL}":"{}","{INTENT_OPERATION_LABEL}":"{}"}},"State":"exited"}}]"#,
                    intent.operation_id, intent.operation_id
                ),
            )],
            "socket-intent-missing-labels" => {
                vec![(ok.clone(), format!(r#"[{{"Id":"{ID}","State":"exited"}}]"#))]
            }
            "socket-intent-invalid-labels" => {
                let mut invalid = labels.clone();
                invalid[INTENT_FENCING_LABEL] = serde_json::json!("4");
                vec![(ok.clone(), list(vec![list_entry(ID, &invalid)]))]
            }
            "socket-intent-invalid-id" => {
                vec![(ok.clone(), list(vec![list_entry("bad", &labels)]))]
            }
            "socket-intent-http-error" => {
                vec![("500 Internal Server Error".to_owned(), String::new())]
            }
            _ => panic!("unknown intent fixture case"),
        };
        let expected = match case {
            "socket-intent-one" => Ok(Some(super::DockerContainerState {
                id: ID.to_owned(),
                running: false,
            })),
            "socket-intent-zero" => Ok(None),
            "socket-intent-race" => Err(DockerPreflightError::ContainerMismatch),
            "socket-intent-multiple" => Err(DockerPreflightError::AmbiguousIntentContainers),
            "socket-intent-invalid-labels"
            | "socket-intent-invalid-id"
            | "socket-intent-duplicate-id" => Err(DockerPreflightError::ContainerMismatch),
            "socket-intent-missing-labels" | "socket-intent-duplicate-label" => {
                Err(DockerPreflightError::InvalidInfo)
            }
            "socket-intent-http-error" => Err(DockerPreflightError::CommandFailed),
            _ => unreachable!(),
        };
        let (socket, server) = socket_http_sequence_fixture(responses);
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(observe_docker_intent(&socket, &intent));
        let requests = server.join().unwrap();
        fs::remove_file(socket).unwrap();
        assert_eq!(result, expected);
        assert_eq!(
            requests.len(),
            match case {
                "socket-intent-one" => 3,
                "socket-intent-zero" | "socket-intent-race" => 2,
                _ => 1,
            }
        );
        for index in [0, requests.len() - 1] {
            let target = requests[index]
                .strip_prefix("GET ")
                .unwrap()
                .strip_suffix(" HTTP/1.1")
                .unwrap();
            let url = reqwest::Url::parse(&format!("http://localhost{target}")).unwrap();
            let pairs = url.query_pairs().collect::<Vec<_>>();
            assert!(
                pairs
                    .iter()
                    .any(|(key, value)| key == "all" && value == "1")
            );
            let filters = pairs.iter().find(|(key, _)| key == "filters").unwrap();
            let filters: serde_json::Value = serde_json::from_str(&filters.1).unwrap();
            assert_eq!(
                filters["label"],
                serde_json::json!([format!("{INTENT_OPERATION_LABEL}={}", intent.operation_id)])
            );
        }
        if case == "socket-intent-one" {
            assert_eq!(requests[1], format!("GET /containers/{ID}/json HTTP/1.1"));
        }
    }

    #[cfg(target_os = "linux")]
    fn run_isolated_child(case: &str) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "docker_preflight::tests::isolated_failure_child",
                "--nocapture",
            ])
            .env(CHILD_CASE_ENV, case)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    assert!(status.success(), "isolated fixture failed");
                    return;
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                _ => {
                    let _ = child.kill();
                    let reap_deadline = Instant::now() + Duration::from_millis(500);
                    while Instant::now() < reap_deadline {
                        if let Ok(Some(_)) = child.try_wait() {
                            panic!("isolated fixture exceeded its bound");
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    panic!("isolated fixture did not finish within its bound");
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn stop_fixture_grandchild(pid_file: &Path) {
        let pid = fs::read_to_string(pid_file).unwrap();
        let pid = pid.trim().parse::<u32>().unwrap();
        assert!(pid > 1);
        let pid = pid.to_string();
        let _ = Command::new("/bin/sh")
            .args(["-c", "kill -KILL \"$1\"", "sh", &pid])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let deadline = Instant::now() + Duration::from_secs(2);
        let reaped = loop {
            let status = Command::new("/bin/sh")
                .args(["-c", "kill -0 \"$1\"", "sh", &pid])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            if !status.success() {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert!(reaped, "fixture grandchild was not reaped");
        fs::remove_file(pid_file).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn isolated_failure_child() {
        let Ok(case) = std::env::var(CHILD_CASE_ENV) else {
            return;
        };
        if case.starts_with("socket-inspect-") {
            run_socket_inspect_case(&case);
            return;
        }
        if case.starts_with("socket-intent-") {
            run_socket_intent_case(&case);
            return;
        }
        if case.starts_with("socket-") {
            run_socket_preflight_case(&case);
            return;
        }
        let socket = temp_path("isolated-socket");
        let listener = UnixListener::bind(&socket).unwrap();
        let pid_file = temp_path("grandchild-pid");
        let (body, expected, retry_error) = match case.as_str() {
            "timeout" => (
                format!("/bin/sleep 30 & echo $! > '{}'\nexit 0", pid_file.display()),
                DockerPreflightError::Timeout,
                DockerPreflightError::AlreadyRunning,
            ),
            "output-limit" => (
                "exec /usr/bin/head -c 131073 /dev/zero".to_owned(),
                DockerPreflightError::OutputLimit,
                DockerPreflightError::AlreadyRunning,
            ),
            "command-failure" => (
                "printf '%s\\n' 'synthetic stderr' >&2\nexit 7".to_owned(),
                DockerPreflightError::CommandFailed,
                DockerPreflightError::InvalidBinary,
            ),
            _ => panic!("unknown isolated fixture case"),
        };
        assert_eq!(run_cli_fixture(&socket, &body), Err(expected));
        if case == "timeout" {
            stop_fixture_grandchild(&pid_file);
        }
        assert_eq!(
            check_rootless_docker(Path::new("/not-a-docker-binary"), &socket),
            Err(retry_error)
        );
        drop(listener);
        fs::remove_file(socket).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn timeout_leaves_the_gate_closed_when_a_pipe_holding_grandchild_outlives_cli() {
        run_isolated_child("timeout");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn output_limit_failure_isolated_from_other_tests() {
        run_isolated_child("output-limit");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn command_failure_releases_the_gate_without_leaking_stderr() {
        run_isolated_child("command-failure");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn rejects_unsupported_platform_before_spawning() {
        assert_eq!(
            check_rootless_docker(
                Path::new("/not-a-docker-binary"),
                Path::new("/not-a-socket")
            ),
            Err(DockerPreflightError::UnsupportedPlatform)
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn socket_preflight_rejects_unsupported_platform_before_validating_socket() {
        assert_eq!(
            check_rootless_docker_socket(Path::new("/not-a-socket")).await,
            Err(DockerPreflightError::UnsupportedPlatform)
        );
    }
}

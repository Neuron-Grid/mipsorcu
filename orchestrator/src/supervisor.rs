//! Rootless Docker execution for the credential-free synthetic mock agent.
//!
//! This module intentionally has no provider command and no credential mount.
//! Production provider execution remains unavailable until authentication and
//! billing routes can be established independently of this sandbox.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt::{self, Display, Formatter},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use reqwest::{Client, Method, StatusCode, header::CONTENT_TYPE, redirect::Policy, retry};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    agent::{AgentStage, Cancellation},
    docker_preflight::{
        DockerContainerState, DockerPreflightError, check_rootless_docker_socket,
        docker_intent_labels, inspect_docker_container, observe_docker_intent,
    },
    source_snapshot::SourceSnapshot,
    supervisor_lock::{
        SupervisorBinding, SupervisorIntent, SupervisorLock, SupervisorLockError,
    },
};

const DOCKER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_API_BYTES: usize = 1024 * 1024;
const MAX_RESULT_BYTES: usize = 4096;
const MAX_CGROUPS: usize = 4096;
const GATE_FILE_PREFIX: &str = ".mipsorcu-gate-";
const RESULT_PATH: &str = "/workspace/.mipsorcu-result.json";
const GATE_PATH: &str = "/run/mipsorcu/start-gate";
const MOCK_BOOTSTRAP: &str = "while [ ! -s /run/mipsorcu/start-gate ]; do sleep 0.02; done; printf '{\"task_id\":\"%s\",\"operation_id\":\"%s\",\"attempt\":%s,\"stage\":\"%s\",\"outcome\":\"%s\"}\\n' \"$MIPSORCU_TASK_ID\" \"$MIPSORCU_OPERATION_ID\" \"$MIPSORCU_ATTEMPT\" \"$MIPSORCU_STAGE\" \"$MIPSORCU_OUTCOME\" > /workspace/.mipsorcu-result.json";

/// Fixed limits and mounts for one isolated mock-agent container.
#[derive(Clone)]
pub struct MockContainerConfig {
    pub daemon_socket: PathBuf,
    /// Operator-pinned `repository@sha256:<digest>`; image pulls are never attempted.
    pub image: String,
    pub source: Arc<SourceSnapshot>,
    pub workspace: PathBuf,
    /// Same private operator-managed directory used by [`SupervisorLock`].
    pub state_directory: PathBuf,
    pub memory_bytes: u64,
    pub nano_cpus: u64,
    pub pids_limit: u64,
    pub cpu_period_micros: u64,
    pub operation_timeout: Duration,
}

/// Non-sensitive categories; values, command output, and daemon error bodies are never rendered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorError {
    InvalidConfiguration,
    UnsupportedPlatform,
    UnsafeWorkspace,
    RootlessUnavailable,
    MissingCgroupController,
    AmbiguousContainer,
    ContainerMismatch,
    DockerUnavailable,
    DockerTimeout,
    DockerResponse,
    CgroupUnavailable,
    CgroupMismatch,
    ResourceLimitMismatch,
    Cancelled,
    TimedOut,
    OutputInvalid,
    Lock,
    Io,
}

impl Display for SupervisorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "container supervisor configuration is invalid",
            Self::UnsupportedPlatform => "rootless container supervision requires Linux",
            Self::UnsafeWorkspace => "container workspace is not private and task-scoped",
            Self::RootlessUnavailable => "the selected Docker daemon is not verified rootless",
            Self::MissingCgroupController => "required cgroup v2 controllers are unavailable",
            Self::AmbiguousContainer => "container identity is ambiguous; operation remains blocked",
            Self::ContainerMismatch => "container identity does not match the durable operation",
            Self::DockerUnavailable => "Docker operation failed; durable intent remains unresolved",
            Self::DockerTimeout => "Docker operation timed out; durable intent remains unresolved",
            Self::DockerResponse => "Docker response is invalid; durable intent remains unresolved",
            Self::CgroupUnavailable => "container cgroup could not be independently verified",
            Self::CgroupMismatch => "container cgroup identity changed",
            Self::ResourceLimitMismatch => "effective container limits do not satisfy policy",
            Self::Cancelled => "container operation was cancelled",
            Self::TimedOut => "container operation timed out",
            Self::OutputInvalid => "container output failed validation",
            Self::Lock => "supervisor durable state could not be verified",
            Self::Io => "supervisor local I/O failed",
        })
    }
}

impl Error for SupervisorError {}

impl From<SupervisorLockError> for SupervisorError {
    fn from(_: SupervisorLockError) -> Self {
        Self::Lock
    }
}

impl From<DockerPreflightError> for SupervisorError {
    fn from(error: DockerPreflightError) -> Self {
        match error {
            DockerPreflightError::UnsupportedPlatform => Self::UnsupportedPlatform,
            DockerPreflightError::Timeout => Self::DockerTimeout,
            DockerPreflightError::ContainerMismatch | DockerPreflightError::InvalidContainerId => {
                Self::ContainerMismatch
            }
            _ => Self::DockerUnavailable,
        }
    }
}

/// Credential-free mock worker. It emits only a task-bound stage outcome.
pub struct RootlessMockWorker {
    config: MockContainerConfig,
    lock: Arc<SupervisorLock>,
    client: Client,
}

impl RootlessMockWorker {
    /// Verifies operator configuration and rootless/cgroup-v2 prerequisites.
    /// This constructor fails closed on macOS, rootful Docker, or undelegated controls.
    pub async fn new(
        config: MockContainerConfig,
        lock: Arc<SupervisorLock>,
    ) -> Result<Self, SupervisorError> {
        if !cfg!(target_os = "linux") {
            return Err(SupervisorError::UnsupportedPlatform);
        }
        validate_config(&config)?;
        check_rootless_docker_socket(&config.daemon_socket)
            .await
            .map_err(|_| SupervisorError::RootlessUnavailable)?;
        verify_delegated_cgroup_controllers(Path::new("/sys/fs/cgroup"))?;
        let client = Client::builder()
            .http1_only()
            .redirect(Policy::none())
            .retry(retry::never())
            .connect_timeout(DOCKER_TIMEOUT)
            .timeout(DOCKER_TIMEOUT)
            .unix_socket(&config.daemon_socket)
            .no_proxy()
            .build()
            .map_err(|_| SupervisorError::DockerUnavailable)?;
        Ok(Self {
            config,
            lock,
            client,
        })
    }

    /// Runs only the fixed synthetic worker. The returned value is parsed from
    /// the container's bounded result file and checked against every identity field.
    pub async fn run_mock_agent(
        &self,
        task_id: Uuid,
        operation_id: Uuid,
        attempt: u32,
        fencing_token: u64,
        stage: AgentStage,
        cancellation: Cancellation,
    ) -> Result<MockAgentResult, SupervisorError> {
        let intent = SupervisorIntent {
            task_id,
            operation_id,
            attempt,
            fencing_token,
        };
        if task_id.is_nil()
            || operation_id.is_nil()
            || fencing_token == 0
            || attempt > 3
            || !matches!(stage, AgentStage::Plan | AgentStage::Implement | AgentStage::Review)
        {
            return Err(SupervisorError::InvalidConfiguration);
        }
        let _execution = self.lock.acquire_operation_guard(intent)?;
        self.config
            .source
            .verify_identity()
            .map_err(|_| SupervisorError::UnsafeWorkspace)?;
        self.lock.persist_intent(intent)?;
        let gate = create_gate(&self.config.state_directory, operation_id)?;
        let labels = docker_intent_labels(&intent).map_err(|_| SupervisorError::InvalidConfiguration)?;
        let container_id = match self.create_container(intent, stage, &labels, gate.path()) .await {
            Ok(id) => id,
            Err(error) => return Err(error),
        };
        let inspect = self.inspect_full(&container_id).await?;
        validate_inspect(&inspect, &container_id, &labels, &self.config)?;
        if inspect.state.pid <= 0 || !inspect.state.running {
            return Err(SupervisorError::ContainerMismatch);
        }
        let (cgroup_path, device, inode) = capture_cgroup(
            u32::try_from(inspect.state.pid).map_err(|_| SupervisorError::CgroupMismatch)?,
            &container_id,
        )?;
        let binding = SupervisorBinding {
            intent,
            container_id: container_id.clone(),
            cgroup_path,
            cgroup_device: device,
            cgroup_inode: inode,
            memory_bytes: self.config.memory_bytes,
            cpu_quota_micros: self.config.nano_cpus / 1000,
            cpu_period_micros: self.config.cpu_period_micros,
            pids_limit: self.config.pids_limit,
        };
        verify_effective_limits(Path::new("/sys/fs/cgroup"), &binding)?;
        self.lock.persist_binding(&binding)?;

        // The worker cannot run before the full container identity, cgroup inode,
        // and effective hard limits have reached stable storage.
        if cancellation.cancelled() {
            return Err(SupervisorError::Cancelled);
        }
        gate.release()?;
        let started = Instant::now();
        loop {
            if cancellation.cancelled() {
                self.stop_and_resolve(intent, &binding).await?;
                return Err(SupervisorError::Cancelled);
            }
            if started.elapsed() >= self.config.operation_timeout {
                self.stop_and_resolve(intent, &binding).await?;
                return Err(SupervisorError::TimedOut);
            }
            let state = self.inspect_state(&container_id).await?;
            if !state.running() {
                let bytes = read_bounded_result(&self.config.workspace)?;
                let result = parse_result(&bytes, intent, stage)?;
                self.stop_and_resolve(intent, &binding).await?;
                return Ok(result);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Stop verification is idempotent only for the same durable operation.
    /// Missing or ambiguous bindings remain unresolved and never authorize replay.
    pub async fn stop_and_verify(
        &self,
        intent: SupervisorIntent,
    ) -> Result<(), SupervisorError> {
        if self.lock.read_intent()? != Some(intent) {
            return Err(SupervisorError::Lock);
        }
        let binding = self
            .lock
            .read_binding(intent.operation_id)?
            .ok_or(SupervisorError::AmbiguousContainer)?;
        if binding.intent != intent {
            return Err(SupervisorError::ContainerMismatch);
        }
        self.stop_and_resolve(intent, &binding).await
    }

    async fn stop_and_resolve(
        &self,
        intent: SupervisorIntent,
        binding: &SupervisorBinding,
    ) -> Result<(), SupervisorError> {
        let current = inspect_docker_container(&self.config.daemon_socket, &binding.container_id)
            .await?;
        if current.running() {
            self.request(
                Method::POST,
                &format!("/containers/{}/kill?signal=KILL", binding.container_id),
                None,
                &[StatusCode::NO_CONTENT, StatusCode::NOT_MODIFIED],
            )
            .await?;
            self.wait_stopped(&binding.container_id).await?;
        }
        let stopped = inspect_docker_container(&self.config.daemon_socket, &binding.container_id)
            .await?;
        let proof = self
            .lock
            .verify_container_stopped(intent, binding, &stopped)?;
        self.request(
            Method::DELETE,
            &format!("/containers/{}?force=false&v=false", binding.container_id),
            None,
            &[StatusCode::NO_CONTENT, StatusCode::NOT_FOUND],
        )
        .await?;
        match inspect_docker_container(&self.config.daemon_socket, &binding.container_id).await {
            Err(DockerPreflightError::ContainerUnknown) => {}
            _ => return Err(SupervisorError::DockerResponse),
        }
        self.lock.resolve_intent(proof)?;
        Ok(())
    }

    async fn wait_stopped(&self, id: &str) -> Result<(), SupervisorError> {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(10) {
            if !self.inspect_state(id).await?.running() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(SupervisorError::DockerTimeout)
    }

    async fn create_container(
        &self,
        intent: SupervisorIntent,
        stage: AgentStage,
        labels: &BTreeMap<String, String>,
        gate_path: &Path,
    ) -> Result<String, SupervisorError> {
        let source = self.config.source.path().to_str().ok_or(SupervisorError::InvalidConfiguration)?;
        let workspace = self.config.workspace.to_str().ok_or(SupervisorError::InvalidConfiguration)?;
        let gate = gate_path.to_str().ok_or(SupervisorError::InvalidConfiguration)?;
        let outcome = if stage == AgentStage::Review { "approved" } else { "completed" };
        let body = json!({
            "Image": self.config.image,
            "Cmd": ["/bin/sh", "-c", MOCK_BOOTSTRAP],
            "Env": [
                format!("MIPSORCU_TASK_ID={}", intent.task_id),
                format!("MIPSORCU_OPERATION_ID={}", intent.operation_id),
                format!("MIPSORCU_ATTEMPT={}", intent.attempt),
                format!("MIPSORCU_STAGE={}", stage_name(stage)),
                format!("MIPSORCU_OUTCOME={outcome}"),
            ],
            "Labels": labels,
            "WorkingDir": "/workspace",
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": true,
                "Privileged": false,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "Memory": self.config.memory_bytes,
                "NanoCpus": self.config.nano_cpus,
                "PidsLimit": self.config.pids_limit,
                "CpuPeriod": self.config.cpu_period_micros,
                "CpuQuota": self.config.nano_cpus / 1000,
                "Init": true,
                "Binds": [
                    format!("{source}:/source:ro"),
                    format!("{workspace}:/workspace:rw"),
                    format!("{gate}:{GATE_PATH}:ro"),
                ],
            }
        });
        let response = self.request(
            Method::POST,
            "/containers/create",
            Some(body),
            &[StatusCode::CREATED],
        ).await?;
        let created: CreateResponse = serde_json::from_slice(&response)
            .map_err(|_| SupervisorError::DockerResponse)?;
        validate_container_id(&created.id)?;
        Ok(created.id)
    }

    async fn inspect_full(&self, id: &str) -> Result<InspectResponse, SupervisorError> {
        validate_container_id(id)?;
        let response = self.request(
            Method::GET,
            &format!("/containers/{id}/json"),
            None,
            &[StatusCode::OK],
        ).await?;
        serde_json::from_slice(&response).map_err(|_| SupervisorError::DockerResponse)
    }

    async fn inspect_state(&self, id: &str) -> Result<DockerContainerState, SupervisorError> {
        inspect_docker_container(&self.config.daemon_socket, id)
            .await
            .map_err(Into::into)
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        expected: &[StatusCode],
    ) -> Result<Vec<u8>, SupervisorError> {
        let url = format!("http://localhost{path}");
        let mut request = self.client.request(method, url);
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").json(&body);
        }
        let response = tokio::time::timeout(DOCKER_TIMEOUT, request.send())
            .await
            .map_err(|_| SupervisorError::DockerTimeout)?
            .map_err(|_| SupervisorError::DockerUnavailable)?;
        if !expected.contains(&response.status()) {
            return Err(SupervisorError::DockerResponse);
        }
        if response.content_length().is_some_and(|size| size > MAX_API_BYTES as u64) {
            return Err(SupervisorError::DockerResponse);
        }
        let mut body = Vec::new();
        let mut stream = response;
        while let Some(chunk) = stream.chunk().await.map_err(|_| SupervisorError::DockerUnavailable)? {
            if chunk.len() > MAX_API_BYTES.saturating_sub(body.len()) {
                return Err(SupervisorError::DockerResponse);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

/// Container-derived, task-bound outcome. It carries no generated content or secrets.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MockAgentResult {
    pub task_id: Uuid,
    pub operation_id: Uuid,
    pub attempt: u32,
    pub stage: AgentStage,
    pub outcome: MockOutcome,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MockOutcome {
    Completed,
    Approved,
}

#[derive(Deserialize)]
struct CreateResponse {
    #[serde(rename = "Id")]
    id: String,
}

#[derive(Deserialize)]
struct InspectResponse {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Config")]
    config: InspectConfig,
    #[serde(rename = "HostConfig")]
    host_config: InspectHostConfig,
    #[serde(rename = "State")]
    state: InspectState,
}

#[derive(Deserialize)]
struct InspectConfig {
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "Labels")]
    labels: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct InspectHostConfig {
    #[serde(rename = "NetworkMode")]
    network_mode: String,
    #[serde(rename = "ReadonlyRootfs")]
    readonly_rootfs: bool,
    #[serde(rename = "Privileged")]
    privileged: bool,
    #[serde(rename = "Memory")]
    memory: u64,
    #[serde(rename = "NanoCpus")]
    nano_cpus: u64,
    #[serde(rename = "PidsLimit")]
    pids_limit: Option<i64>,
}

#[derive(Deserialize)]
struct InspectState {
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "Pid")]
    pid: i64,
}

fn validate_config(config: &MockContainerConfig) -> Result<(), SupervisorError> {
    let digest = config.image.split_once("@sha256:");
    if config.daemon_socket.as_os_str().is_empty()
        || digest.is_none_or(|(repo, hash)| {
            repo.is_empty() || hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        || config.memory_bytes < 32 * 1024 * 1024
        || config.nano_cpus == 0
        || config.pids_limit == 0
        || config.cpu_period_micros == 0
        || config.operation_timeout.is_zero()
        || config.operation_timeout > Duration::from_secs(60 * 60)
        || !config.state_directory.is_absolute()
        || !config.workspace.is_absolute()
    {
        return Err(SupervisorError::InvalidConfiguration);
    }
    let source = config.source.path().canonicalize().map_err(|_| SupervisorError::UnsafeWorkspace)?;
    let workspace = config.workspace.canonicalize().map_err(|_| SupervisorError::UnsafeWorkspace)?;
    let state = config.state_directory.canonicalize().map_err(|_| SupervisorError::UnsafeWorkspace)?;
    if source == workspace || source.starts_with(&workspace) || workspace.starts_with(&source)
        || workspace == state || workspace.starts_with(&state) || state.starts_with(&workspace)
    {
        return Err(SupervisorError::UnsafeWorkspace);
    }
    let metadata = fs::symlink_metadata(&workspace).map_err(|_| SupervisorError::UnsafeWorkspace)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.mode() & 0o7777 != 0o700 {
        return Err(SupervisorError::UnsafeWorkspace);
    }
    Ok(())
}

fn verify_delegated_cgroup_controllers(root: &Path) -> Result<(), SupervisorError> {
    let metadata = fs::symlink_metadata(root).map_err(|_| SupervisorError::CgroupUnavailable)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SupervisorError::CgroupUnavailable);
    }
    let controllers = fs::read_to_string(root.join("cgroup.controllers"))
        .map_err(|_| SupervisorError::CgroupUnavailable)?;
    for required in ["cpu", "memory", "pids"] {
        if !controllers.split_ascii_whitespace().any(|controller| controller == required) {
            return Err(SupervisorError::MissingCgroupController);
        }
    }
    Ok(())
}

fn capture_cgroup(pid: u32, container_id: &str) -> Result<(String, u64, u64), SupervisorError> {
    validate_container_id(container_id)?;
    let cgroups = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|_| SupervisorError::CgroupUnavailable)?;
    let path = cgroups.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        (fields.next() == Some("0") && fields.next() == Some(""))
            .then(|| fields.next())
            .flatten()
    }).ok_or(SupervisorError::CgroupUnavailable)?;
    if !path.contains(container_id) || !path.starts_with('/') || path.contains("..") {
        return Err(SupervisorError::CgroupMismatch);
    }
    let relative = Path::new(path).strip_prefix("/").map_err(|_| SupervisorError::CgroupMismatch)?;
    let full = Path::new("/sys/fs/cgroup").join(relative);
    let metadata = fs::symlink_metadata(&full).map_err(|_| SupervisorError::CgroupUnavailable)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(SupervisorError::CgroupMismatch);
    }
    Ok((path.to_owned(), metadata.dev(), metadata.ino()))
}

fn verify_effective_limits(root: &Path, binding: &SupervisorBinding) -> Result<(), SupervisorError> {
    verify_delegated_cgroup_controllers(root)?;
    let relative = Path::new(&binding.cgroup_path).strip_prefix("/").map_err(|_| SupervisorError::CgroupMismatch)?;
    let cgroup = root.join(relative);
    let metadata = fs::symlink_metadata(&cgroup).map_err(|_| SupervisorError::CgroupUnavailable)?;
    if metadata.dev() != binding.cgroup_device || metadata.ino() != binding.cgroup_inode || metadata.file_type().is_symlink() {
        return Err(SupervisorError::CgroupMismatch);
    }
    let memory = fs::read_to_string(cgroup.join("memory.max")).map_err(|_| SupervisorError::CgroupUnavailable)?
        .trim().parse::<u64>().map_err(|_| SupervisorError::ResourceLimitMismatch)?;
    let cpu = fs::read_to_string(cgroup.join("cpu.max")).map_err(|_| SupervisorError::CgroupUnavailable)?;
    let mut cpu_fields = cpu.split_ascii_whitespace();
    let quota = cpu_fields.next().and_then(|value| value.parse::<u64>().ok()).ok_or(SupervisorError::ResourceLimitMismatch)?;
    let period = cpu_fields.next().and_then(|value| value.parse::<u64>().ok()).ok_or(SupervisorError::ResourceLimitMismatch)?;
    let pids = fs::read_to_string(cgroup.join("pids.max")).map_err(|_| SupervisorError::CgroupUnavailable)?
        .trim().parse::<u64>().map_err(|_| SupervisorError::ResourceLimitMismatch)?;
    if memory > binding.memory_bytes
        || u128::from(quota) * u128::from(binding.cpu_period_micros)
            > u128::from(binding.cpu_quota_micros) * u128::from(period)
        || pids > binding.pids_limit
    {
        return Err(SupervisorError::ResourceLimitMismatch);
    }
    Ok(())
}

fn validate_inspect(
    inspect: &InspectResponse,
    requested_id: &str,
    labels: &BTreeMap<String, String>,
    config: &MockContainerConfig,
) -> Result<(), SupervisorError> {
    if inspect.id != requested_id
        || inspect.config.image != config.image
        || &inspect.config.labels != labels
        || inspect.host_config.network_mode != "none"
        || !inspect.host_config.readonly_rootfs
        || inspect.host_config.privileged
        || inspect.host_config.memory != config.memory_bytes
        || inspect.host_config.nano_cpus != config.nano_cpus
        || inspect.host_config.pids_limit != i64::try_from(config.pids_limit).ok()
    {
        return Err(SupervisorError::ContainerMismatch);
    }
    Ok(())
}

fn validate_container_id(id: &str) -> Result<(), SupervisorError> {
    if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) {
        return Err(SupervisorError::ContainerMismatch);
    }
    Ok(())
}

fn stage_name(stage: AgentStage) -> &'static str {
    match stage {
        AgentStage::Plan => "plan",
        AgentStage::Implement => "implement",
        AgentStage::Review => "review",
    }
}

fn parse_result(bytes: &[u8], intent: SupervisorIntent, stage: AgentStage) -> Result<MockAgentResult, SupervisorError> {
    let result: MockAgentResult = serde_json::from_slice(bytes).map_err(|_| SupervisorError::OutputInvalid)?;
    let expected_outcome = if stage == AgentStage::Review { MockOutcome::Approved } else { MockOutcome::Completed };
    if result.task_id != intent.task_id || result.operation_id != intent.operation_id
        || result.attempt != intent.attempt || result.stage != stage || result.outcome != expected_outcome
    {
        return Err(SupervisorError::OutputInvalid);
    }
    Ok(result)
}

fn read_bounded_result(workspace: &Path) -> Result<Vec<u8>, SupervisorError> {
    let path = workspace.join(".mipsorcu-result.json");
    let before = fs::symlink_metadata(&path).map_err(|_| SupervisorError::OutputInvalid)?;
    if !before.is_file() || before.file_type().is_symlink() || before.nlink() != 1 || before.len() == 0 || before.len() > MAX_RESULT_BYTES as u64 {
        return Err(SupervisorError::OutputInvalid);
    }
    let mut file = OpenOptions::new().read(true).custom_flags(libc_no_follow()).open(&path).map_err(|_| SupervisorError::OutputInvalid)?;
    let opened = file.metadata().map_err(|_| SupervisorError::OutputInvalid)?;
    if opened.dev() != before.dev() || opened.ino() != before.ino() {
        return Err(SupervisorError::OutputInvalid);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.take((MAX_RESULT_BYTES + 1) as u64).read_to_end(&mut bytes).map_err(|_| SupervisorError::OutputInvalid)?;
    if bytes.len() != before.len() as usize || bytes.len() > MAX_RESULT_BYTES {
        return Err(SupervisorError::OutputInvalid);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn libc_no_follow() -> i32 {
    0x20000
}

fn create_gate(state_directory: &Path, operation_id: Uuid) -> Result<Gate, SupervisorError> {
    let path = state_directory.join(format!("{GATE_FILE_PREFIX}{operation_id}"));
    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).map_err(|_| SupervisorError::Io)?;
    file.sync_all().map_err(|_| SupervisorError::Io)?;
    File::open(state_directory).and_then(|directory| directory.sync_all()).map_err(|_| SupervisorError::Io)?;
    Ok(Gate { path, file: Some(file) })
}

struct Gate {
    path: PathBuf,
    file: Option<File>,
}

impl Gate {
    fn path(&self) -> &Path { &self.path }
    fn release(mut self) -> Result<(), SupervisorError> {
        let mut file = self.file.take().ok_or(SupervisorError::Io)?;
        file.write_all(b"1").and_then(|()| file.sync_all()).map_err(|_| SupervisorError::Io)
    }
}

//! Typed agent execution boundary. Real providers remain unavailable until
//! their authentication and billing routes can be verified.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Codex,
    Claude,
    DeepSeekHarness,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyConfig {
    pub max_concurrent_tasks: u8,
    pub max_concurrent_agents: u8,
    pub implementer: Provider,
    pub reviewer: Provider,
    pub max_repair_attempts: u8,
    pub agent_timeout_minutes: u16,
    pub allow_extra_api_billing: bool,
    pub allow_main_merge: bool,
    pub allow_release: bool,
}

pub type AgentSettings = AutonomyConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    ConcurrentTasks,
    ConcurrentAgents,
    SameProviderLineage,
    Implementer,
    Reviewer,
    RepairLimit,
    Timeout,
    ExtraApiBilling,
    MainMerge,
    Release,
}

impl AutonomyConfig {
    pub fn approved_mock_defaults() -> Self {
        Self {
            max_concurrent_tasks: 1,
            max_concurrent_agents: 1,
            implementer: Provider::Codex,
            reviewer: Provider::Claude,
            max_repair_attempts: 3,
            agent_timeout_minutes: 45,
            allow_extra_api_billing: false,
            allow_main_merge: false,
            allow_release: false,
        }
    }

    /// Reject any setting outside the explicitly approved, mock-only envelope.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_concurrent_tasks != 1 {
            return Err(ConfigError::ConcurrentTasks);
        }
        if self.max_concurrent_agents != 1 {
            return Err(ConfigError::ConcurrentAgents);
        }
        if self.implementer == self.reviewer {
            return Err(ConfigError::SameProviderLineage);
        }
        if self.implementer != Provider::Codex {
            return Err(ConfigError::Implementer);
        }
        if self.reviewer != Provider::Claude {
            return Err(ConfigError::Reviewer);
        }
        if self.max_repair_attempts != 3 {
            return Err(ConfigError::RepairLimit);
        }
        if self.agent_timeout_minutes != 45 {
            return Err(ConfigError::Timeout);
        }
        if self.allow_extra_api_billing {
            return Err(ConfigError::ExtraApiBilling);
        }
        if self.allow_main_merge {
            return Err(ConfigError::MainMerge);
        }
        if self.allow_release {
            return Err(ConfigError::Release);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Authentication,
    Quota,
    Connection,
    Cancelled,
    Timeout,
    Unavailable,
    InvalidSession,
    InvalidInput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Session {
    Ready,
    Running,
    Interrupted,
    Completed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStage {
    Plan,
    Implement,
    Validate,
    Review,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Implementer,
    Reviewer,
}

/// Identifies one durable stage execution without carrying prompts or output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentRequest {
    pub task_id: Uuid,
    pub operation_id: Uuid,
    pub stage: AgentStage,
    pub role: AgentRole,
    pub attempt: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Approved,
    ChangesRequested,
    Completed,
}

#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    /// Returns whether cancellation has been requested for this invocation.
    pub fn cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub trait AgentAdapter {
    fn provider(&self) -> Provider;
    /// Whether this adapter is configured for use, independent of session state.
    /// This does not prove authentication, allow a completed session to be reused,
    /// or authorize a paid request.
    fn is_available(&self) -> bool {
        false
    }
    fn session(&self) -> Session;
    fn execute(
        &mut self,
        cancellation: Cancellation,
        timeout: Duration,
    ) -> impl Future<Output = Result<Outcome, Failure>> + Send;
}

/// Orchestration requires durable task and operation identity. Implementing
/// this trait does not expose the legacy untyped execution method.
pub trait TypedAgentAdapter {
    fn execute_request(
        &mut self,
        request: AgentRequest,
        cancellation: Cancellation,
        timeout: Duration,
    ) -> impl Future<Output = Result<Outcome, Failure>> + Send;
}

/// Explicitly disabled provider adapter. It never starts a process or makes a
/// network request while provider auth and billing routes are unverified.
pub struct UnavailableAdapter {
    provider: Provider,
}

impl UnavailableAdapter {
    pub const fn new(provider: Provider) -> Self {
        Self { provider }
    }
}

impl AgentAdapter for UnavailableAdapter {
    fn provider(&self) -> Provider {
        self.provider
    }

    fn session(&self) -> Session {
        Session::Ready
    }

    async fn execute(&mut self, _: Cancellation, _: Duration) -> Result<Outcome, Failure> {
        Err(Failure::Unavailable)
    }
}

impl TypedAgentAdapter for UnavailableAdapter {
    async fn execute_request(
        &mut self,
        _: AgentRequest,
        _: Cancellation,
        _: Duration,
    ) -> Result<Outcome, Failure> {
        Err(Failure::Unavailable)
    }
}

/// Scripted outcomes carry no prompts, credentials, or raw provider output.
pub struct MockAdapter {
    provider: Provider,
    session: Session,
    request: Option<AgentRequest>,
    delay: Duration,
    result: Result<Outcome, Failure>,
}

struct RunningSession<'a>(&'a mut Session);

impl Drop for RunningSession<'_> {
    fn drop(&mut self) {
        if *self.0 == Session::Running {
            *self.0 = Session::Interrupted;
        }
    }
}

impl MockAdapter {
    pub fn new(provider: Provider, delay: Duration, result: Result<Outcome, Failure>) -> Self {
        Self {
            provider,
            session: Session::Ready,
            request: None,
            delay,
            result,
        }
    }
}

impl AgentAdapter for MockAdapter {
    fn provider(&self) -> Provider {
        self.provider
    }
    fn is_available(&self) -> bool {
        true
    }
    fn session(&self) -> Session {
        self.session
    }

    async fn execute(
        &mut self,
        cancellation: Cancellation,
        timeout: Duration,
    ) -> Result<Outcome, Failure> {
        self.run(cancellation, timeout).await
    }
}

impl TypedAgentAdapter for MockAdapter {
    async fn execute_request(
        &mut self,
        request: AgentRequest,
        cancellation: Cancellation,
        timeout: Duration,
    ) -> Result<Outcome, Failure> {
        if request.task_id.is_nil()
            || request.operation_id.is_nil()
            || request.attempt > 3
            || !matches!(
                (request.stage, request.role),
                (
                    AgentStage::Plan | AgentStage::Implement | AgentStage::Validate,
                    AgentRole::Implementer
                ) | (AgentStage::Review, AgentRole::Reviewer)
            )
        {
            return Err(Failure::InvalidInput);
        }
        if self.request.is_some_and(|previous| previous != request) {
            return Err(Failure::InvalidSession);
        }
        self.request = Some(request);
        self.run(cancellation, timeout).await
    }
}

impl MockAdapter {
    async fn run(
        &mut self,
        cancellation: Cancellation,
        timeout: Duration,
    ) -> Result<Outcome, Failure> {
        if !matches!(self.session, Session::Ready | Session::Interrupted) {
            return Err(Failure::InvalidSession);
        }
        self.session = Session::Running;
        let session = RunningSession(&mut self.session);
        let run = async {
            let deadline =
                tokio::time::Instant::now() + self.delay.min(Duration::from_secs(45 * 60));
            loop {
                if cancellation.cancelled() {
                    return Err(Failure::Cancelled);
                }
                if tokio::time::Instant::now() >= deadline {
                    return if self.delay > Duration::from_secs(45 * 60) {
                        Err(Failure::Timeout)
                    } else {
                        self.result
                    };
                }
                tokio::time::sleep_until(
                    deadline.min(tokio::time::Instant::now() + Duration::from_millis(10)),
                )
                .await;
            }
        };
        let result = tokio::time::timeout(timeout.min(Duration::from_secs(45 * 60)), run)
            .await
            .unwrap_or(Err(Failure::Timeout));
        *session.0 = if matches!(result, Err(Failure::Cancelled | Failure::Timeout)) {
            Session::Interrupted
        } else {
            Session::Completed
        };
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approved_config() -> AutonomyConfig {
        AutonomyConfig {
            max_concurrent_tasks: 1,
            max_concurrent_agents: 1,
            implementer: Provider::Codex,
            reviewer: Provider::Claude,
            max_repair_attempts: 3,
            agent_timeout_minutes: 45,
            allow_extra_api_billing: false,
            allow_main_merge: false,
            allow_release: false,
        }
    }

    #[test]
    fn fixed_settings_accept_only_the_approved_mock_envelope() {
        assert_eq!(approved_config().validate(), Ok(()));
        let mut invalid = approved_config();
        invalid.max_concurrent_tasks = 2;
        assert_eq!(invalid.validate(), Err(ConfigError::ConcurrentTasks));
        let mut invalid = approved_config();
        invalid.max_concurrent_agents = 2;
        assert_eq!(invalid.validate(), Err(ConfigError::ConcurrentAgents));
        let mut invalid = approved_config();
        invalid.reviewer = Provider::Codex;
        assert_eq!(invalid.validate(), Err(ConfigError::SameProviderLineage));
        let mut invalid = approved_config();
        invalid.implementer = Provider::DeepSeekHarness;
        assert_eq!(invalid.validate(), Err(ConfigError::Implementer));
        let mut invalid = approved_config();
        invalid.max_repair_attempts = 4;
        assert_eq!(invalid.validate(), Err(ConfigError::RepairLimit));
        let mut invalid = approved_config();
        invalid.agent_timeout_minutes = 46;
        assert_eq!(invalid.validate(), Err(ConfigError::Timeout));
        let mut invalid = approved_config();
        invalid.allow_extra_api_billing = true;
        assert_eq!(invalid.validate(), Err(ConfigError::ExtraApiBilling));
        let mut invalid = approved_config();
        invalid.allow_main_merge = true;
        assert_eq!(invalid.validate(), Err(ConfigError::MainMerge));
        let mut invalid = approved_config();
        invalid.allow_release = true;
        assert_eq!(invalid.validate(), Err(ConfigError::Release));
    }

    #[tokio::test]
    async fn interrupted_mock_can_resume_and_completed_session_cannot_repeat() {
        let mut agent = MockAdapter::new(
            Provider::Codex,
            Duration::from_millis(20),
            Ok(Outcome::Completed),
        );
        assert_eq!(
            agent
                .execute(Cancellation::default(), Duration::from_millis(1))
                .await,
            Err(Failure::Timeout)
        );
        assert_eq!(agent.session(), Session::Interrupted);
        assert_eq!(
            agent
                .execute(Cancellation::default(), Duration::from_secs(1))
                .await,
            Ok(Outcome::Completed)
        );
        assert_eq!(
            agent
                .execute(Cancellation::default(), Duration::from_secs(1))
                .await,
            Err(Failure::InvalidSession)
        );
    }

    #[tokio::test]
    async fn cancellation_and_provider_failures_are_structured() {
        let mut agent = MockAdapter::new(Provider::Claude, Duration::ZERO, Err(Failure::Quota));
        let cancellation = Cancellation::default();
        cancellation.cancel();
        assert_eq!(
            agent.execute(cancellation, Duration::from_secs(1)).await,
            Err(Failure::Cancelled)
        );
        assert_eq!(
            agent
                .execute(Cancellation::default(), Duration::from_secs(1))
                .await,
            Err(Failure::Quota)
        );
        assert_eq!(agent.provider(), Provider::Claude);
    }

    #[tokio::test]
    async fn dropping_execution_marks_the_session_interrupted() {
        let mut agent = MockAdapter::new(
            Provider::Codex,
            Duration::from_secs(1),
            Ok(Outcome::Completed),
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(1),
                agent.execute(Cancellation::default(), Duration::from_secs(2))
            )
            .await
            .is_err()
        );
        assert_eq!(agent.session(), Session::Interrupted);
    }

    #[tokio::test]
    async fn every_real_provider_fails_closed_without_starting_a_session() {
        for provider in [Provider::Codex, Provider::Claude, Provider::DeepSeekHarness] {
            let mut adapter = UnavailableAdapter::new(provider);
            assert_eq!(adapter.provider(), provider);
            assert!(!adapter.is_available());
            assert_eq!(adapter.session(), Session::Ready);
            assert_eq!(
                adapter
                    .execute_request(
                        request(AgentStage::Plan, AgentRole::Implementer),
                        Cancellation::default(),
                        Duration::from_secs(1),
                    )
                    .await,
                Err(Failure::Unavailable)
            );
            assert!(!adapter.is_available());
            assert_eq!(adapter.session(), Session::Ready);
        }
    }

    #[tokio::test]
    async fn mock_accepts_the_typed_execution_contract() {
        let mut adapter = MockAdapter::new(Provider::Codex, Duration::ZERO, Ok(Outcome::Completed));
        assert!(adapter.is_available());
        assert_eq!(
            adapter
                .execute_request(
                    request(AgentStage::Implement, AgentRole::Implementer),
                    Cancellation::default(),
                    Duration::from_secs(1),
                )
                .await,
            Ok(Outcome::Completed)
        );
        assert!(adapter.is_available());
    }

    #[tokio::test]
    async fn typed_mock_rejects_invalid_or_changed_execution_identity() {
        let mut adapter = MockAdapter::new(Provider::Codex, Duration::ZERO, Ok(Outcome::Completed));
        let valid = request(AgentStage::Implement, AgentRole::Implementer);
        for invalid in [
            AgentRequest {
                task_id: Uuid::nil(),
                ..valid
            },
            AgentRequest {
                operation_id: Uuid::nil(),
                ..valid
            },
            AgentRequest {
                role: AgentRole::Reviewer,
                ..valid
            },
            AgentRequest {
                attempt: 4,
                ..valid
            },
        ] {
            assert_eq!(
                adapter
                    .execute_request(invalid, Cancellation::default(), Duration::from_secs(1))
                    .await,
                Err(Failure::InvalidInput)
            );
        }
        let cancellation = Cancellation::default();
        cancellation.cancel();
        assert_eq!(
            adapter
                .execute_request(valid, cancellation, Duration::from_secs(1))
                .await,
            Err(Failure::Cancelled)
        );
        let changed = AgentRequest {
            operation_id: Uuid::from_u128(3),
            ..valid
        };
        assert_eq!(
            adapter
                .execute_request(changed, Cancellation::default(), Duration::from_secs(1))
                .await,
            Err(Failure::InvalidSession)
        );
        assert_eq!(
            adapter
                .execute_request(valid, Cancellation::default(), Duration::from_secs(1))
                .await,
            Ok(Outcome::Completed)
        );
    }

    fn request(stage: AgentStage, role: AgentRole) -> AgentRequest {
        AgentRequest {
            task_id: Uuid::from_u128(1),
            operation_id: Uuid::from_u128(2),
            stage,
            role,
            attempt: 0,
        }
    }
}

//! Mock-only agent boundary. Real providers are deliberately unavailable.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};

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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Session {
    Ready,
    Running,
    Interrupted,
    Completed,
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
    fn cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub trait AgentAdapter {
    fn provider(&self) -> Provider;
    fn session(&self) -> Session;
    fn execute(
        &mut self,
        cancellation: Cancellation,
        timeout: Duration,
    ) -> impl Future<Output = Result<Outcome, Failure>> + Send;
}

/// Scripted outcomes carry no prompts, credentials, or raw provider output.
pub struct MockAdapter {
    provider: Provider,
    session: Session,
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
            delay,
            result,
        }
    }
}

impl AgentAdapter for MockAdapter {
    fn provider(&self) -> Provider {
        self.provider
    }
    fn session(&self) -> Session {
        self.session
    }

    async fn execute(
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
}

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::types::SourceEventAt;

use super::catalog::ScheduledJobSpec;

#[derive(Clone, Default)]
pub struct SchedulerStatusState {
    inner: Arc<RwLock<SchedulerStatusInner>>,
}

#[derive(Clone)]
struct SchedulerStatusInner {
    enabled: bool,
    startup_delay: Duration,
    jobs: HashMap<&'static str, SchedulerJobStatus>,
}

impl Default for SchedulerStatusInner {
    fn default() -> Self {
        Self {
            enabled: false,
            startup_delay: Duration::from_secs(30),
            jobs: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct SchedulerStatusSnapshot {
    pub enabled: bool,
    pub engine: &'static str,
    pub startup_delay_seconds: u64,
    pub jobs: Vec<SchedulerJobStatus>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SchedulerJobStatus {
    pub job_name: &'static str,
    pub cron: &'static str,
    pub timeout_seconds: u64,
    pub running: bool,
    pub last_status: Option<&'static str>,
    pub last_started_at: Option<String>,
    pub last_completed_at: Option<String>,
    pub last_failed_at: Option<String>,
    pub last_skipped_at: Option<String>,
    pub failure_streak: u32,
    pub failure_streak_started_at: Option<String>,
}

#[derive(Clone, Copy)]
enum SchedulerJobTransition<'a> {
    Started(&'a SourceEventAt),
    Completed(&'a SourceEventAt),
    Failed(&'a SourceEventAt),
    Skipped(&'a SourceEventAt),
}

impl SchedulerStatusState {
    pub fn new(enabled: bool, startup_delay: Duration) -> Self {
        let state = Self::default();
        state.set_enabled(enabled, startup_delay);
        state
    }

    pub fn set_enabled(&self, enabled: bool, startup_delay: Duration) {
        self.with_write(|inner| {
            inner.enabled = enabled;
            inner.startup_delay = startup_delay;
        });
    }

    pub(crate) fn register_jobs(&self, specs: &[ScheduledJobSpec]) {
        self.with_write(|inner| {
            specs.iter().for_each(|spec| {
                inner
                    .jobs
                    .entry(spec.name.as_str())
                    .or_insert_with(|| SchedulerJobStatus::new(*spec));
            });
        });
    }

    pub(crate) fn mark_started(&self, spec: ScheduledJobSpec, started_at: &SourceEventAt) {
        self.apply_job_transition(spec, SchedulerJobTransition::Started(started_at));
    }

    pub(crate) fn mark_completed(&self, spec: ScheduledJobSpec, completed_at: &SourceEventAt) {
        self.apply_job_transition(spec, SchedulerJobTransition::Completed(completed_at));
    }

    pub(crate) fn mark_failed(&self, spec: ScheduledJobSpec, failed_at: &SourceEventAt) -> u32 {
        self.apply_job_transition(spec, SchedulerJobTransition::Failed(failed_at))
            .failure_streak
    }

    pub(crate) fn mark_skipped(&self, spec: ScheduledJobSpec, skipped_at: &SourceEventAt) {
        self.apply_job_transition(spec, SchedulerJobTransition::Skipped(skipped_at));
    }

    pub fn snapshot(&self) -> SchedulerStatusSnapshot {
        self.with_read(|inner| {
            let mut jobs = inner.jobs.values().cloned().collect::<Vec<_>>();
            jobs.sort_by_key(|job| job.job_name);
            SchedulerStatusSnapshot {
                enabled: inner.enabled,
                engine: "tokio_cron_scheduler",
                startup_delay_seconds: inner.startup_delay.as_secs(),
                jobs,
            }
        })
    }

    fn apply_job_transition(
        &self,
        spec: ScheduledJobSpec,
        transition: SchedulerJobTransition<'_>,
    ) -> SchedulerJobStatus {
        self.with_write(|inner| {
            let current = inner
                .jobs
                .entry(spec.name.as_str())
                .or_insert_with(|| SchedulerJobStatus::new(spec))
                .clone();
            let next = current.apply_transition(transition);
            inner.jobs.insert(spec.name.as_str(), next.clone());
            next
        })
    }

    fn with_read<T>(&self, read: impl FnOnce(&SchedulerStatusInner) -> T) -> T {
        match self.inner.read() {
            Ok(guard) => read(&guard),
            Err(poisoned) => read(&poisoned.into_inner()),
        }
    }

    fn with_write<T>(&self, write: impl FnOnce(&mut SchedulerStatusInner) -> T) -> T {
        match self.inner.write() {
            Ok(mut guard) => write(&mut guard),
            Err(poisoned) => write(&mut poisoned.into_inner()),
        }
    }
}

impl SchedulerJobStatus {
    fn new(spec: ScheduledJobSpec) -> Self {
        Self {
            job_name: spec.name.as_str(),
            cron: spec.cron,
            timeout_seconds: spec.timeout.as_secs(),
            running: false,
            last_status: None,
            last_started_at: None,
            last_completed_at: None,
            last_failed_at: None,
            last_skipped_at: None,
            failure_streak: 0,
            failure_streak_started_at: None,
        }
    }

    fn apply_transition(mut self, transition: SchedulerJobTransition<'_>) -> Self {
        match transition {
            SchedulerJobTransition::Started(started_at) => {
                self.running = true;
                self.last_status = Some("started");
                self.last_started_at = Some(timestamp_string(started_at));
            }
            SchedulerJobTransition::Completed(completed_at) => {
                self.running = false;
                self.last_status = Some("completed");
                self.last_completed_at = Some(timestamp_string(completed_at));
                self.failure_streak = 0;
                self.failure_streak_started_at = None;
            }
            SchedulerJobTransition::Failed(failed_at) => {
                self.running = false;
                self.last_status = Some("failed");
                self.last_failed_at = Some(timestamp_string(failed_at));
                if self.failure_streak == 0 {
                    self.failure_streak_started_at = Some(timestamp_string(failed_at));
                }
                self.failure_streak = self.failure_streak.saturating_add(1);
            }
            SchedulerJobTransition::Skipped(skipped_at) => {
                self.running = false;
                self.last_status = Some("skipped");
                self.last_skipped_at = Some(timestamp_string(skipped_at));
            }
        }
        self
    }
}

fn timestamp_string(timestamp: &SourceEventAt) -> String {
    timestamp.as_str().to_owned()
}

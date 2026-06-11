mod audit;
mod catalog;
mod engine;
mod jobs;
#[cfg(test)]
mod legacy_test;
mod status;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::archive::AnyArchiveBackend;
use crate::timestamping::AnyTimestampingProvider;

pub use engine::run_scheduler_loop;
pub use status::{SchedulerJobStatus, SchedulerStatusSnapshot, SchedulerStatusState};

pub(crate) use jobs::verify_full_ledger_signatures;

#[cfg(test)]
pub(crate) use catalog::{SCHEDULED_JOB_SPECS, ScheduledJobName};
#[cfg(test)]
pub(crate) use jobs::previous_month_period;
#[cfg(test)]
pub(crate) use legacy_test::{
    JobLock, JobRunKey, SchedulerRuntimeState, daily_due, daily_period_key, monthly_due,
    quarterly_due, run_once_per_period,
};
#[cfg(test)]
pub(crate) use time::{Month, OffsetDateTime};

#[derive(Clone)]
pub struct SchedulerConfig {
    pub startup_delay: Duration,
    pub poll_interval: Duration,
    pub monthly_day: u8,
    pub monthly_hour_utc: u8,
    pub quarterly_hour_utc: u8,
    pub daily_hour_utc: u8,
    pub envelope_migration_batch_size: u32,
    pub envelope_migration_max_batches: u32,
    pub restore_test_sample_limit: u32,
    pub local_archive_dir: PathBuf,
    pub archive_backend: Option<Arc<AnyArchiveBackend>>,
    pub timestamping_provider: Option<Arc<AnyTimestampingProvider>>,
}

#[cfg(test)]
#[path = "../../tests/unit/server/scheduler/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/unit/server/scheduler/ledger_verification_count_tests.rs"]
mod ledger_verification_count_tests;

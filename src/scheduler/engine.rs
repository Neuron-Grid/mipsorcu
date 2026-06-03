use std::time::{Duration, Instant};

use tokio::sync::watch;
use tokio_cron_scheduler::{Job, JobScheduler};

use crate::server::state::AppState;
use crate::types::SourceEventAt;

use super::SchedulerConfig;
use super::audit::{
    record_scheduler_completed, record_scheduler_failed, record_scheduler_failure_incident,
    record_scheduler_skipped, record_scheduler_started,
};
use super::catalog::{SCHEDULED_JOB_SPECS, SCHEDULER_LOCK_TTL_SECONDS, ScheduledJobSpec};
use super::jobs::{JobExecutionSummary, run_job_body};
use super::status::SchedulerStatusState;

const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(250);

pub async fn run_scheduler_loop(
    state: AppState,
    config: SchedulerConfig,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    state.scheduler_status.register_jobs(SCHEDULED_JOB_SPECS);
    if sleep_until_first_run(config.startup_delay, &mut shutdown_receiver).await {
        return;
    }

    let Some(mut scheduler) = initialize_scheduler().await else {
        return;
    };

    if !register_scheduled_jobs(&mut scheduler, &state, &config).await {
        return;
    }

    if !start_scheduler(&mut scheduler).await {
        return;
    }

    wait_for_shutdown_signal(&mut shutdown_receiver).await;
    stop_scheduler(&mut scheduler, &state).await;
}

async fn initialize_scheduler() -> Option<JobScheduler> {
    match JobScheduler::new().await {
        Ok(scheduler) => Some(scheduler),
        Err(error) => {
            tracing::error!(error = %error, "scheduler engine initialization failed");
            None
        }
    }
}

async fn register_scheduled_jobs(
    scheduler: &mut JobScheduler,
    state: &AppState,
    config: &SchedulerConfig,
) -> bool {
    for &spec in SCHEDULED_JOB_SPECS {
        let Some(job) = build_scheduled_job(state, config, spec) else {
            return false;
        };
        if let Err(error) = scheduler.add(job).await {
            tracing::error!(
                job_name = spec.name.as_str(),
                cron = spec.cron,
                error = %error,
                "scheduler job add failed"
            );
            return false;
        }
    }
    true
}

fn build_scheduled_job(
    state: &AppState,
    config: &SchedulerConfig,
    spec: ScheduledJobSpec,
) -> Option<Job> {
    let job_state = state.clone();
    let job_config = config.clone();
    match Job::new_async(spec.cron, move |_job_id, _scheduler| {
        let run_state = job_state.clone();
        let run_config = job_config.clone();
        Box::pin(async move {
            run_scheduled_job(run_state, run_config, spec).await;
        })
    }) {
        Ok(job) => Some(job),
        Err(error) => {
            tracing::error!(
                job_name = spec.name.as_str(),
                cron = spec.cron,
                error = %error,
                "scheduler job registration failed"
            );
            None
        }
    }
}

async fn start_scheduler(scheduler: &mut JobScheduler) -> bool {
    match scheduler.start().await {
        Ok(()) => true,
        Err(error) => {
            tracing::error!(error = %error, "scheduler engine start failed");
            false
        }
    }
}

async fn wait_for_shutdown_signal(shutdown_receiver: &mut watch::Receiver<bool>) {
    loop {
        let result = shutdown_receiver.changed().await;
        if result.is_err() || *shutdown_receiver.borrow() {
            break;
        }
    }
}

async fn stop_scheduler(scheduler: &mut JobScheduler, state: &AppState) {
    if let Err(error) = scheduler.shutdown().await {
        tracing::error!(error = %error, "scheduler engine shutdown failed");
    }
    wait_for_running_jobs_to_drain(&state.scheduler_status, SHUTDOWN_DRAIN_TIMEOUT).await;
    tracing::info!("scheduler loop stopped");
}

async fn wait_for_running_jobs_to_drain(status: &SchedulerStatusState, max_wait: Duration) {
    let started_at = Instant::now();
    loop {
        if !has_running_jobs(status) {
            return;
        }
        if started_at.elapsed() >= max_wait {
            tracing::warn!(
                error_code = "scheduler_shutdown_timeout",
                "scheduler shutdown timed out while jobs were still running"
            );
            return;
        }
        tokio::time::sleep(SHUTDOWN_DRAIN_POLL_INTERVAL).await;
    }
}

fn has_running_jobs(status: &SchedulerStatusState) -> bool {
    status.snapshot().jobs.iter().any(|job| job.running)
}

enum JobLockOutcome {
    Acquired,
    Skipped,
    Failed,
}

async fn run_scheduled_job(state: AppState, config: SchedulerConfig, spec: ScheduledJobSpec) {
    let Some(scheduled_at) = source_event_at(spec) else {
        return;
    };

    match acquire_job_lock(&state, spec, &scheduled_at).await {
        JobLockOutcome::Acquired => {}
        JobLockOutcome::Skipped => {
            record_job_skipped(&state, spec, &scheduled_at).await;
            return;
        }
        JobLockOutcome::Failed => return,
    }

    let started_at = mark_job_started(&state, spec, &scheduled_at).await;
    let result = run_job_with_timeout(state.clone(), config.clone(), spec).await;
    record_job_result(&state, spec, &started_at, result).await;
    release_job_lock(&state, spec).await;
}

async fn acquire_job_lock(
    state: &AppState,
    spec: ScheduledJobSpec,
    scheduled_at: &SourceEventAt,
) -> JobLockOutcome {
    match state
        .supabase_client
        .acquire_scheduler_lock(spec.name.as_str(), SCHEDULER_LOCK_TTL_SECONDS)
        .await
    {
        Ok(true) => JobLockOutcome::Acquired,
        Ok(false) => JobLockOutcome::Skipped,
        Err(error) => {
            let failed_at = source_event_at_or(scheduled_at);
            record_job_failed(
                state,
                spec,
                scheduled_at,
                &failed_at,
                "scheduler_lock_acquire_failed",
            )
            .await;
            tracing::error!(
                job_name = spec.name.as_str(),
                error = %error,
                "scheduler lock acquire RPC failed"
            );
            JobLockOutcome::Failed
        }
    }
}

async fn record_job_skipped(
    state: &AppState,
    spec: ScheduledJobSpec,
    scheduled_at: &SourceEventAt,
) {
    let skipped_at = source_event_at_or(scheduled_at);
    state.scheduler_status.mark_skipped(spec, &skipped_at);
    let _ = record_scheduler_skipped(state, spec, &skipped_at, "lock_not_acquired").await;
}

async fn mark_job_started(
    state: &AppState,
    spec: ScheduledJobSpec,
    scheduled_at: &SourceEventAt,
) -> SourceEventAt {
    let started_at = source_event_at_or(scheduled_at);
    state.scheduler_status.mark_started(spec, &started_at);
    if record_scheduler_started(state, spec, scheduled_at, &started_at)
        .await
        .is_err()
    {
        tracing::error!(
            job_name = spec.name.as_str(),
            "scheduler started audit recording failed"
        );
    }
    started_at
}

async fn run_job_with_timeout(
    state: AppState,
    config: SchedulerConfig,
    spec: ScheduledJobSpec,
) -> Result<JobExecutionSummary, &'static str> {
    let handle = tokio::spawn(async move { run_job_body(&state, &config, spec).await });
    match tokio::time::timeout(spec.timeout, handle).await {
        Ok(Ok(Ok(summary))) => Ok(summary),
        Ok(Ok(Err(error_code))) => Err(error_code),
        Ok(Err(error)) => {
            tracing::error!(
                job_name = spec.name.as_str(),
                error = %error,
                "scheduler job task failed to join"
            );
            Err("scheduler_job_join_failed")
        }
        Err(_) => Err("scheduler_job_timeout"),
    }
}

async fn record_job_result(
    state: &AppState,
    spec: ScheduledJobSpec,
    started_at: &SourceEventAt,
    result: Result<JobExecutionSummary, &'static str>,
) {
    match result {
        Ok(summary) => {
            let completed_at = source_event_at_or(started_at);
            state.scheduler_status.mark_completed(spec, &completed_at);
            let _ =
                record_scheduler_completed(state, spec, started_at, &completed_at, &summary).await;
        }
        Err(error_code) => {
            let failed_at = source_event_at_or(started_at);
            record_job_failed(state, spec, started_at, &failed_at, error_code).await;
        }
    }
}

async fn record_job_failed(
    state: &AppState,
    spec: ScheduledJobSpec,
    started_at: &SourceEventAt,
    failed_at: &SourceEventAt,
    error_code: &'static str,
) {
    let failure_streak = state.scheduler_status.mark_failed(spec, failed_at);
    let _ = record_scheduler_failed(state, spec, started_at, failed_at, error_code).await;
    if failure_streak >= 3 {
        record_scheduler_failure_incident(state, spec, error_code).await;
    }
}

async fn release_job_lock(state: &AppState, spec: ScheduledJobSpec) {
    if let Err(error) = state
        .supabase_client
        .release_scheduler_lock(spec.name.as_str())
        .await
    {
        tracing::error!(
            job_name = spec.name.as_str(),
            error = %error,
            "scheduler lock release RPC failed"
        );
    }
}

fn source_event_at(spec: ScheduledJobSpec) -> Option<SourceEventAt> {
    match SourceEventAt::now_utc() {
        Ok(timestamp) => Some(timestamp),
        Err(error) => {
            tracing::error!(
                job_name = spec.name.as_str(),
                error = %error,
                "scheduler scheduled_at generation failed"
            );
            None
        }
    }
}

fn source_event_at_or(fallback: &SourceEventAt) -> SourceEventAt {
    SourceEventAt::now_utc().unwrap_or_else(|_| fallback.clone())
}

async fn sleep_until_first_run(
    startup_delay: Duration,
    shutdown_receiver: &mut watch::Receiver<bool>,
) -> bool {
    if startup_delay.is_zero() {
        return false;
    }

    tokio::select! {
        result = shutdown_receiver.changed() => {
            if result.is_err() || *shutdown_receiver.borrow() {
                tracing::info!("scheduler loop stopped before first run");
                true
            } else {
                false
            }
        }
        _ = tokio::time::sleep(startup_delay) => false,
    }
}

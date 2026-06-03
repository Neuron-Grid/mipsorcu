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
use super::jobs::run_job_body;
use super::status::SchedulerStatusState;

pub async fn run_scheduler_loop(
    state: AppState,
    config: SchedulerConfig,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    state.scheduler_status.register_jobs(SCHEDULED_JOB_SPECS);
    if sleep_until_first_run(config.startup_delay, &mut shutdown_receiver).await {
        return;
    }

    let mut scheduler = match JobScheduler::new().await {
        Ok(scheduler) => scheduler,
        Err(error) => {
            tracing::error!(error = %error, "scheduler engine initialization failed");
            return;
        }
    };

    for &spec in SCHEDULED_JOB_SPECS {
        let job_state = state.clone();
        let job_config = config.clone();
        let job = match Job::new_async(spec.cron, move |_job_id, _scheduler| {
            let run_state = job_state.clone();
            let run_config = job_config.clone();
            Box::pin(async move {
                run_scheduled_job(run_state, run_config, spec).await;
            })
        }) {
            Ok(job) => job,
            Err(error) => {
                tracing::error!(
                    job_name = spec.name.as_str(),
                    cron = spec.cron,
                    error = %error,
                    "scheduler job registration failed"
                );
                return;
            }
        };
        if let Err(error) = scheduler.add(job).await {
            tracing::error!(
                job_name = spec.name.as_str(),
                cron = spec.cron,
                error = %error,
                "scheduler job add failed"
            );
            return;
        }
    }

    if let Err(error) = scheduler.start().await {
        tracing::error!(error = %error, "scheduler engine start failed");
        return;
    }

    loop {
        let result = shutdown_receiver.changed().await;
        if result.is_err() || *shutdown_receiver.borrow() {
            break;
        }
    }

    if let Err(error) = scheduler.shutdown().await {
        tracing::error!(error = %error, "scheduler engine shutdown failed");
    }
    wait_for_running_jobs_to_drain(&state.scheduler_status, Duration::from_secs(30)).await;
    tracing::info!("scheduler loop stopped");
}

async fn wait_for_running_jobs_to_drain(status: &SchedulerStatusState, max_wait: Duration) {
    let started_at = Instant::now();
    loop {
        if !status.snapshot().jobs.iter().any(|job| job.running) {
            return;
        }
        if started_at.elapsed() >= max_wait {
            tracing::warn!(
                error_code = "scheduler_shutdown_timeout",
                "scheduler shutdown timed out while jobs were still running"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn run_scheduled_job(state: AppState, config: SchedulerConfig, spec: ScheduledJobSpec) {
    let scheduled_at = match SourceEventAt::now_utc() {
        Ok(timestamp) => timestamp,
        Err(error) => {
            tracing::error!(
                job_name = spec.name.as_str(),
                error = %error,
                "scheduler scheduled_at generation failed"
            );
            return;
        }
    };

    let acquired = match state
        .supabase_client
        .acquire_scheduler_lock(spec.name.as_str(), SCHEDULER_LOCK_TTL_SECONDS)
        .await
    {
        Ok(acquired) => acquired,
        Err(error) => {
            let failed_at = match SourceEventAt::now_utc() {
                Ok(timestamp) => timestamp,
                Err(_) => scheduled_at.clone(),
            };
            let failure_streak = state.scheduler_status.mark_failed(spec, &failed_at);
            let _ = record_scheduler_failed(
                &state,
                spec,
                &scheduled_at,
                &failed_at,
                "scheduler_lock_acquire_failed",
            )
            .await;
            if failure_streak >= 3 {
                record_scheduler_failure_incident(&state, spec, "scheduler_lock_acquire_failed")
                    .await;
            }
            tracing::error!(
                job_name = spec.name.as_str(),
                error = %error,
                "scheduler lock acquire RPC failed"
            );
            return;
        }
    };

    if !acquired {
        let skipped_at = match SourceEventAt::now_utc() {
            Ok(timestamp) => timestamp,
            Err(_) => scheduled_at.clone(),
        };
        state.scheduler_status.mark_skipped(spec, &skipped_at);
        let _ = record_scheduler_skipped(&state, spec, &skipped_at, "lock_not_acquired").await;
        return;
    }

    let started_at = match SourceEventAt::now_utc() {
        Ok(timestamp) => timestamp,
        Err(_) => scheduled_at.clone(),
    };
    state.scheduler_status.mark_started(spec, &started_at);
    if record_scheduler_started(&state, spec, &scheduled_at, &started_at)
        .await
        .is_err()
    {
        tracing::error!(
            job_name = spec.name.as_str(),
            "scheduler started audit recording failed"
        );
    }

    let run_state = state.clone();
    let run_config = config.clone();
    let handle = tokio::spawn(async move { run_job_body(&run_state, &run_config, spec).await });
    let result = match tokio::time::timeout(spec.timeout, handle).await {
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
    };

    match result {
        Ok(summary) => {
            let completed_at = match SourceEventAt::now_utc() {
                Ok(timestamp) => timestamp,
                Err(_) => started_at.clone(),
            };
            state.scheduler_status.mark_completed(spec, &completed_at);
            let _ = record_scheduler_completed(&state, spec, &started_at, &completed_at, &summary)
                .await;
        }
        Err(error_code) => {
            let failed_at = match SourceEventAt::now_utc() {
                Ok(timestamp) => timestamp,
                Err(_) => started_at.clone(),
            };
            let failure_streak = state.scheduler_status.mark_failed(spec, &failed_at);
            let _ =
                record_scheduler_failed(&state, spec, &started_at, &failed_at, error_code).await;
            if failure_streak >= 3 {
                record_scheduler_failure_incident(&state, spec, error_code).await;
            }
        }
    }

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

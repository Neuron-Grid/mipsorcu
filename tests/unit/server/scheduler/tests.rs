use super::*;
use time::{Date, Time};

fn dt(year: i32, month: Month, day: u8, hour: u8) -> OffsetDateTime {
    let date = Date::from_calendar_date(year, month, day).expect("valid test date");
    let time = Time::from_hms(hour, 0, 0).expect("valid test time");
    date.with_time(time).assume_utc()
}

#[test]
fn monthly_due_respects_day_and_hour() {
    assert!(monthly_due(dt(2026, Month::June, 1, 3), 1, 3));
    assert!(monthly_due(dt(2026, Month::June, 1, 4), 1, 3));
    assert!(!monthly_due(dt(2026, Month::June, 1, 2), 1, 3));
    assert!(!monthly_due(dt(2026, Month::June, 2, 3), 1, 3));
}

#[test]
fn quarterly_due_only_runs_on_quarter_boundary_months() {
    assert!(quarterly_due(dt(2026, Month::April, 1, 4), 1, 4));
    assert!(!quarterly_due(dt(2026, Month::May, 1, 4), 1, 4));
    assert!(!quarterly_due(dt(2026, Month::April, 1, 3), 1, 4));
}

#[test]
fn daily_due_respects_hour_boundary() {
    assert!(!daily_due(dt(2026, Month::June, 1, 3), 4));
    assert!(daily_due(dt(2026, Month::June, 1, 4), 4));
    assert!(daily_due(dt(2026, Month::June, 1, 5), 4));
    assert!(daily_due(dt(2026, Month::June, 1, 23), 4));
}

#[test]
fn daily_period_key_encodes_year_month_day() {
    assert_eq!(daily_period_key(dt(2026, Month::June, 1, 4)), "2026-06-01");
    assert_eq!(
        daily_period_key(dt(2025, Month::December, 31, 23)),
        "2025-12-31"
    );
}

#[test]
fn scheduled_job_name_includes_new_v02_jobs() {
    assert_eq!(
        ScheduledJobName::MonthlyTimestampingObtain.as_str(),
        "monthly_timestamping_obtain"
    );
    assert_eq!(
        ScheduledJobName::DailyEnvelopeLazyMigration.as_str(),
        "daily_envelope_lazy_migration"
    );
}

#[test]
fn scheduler_runtime_state_assigns_distinct_locks_for_new_jobs() {
    let runtime_state = SchedulerRuntimeState::new();
    let timestamping_lock_ptr = std::ptr::from_ref::<JobLock>(
        runtime_state.lock_for(ScheduledJobName::MonthlyTimestampingObtain),
    );
    let envelope_lock_ptr = std::ptr::from_ref::<JobLock>(
        runtime_state.lock_for(ScheduledJobName::DailyEnvelopeLazyMigration),
    );
    let archive_lock_ptr =
        std::ptr::from_ref::<JobLock>(runtime_state.lock_for(ScheduledJobName::ArchiveExport));
    assert_ne!(timestamping_lock_ptr, envelope_lock_ptr);
    assert_ne!(timestamping_lock_ptr, archive_lock_ptr);
    assert_ne!(envelope_lock_ptr, archive_lock_ptr);
}

#[tokio::test]
async fn run_once_per_period_marks_new_jobs_distinctly() {
    let mut runtime_state = SchedulerRuntimeState::new();
    let timestamping_key = JobRunKey {
        job_name: ScheduledJobName::MonthlyTimestampingObtain,
        period_key: "2026-05".to_owned(),
    };
    let envelope_key = JobRunKey {
        job_name: ScheduledJobName::DailyEnvelopeLazyMigration,
        period_key: "2026-05-29".to_owned(),
    };

    let first = run_once_per_period(&mut runtime_state, timestamping_key.clone(), async {
        Ok::<_, &str>("ok")
    })
    .await;
    let second = run_once_per_period(&mut runtime_state, envelope_key.clone(), async {
        Ok::<_, &str>("ok")
    })
    .await;
    let third = run_once_per_period(&mut runtime_state, timestamping_key.clone(), async {
        Ok::<_, &str>("ok")
    })
    .await;

    assert_eq!(first, Ok(Some("ok")));
    assert_eq!(second, Ok(Some("ok")));
    assert_eq!(third, Ok(None));
    assert!(runtime_state.completed.contains(&timestamping_key));
    assert!(runtime_state.completed.contains(&envelope_key));
}

#[test]
fn previous_month_period_wraps_year() {
    assert_eq!(
        previous_month_period(dt(2026, Month::June, 1, 3))
            .unwrap()
            .as_str(),
        "2026-05"
    );
    assert_eq!(
        previous_month_period(dt(2026, Month::January, 1, 3))
            .unwrap()
            .as_str(),
        "2025-12"
    );
}

#[test]
fn job_lock_prevents_reentry_until_guard_drops() {
    let lock = JobLock::new();
    let first = lock.try_enter();
    assert!(first.is_some());
    assert!(lock.try_enter().is_none());
    drop(first);
    assert!(lock.try_enter().is_some());
}

#[tokio::test]
async fn run_once_per_period_does_not_complete_failed_job() {
    let mut runtime_state = SchedulerRuntimeState::new();
    let key = JobRunKey {
        job_name: ScheduledJobName::MonthlyDigestGenerate,
        period_key: "2026-05".to_owned(),
    };

    let result = run_once_per_period(&mut runtime_state, key.clone(), async {
        Err::<(), _>("synthetic_failure")
    })
    .await;

    assert_eq!(result, Err("synthetic_failure"));
    assert!(!runtime_state.completed.contains(&key));
}

#[tokio::test]
async fn run_once_per_period_returns_none_for_completed_job() {
    let mut runtime_state = SchedulerRuntimeState::new();
    let key = JobRunKey {
        job_name: ScheduledJobName::ArchiveExport,
        period_key: "2026-05".to_owned(),
    };

    let first =
        run_once_per_period(&mut runtime_state, key.clone(), async { Ok::<_, &str>(7) }).await;
    let second = run_once_per_period(&mut runtime_state, key, async { Ok::<_, &str>(11) }).await;

    assert_eq!(first, Ok(Some(7)));
    assert_eq!(second, Ok(None));
}

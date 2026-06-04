use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::audit::AuditEventError;
use crate::types::SourceEventAt;

use super::{
    ComponentName, IncidentCategory, IncidentDtoError, IncidentId, IncidentNotification,
    IncidentSeverity, IncidentSummary,
};

const SCHEDULER_FAILURE_STREAK_THRESHOLD: u32 = 3;
const PERSISTENT_FAILURE_THRESHOLD: Duration = Duration::from_secs(24 * 60 * 60);
const SIEM_BUFFER_THRESHOLD_BYTES: u64 = 80 * 1024 * 1024;
const ENVELOPE_FAILURE_BURST_THRESHOLD: usize = 10;
const AUTH_FAILURE_BURST_THRESHOLD: usize = 10;
const BURST_WINDOW: Duration = Duration::from_secs(60 * 60);

#[derive(Debug)]
pub enum IncidentDetectorError {
    IdGenerationFailed,
    TimestampUnavailable,
    InvalidNotification(IncidentDtoError),
}

impl fmt::Display for IncidentDetectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdGenerationFailed => formatter.write_str("incident id generation failed"),
            Self::TimestampUnavailable => formatter.write_str("incident timestamp unavailable"),
            Self::InvalidNotification(error) => {
                write!(formatter, "invalid incident notification: {error}")
            }
        }
    }
}

impl std::error::Error for IncidentDetectorError {}

impl From<AuditEventError> for IncidentDetectorError {
    fn from(_error: AuditEventError) -> Self {
        Self::IdGenerationFailed
    }
}

impl From<IncidentDtoError> for IncidentDetectorError {
    fn from(error: IncidentDtoError) -> Self {
        Self::InvalidNotification(error)
    }
}

#[derive(Clone, Default)]
pub struct IncidentDetector {
    envelope_failures: Arc<Mutex<VecDeque<Instant>>>,
    auth_failures: Arc<Mutex<VecDeque<Instant>>>,
}

impl IncidentDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn scheduler_failure(
        &self,
        job_name: &str,
        failure_streak: u32,
        error_code: &str,
    ) -> Result<Option<IncidentNotification>, IncidentDetectorError> {
        if failure_streak < SCHEDULER_FAILURE_STREAK_THRESHOLD {
            return Ok(None);
        }
        build_notification(
            IncidentCategory::SchedulerFailure,
            IncidentSeverity::High,
            format!("scheduler job {job_name} failed {failure_streak} consecutive times"),
            vec![ComponentName::scheduler()],
            format!("scheduler:{job_name}:{error_code}"),
        )
        .map(Some)
    }

    pub fn ledger_anomaly(
        &self,
        source: &str,
        error_code: &str,
    ) -> Result<IncidentNotification, IncidentDetectorError> {
        build_notification(
            IncidentCategory::LedgerAnomaly,
            IncidentSeverity::Critical,
            format!("ledger anomaly detected by {source}"),
            vec![ComponentName::ledger()],
            format!("ledger:{source}:{error_code}"),
        )
    }

    pub fn persistent_archive_failure(
        &self,
        failed_for: Duration,
        error_code: &str,
    ) -> Result<Option<IncidentNotification>, IncidentDetectorError> {
        if failed_for < PERSISTENT_FAILURE_THRESHOLD {
            return Ok(None);
        }
        build_notification(
            IncidentCategory::ArchiveFailurePersistent,
            IncidentSeverity::High,
            "archive failure persisted for 24 hours",
            vec![ComponentName::archive()],
            format!("archive:persistent:{error_code}"),
        )
        .map(Some)
    }

    pub fn persistent_timestamping_failure(
        &self,
        failed_for: Duration,
        error_code: &str,
    ) -> Result<Option<IncidentNotification>, IncidentDetectorError> {
        if failed_for < PERSISTENT_FAILURE_THRESHOLD {
            return Ok(None);
        }
        build_notification(
            IncidentCategory::TimestampingFailurePersistent,
            IncidentSeverity::High,
            "timestamping failure persisted for 24 hours",
            vec![ComponentName::timestamping()],
            format!("timestamping:persistent:{error_code}"),
        )
        .map(Some)
    }

    pub fn siem_buffer_threshold(
        &self,
        current_size_bytes: u64,
    ) -> Result<Option<IncidentNotification>, IncidentDetectorError> {
        if current_size_bytes < SIEM_BUFFER_THRESHOLD_BYTES {
            return Ok(None);
        }
        build_notification(
            IncidentCategory::SiemBufferThreshold,
            IncidentSeverity::High,
            "siem fallback buffer reached notification threshold",
            vec![ComponentName::siem()],
            format!("siem:buffer:{current_size_bytes}"),
        )
        .map(Some)
    }

    pub fn record_envelope_migration_failure(
        &self,
        error_code: &str,
    ) -> Result<Option<IncidentNotification>, IncidentDetectorError> {
        let now = Instant::now();
        let count = record_burst_event(&self.envelope_failures, now, BURST_WINDOW);
        if count < ENVELOPE_FAILURE_BURST_THRESHOLD {
            return Ok(None);
        }
        build_notification(
            IncidentCategory::EnvelopeMigrationFailureBurst,
            IncidentSeverity::High,
            format!("envelope migration failure burst reached {count} events"),
            vec![
                ComponentName::envelope_migration(),
                ComponentName::key_rotation(),
            ],
            format!("envelope_migration:burst:{error_code}"),
        )
        .map(Some)
    }

    pub fn record_auth_failure(
        &self,
        _error_code: &str,
    ) -> Result<Option<IncidentNotification>, IncidentDetectorError> {
        let now = Instant::now();
        let count = record_burst_event(&self.auth_failures, now, BURST_WINDOW);
        if count < AUTH_FAILURE_BURST_THRESHOLD {
            return Ok(None);
        }
        build_notification(
            IncidentCategory::AuthFailureBurst,
            IncidentSeverity::Medium,
            format!("global auth failure burst reached {count} events"),
            vec![ComponentName::auth()],
            "auth:global_burst",
        )
        .map(Some)
    }

    pub fn key_rotation_failure(
        &self,
        error_code: &str,
    ) -> Result<IncidentNotification, IncidentDetectorError> {
        build_notification(
            IncidentCategory::KeyRotationFailure,
            IncidentSeverity::High,
            "key rotation failure detected",
            vec![ComponentName::key_rotation()],
            format!("key_rotation:{error_code}"),
        )
    }
}

fn record_burst_event(
    events: &Arc<Mutex<VecDeque<Instant>>>,
    now: Instant,
    window: Duration,
) -> usize {
    let mut guard = match events.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.push_back(now);
    while guard
        .front()
        .is_some_and(|event_at| now.duration_since(*event_at) > window)
    {
        let _ = guard.pop_front();
    }
    guard.len()
}

fn build_notification(
    category: IncidentCategory,
    severity: IncidentSeverity,
    summary: impl Into<String>,
    components: Vec<ComponentName>,
    correlation_id: impl Into<String>,
) -> Result<IncidentNotification, IncidentDetectorError> {
    let source_event_at =
        SourceEventAt::now_utc().map_err(|_| IncidentDetectorError::TimestampUnavailable)?;
    let detected_at = source_event_at.clone();
    let notification = IncidentNotification::new(
        IncidentId::generate()?,
        detected_at,
        category,
        severity,
        IncidentSummary::new(summary.into())?,
        components,
        source_event_at,
    )?
    .with_correlation_id(correlation_id.into())?;
    Ok(notification)
}

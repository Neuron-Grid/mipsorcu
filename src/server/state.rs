use std::sync::{Arc, RwLock};
use std::time::Duration;

use time::OffsetDateTime;

use crate::MasterKeyRing;
use crate::audit::{AuditRecorder, LocalAuditFallbackStore};
use crate::auth::JwtVerifier;

use super::supabase::{SupabaseAuditAppender, SupabaseClient};

#[derive(Clone)]
pub struct AppState {
    pub master_key_ring: Arc<MasterKeyRing>,
    pub jwt_verifier: Arc<JwtVerifier>,
    pub supabase_client: Arc<SupabaseClient>,
    pub audit_recorder: Arc<AuditRecorder<SupabaseAuditAppender>>,
    pub audit_fallback_store: LocalAuditFallbackStore,
    pub readiness_state: ReadinessState,
    pub health_readiness_poll_interval: Duration,
}

#[derive(Clone, Default)]
pub struct ReadinessState {
    inner: Arc<RwLock<ReadinessStateInner>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct ReadinessStateInner {
    supabase_reachable: bool,
    supabase_last_checked_at: Option<OffsetDateTime>,
    failure_audit_both_failed_last_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReadinessSnapshot {
    pub supabase_reachable: bool,
    pub supabase_last_checked_at: Option<OffsetDateTime>,
    pub failure_audit_both_failed_last_at: Option<OffsetDateTime>,
}

impl ReadinessState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> ReadinessSnapshot {
        self.with_read(|state| ReadinessSnapshot {
            supabase_reachable: state.supabase_reachable,
            supabase_last_checked_at: state.supabase_last_checked_at,
            failure_audit_both_failed_last_at: state.failure_audit_both_failed_last_at,
        })
    }

    pub fn record_supabase_probe_result(&self, reachable: bool) {
        self.record_supabase_probe_result_at(reachable, OffsetDateTime::now_utc());
    }

    pub fn record_supabase_probe_result_at(&self, reachable: bool, checked_at: OffsetDateTime) {
        self.with_write(|state| {
            state.supabase_reachable = reachable;
            state.supabase_last_checked_at = Some(checked_at);
        });
    }

    pub fn mark_failure_audit_both_failed(&self) {
        self.mark_failure_audit_both_failed_at(OffsetDateTime::now_utc());
    }

    pub fn mark_failure_audit_both_failed_at(&self, occurred_at: OffsetDateTime) {
        self.with_write(|state| {
            state.failure_audit_both_failed_last_at = Some(occurred_at);
        });
    }

    fn with_read<T>(&self, read: impl FnOnce(&ReadinessStateInner) -> T) -> T {
        match self.inner.read() {
            Ok(guard) => read(&guard),
            Err(poisoned) => read(&poisoned.into_inner()),
        }
    }

    fn with_write(&self, write: impl FnOnce(&mut ReadinessStateInner)) {
        match self.inner.write() {
            Ok(mut guard) => write(&mut guard),
            Err(poisoned) => write(&mut poisoned.into_inner()),
        }
    }
}

impl ReadinessSnapshot {
    pub fn supabase_is_fresh(&self, now: OffsetDateTime, max_age: Duration) -> bool {
        is_timestamp_within_age(self.supabase_last_checked_at, now, max_age)
    }

    pub fn failure_audit_both_failed_recent(&self, now: OffsetDateTime, ttl: Duration) -> bool {
        is_timestamp_within_age(self.failure_audit_both_failed_last_at, now, ttl)
    }
}

fn is_timestamp_within_age(
    timestamp: Option<OffsetDateTime>,
    now: OffsetDateTime,
    max_age: Duration,
) -> bool {
    let Some(timestamp) = timestamp else {
        return false;
    };
    let Ok(max_age) = time::Duration::try_from(max_age) else {
        return false;
    };

    now - timestamp <= max_age
}

impl std::fmt::Debug for ReadinessState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snapshot = self.snapshot();

        formatter
            .debug_struct("ReadinessState")
            .field("supabase_reachable", &snapshot.supabase_reachable)
            .field(
                "supabase_last_checked_at",
                &snapshot
                    .supabase_last_checked_at
                    .map(|timestamp| timestamp.unix_timestamp()),
            )
            .field(
                "failure_audit_both_failed_last_at",
                &snapshot
                    .failure_audit_both_failed_last_at
                    .map(|timestamp| timestamp.unix_timestamp()),
            )
            .finish()
    }
}

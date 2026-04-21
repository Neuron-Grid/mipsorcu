use std::fs::OpenOptions;
use std::path::Path;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::server::dto::{ApiErrorResponse, HealthResponse, ReadyResponse};
use crate::server::state::AppState;

const FAILURE_AUDIT_BOTH_FAILED_TTL: Duration = Duration::from_secs(5 * 60);

pub async fn health_check(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let now = OffsetDateTime::now_utc();
    let snapshot = state.readiness_state.snapshot();
    let supabase_max_age = state
        .health_readiness_poll_interval
        .checked_mul(2)
        .unwrap_or(Duration::MAX);
    let supabase_reachable =
        snapshot.supabase_reachable && snapshot.supabase_is_fresh(now, supabase_max_age);
    let master_key_loaded = true;
    let disk_free_mb = available_disk_space_mb(state.audit_fallback_store.path());
    let is_up = supabase_reachable && master_key_loaded;
    let status = if is_up {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(HealthResponse {
            status: if is_up { "up" } else { "down" },
            supabase_reachable,
            master_key_loaded,
            disk_free_mb,
        }),
    )
}

pub async fn ready_check(State(state): State<AppState>) -> (StatusCode, Json<ReadyResponse>) {
    let now = OffsetDateTime::now_utc();
    let snapshot = state.readiness_state.snapshot();
    let supabase_max_age = state
        .health_readiness_poll_interval
        .checked_mul(2)
        .unwrap_or(Duration::MAX);
    let supabase_fresh = snapshot.supabase_is_fresh(now, supabase_max_age);
    let fallback_writable = fallback_is_writable(state.audit_fallback_store.path());
    let disk_free_mb = available_disk_space_mb(state.audit_fallback_store.path());
    let audit_failure_append_both_failed_recent =
        snapshot.failure_audit_both_failed_recent(now, FAILURE_AUDIT_BOTH_FAILED_TTL);
    let audit_fallback_pending = audit_fallback_pending_count(&state).await;
    let supabase_last_checked_at = format_timestamp(snapshot.supabase_last_checked_at);
    let master_key_loaded = true;
    let is_ready = snapshot.supabase_reachable
        && supabase_fresh
        && master_key_loaded
        && fallback_writable
        && !audit_failure_append_both_failed_recent;
    let status = if is_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(ReadyResponse {
            status: if is_ready { "ready" } else { "not_ready" },
            supabase_reachable: snapshot.supabase_reachable,
            supabase_last_checked_at,
            master_key_loaded,
            fallback_writable,
            disk_free_mb,
            audit_fallback_pending,
            audit_failure_append_both_failed_recent,
        }),
    )
}

pub async fn not_found() -> (StatusCode, Json<ApiErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ApiErrorResponse {
            error: "not found".to_owned(),
            code: "not_found".to_owned(),
        }),
    )
}

fn available_disk_space_mb(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::ffi::CString;

        let path_str = path.parent().unwrap_or(path).to_str()?;
        let c_path = CString::new(path_str).ok()?;
        // Safety: `stat` is immediately initialized by `statvfs`, and `c_path` is NUL-terminated.
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        // Safety: the pointers are valid for the duration of the call.
        let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
        if ret == 0 {
            Some((stat.f_bavail as u64 * stat.f_frsize as u64) / (1024 * 1024))
        } else {
            None
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

async fn audit_fallback_pending_count(state: &AppState) -> u64 {
    let fallback_store = state.audit_fallback_store.clone();

    match tokio::task::spawn_blocking(move || {
        fallback_store
            .pending_events()
            .map(|events| match u64::try_from(events.len()) {
                Ok(count) => count,
                Err(_) => u64::MAX,
            })
    })
    .await
    {
        Ok(Ok(count)) => count,
        Ok(Err(error)) => {
            tracing::error!(error = %error, "failed to count pending audit fallback events");
            0
        }
        Err(error) => {
            tracing::error!(error = %error, "pending audit fallback count task failed");
            0
        }
    }
}

fn fallback_is_writable(path: &Path) -> bool {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .is_ok()
}

fn format_timestamp(timestamp: Option<OffsetDateTime>) -> Option<String> {
    timestamp.and_then(|timestamp| timestamp.format(&Rfc3339).ok())
}

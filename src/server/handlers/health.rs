use std::path::Path;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use time::OffsetDateTime;

use crate::server::dto::HealthResponse;
use crate::server::errors::ApiError;
use crate::server::middleware::RequestContext;
use crate::server::state::AppState;

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
            supabase: if supabase_reachable { "ok" } else { "ng" },
            master_key: if master_key_loaded {
                "loaded"
            } else {
                "not_loaded"
            },
            disk_free_mb,
        }),
    )
}

pub async fn ready_check(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let now = OffsetDateTime::now_utc();
    let snapshot = state.readiness_state.snapshot();
    let supabase_max_age = state
        .health_readiness_poll_interval
        .checked_mul(2)
        .unwrap_or(Duration::MAX);
    let supabase_reachable =
        snapshot.supabase_reachable && snapshot.supabase_is_fresh(now, supabase_max_age);
    let disk_free_mb = available_disk_space_mb(state.audit_fallback_store.path());
    let master_key_loaded = true;
    let is_ready = supabase_reachable && master_key_loaded;
    let status = if is_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(HealthResponse {
            status: if is_ready { "ready" } else { "not_ready" },
            supabase: if supabase_reachable { "ok" } else { "ng" },
            master_key: if master_key_loaded {
                "loaded"
            } else {
                "not_loaded"
            },
            disk_free_mb,
        }),
    )
}

pub async fn not_found(request_context: RequestContext) -> impl IntoResponse {
    ApiError::NotFound("not found".to_owned())
        .with_request_id(request_context.request_id())
        .into_response()
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

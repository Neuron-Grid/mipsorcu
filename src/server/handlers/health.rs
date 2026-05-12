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

const READINESS_STALE_MULTIPLIER: u32 = 2;
const BYTES_PER_MEBIBYTE: u64 = 1024 * 1024;

pub async fn health_check(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let components = collect_health_components(&state);
    let is_up = components.supabase_reachable && components.master_key_loaded;

    let status = if is_up {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(HealthResponse {
            status: if is_up { "up" } else { "down" },
            supabase: if components.supabase_reachable {
                "ok"
            } else {
                "ng"
            },
            master_key: if components.master_key_loaded {
                "loaded"
            } else {
                "not_loaded"
            },
            siem: components.siem_status,
            disk_free_mb: components.disk_free_mb,
        }),
    )
}

pub async fn ready_check(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let components = collect_health_components(&state);
    let is_ready = components.supabase_reachable && components.master_key_loaded;

    let status = if is_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(HealthResponse {
            status: if is_ready { "ready" } else { "not_ready" },
            supabase: if components.supabase_reachable {
                "ok"
            } else {
                "ng"
            },
            master_key: if components.master_key_loaded {
                "loaded"
            } else {
                "not_loaded"
            },
            siem: components.siem_status,
            disk_free_mb: components.disk_free_mb,
        }),
    )
}

pub async fn not_found(request_context: RequestContext) -> impl IntoResponse {
    ApiError::NotFound("not found".to_owned())
        .with_request_id(request_context.request_id())
        .into_response()
}

struct HealthComponents {
    supabase_reachable: bool,
    master_key_loaded: bool,
    siem_status: &'static str,
    disk_free_mb: Option<u64>,
}

fn collect_health_components(state: &AppState) -> HealthComponents {
    let now = OffsetDateTime::now_utc();
    let snapshot = state.readiness_state.snapshot();

    let supabase_max_age = readiness_stale_threshold(state.health_readiness_poll_interval);
    let supabase_reachable =
        snapshot.supabase_reachable && snapshot.supabase_is_fresh(now, supabase_max_age);
    let siem_status = if state
        .siem_forwarding
        .status()
        .is_long_failure(now, state.siem_long_failure_threshold)
    {
        "degraded"
    } else {
        "ok"
    };

    HealthComponents {
        supabase_reachable,
        master_key_loaded: true,
        siem_status,
        disk_free_mb: available_disk_space_mb(state.audit_fallback_store.path()),
    }
}

fn readiness_stale_threshold(poll_interval: Duration) -> Duration {
    match poll_interval.checked_mul(READINESS_STALE_MULTIPLIER) {
        Some(duration) => duration,
        None => Duration::MAX,
    }
}

fn available_disk_space_mb(path: &Path) -> Option<u64> {
    let target = filesystem_probe_path(path);

    fs4::available_space(target)
        .ok()
        .map(|bytes| bytes / BYTES_PER_MEBIBYTE)
}

fn filesystem_probe_path(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) => parent,
        None => path,
    }
}

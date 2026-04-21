use std::path::Path;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use crate::server::dto::{ApiErrorResponse, HealthResponse};
use crate::server::state::AppState;

pub async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    let supabase_ok = state.supabase_client.check_connectivity().await;
    let disk_space = available_disk_space_mb(&state.audit_fallback_path);

    Json(HealthResponse {
        status: "up",
        supabase: if supabase_ok { "ok" } else { "ng" },
        master_key: "loaded",
        disk_space_mb: disk_space,
    })
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

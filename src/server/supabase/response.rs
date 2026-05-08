use reqwest::Response;
use serde_json::Value;

use super::SupabaseRpcError;

pub(super) async fn ensure_success(response: Response) -> Result<Response, SupabaseRpcError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }

    let body = response.text().await.unwrap_or_else(|_| String::new());
    Err(SupabaseRpcError::NonSuccessStatus {
        status: status.as_u16(),
        body,
    })
}

pub(super) fn response_contains_marker(body: &str, marker: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return body.contains(marker);
    };

    ["message", "details", "hint"].into_iter().any(|field| {
        value
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|text| text.contains(marker))
    })
}

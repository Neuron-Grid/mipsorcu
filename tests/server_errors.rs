use axum::body;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use mipsorcu::server::errors::ApiError;

#[tokio::test]
async fn internal_errors_do_not_expose_internal_messages_to_clients() {
    let response = ApiError::InternalInvariantViolation(
        "expected one current secret version row, got 2".to_owned(),
    )
    .into_response();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body_bytes = body::to_bytes(response.into_body(), 1024)
        .await
        .expect("response body should be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("error body should be JSON");

    assert_eq!(body["error"], "internal error");
    assert_eq!(body["code"], "internal_invariant_violation");
}

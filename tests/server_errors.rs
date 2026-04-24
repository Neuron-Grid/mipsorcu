use axum::body;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use mipsorcu::RequestId;
use mipsorcu::server::errors::{ApiError, RequestAwareApiError};
use mipsorcu::server::supabase::SupabaseRpcError;

const REQUEST_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn into_response_with_request_id(error: ApiError) -> axum::response::Response {
    RequestAwareApiError::new(
        error,
        RequestId::parse(REQUEST_ID).expect("test request id should parse"),
    )
    .into_response()
}

#[tokio::test]
async fn internal_errors_do_not_expose_internal_messages_to_clients() {
    let response = into_response_with_request_id(ApiError::InternalInvariantViolation(
        "expected one current secret version row, got 2".to_owned(),
    ));

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body_bytes = body::to_bytes(response.into_body(), 1024)
        .await
        .expect("response body should be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("error body should be JSON");

    assert_eq!(body["code"], "internal_invariant_violation");
    assert_eq!(body["request_id"], REQUEST_ID);
    assert!(
        !body
            .as_object()
            .is_some_and(|object| object.contains_key("error"))
    );
}

#[tokio::test]
async fn db_integrity_violations_do_not_expose_internal_messages_to_clients() {
    let response = into_response_with_request_id(ApiError::DbIntegrityViolation(
        "secret version classification does not match secret classification".to_owned(),
    ));

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let body_bytes = body::to_bytes(response.into_body(), 1024)
        .await
        .expect("response body should be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("error body should be JSON");

    assert_eq!(body["code"], "db_integrity_violation");
    assert_eq!(body["request_id"], REQUEST_ID);
    assert!(
        !body
            .as_object()
            .is_some_and(|object| object.contains_key("error"))
    );
}

#[tokio::test]
async fn upstream_supabase_errors_return_bad_gateway_without_leaking_details() {
    let response =
        into_response_with_request_id(ApiError::from(SupabaseRpcError::NonSuccessStatus {
            status: 401,
            body: "secret internal upstream details".to_owned(),
        }));

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

    let body_bytes = body::to_bytes(response.into_body(), 1024)
        .await
        .expect("response body should be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("error body should be JSON");

    assert_eq!(body["code"], "upstream_dependency_failed");
    assert_eq!(body["request_id"], REQUEST_ID);
    assert!(
        !body
            .as_object()
            .is_some_and(|object| object.contains_key("error"))
    );
    let rendered = String::from_utf8(body_bytes.to_vec()).expect("response body should be UTF-8");
    assert!(!rendered.contains("secret internal upstream details"));
}

#[tokio::test]
async fn audit_record_failures_return_service_unavailable_without_details() {
    let response = into_response_with_request_id(ApiError::AuditRecordFailed);

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body_bytes = body::to_bytes(response.into_body(), 1024)
        .await
        .expect("response body should be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("error body should be JSON");

    assert_eq!(body["code"], "audit_record_failed");
    assert_eq!(body["request_id"], REQUEST_ID);
    assert!(
        !body
            .as_object()
            .is_some_and(|object| object.contains_key("error"))
    );
}

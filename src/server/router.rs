use axum::Router;
use axum::routing::{get, post};
use tower_http::LatencyUnit;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::{
    DefaultMakeSpan, DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer,
};

use crate::server::handlers;
use crate::server::middleware;
use crate::server::state::AppState;

pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/v1/secrets", post(handlers::create_secret))
        .route(
            "/v1/secrets/{secret_id}/versions",
            post(handlers::rotate_secret),
        )
        .route(
            "/v1/secrets/{secret_id}/decrypt",
            post(handlers::decrypt_secret),
        )
        .route("/health", get(handlers::health_check))
        .route("/ready", get(handlers::ready_check))
        .fallback(handlers::not_found)
        .layer(axum::middleware::from_fn(
            middleware::attach_request_context,
        ))
        .layer(SetSensitiveRequestHeadersLayer::new([
            http::header::AUTHORIZATION,
        ]))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().include_headers(false))
                .on_request(DefaultOnRequest::new().level(tracing::Level::INFO))
                .on_response(
                    DefaultOnResponse::new()
                        .level(tracing::Level::INFO)
                        .include_headers(false)
                        .latency_unit(LatencyUnit::Millis),
                )
                .on_failure(
                    DefaultOnFailure::new()
                        .level(tracing::Level::ERROR)
                        .latency_unit(LatencyUnit::Millis),
                ),
        )
        .with_state(state)
}

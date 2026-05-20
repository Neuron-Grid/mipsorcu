use axum::Router;
use axum::routing::{get, post, put};
use tower_http::LatencyUnit;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::{DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer};

use crate::server::handlers;
use crate::server::middleware;
use crate::server::state::AppState;

pub fn build_app(state: AppState) -> Router {
    let router = Router::new()
        .nest("/audit/v1", handlers::audit_ui::build_audit_read_router())
        .route("/v1/secrets", post(handlers::create_secret))
        .route(
            "/v1/secrets/{secret_ref}/versions",
            post(handlers::rotate_secret),
        )
        .route(
            "/v1/secrets/{secret_ref}/decrypt",
            post(handlers::decrypt_secret),
        )
        .route(
            "/v1/secrets/{secret_id}/aliases",
            post(handlers::create_secret_alias),
        )
        .route(
            "/v1/aliases/{alias_id}",
            put(handlers::update_secret_alias).delete(handlers::delete_secret_alias),
        )
        .route("/v1/aliases", get(handlers::list_secret_aliases))
        .route("/v1/aliases/resolve", post(handlers::resolve_secret_alias))
        .route("/health", get(handlers::health_check))
        .route("/ready", get(handlers::ready_check))
        .fallback(handlers::not_found);

    apply_standard_layers(router, state)
}

pub(crate) fn apply_standard_layers(router: Router<AppState>, state: AppState) -> Router {
    let handler_timeout = state.http_handler_timeout;
    let rate_limit_requests = state.http_rate_limit_requests;
    let rate_limit_window = state.http_rate_limit_window;
    let runtime_resilience =
        middleware::RuntimeResilience::new(handler_timeout, rate_limit_requests, rate_limit_window);

    router
        .layer(axum::middleware::from_fn_with_state(
            runtime_resilience,
            middleware::enforce_runtime_resilience,
        ))
        .layer(axum::middleware::from_fn(
            middleware::attach_request_context,
        ))
        .layer(SetSensitiveRequestHeadersLayer::new([
            http::header::AUTHORIZATION,
        ]))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &http::Request<_>| {
                    tracing::info_span!("http_request", method = %request.method())
                })
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

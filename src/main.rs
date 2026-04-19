mod server;

use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;

use mipsorcu::audit::{AuditRecorder, LocalAuditFallbackStore};
use mipsorcu::auth::{Jwks, JwtVerifier, JwtVerifierConfig};

use server::config;
use server::handlers;
use server::state::AppState;
use server::supabase::{SupabaseAuditAppender, SupabaseClient};

#[tokio::main]
async fn main() {
    fmt::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = config::load_config().unwrap_or_else(|error| {
        tracing::error!(error = %error, "configuration loading failed");
        std::process::exit(1);
    });

    let listen_addr = config.listen_addr;
    tracing::info!(listen_addr = %listen_addr, "starting mipsorcu");

    let jwks: Jwks = serde_json::from_str(&config.jwks_json).unwrap_or_else(|error| {
        tracing::error!(error = %error, "JWKS parsing failed");
        std::process::exit(1);
    });

    let jwt_config = JwtVerifierConfig::new(&config.jwt_issuer, &config.jwt_audience)
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "JWT verifier config is invalid");
            std::process::exit(1);
        });

    let jwt_verifier = Arc::new(JwtVerifier::new(jwt_config, jwks));

    let http_client = reqwest::Client::new();
    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url,
        config.supabase_service_role_key,
        config.supabase_publishable_key,
    ));

    let runtime_handle = tokio::runtime::Handle::current();
    let audit_appender = SupabaseAuditAppender::new(supabase_client.clone(), runtime_handle);
    let fallback_store = LocalAuditFallbackStore::new(&config.audit_fallback_path);
    let audit_recorder = Arc::new(AuditRecorder::new(audit_appender, fallback_store));

    let state = AppState {
        master_key: Arc::new(config.master_key),
        key_version: config.key_version,
        jwt_verifier,
        supabase_client,
        audit_recorder,
        audit_fallback_path: config.audit_fallback_path,
    };

    let app = Router::new()
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
        .fallback(handlers::not_found)
        .layer(SetSensitiveRequestHeadersLayer::new([
            http::header::AUTHORIZATION,
        ]))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .unwrap_or_else(|error| {
            tracing::error!(listen_addr = %listen_addr, error = %error, "failed to bind");
            std::process::exit(1);
        });

    tracing::info!(listen_addr = %listen_addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "server error");
            std::process::exit(1);
        });
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c().await.ok();
    tracing::info!("shutdown signal received");
}

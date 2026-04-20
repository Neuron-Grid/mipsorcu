mod server;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::{get, post};
use tokio::sync::watch;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;

use mipsorcu::audit::{
    AuditRecordError, AuditRecorder, LocalAuditFallbackStore, ResendAuditSummary,
};
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
    let audit_resend_interval = config.audit_resend_interval;
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let audit_resend_recorder = audit_recorder.clone();
    tokio::spawn(run_audit_resend_loop(
        audit_resend_recorder,
        audit_resend_interval,
        shutdown_receiver,
    ));

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
        .with_graceful_shutdown(shutdown_signal(shutdown_sender))
        .await
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "server error");
            std::process::exit(1);
        });
}

async fn shutdown_signal(shutdown_sender: watch::Sender<bool>) {
    tokio::signal::ctrl_c().await.ok();
    let _ = shutdown_sender.send(true);
    tracing::info!("shutdown signal received");
}

async fn run_audit_resend_loop(
    audit_recorder: Arc<AuditRecorder<SupabaseAuditAppender>>,
    interval_duration: Duration,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    record_audit_resend_result(resend_pending_once(audit_recorder.clone()).await);

    let mut interval = tokio::time::interval(interval_duration);
    interval.tick().await;

    loop {
        tokio::select! {
            result = shutdown_receiver.changed() => {
                if result.is_err() || *shutdown_receiver.borrow() {
                    tracing::info!("audit fallback resend loop stopped");
                    break;
                }
            }
            _ = interval.tick() => {
                record_audit_resend_result(resend_pending_once(audit_recorder.clone()).await);
            }
        }
    }
}

async fn resend_pending_once(
    audit_recorder: Arc<AuditRecorder<SupabaseAuditAppender>>,
) -> Result<ResendAuditSummary, AuditRecordError> {
    tokio::task::spawn_blocking(move || audit_recorder.resend_pending())
        .await
        .map_err(|_| {
            AuditRecordError::ResendReadFailed(std::io::Error::other("join failed").into())
        })?
}

fn record_audit_resend_result(result: Result<ResendAuditSummary, AuditRecordError>) {
    match result {
        Ok(summary) => {
            tracing::info!(
                attempted = summary.attempted,
                sent = summary.sent,
                failed = summary.failed,
                "audit fallback resend completed"
            );
        }
        Err(error) => {
            tracing::error!(
                error_kind = audit_record_error_kind(&error),
                "audit fallback resend failed"
            );
        }
    }
}

fn audit_record_error_kind(error: &AuditRecordError) -> &'static str {
    match error {
        AuditRecordError::FallbackWriteFailed { .. } => "fallback_write_failed",
        AuditRecordError::ResendReadFailed(_) => "resend_read_failed",
        AuditRecordError::ResendMarkSentFailed(_) => "resend_mark_sent_failed",
    }
}

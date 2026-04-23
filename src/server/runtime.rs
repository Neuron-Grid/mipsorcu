use std::sync::Arc;

use axum::Router;
use tokio::sync::watch;
use tracing_subscriber::{EnvFilter, fmt};

use crate::audit::{AuditRecorder, LocalAuditFallbackStore};
use crate::auth::{JwksCache, JwtVerifier, JwtVerifierConfig, fetch_jwks};
use crate::server::state::{AppState, ReadinessState};
use crate::server::supabase::{SupabaseAuditAppender, SupabaseClient};
use crate::server::{background, config, restore_test, router};

pub use crate::server::background::{
    AuditFallbackSizeAlert, JwtVerifierInitError, audit_fallback_file_size,
    audit_fallback_size_alert, initialize_jwt_verifier_from_jwks_url, refresh_jwks_cache_once,
    run_audit_fallback_rollover_once, sweep_audit_fallback_archive_once,
};

pub async fn run() {
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

    let http_client = reqwest::Client::new();
    let jwks = fetch_jwks(&http_client, &config.jwks_url)
        .await
        .unwrap_or_else(|error| {
            tracing::error!(
                jwks_url = %config.jwks_url,
                error_kind = background::jwks_fetch_error_kind(&error),
                "configuration JWKS loading failed"
            );
            std::process::exit(1);
        });
    let jwks_cache = JwksCache::new(jwks);

    let jwt_config = JwtVerifierConfig::new(&config.jwt_issuer, &config.jwt_audience)
        .unwrap_or_else(|error| {
            tracing::error!(error = %error, "JWT verifier config is invalid");
            std::process::exit(1);
        });

    let jwt_verifier = Arc::new(JwtVerifier::with_cache(jwt_config, jwks_cache.clone()));

    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    tokio::spawn(background::run_jwks_refresh_loop(
        jwks_cache,
        http_client.clone(),
        config.jwks_url.clone(),
        config.jwks_refresh_interval,
        shutdown_sender.subscribe(),
    ));

    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url,
        config.supabase_service_role_key,
        config.supabase_publishable_key,
    ));
    let readiness_state = ReadinessState::new();
    tokio::spawn(background::run_supabase_readiness_poll_loop(
        readiness_state.clone(),
        supabase_client.clone(),
        config.health_readiness_poll_interval,
        shutdown_sender.subscribe(),
    ));

    let audit_appender = SupabaseAuditAppender::new(supabase_client.clone());
    let fallback_store = LocalAuditFallbackStore::with_rollover_config(
        &config.audit_fallback_path,
        &config.audit_fallback_archive_dir,
        config.audit_fallback_rotate_size_bytes,
    );
    let app_fallback_store = fallback_store.clone();
    let audit_recorder = Arc::new(AuditRecorder::new(audit_appender, fallback_store.clone()));
    tokio::spawn(background::run_audit_resend_loop(
        audit_recorder.clone(),
        fallback_store,
        config.audit_resend_interval,
        config.audit_fallback_alert_threshold_bytes,
        config.audit_fallback_archive_auto_delete_enabled,
        config.audit_fallback_archive_retention,
        shutdown_receiver,
    ));

    let state = AppState {
        master_key: Arc::new(config.master_key),
        key_version: config.key_version,
        jwt_verifier,
        supabase_client,
        audit_recorder,
        audit_fallback_store: app_fallback_store,
        readiness_state,
        health_readiness_poll_interval: config.health_readiness_poll_interval,
    };
    tokio::spawn(background::run_restore_test_loop(
        state.clone(),
        config.restore_test_interval,
        config.restore_test_sample_limit,
        shutdown_sender.subscribe(),
    ));

    serve_app(state, listen_addr, shutdown_sender).await;
}

pub async fn run_restore_test_once(state: &AppState, sample_limit: u32) {
    restore_test::run_restore_test_once(state, sample_limit).await;
}

async fn serve_app(
    state: AppState,
    listen_addr: std::net::SocketAddr,
    shutdown_sender: watch::Sender<bool>,
) {
    let app = build_app(state);

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

fn build_app(state: AppState) -> Router {
    router::build_app(state)
}

async fn shutdown_signal(shutdown_sender: watch::Sender<bool>) {
    tokio::signal::ctrl_c().await.ok();
    let _ = shutdown_sender.send(true);
    tracing::info!("shutdown signal received");
}

#[doc(hidden)]
pub mod testing {
    use std::time::Duration;

    use axum::Router;
    use tokio::sync::watch;

    use crate::audit::AuditMetadata;
    use crate::auth::JwksCache;
    use crate::read::DecryptCurrentSecretVersionInput;
    use crate::server::errors::ApiError;
    use crate::server::state::AppState;
    use crate::server::supabase::RestoreTestSampleRow;

    pub fn build_restore_test_decrypt_input(
        row: RestoreTestSampleRow,
    ) -> Result<DecryptCurrentSecretVersionInput, ApiError> {
        crate::server::restore_test::testing::build_restore_test_decrypt_input(row)
    }

    pub fn restore_test_metadata(
        sample_count: u64,
        error_code: Option<&'static str>,
        failed_version: Option<u32>,
    ) -> AuditMetadata {
        crate::server::restore_test::testing::restore_test_metadata(
            sample_count,
            error_code,
            failed_version,
        )
    }

    pub fn build_app(state: AppState) -> Router {
        super::build_app(state)
    }

    pub async fn run_jwks_refresh_loop(
        cache: JwksCache,
        http_client: reqwest::Client,
        jwks_url: String,
        interval_duration: Duration,
        shutdown_receiver: watch::Receiver<bool>,
    ) {
        crate::server::background::run_jwks_refresh_loop(
            cache,
            http_client,
            jwks_url,
            interval_duration,
            shutdown_receiver,
        )
        .await;
    }
}

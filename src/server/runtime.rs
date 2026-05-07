use std::sync::Arc;

use axum::Router;
use tokio::sync::watch;
use tracing_subscriber::{EnvFilter, fmt};

use crate::audit::{AuditRecorder, LocalAuditFallbackStore};
use crate::auth::{JwksCache, JwtVerifier, JwtVerifierConfig, fetch_jwks};
use crate::server::state::{AppState, ReadinessState};
use crate::server::supabase::{SupabaseAuditAppender, SupabaseClient};
use crate::server::{background, config, integrity_check, key_rotation, restore_test, router};

pub use crate::server::background::{
    AuditFallbackSizeAlert, JwtVerifierInitError, audit_fallback_file_size,
    audit_fallback_size_alert, initialize_jwt_verifier_from_jwks_url, refresh_jwks_cache_once,
    run_audit_fallback_rollover_once, sweep_audit_fallback_archive_once,
};

pub async fn run_entrypoint() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();

    match args.split_first() {
        None => run().await,
        Some((command, command_args)) if command == "key-rotation" => {
            init_tracing();
            let config = config::load_config().unwrap_or_else(|error| {
                tracing::error!(error = %error, "configuration loading failed");
                std::process::exit(1);
            });

            if let Err(error) = key_rotation::run_cli(config, command_args).await {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        Some((command, command_args)) if command == "integrity-check" => {
            init_tracing();
            let config = config::load_config().unwrap_or_else(|error| {
                tracing::error!(error = %error, "configuration loading failed");
                std::process::exit(1);
            });

            if let Err(error) = integrity_check::run_cli(config, command_args).await {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        Some(_) => {
            eprintln!("{}", usage());
            std::process::exit(2);
        }
    }
}

pub async fn run() {
    init_tracing();

    let config = config::load_config().unwrap_or_else(|error| {
        tracing::error!(error = %error, "configuration loading failed");
        std::process::exit(1);
    });

    run_server_with_config(config).await;
}

fn init_tracing() {
    fmt::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}

async fn run_server_with_config(config: config::AppConfig) {
    let listen_addr = config.listen_addr;
    tracing::info!(listen_addr = %listen_addr, "starting mipsorcu");

    let http_client = config::build_outbound_http_client(&config).unwrap_or_else(|error| {
        tracing::error!(error = %error, "HTTP client initialization failed");
        std::process::exit(1);
    });
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
    let ledger_appender = Arc::new(crate::server::ledger_appender::LedgerAppender::new(
        supabase_client.clone(),
        config.ledger_signing_key.clone(),
    ));
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
        master_key_ring: Arc::new(config.master_key_ring),
        jwt_verifier,
        supabase_client,
        audit_recorder,
        ledger_appender,
        audit_fallback_store: app_fallback_store,
        readiness_state,
        health_readiness_poll_interval: config.health_readiness_poll_interval,
        http_handler_timeout: config.http_handler_timeout,
        http_rate_limit_requests: config.http_rate_limit_requests,
        http_rate_limit_window: config.http_rate_limit_window,
    };
    tokio::spawn(background::run_restore_test_loop(
        state.clone(),
        config.restore_test_interval,
        config.restore_test_startup_delay,
        config.restore_test_sample_limit,
        shutdown_sender.subscribe(),
    ));
    tokio::spawn(background::run_integrity_check_loop(
        state.clone(),
        config.integrity_check_interval,
        config.integrity_check_startup_delay,
        shutdown_sender.subscribe(),
    ));

    serve_app(state, listen_addr, shutdown_sender).await;
}

pub async fn run_restore_test_once(state: &AppState, sample_limit: u32) {
    restore_test::run_restore_test_once(state, sample_limit, crate::audit::AuditTrigger::Cli).await;
}

fn usage() -> String {
    [key_rotation::usage(), integrity_check::usage()].join("\n")
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
    let signal = wait_for_shutdown_signal().await;
    let _ = shutdown_sender.send(true);
    tracing::info!(signal, "shutdown signal received");
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> &'static str {
    let ctrl_c = tokio::signal::ctrl_c();
    let terminate = async {
        let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        match signal {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    error_code = "sigterm_handler_setup_failed",
                    "failed to install SIGTERM handler"
                );
                std::future::pending::<()>().await;
            }
        }
    };

    tokio::select! {
        result = ctrl_c => {
            if let Err(error) = result {
                tracing::error!(
                    error = %error,
                    error_code = "sigint_handler_failed",
                    "SIGINT handler failed"
                );
            }
            "sigint"
        }
        () = terminate => "sigterm",
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> &'static str {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(
            error = %error,
            error_code = "sigint_handler_failed",
            "SIGINT handler failed"
        );
    }

    "sigint"
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
            crate::audit::AuditTrigger::Cli,
        )
    }

    pub fn restore_test_metadata_with_trigger(
        sample_count: u64,
        error_code: Option<&'static str>,
        failed_version: Option<u32>,
        trigger: crate::audit::AuditTrigger,
    ) -> AuditMetadata {
        crate::server::restore_test::testing::restore_test_metadata(
            sample_count,
            error_code,
            failed_version,
            trigger,
        )
    }

    pub fn integrity_check_metadata(
        summary: &crate::server::supabase::IntegrityCheckSummary,
        trigger: crate::audit::AuditTrigger,
        error_code: Option<&'static str>,
    ) -> Result<AuditMetadata, crate::audit::AuditEventError> {
        crate::server::integrity_check::testing::build_integrity_check_metadata(
            summary, trigger, error_code,
        )
    }

    pub fn integrity_check_usage() -> String {
        crate::server::integrity_check::testing::usage()
    }

    pub fn build_app(state: AppState) -> Router {
        super::build_app(state)
    }

    pub fn build_sleep_app(state: AppState, sleep_duration: Duration) -> Router {
        crate::server::router::build_sleep_app_for_testing(state, sleep_duration)
    }

    pub async fn wait_for_shutdown_signal_for_testing<SignalFuture>(
        signal: SignalFuture,
        shutdown_sender: watch::Sender<bool>,
        signal_name: &'static str,
    ) where
        SignalFuture: std::future::Future<Output = ()>,
    {
        signal.await;
        let _ = shutdown_sender.send(true);
        tracing::info!(signal = signal_name, "shutdown signal received");
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

    pub async fn run_restore_test_loop(
        state: AppState,
        interval_duration: Duration,
        startup_delay: Duration,
        sample_limit: u32,
        shutdown_receiver: watch::Receiver<bool>,
    ) {
        crate::server::background::run_restore_test_loop(
            state,
            interval_duration,
            startup_delay,
            sample_limit,
            shutdown_receiver,
        )
        .await;
    }

    pub async fn run_integrity_check_loop(
        state: AppState,
        interval_duration: Duration,
        startup_delay: Duration,
        shutdown_receiver: watch::Receiver<bool>,
    ) {
        crate::server::background::run_integrity_check_loop(
            state,
            interval_duration,
            startup_delay,
            shutdown_receiver,
        )
        .await;
    }
}

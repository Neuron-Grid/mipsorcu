use std::sync::Arc;

use axum::Router;
use tokio::sync::watch;
use tracing_subscriber::{EnvFilter, fmt};

use crate::audit::{AuditRecorder, LocalAuditFallbackStore};
use crate::auth::{JwksCache, JwtVerifier, JwtVerifierConfig, fetch_jwks};
use crate::incident::{DummyNotificationSink, IncidentRecorder};
use crate::server::state::{AppState, ReadinessState};
use crate::server::supabase::{SupabaseAuditAppender, SupabaseClient};
use crate::server::{
    audit_report, auditor, background, config, digest, integrity_check, key_rotation, restore_test,
    router, scheduler, signature_key,
};
use crate::siem::{InMemorySiemSink, LocalSiemFallbackBuffer, SiemForwarder};

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
        Some((command, command_args)) if command == "auditor" => {
            init_tracing();
            let config = config::load_config().unwrap_or_else(|error| {
                tracing::error!(error = %error, "configuration loading failed");
                std::process::exit(1);
            });

            if let Err(error) = auditor::run_cli(config, command_args).await {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        Some((command, command_args)) if command == "digest" => {
            init_tracing();
            let config = config::load_config().unwrap_or_else(|error| {
                tracing::error!(error = %error, "configuration loading failed");
                std::process::exit(1);
            });

            if let Err(error) = digest::run_cli(config, command_args).await {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        Some((command, command_args)) if command == "audit-report" => {
            init_tracing();
            let config = config::load_config().unwrap_or_else(|error| {
                tracing::error!(error = %error, "configuration loading failed");
                std::process::exit(1);
            });

            if let Err(error) = audit_report::run_cli(config, command_args).await {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        Some((command, command_args)) if command == "signature-key" => {
            init_tracing();
            let config = config::load_config().unwrap_or_else(|error| {
                tracing::error!(error = %error, "configuration loading failed");
                std::process::exit(1);
            });

            if let Err(error) = signature_key::run_cli(config, command_args).await {
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
    let ledger_signing_key = config.ledger_signing_key.clone();
    ensure_active_ledger_signing_public_key_at_startup(&supabase_client, &ledger_signing_key).await;
    let ledger_appender = Arc::new(crate::server::ledger_appender::LedgerAppender::new(
        supabase_client.clone(),
        ledger_signing_key,
    ));
    let incident_recorder = Arc::new(IncidentRecorder::new(
        supabase_client.clone(),
        ledger_appender.clone(),
        DummyNotificationSink::new(),
    ));
    let siem_buffer = LocalSiemFallbackBuffer::new(config.siem_buffer_path.clone());
    let siem_forwarder = SiemForwarder::new(InMemorySiemSink::new(), siem_buffer);
    let siem_forwarding = Arc::new(crate::server::siem_forwarding::SiemForwardingService::new(
        siem_forwarder,
        audit_recorder.clone(),
        readiness_state.clone(),
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
        incident_recorder,
        siem_forwarding: siem_forwarding.clone(),
        audit_fallback_store: app_fallback_store,
        readiness_state,
        health_readiness_poll_interval: config.health_readiness_poll_interval,
        siem_long_failure_threshold: config.siem_long_failure_threshold,
        http_handler_timeout: config.http_handler_timeout,
        http_rate_limit_requests: config.http_rate_limit_requests,
        http_rate_limit_window: config.http_rate_limit_window,
    };
    if !config.scheduler_enabled {
        tokio::spawn(background::run_restore_test_loop(
            state.clone(),
            config.restore_test_interval,
            config.restore_test_startup_delay,
            config.restore_test_sample_limit,
            shutdown_sender.subscribe(),
        ));
    }
    tokio::spawn(background::run_integrity_check_loop(
        state.clone(),
        config.integrity_check_interval,
        config.integrity_check_startup_delay,
        shutdown_sender.subscribe(),
    ));
    tokio::spawn(background::run_siem_resend_loop(
        siem_forwarding,
        state.incident_recorder.clone(),
        config.siem_resend_interval,
        config.siem_long_failure_threshold,
        shutdown_sender.subscribe(),
    ));
    if config.scheduler_enabled {
        tokio::spawn(scheduler::run_scheduler_loop(
            state.clone(),
            scheduler::SchedulerConfig {
                startup_delay: config.scheduler_startup_delay,
                poll_interval: config.scheduler_poll_interval,
                monthly_day: config.scheduler_monthly_day,
                monthly_hour_utc: config.scheduler_monthly_hour_utc,
                quarterly_hour_utc: config.scheduler_quarterly_hour_utc,
                restore_test_sample_limit: config.restore_test_sample_limit,
                local_archive_dir: config.scheduler_local_archive_dir.clone(),
            },
            shutdown_sender.subscribe(),
        ));
    }

    serve_app(state, listen_addr, shutdown_sender).await;
}

pub async fn run_restore_test_once(state: &AppState, sample_limit: u32) -> bool {
    matches!(
        restore_test::run_restore_test_once(state, sample_limit, crate::audit::AuditTrigger::Cli)
            .await,
        restore_test::RestoreTestOutcome::Success
    )
}

async fn ensure_active_ledger_signing_public_key_at_startup(
    client: &SupabaseClient,
    signing_key: &crate::ledger::LedgerSigningKey,
) {
    let verification_key = signing_key.verification_key();
    let key_version = verification_key.key_version().get();

    match client
        .ensure_active_ledger_signing_public_key(&verification_key)
        .await
    {
        Ok(()) => tracing::info!(key_version, "ledger signing public key is active"),
        Err(error) => {
            tracing::error!(
                key_version,
                error_code = "ledger_signing_public_key_not_active",
                upstream_status = error.upstream_status(),
                "configured ledger signing public key is not active"
            );
            std::process::exit(1);
        }
    }
}

fn usage() -> String {
    [
        key_rotation::usage(),
        integrity_check::usage(),
        auditor::usage(),
        digest::usage(),
        audit_report::usage(),
        signature_key::usage(),
    ]
    .join("\n")
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

pub fn build_app(state: AppState) -> Router {
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

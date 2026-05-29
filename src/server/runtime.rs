use std::sync::Arc;

use axum::Router;
use tokio::sync::watch;
use tracing_subscriber::{EnvFilter, fmt};

use crate::audit::{AuditRecorder, LocalAuditFallbackStore};
use crate::auth::{JwksCache, JwtVerifier, JwtVerifierConfig, fetch_jwks};
use crate::incident::{
    AnyNotificationSink, DummyNotificationSink, IncidentRecorder, WebhookNotificationSink,
};
use crate::server::state::{AppState, ReadinessState};
use crate::server::supabase::{SupabaseAuditAppender, SupabaseClient};
use crate::server::{
    audit_report, auditor, background, config, digest, integrity_check, key_rotation, restore_test,
    router, scheduler, signature_key,
};
use crate::siem::{
    AnySiemSink, InMemorySiemSink, LocalSiemFallbackBuffer, OtlpSiemSink, SiemForwarder,
    SplunkHecSiemSink,
};

pub use crate::server::background::{
    AuditFallbackSizeAlert, JwtVerifierInitError, audit_fallback_file_size,
    audit_fallback_size_alert, initialize_jwt_verifier_from_jwks_url, refresh_jwks_cache_once,
    run_audit_fallback_rollover_once, sweep_audit_fallback_archive_once,
};

pub async fn run_entrypoint() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();

    match parse_entrypoint_command(&args) {
        EntrypointCommand::Server => run().await,
        EntrypointCommand::KeyRotation(command_args) => {
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
        EntrypointCommand::IntegrityCheck(command_args) => {
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
        EntrypointCommand::Auditor(command_args) => {
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
        EntrypointCommand::Digest(command_args) => {
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
        EntrypointCommand::AuditReport(command_args) => {
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
        EntrypointCommand::SignatureKey(command_args) => {
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
        EntrypointCommand::Usage => {
            eprintln!("{}", usage());
            std::process::exit(2);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum EntrypointCommand<'a> {
    Server,
    KeyRotation(&'a [String]),
    IntegrityCheck(&'a [String]),
    Auditor(&'a [String]),
    Digest(&'a [String]),
    AuditReport(&'a [String]),
    SignatureKey(&'a [String]),
    Usage,
}

fn parse_entrypoint_command(args: &[String]) -> EntrypointCommand<'_> {
    match args.split_first() {
        None => EntrypointCommand::Server,
        Some((command, command_args)) => match command.as_str() {
            "server" if command_args.is_empty() => EntrypointCommand::Server,
            "server" => EntrypointCommand::Usage,
            "key-rotation" => EntrypointCommand::KeyRotation(command_args),
            "integrity-check" => EntrypointCommand::IntegrityCheck(command_args),
            "auditor" => EntrypointCommand::Auditor(command_args),
            "digest" => EntrypointCommand::Digest(command_args),
            "audit-report" => EntrypointCommand::AuditReport(command_args),
            "signature-key" => EntrypointCommand::SignatureKey(command_args),
            _ => EntrypointCommand::Usage,
        },
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

    let siem_buffer = LocalSiemFallbackBuffer::new(config.siem_buffer_path.clone());
    let siem_sink = build_siem_sink(&config, http_client.clone()).unwrap_or_else(|error| {
        tracing::error!(error = %error, "SIEM exporter initialization failed");
        std::process::exit(1);
    });
    let notification_sink =
        build_notification_sink(&config, http_client.clone()).unwrap_or_else(|error| {
            tracing::error!(error = %error, "incident notification sink initialization failed");
            std::process::exit(1);
        });
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
        notification_sink,
    ));
    let siem_forwarder = SiemForwarder::new(siem_sink, siem_buffer);
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
        alias_encryption_key: Arc::new(config.alias_encryption_key),
        alias_encryption_key_version: config.alias_encryption_key_version,
        alias_fingerprint_key: Arc::new(config.alias_fingerprint_key),
        alias_fingerprint_key_version: config.alias_fingerprint_key_version,
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
                daily_hour_utc: config.scheduler_daily_hour_utc,
                envelope_migration_batch_size: config.scheduler_envelope_migration_batch_size,
                envelope_migration_max_batches: config.scheduler_envelope_migration_max_batches,
                restore_test_sample_limit: config.restore_test_sample_limit,
                local_archive_dir: config.scheduler_local_archive_dir.clone(),
            },
            shutdown_sender.subscribe(),
        ));
    }

    serve_app(state, listen_addr, shutdown_sender).await;
}

fn build_notification_sink(
    config: &config::AppConfig,
    http_client: reqwest::Client,
) -> Result<AnyNotificationSink, &'static str> {
    match &config.incident_notifier {
        config::IncidentNotifierConfig::Disabled => {
            Ok(AnyNotificationSink::Dummy(DummyNotificationSink::new()))
        }
        config::IncidentNotifierConfig::Webhook { endpoint, secret } => {
            Ok(AnyNotificationSink::Webhook(WebhookNotificationSink::new(
                http_client,
                endpoint.clone(),
                secret.clone(),
            )))
        }
    }
}

fn build_siem_sink(
    config: &config::AppConfig,
    http_client: reqwest::Client,
) -> Result<AnySiemSink, &'static str> {
    match &config.siem_exporter {
        config::SiemExporterConfig::Disabled => Ok(AnySiemSink::InMemory(InMemorySiemSink::new())),
        config::SiemExporterConfig::Otlp {
            endpoint,
            auth_token,
        } => Ok(AnySiemSink::Otlp(OtlpSiemSink::new(
            http_client,
            endpoint.clone(),
            auth_token.clone(),
        ))),
        config::SiemExporterConfig::SplunkHec { endpoint, token } => Ok(AnySiemSink::SplunkHec(
            SplunkHecSiemSink::new(http_client, endpoint.clone(), token.clone()),
        )),
    }
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
        "usage:\n  mipsorcu [server]".to_owned(),
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

#[cfg(test)]
mod tests {
    use super::{EntrypointCommand, parse_entrypoint_command};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parse_entrypoint_defaults_to_server_without_args() {
        assert_eq!(parse_entrypoint_command(&[]), EntrypointCommand::Server);
    }

    #[test]
    fn parse_entrypoint_accepts_explicit_server_without_extra_args() {
        let args = args(&["server"]);

        assert_eq!(parse_entrypoint_command(&args), EntrypointCommand::Server);
    }

    #[test]
    fn parse_entrypoint_rejects_explicit_server_with_extra_args() {
        let args = args(&["server", "--unexpected"]);

        assert_eq!(parse_entrypoint_command(&args), EntrypointCommand::Usage);
    }

    #[test]
    fn parse_entrypoint_preserves_cli_subcommand_args() {
        let args = args(&["signature-key", "public-key", "--format", "json"]);

        assert_eq!(
            parse_entrypoint_command(&args),
            EntrypointCommand::SignatureKey(&args[1..])
        );
    }
}

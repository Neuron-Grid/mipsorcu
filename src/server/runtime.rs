use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use tokio::{sync::watch, task::JoinHandle};
use tracing_subscriber::{EnvFilter, fmt};

use crate::audit::{AuditRecorder, LocalAuditFallbackStore};
use crate::auth::{JwksCache, JwtVerifier, JwtVerifierConfig, fetch_jwks};
use crate::incident::{
    AnyNotificationSink, DummyNotificationSink, IncidentDetector, IncidentDispatcher,
    IncidentRecorder, WebhookNotificationSink,
};
use crate::server::ledger_appender::LedgerAppender;
use crate::server::siem_forwarding::SiemForwardingService;
use crate::server::state::{AppState, ReadinessState};
use crate::server::supabase::{SupabaseAuditAppender, SupabaseClient};
use crate::server::{
    archive, audit_report, auditor, background, config, digest, integrity_check, key_rotation,
    restore_test, router, scheduler, signature_key, timestamping,
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

            if let Err(error) = key_rotation::run_cli(&config, command_args).await {
                record_key_rotation_failure_incident(&config, &error).await;
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
        EntrypointCommand::Archive(command_args) => {
            init_tracing();
            let config = config::load_config().unwrap_or_else(|error| {
                tracing::error!(error = %error, "configuration loading failed");
                std::process::exit(1);
            });

            if let Err(error) = archive::run_cli(config, command_args).await {
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
        EntrypointCommand::Timestamping(command_args) => {
            init_tracing();
            let config = config::load_config().unwrap_or_else(|error| {
                tracing::error!(error = %error, "configuration loading failed");
                std::process::exit(1);
            });

            if let Err(error) = timestamping::run_cli(config, command_args).await {
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
    Archive(&'a [String]),
    AuditReport(&'a [String]),
    SignatureKey(&'a [String]),
    Timestamping(&'a [String]),
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
            "archive" => EntrypointCommand::Archive(command_args),
            "audit-report" => EntrypointCommand::AuditReport(command_args),
            "signature-key" => EntrypointCommand::SignatureKey(command_args),
            "timestamping" => EntrypointCommand::Timestamping(command_args),
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

    let (state, deps) = build_app_state(config, http_client).await;

    let (shutdown_sender, _shutdown_receiver) = watch::channel(false);
    let background_handles = spawn_background_loops(&state, deps, &shutdown_sender);

    serve_app(state, listen_addr, shutdown_sender, background_handles).await;
}

/// `build_app_state` がバックグラウンドループ起動側へ受け渡す依存一式。
///
/// `AppState` に含まれないハンドル（jwks_cache・http client・fallback store）と、
/// ループ駆動に必要な設定値のスナップショットをまとめる。
struct BackgroundDeps {
    http_client: reqwest::Client,
    jwks_cache: JwksCache,
    jwks_url: String,
    jwks_refresh_interval: Duration,
    health_readiness_poll_interval: Duration,
    audit_fallback_store: LocalAuditFallbackStore,
    audit_resend_interval: Duration,
    audit_fallback_alert_threshold_bytes: u64,
    audit_fallback_archive_auto_delete_enabled: bool,
    audit_fallback_archive_retention: Duration,
    restore_test_interval: Duration,
    restore_test_startup_delay: Duration,
    restore_test_sample_limit: u32,
    integrity_check_interval: Duration,
    integrity_check_startup_delay: Duration,
    siem_resend_interval: Duration,
    siem_long_failure_threshold: Duration,
    scheduler_enabled: bool,
    scheduler: scheduler::SchedulerConfig,
}

struct BackgroundLoopHandles {
    incident_aggregate_flush: Option<JoinHandle<()>>,
}

/// 設定からインフラ（暗号鍵・各種クライアント・recorder・forwarder）を構築し、
/// `AppState` とバックグラウンドループ用の依存をまとめて返す。
///
/// 構築中の致命的失敗は既存どおり `std::process::exit(1)` で停止する。
/// ループの spawn は行わず、`spawn_background_loops` に委ねる。
async fn build_app_state(
    config: config::AppConfig,
    http_client: reqwest::Client,
) -> (AppState, BackgroundDeps) {
    // ── 1. JWT 検証基盤（JWKS 取得・キャッシュ・verifier 構築） ──
    let (jwks_cache, jwt_verifier) = init_jwt_auth(&http_client, &config).await;

    // ── 2. 外部送信 sink（SIEM exporter / incident 通知） ──
    let siem_sink = build_siem_sink(&config, http_client.clone()).unwrap_or_else(|error| {
        tracing::error!(error = %error, "SIEM exporter initialization failed");
        std::process::exit(1);
    });
    let notification_sink =
        build_notification_sink(&config, http_client.clone()).unwrap_or_else(|error| {
            tracing::error!(error = %error, "incident notification sink initialization failed");
            std::process::exit(1);
        });

    // ── 3. Supabase クライアント（jwks refresh 用に http client を複製してから構築） ──
    let jwks_refresh_http_client = http_client.clone();
    let supabase_client = build_supabase_client(http_client, &config);
    let readiness_state = ReadinessState::new();

    // ── 4. 監査 / ledger / incident / SIEM 転送サービスを構築 ──
    let (audit_recorder, fallback_store) = build_audit_recorder(&supabase_client, &config);
    let app_fallback_store = fallback_store.clone();
    let ledger_appender = build_ledger_appender(&supabase_client, &config).await;
    let notification_sink_name = notification_sink.as_ref().map_or(
        config.incident_notifier.kind_name(),
        AnyNotificationSink::kind_name,
    );
    let incident_recorder =
        build_incident_recorder(&supabase_client, &ledger_appender, notification_sink_name);
    let incident_dispatcher = notification_sink.map(|sink| {
        Arc::new(IncidentDispatcher::new(
            Arc::new(sink),
            audit_recorder.clone(),
        ))
    });
    let incident_detector = IncidentDetector::new();
    let siem_forwarding = build_siem_forwarding(
        siem_sink,
        &config,
        &audit_recorder,
        &incident_recorder,
        incident_dispatcher.as_ref(),
        &readiness_state,
    );

    // ── 5. バックグラウンド依存と AppState を組み立てる ──
    let deps = BackgroundDeps {
        http_client: jwks_refresh_http_client,
        jwks_cache,
        jwks_url: config.jwks_url.clone(),
        jwks_refresh_interval: config.jwks_refresh_interval,
        health_readiness_poll_interval: config.health_readiness_poll_interval,
        audit_fallback_store: fallback_store,
        audit_resend_interval: config.audit_resend_interval,
        audit_fallback_alert_threshold_bytes: config.audit_fallback_alert_threshold_bytes,
        audit_fallback_archive_auto_delete_enabled: config
            .audit_fallback_archive_auto_delete_enabled,
        audit_fallback_archive_retention: config.audit_fallback_archive_retention,
        restore_test_interval: config.restore_test_interval,
        restore_test_startup_delay: config.restore_test_startup_delay,
        restore_test_sample_limit: config.restore_test_sample_limit,
        integrity_check_interval: config.integrity_check_interval,
        integrity_check_startup_delay: config.integrity_check_startup_delay,
        siem_resend_interval: config.siem_resend_interval,
        siem_long_failure_threshold: config.siem_long_failure_threshold,
        scheduler_enabled: config.scheduler_enabled,
        scheduler: build_scheduler_runtime_config(&config),
    };

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
        incident_dispatcher,
        incident_detector,
        siem_forwarding,
        audit_fallback_store: app_fallback_store,
        readiness_state,
        health_readiness_poll_interval: config.health_readiness_poll_interval,
        siem_long_failure_threshold: config.siem_long_failure_threshold,
        http_handler_timeout: config.http_handler_timeout,
        http_rate_limit_requests: config.http_rate_limit_requests,
        http_rate_limit_window: config.http_rate_limit_window,
        scheduler_status: crate::scheduler::SchedulerStatusState::new(
            config.scheduler_enabled,
            config.scheduler_startup_delay,
        ),
    };

    (state, deps)
}

fn build_scheduler_runtime_config(config: &config::AppConfig) -> scheduler::SchedulerConfig {
    let (archive_backend, timestamping_provider) = if config.scheduler_enabled {
        let archive_backend = archive::build_backend(config).unwrap_or_else(|error| {
            tracing::error!(error = %error, "scheduler archive backend initialization failed");
            std::process::exit(1);
        });
        let timestamping_provider = timestamping::build_provider(config).unwrap_or_else(|error| {
            tracing::error!(error = %error, "scheduler timestamping provider initialization failed");
            std::process::exit(1);
        });
        (
            Some(Arc::new(archive_backend)),
            Some(Arc::new(timestamping_provider)),
        )
    } else {
        (None, None)
    };

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
        archive_backend,
        timestamping_provider,
    }
}

/// JWKS を取得してキャッシュし、JWT verifier を構築する。
///
/// JWKS 取得失敗・verifier 設定不正はいずれも `std::process::exit(1)` で停止する。
/// 返り値の `JwksCache` は refresh ループへ渡すため verifier とは別に返す。
async fn init_jwt_auth(
    http_client: &reqwest::Client,
    config: &config::AppConfig,
) -> (JwksCache, Arc<JwtVerifier>) {
    let jwks = fetch_jwks(http_client, &config.jwks_url)
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

    (jwks_cache, jwt_verifier)
}

/// Supabase クライアントを構築する。
///
/// URL・キーは `config` の値を複製して渡す（`config` は後段の AppState 構築でも
/// 個別フィールドを参照するため、ここでは move せず保持する）。
fn build_supabase_client(
    http_client: reqwest::Client,
    config: &config::AppConfig,
) -> Arc<SupabaseClient> {
    Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url.clone(),
        config.supabase_service_role_key.clone(),
        config.supabase_publishable_key.clone(),
    ))
}

/// 監査 recorder とそのローカルフォールバックストアを構築する。
///
/// `LocalAuditFallbackStore` は AppState とバックグラウンド依存の双方で使うため、
/// recorder と併せて返す。
fn build_audit_recorder(
    supabase_client: &Arc<SupabaseClient>,
    config: &config::AppConfig,
) -> (
    Arc<AuditRecorder<SupabaseAuditAppender>>,
    LocalAuditFallbackStore,
) {
    let audit_appender = SupabaseAuditAppender::new(supabase_client.clone());
    let fallback_store = LocalAuditFallbackStore::with_rollover_config(
        &config.audit_fallback_path,
        &config.audit_fallback_archive_dir,
        config.audit_fallback_rotate_size_bytes,
    );
    let audit_recorder = Arc::new(AuditRecorder::new(audit_appender, fallback_store.clone()));

    (audit_recorder, fallback_store)
}

/// ledger 署名鍵の active 公開鍵を起動時に検証し、ledger appender を構築する。
async fn build_ledger_appender(
    supabase_client: &Arc<SupabaseClient>,
    config: &config::AppConfig,
) -> Arc<LedgerAppender> {
    let ledger_signing_key = config.ledger_signing_key.clone();
    ensure_active_ledger_signing_public_key_at_startup(supabase_client, &ledger_signing_key).await;
    Arc::new(LedgerAppender::new(
        supabase_client.clone(),
        ledger_signing_key,
    ))
}

/// incident recorder を構築する。
fn build_incident_recorder(
    supabase_client: &Arc<SupabaseClient>,
    ledger_appender: &Arc<LedgerAppender>,
    notification_sink_name: &str,
) -> Arc<IncidentRecorder> {
    Arc::new(IncidentRecorder::new(
        supabase_client.clone(),
        ledger_appender.clone(),
        notification_sink_name,
    ))
}

/// SIEM 転送サービス（forwarder + ローカルバッファ）を構築する。
fn build_siem_forwarding(
    siem_sink: AnySiemSink,
    config: &config::AppConfig,
    audit_recorder: &Arc<AuditRecorder<SupabaseAuditAppender>>,
    incident_recorder: &Arc<IncidentRecorder>,
    incident_dispatcher: Option<
        &Arc<IncidentDispatcher<AnyNotificationSink, SupabaseAuditAppender>>,
    >,
    readiness_state: &ReadinessState,
) -> Arc<SiemForwardingService<AnySiemSink>> {
    let siem_buffer = LocalSiemFallbackBuffer::with_limits(
        config.siem_buffer_path.clone(),
        config.siem_buffer_max_bytes,
        config.siem_buffer_total_max_bytes,
    );
    let siem_forwarder = SiemForwarder::new(siem_sink, siem_buffer);
    Arc::new(SiemForwardingService::new_with_incident(
        siem_forwarder,
        audit_recorder.clone(),
        incident_recorder.clone(),
        incident_dispatcher.cloned(),
        readiness_state.clone(),
    ))
}

/// すべてのバックグラウンドループを spawn する。
///
/// shutdown は `shutdown_sender.subscribe()` で各ループへ配信する。
fn spawn_background_loops(
    state: &AppState,
    deps: BackgroundDeps,
    shutdown_sender: &watch::Sender<bool>,
) -> BackgroundLoopHandles {
    let BackgroundDeps {
        http_client,
        jwks_cache,
        jwks_url,
        jwks_refresh_interval,
        health_readiness_poll_interval,
        audit_fallback_store,
        audit_resend_interval,
        audit_fallback_alert_threshold_bytes,
        audit_fallback_archive_auto_delete_enabled,
        audit_fallback_archive_retention,
        restore_test_interval,
        restore_test_startup_delay,
        restore_test_sample_limit,
        integrity_check_interval,
        integrity_check_startup_delay,
        siem_resend_interval,
        siem_long_failure_threshold,
        scheduler_enabled,
        scheduler,
    } = deps;

    let incident_aggregate_flush =
        spawn_incident_aggregate_flush_loop(state.incident_dispatcher.as_ref(), shutdown_sender);

    tokio::spawn(background::run_jwks_refresh_loop(
        jwks_cache,
        http_client,
        jwks_url,
        jwks_refresh_interval,
        shutdown_sender.subscribe(),
    ));

    tokio::spawn(background::run_supabase_readiness_poll_loop(
        state.readiness_state.clone(),
        state.supabase_client.clone(),
        health_readiness_poll_interval,
        shutdown_sender.subscribe(),
    ));

    tokio::spawn(background::run_audit_resend_loop(
        state.audit_recorder.clone(),
        audit_fallback_store,
        audit_resend_interval,
        audit_fallback_alert_threshold_bytes,
        audit_fallback_archive_auto_delete_enabled,
        audit_fallback_archive_retention,
        shutdown_sender.subscribe(),
    ));

    if !scheduler_enabled {
        tokio::spawn(background::run_restore_test_loop(
            state.clone(),
            restore_test_interval,
            restore_test_startup_delay,
            restore_test_sample_limit,
            shutdown_sender.subscribe(),
        ));
    }

    tokio::spawn(background::run_integrity_check_loop(
        state.clone(),
        integrity_check_interval,
        integrity_check_startup_delay,
        shutdown_sender.subscribe(),
    ));

    if scheduler_enabled {
        tokio::spawn(scheduler::run_scheduler_loop(
            state.clone(),
            scheduler,
            shutdown_sender.subscribe(),
        ));
    } else {
        tokio::spawn(background::run_siem_resend_loop(
            state.siem_forwarding.clone(),
            state.clone(),
            siem_resend_interval,
            siem_long_failure_threshold,
            shutdown_sender.subscribe(),
        ));
    }

    BackgroundLoopHandles {
        incident_aggregate_flush,
    }
}

fn spawn_incident_aggregate_flush_loop(
    incident_dispatcher: Option<
        &Arc<IncidentDispatcher<AnyNotificationSink, SupabaseAuditAppender>>,
    >,
    shutdown_sender: &watch::Sender<bool>,
) -> Option<JoinHandle<()>> {
    let dispatcher = incident_dispatcher?.clone();
    let flush_interval = dispatcher.rate_limit_window();
    Some(tokio::spawn(background::run_incident_aggregate_flush_loop(
        dispatcher,
        flush_interval,
        shutdown_sender.subscribe(),
    )))
}

fn build_notification_sink(
    config: &config::AppConfig,
    _http_client: reqwest::Client,
) -> Result<Option<AnyNotificationSink>, &'static str> {
    match &config.incident_notifier {
        config::IncidentNotifierConfig::None => Ok(None),
        config::IncidentNotifierConfig::Dummy => Ok(Some(AnyNotificationSink::Dummy(
            DummyNotificationSink::new(),
        ))),
        config::IncidentNotifierConfig::Webhook {
            endpoint,
            secret,
            request_timeout,
        } => {
            let client = reqwest::Client::builder()
                .timeout(*request_timeout)
                .build()
                .map_err(|_| "incident_webhook_client_init_failed")?;
            Ok(Some(AnyNotificationSink::Webhook(
                WebhookNotificationSink::new(client, endpoint.clone(), secret.clone()),
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

async fn record_key_rotation_failure_incident(
    config: &config::AppConfig,
    error: &key_rotation::KeyRotationCliError,
) {
    let Some(error_code) = error.incident_error_code() else {
        return;
    };
    let http_client = match config::build_outbound_http_client(config) {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(
                error = %error,
                error_code = "key_rotation_incident_http_client_failed",
                "key rotation incident notification setup failed"
            );
            return;
        }
    };
    let supabase_client = build_supabase_client(http_client.clone(), config);
    let (audit_recorder, _fallback_store) = build_audit_recorder(&supabase_client, config);
    let ledger_appender = Arc::new(LedgerAppender::new(
        supabase_client.clone(),
        config.ledger_signing_key.clone(),
    ));
    let notification_sink = match build_notification_sink(config, http_client) {
        Ok(sink) => sink,
        Err(error) => {
            tracing::error!(
                error,
                error_code = "key_rotation_incident_notifier_setup_failed",
                "key rotation incident notifier setup failed"
            );
            None
        }
    };
    let notification_sink_name = notification_sink.as_ref().map_or(
        config.incident_notifier.kind_name(),
        AnyNotificationSink::kind_name,
    );
    let incident_recorder =
        IncidentRecorder::new(supabase_client, ledger_appender, notification_sink_name);
    let incident_dispatcher =
        notification_sink.map(|sink| IncidentDispatcher::new(Arc::new(sink), audit_recorder));
    let detector = IncidentDetector::new();
    let notification = match detector.key_rotation_failure(error_code) {
        Ok(notification) => notification,
        Err(error) => {
            tracing::error!(
                error = %error,
                error_code = "key_rotation_incident_detection_failed",
                "key rotation incident detection failed"
            );
            return;
        }
    };
    let detected = crate::server::incident::DetectedIncident::from_notification(
        notification,
        "key_rotation_cli",
        error_code,
    );
    let (record_input, notification) = detected.into_parts();
    if let Err(error) = incident_recorder.record(record_input).await {
        tracing::error!(
            error = %error,
            error_code = "key_rotation_incident_record_failed",
            "key rotation incident recording failed"
        );
    }
    if let Some(dispatcher) = incident_dispatcher {
        let _ = dispatcher.dispatch(notification).await;
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
        archive::usage(),
        audit_report::usage(),
        signature_key::usage(),
        timestamping::usage(),
    ]
    .join("\n")
}

async fn serve_app(
    state: AppState,
    listen_addr: std::net::SocketAddr,
    shutdown_sender: watch::Sender<bool>,
    background_handles: BackgroundLoopHandles,
) {
    let incident_dispatcher = state.incident_dispatcher.clone();
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

    drain_incident_aggregate_flush(
        incident_dispatcher,
        background_handles.incident_aggregate_flush,
    )
    .await;
}

pub fn build_app(state: AppState) -> Router {
    router::build_app(state)
}

async fn shutdown_signal(shutdown_sender: watch::Sender<bool>) {
    let signal = wait_for_shutdown_signal().await;
    let _ = shutdown_sender.send(true);
    tracing::info!(signal, "shutdown signal received");
}

async fn drain_incident_aggregate_flush(
    incident_dispatcher: Option<
        Arc<IncidentDispatcher<AnyNotificationSink, SupabaseAuditAppender>>,
    >,
    incident_aggregate_flush: Option<JoinHandle<()>>,
) {
    if let Some(handle) = incident_aggregate_flush {
        match handle.await {
            Ok(()) => {}
            Err(error) => {
                tracing::error!(error = %error, "incident aggregate flush loop task failed");
            }
        }
    }

    if let Some(dispatcher) = incident_dispatcher {
        dispatcher.flush_due_aggregates().await;
    }
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
#[path = "../../tests/unit/server/runtime/tests.rs"]
mod tests;

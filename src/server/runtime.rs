use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::aad::AadV1;
use crate::audit::{
    ArchiveSweepOutcome, AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditMetadata,
    AuditRecordError, AuditRecordOutcome, AuditRecorder, AuditResult, LocalAuditFallbackStore,
    LocalAuditStoreError, RequestId, ResendAuditSummary, RolloverOutcome,
};
use crate::auth::{
    JwksCache, JwksFetchError, JwtVerifier, JwtVerifierConfig, VerifiedJwtClaims, fetch_jwks,
};
use crate::decrypt_current_secret_version;
use crate::read::{DecryptCurrentSecretVersionInput, DecryptCurrentSecretVersionInputParts};
use axum::Router;
use axum::routing::{get, post};
use tokio::sync::watch;
use tower_http::LatencyUnit;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::{
    DefaultMakeSpan, DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer,
};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;

use crate::server::config;
use crate::server::errors::ApiError;
use crate::server::handlers;
use crate::server::state::{AppState, ReadinessState};
use crate::server::supabase::{RestoreTestSampleRow, SupabaseAuditAppender, SupabaseClient};
use crate::{
    Ciphertext, Classification, CreatedAt, EncryptedDataKey, KeyVersion, Nonce, OwnerUserId,
    SecretId, SecretVersion,
};

const AUDIT_ARCHIVE_SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

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
                error_kind = jwks_fetch_error_kind(&error),
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

    let jwks_refresh_http_client = http_client.clone();
    let jwks_refresh_url = config.jwks_url.clone();
    let jwks_refresh_interval = config.jwks_refresh_interval;
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    tokio::spawn(run_jwks_refresh_loop(
        jwks_cache,
        jwks_refresh_http_client,
        jwks_refresh_url,
        jwks_refresh_interval,
        shutdown_sender.subscribe(),
    ));

    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        config.supabase_url,
        config.supabase_service_role_key,
        config.supabase_publishable_key,
    ));
    let readiness_state = ReadinessState::new();
    let health_readiness_poll_interval = config.health_readiness_poll_interval;
    tokio::spawn(run_supabase_readiness_poll_loop(
        readiness_state.clone(),
        supabase_client.clone(),
        health_readiness_poll_interval,
        shutdown_sender.subscribe(),
    ));

    let runtime_handle = tokio::runtime::Handle::current();
    let audit_appender = SupabaseAuditAppender::new(supabase_client.clone(), runtime_handle);
    let fallback_store = LocalAuditFallbackStore::with_rollover_config(
        &config.audit_fallback_path,
        &config.audit_fallback_archive_dir,
        config.audit_fallback_rotate_size_bytes,
    );
    let app_fallback_store = fallback_store.clone();
    let audit_recorder = Arc::new(AuditRecorder::new(audit_appender, fallback_store.clone()));
    let audit_resend_interval = config.audit_resend_interval;
    let audit_fallback_alert_threshold_bytes = config.audit_fallback_alert_threshold_bytes;
    let audit_fallback_archive_auto_delete_enabled =
        config.audit_fallback_archive_auto_delete_enabled;
    let audit_fallback_archive_retention = config.audit_fallback_archive_retention;
    let restore_test_interval = config.restore_test_interval;
    let restore_test_sample_limit = config.restore_test_sample_limit;
    let audit_resend_recorder = audit_recorder.clone();
    tokio::spawn(run_audit_resend_loop(
        audit_resend_recorder,
        fallback_store,
        audit_resend_interval,
        audit_fallback_alert_threshold_bytes,
        audit_fallback_archive_auto_delete_enabled,
        audit_fallback_archive_retention,
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
        health_readiness_poll_interval,
    };
    let restore_test_state = state.clone();
    tokio::spawn(run_restore_test_loop(
        restore_test_state,
        restore_test_interval,
        restore_test_sample_limit,
        shutdown_sender.subscribe(),
    ));

    serve_app(state, listen_addr, shutdown_sender).await;
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

pub async fn initialize_jwt_verifier_from_jwks_url(
    http_client: &reqwest::Client,
    jwks_url: &str,
    jwt_issuer: &str,
    jwt_audience: &str,
) -> Result<JwtVerifier, JwtVerifierInitError> {
    let jwks = fetch_jwks(http_client, jwks_url)
        .await
        .map_err(JwtVerifierInitError::Fetch)?;
    let jwt_config =
        JwtVerifierConfig::new(jwt_issuer, jwt_audience).map_err(JwtVerifierInitError::Config)?;

    Ok(JwtVerifier::with_cache(jwt_config, JwksCache::new(jwks)))
}

#[derive(Debug)]
pub enum JwtVerifierInitError {
    Fetch(JwksFetchError),
    Config(crate::JwtVerificationError),
}

impl std::fmt::Display for JwtVerifierInitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fetch(error) => write!(formatter, "JWKS loading failed: {error}"),
            Self::Config(error) => write!(formatter, "JWT verifier config is invalid: {error}"),
        }
    }
}

impl std::error::Error for JwtVerifierInitError {}

pub async fn refresh_jwks_cache_once(
    cache: &JwksCache,
    http_client: &reqwest::Client,
    jwks_url: &str,
) -> Result<(), JwksFetchError> {
    let jwks = fetch_jwks(http_client, jwks_url).await?;
    cache.replace(jwks).map_err(JwksFetchError::InvalidJwks)
}

async fn run_jwks_refresh_loop(
    cache: JwksCache,
    http_client: reqwest::Client,
    jwks_url: String,
    interval_duration: Duration,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(interval_duration);
    interval.tick().await;

    loop {
        tokio::select! {
            result = shutdown_receiver.changed() => {
                if result.is_err() || *shutdown_receiver.borrow() {
                    tracing::info!("JWKS refresh loop stopped");
                    break;
                }
            }
            _ = interval.tick() => {
                match refresh_jwks_cache_once(&cache, &http_client, &jwks_url).await {
                    Ok(()) => {
                        tracing::info!(jwks_url = %jwks_url, "JWKS cache refreshed");
                    }
                    Err(error) => {
                        tracing::error!(
                            jwks_url = %jwks_url,
                            error_kind = jwks_fetch_error_kind(&error),
                            "JWKS cache refresh failed"
                        );
                    }
                }
            }
        }
    }
}

async fn run_supabase_readiness_poll_loop(
    readiness_state: ReadinessState,
    supabase_client: Arc<SupabaseClient>,
    interval_duration: Duration,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    run_supabase_readiness_probe_once(&readiness_state, &supabase_client).await;

    let mut interval = tokio::time::interval(interval_duration);
    interval.tick().await;

    loop {
        tokio::select! {
            result = shutdown_receiver.changed() => {
                if result.is_err() || *shutdown_receiver.borrow() {
                    tracing::info!("Supabase readiness poll loop stopped");
                    break;
                }
            }
            _ = interval.tick() => {
                run_supabase_readiness_probe_once(&readiness_state, &supabase_client).await;
            }
        }
    }
}

async fn run_supabase_readiness_probe_once(
    readiness_state: &ReadinessState,
    supabase_client: &Arc<SupabaseClient>,
) {
    let reachable = supabase_client.probe_readiness().await;
    readiness_state.record_supabase_probe_result(reachable);
}

fn jwks_fetch_error_kind(error: &JwksFetchError) -> &'static str {
    match error {
        JwksFetchError::Network(_) => "network",
        JwksFetchError::NonSuccessStatus { .. } => "non_success_status",
        JwksFetchError::InvalidResponse(_) => "invalid_response",
        JwksFetchError::InvalidJwks(_) => "invalid_jwks",
    }
}

async fn run_restore_test_loop(
    state: AppState,
    interval_duration: Duration,
    sample_limit: u32,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    run_restore_test_once(&state, sample_limit).await;

    let mut interval = tokio::time::interval(interval_duration);
    interval.tick().await;

    loop {
        tokio::select! {
            result = shutdown_receiver.changed() => {
                if result.is_err() || *shutdown_receiver.borrow() {
                    tracing::info!("restore test loop stopped");
                    break;
                }
            }
            _ = interval.tick() => {
                run_restore_test_once(&state, sample_limit).await;
            }
        }
    }
}

pub async fn run_restore_test_once(state: &AppState, sample_limit: u32) {
    let request_id = match RequestId::generate() {
        Ok(request_id) => request_id,
        Err(error) => {
            tracing::error!(
                error = %error,
                action = "restore_test",
                result = "failure",
                error_code = "request_id_generation_failed",
                "restore test setup failed"
            );
            return;
        }
    };

    let sample_rows = match state
        .supabase_client
        .call_sample_restore_test(sample_limit)
        .await
    {
        Ok(rows) if rows.is_empty() => {
            record_restore_test_audit(
                state,
                &request_id,
                RestoreTestAudit {
                    result: AuditResult::Success,
                    target_secret_id: None,
                    key_version: None,
                    metadata: restore_test_metadata(0, Some("no_current_secret_versions"), None),
                    error_code: None,
                },
            )
            .await;
            tracing::info!(
                request_id = %request_id.as_canonical_string(),
                action = "restore_test",
                result = "success",
                sample_count = 0,
            );
            return;
        }
        Ok(rows) => rows,
        Err(_error) => {
            record_restore_test_audit(
                state,
                &request_id,
                RestoreTestAudit {
                    result: AuditResult::Failure,
                    target_secret_id: None,
                    key_version: None,
                    metadata: restore_test_metadata(0, Some("sample_fetch_failed"), None),
                    error_code: Some("sample_fetch_failed"),
                },
            )
            .await;
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                action = "restore_test",
                result = "failure",
                error_code = "sample_fetch_failed",
                sample_count = 0,
                "restore test sample fetch failed"
            );
            return;
        }
    };

    let sample_count = sample_rows.len() as u64;

    for sample_row in sample_rows {
        let failure_context = restore_test_failure_context_from_raw(&sample_row);
        let prepared = match parse_restore_test_sample(sample_row) {
            Ok(prepared) => prepared,
            Err(_) => {
                let log_target_secret_id = failure_context
                    .target_secret_id
                    .as_ref()
                    .map(SecretId::as_canonical_string);
                let log_key_version = failure_context.key_version.map(KeyVersion::get);
                record_restore_test_audit(
                    state,
                    &request_id,
                    RestoreTestAudit {
                        result: AuditResult::Failure,
                        target_secret_id: failure_context.target_secret_id,
                        key_version: failure_context.key_version,
                        metadata: restore_test_metadata(
                            sample_count,
                            Some("row_validation_failed"),
                            failure_context.failed_version,
                        ),
                        error_code: Some("row_validation_failed"),
                    },
                )
                .await;
                tracing::error!(
                    request_id = %request_id.as_canonical_string(),
                    target_secret_id = log_target_secret_id.as_deref(),
                    key_version = log_key_version,
                    failed_version = failure_context.failed_version,
                    action = "restore_test",
                    result = "failure",
                    error_code = "row_validation_failed",
                    sample_count = sample_count,
                    "restore test row validation failed"
                );
                return;
            }
        };

        let failure_context = RestoreTestFailureContext::from_prepared(&prepared);
        let input = build_restore_test_decrypt_input(prepared);
        let master_key = state.master_key.clone();
        let decrypt_result =
            tokio::task::spawn_blocking(move || decrypt_current_secret_version(&master_key, input))
                .await
                .map_err(|error| ApiError::InternalError(error.to_string()))
                .and_then(|result| result.map_err(ApiError::from));

        if decrypt_result.is_err() {
            record_restore_test_audit(
                state,
                &request_id,
                RestoreTestAudit {
                    result: AuditResult::Failure,
                    target_secret_id: failure_context.target_secret_id.clone(),
                    key_version: failure_context.key_version,
                    metadata: restore_test_metadata(
                        sample_count,
                        Some("decrypt_failed"),
                        failure_context.failed_version,
                    ),
                    error_code: Some("decrypt_failed"),
                },
            )
            .await;
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                target_secret_id = failure_context
                    .target_secret_id
                    .as_ref()
                    .map(SecretId::as_canonical_string)
                    .as_deref(),
                key_version = failure_context.key_version.map(KeyVersion::get),
                failed_version = failure_context.failed_version,
                action = "restore_test",
                result = "failure",
                error_code = "decrypt_failed",
                sample_count = sample_count,
                "restore test decrypt failed"
            );
            return;
        }
    }

    record_restore_test_audit(
        state,
        &request_id,
        RestoreTestAudit {
            result: AuditResult::Success,
            target_secret_id: None,
            key_version: None,
            metadata: restore_test_metadata(sample_count, None, None),
            error_code: None,
        },
    )
    .await;
    tracing::info!(
        request_id = %request_id.as_canonical_string(),
        action = "restore_test",
        result = "success",
        sample_count = sample_count,
    );
}

struct PreparedRestoreTestSample {
    secret_id: SecretId,
    version: SecretVersion,
    owner_user_id: OwnerUserId,
    classification: Classification,
    created_at: CreatedAt,
    key_version: KeyVersion,
    encrypted_data_key: EncryptedDataKey,
    nonce_or_iv: Nonce,
    ciphertext: Ciphertext,
    aad_context: serde_json::Value,
}

fn parse_restore_test_sample(
    row: RestoreTestSampleRow,
) -> Result<PreparedRestoreTestSample, ApiError> {
    let stored_aad = AadV1::from_stored_context(&row.aad_context).map_err(|_| {
        ApiError::DbIntegrityViolation("restore test aad_context is invalid".to_owned())
    })?;
    let secret_id = SecretId::parse(&row.secret_id).map_err(|_| {
        ApiError::DbIntegrityViolation("restore test secret_id is invalid".to_owned())
    })?;
    let version = parse_restore_test_secret_version(row.version)?;
    let classification = Classification::new(&row.classification).map_err(|_| {
        ApiError::DbIntegrityViolation("restore test classification is invalid".to_owned())
    })?;
    let created_at = CreatedAt::parse(&row.created_at).map_err(|_| {
        ApiError::DbIntegrityViolation("restore test created_at is invalid".to_owned())
    })?;
    let owner_user_id = stored_aad.owner_user_id().clone();
    let row_aad = AadV1::from_row_metadata(
        secret_id.clone(),
        version,
        owner_user_id.clone(),
        classification.clone(),
        created_at.clone(),
    );
    let stored_bytes = stored_aad.canonical_bytes().map_err(|_| {
        ApiError::DbIntegrityViolation("restore test aad_context is invalid".to_owned())
    })?;
    let row_bytes = row_aad.canonical_bytes().map_err(|_| {
        ApiError::DbIntegrityViolation("restore test aad_context does not match row".to_owned())
    })?;

    if stored_bytes != row_bytes {
        return Err(ApiError::DbIntegrityViolation(
            "restore test aad_context does not match row".to_owned(),
        ));
    }

    Ok(PreparedRestoreTestSample {
        secret_id,
        version,
        owner_user_id,
        classification,
        created_at,
        key_version: parse_restore_test_key_version(row.key_version)?,
        encrypted_data_key: EncryptedDataKey::parse(&decode_restore_test_bytea(
            &row.encrypted_data_key,
            "encrypted_data_key",
        )?)
        .map_err(|_| {
            ApiError::DbIntegrityViolation("restore test encrypted_data_key is invalid".to_owned())
        })?,
        nonce_or_iv: Nonce::parse(&decode_restore_test_bytea(&row.nonce_or_iv, "nonce_or_iv")?)
            .map_err(|_| {
                ApiError::DbIntegrityViolation("restore test nonce_or_iv is invalid".to_owned())
            })?,
        ciphertext: Ciphertext::new(decode_restore_test_bytea(&row.ciphertext, "ciphertext")?)
            .map_err(|_| {
                ApiError::DbIntegrityViolation("restore test ciphertext is invalid".to_owned())
            })?,
        aad_context: row.aad_context,
    })
}

fn build_restore_test_decrypt_input(
    row: PreparedRestoreTestSample,
) -> DecryptCurrentSecretVersionInput {
    let claims = VerifiedJwtClaims::from_verified_subject(row.owner_user_id.clone());

    DecryptCurrentSecretVersionInput::new(DecryptCurrentSecretVersionInputParts {
        claims,
        secret_id: row.secret_id,
        version: row.version,
        current_version: row.version,
        owner_user_id: row.owner_user_id,
        classification: row.classification,
        created_at: row.created_at,
        key_version: row.key_version,
        encrypted_data_key: row.encrypted_data_key,
        nonce_or_iv: row.nonce_or_iv,
        ciphertext: row.ciphertext,
        aad_context: row.aad_context,
    })
}

fn decode_restore_test_bytea(value: &str, field: &'static str) -> Result<Vec<u8>, ApiError> {
    let Some(hex_value) = value.strip_prefix("\\x") else {
        return Err(ApiError::DbIntegrityViolation(format!(
            "restore test {field} is invalid"
        )));
    };

    hex::decode(hex_value)
        .map_err(|_| ApiError::DbIntegrityViolation(format!("restore test {field} is invalid")))
}

fn parse_restore_test_secret_version(value: i32) -> Result<SecretVersion, ApiError> {
    u32::try_from(value)
        .ok()
        .and_then(|parsed| SecretVersion::new(parsed).ok())
        .ok_or_else(|| ApiError::DbIntegrityViolation("restore test version is invalid".to_owned()))
}

fn parse_restore_test_key_version(value: i32) -> Result<KeyVersion, ApiError> {
    u32::try_from(value)
        .ok()
        .and_then(|parsed| KeyVersion::new(parsed).ok())
        .ok_or_else(|| {
            ApiError::DbIntegrityViolation("restore test key_version is invalid".to_owned())
        })
}

struct RestoreTestFailureContext {
    target_secret_id: Option<SecretId>,
    key_version: Option<KeyVersion>,
    failed_version: Option<u32>,
}

impl RestoreTestFailureContext {
    fn from_prepared(prepared: &PreparedRestoreTestSample) -> Self {
        Self {
            target_secret_id: Some(prepared.secret_id.clone()),
            key_version: Some(prepared.key_version),
            failed_version: Some(prepared.version.get()),
        }
    }
}

fn restore_test_failure_context_from_raw(row: &RestoreTestSampleRow) -> RestoreTestFailureContext {
    RestoreTestFailureContext {
        target_secret_id: SecretId::parse(&row.secret_id).ok(),
        key_version: u32::try_from(row.key_version)
            .ok()
            .and_then(|parsed| KeyVersion::new(parsed).ok()),
        failed_version: u32::try_from(row.version)
            .ok()
            .and_then(|parsed| SecretVersion::new(parsed).ok())
            .map(SecretVersion::get),
    }
}

struct RestoreTestAudit {
    result: AuditResult,
    target_secret_id: Option<crate::SecretId>,
    key_version: Option<crate::KeyVersion>,
    metadata: AuditMetadata,
    error_code: Option<&'static str>,
}

async fn record_restore_test_audit(
    state: &AppState,
    request_id: &RequestId,
    audit: RestoreTestAudit,
) {
    let audit_event_id = match AuditEventId::generate() {
        Ok(audit_event_id) => audit_event_id,
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "restore_test",
                result = "failure",
                error_code = "audit_event_id_generation_failed",
                "restore test audit setup failed"
            );
            return;
        }
    };
    let event = match AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id: request_id.clone(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::RestoreTest,
        target_secret_id: audit.target_secret_id,
        result: audit.result,
        key_version: audit.key_version,
        metadata_json: audit.metadata,
    }) {
        Ok(event) => event,
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "restore_test",
                result = "failure",
                error_code = "audit_event_build_failed",
                "restore test audit setup failed"
            );
            return;
        }
    };

    let recorder = state.audit_recorder.clone();
    let record_result = tokio::task::spawn_blocking(move || recorder.record(&event))
        .await
        .map_err(|error| error.to_string())
        .and_then(|result| result.map_err(|error| error.to_string()));

    match record_result {
        Ok(AuditRecordOutcome::PrimarySucceeded) => {
            tracing::debug!(
                request_id = %request_id.as_canonical_string(),
                action = "restore_test",
                audit_record_outcome = "primary_succeeded",
                "restore test audit recorded"
            );
        }
        Ok(AuditRecordOutcome::FallbackSucceeded) => {
            tracing::warn!(
                request_id = %request_id.as_canonical_string(),
                action = "restore_test",
                audit_record_outcome = "fallback_succeeded",
                "restore test audit recorded to local fallback"
            );
        }
        Err(error) => {
            tracing::error!(
                request_id = %request_id.as_canonical_string(),
                error = %error,
                action = "restore_test",
                result = "failure",
                error_code = audit.error_code.unwrap_or("audit_record_failed"),
                audit_record_outcome = "both_failed",
                "restore test audit recording failed"
            );
        }
    }
}

fn restore_test_metadata(
    sample_count: u64,
    error_code: Option<&'static str>,
    failed_version: Option<u32>,
) -> AuditMetadata {
    let value = match error_code {
        Some("no_current_secret_versions") => serde_json::json!({
            "phase": "verify",
            "sample_count": sample_count,
            "reason": "no_current_secret_versions",
        }),
        Some(code) => serde_json::json!({
            "phase": "verify",
            "sample_count": sample_count,
            "error_code": code,
            "failed_version": failed_version,
        }),
        None => serde_json::json!({
            "phase": "verify",
            "sample_count": sample_count,
        }),
    };

    AuditMetadata::new(value).unwrap_or_else(|_| AuditMetadata::empty())
}

async fn shutdown_signal(shutdown_sender: watch::Sender<bool>) {
    tokio::signal::ctrl_c().await.ok();
    let _ = shutdown_sender.send(true);
    tracing::info!("shutdown signal received");
}

async fn run_audit_resend_loop(
    audit_recorder: Arc<AuditRecorder<SupabaseAuditAppender>>,
    fallback_store: LocalAuditFallbackStore,
    interval_duration: Duration,
    audit_fallback_alert_threshold_bytes: u64,
    audit_fallback_archive_auto_delete_enabled: bool,
    audit_fallback_archive_retention: Duration,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    let mut last_archive_sweep = None;

    record_audit_resend_result(resend_pending_once(audit_recorder.clone()).await);
    record_audit_fallback_post_resend_tasks(
        &fallback_store,
        audit_fallback_alert_threshold_bytes,
        audit_fallback_archive_auto_delete_enabled,
        audit_fallback_archive_retention,
        &mut last_archive_sweep,
    )
    .await;

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
                record_audit_fallback_post_resend_tasks(
                    &fallback_store,
                    audit_fallback_alert_threshold_bytes,
                    audit_fallback_archive_auto_delete_enabled,
                    audit_fallback_archive_retention,
                    &mut last_archive_sweep,
                )
                .await;
            }
        }
    }
}

async fn record_audit_fallback_post_resend_tasks(
    fallback_store: &LocalAuditFallbackStore,
    audit_fallback_alert_threshold_bytes: u64,
    audit_fallback_archive_auto_delete_enabled: bool,
    audit_fallback_archive_retention: Duration,
    last_archive_sweep: &mut Option<Instant>,
) {
    record_audit_fallback_size_alert(fallback_store.path(), audit_fallback_alert_threshold_bytes);
    record_audit_fallback_rollover_result(
        fallback_store.path(),
        run_audit_fallback_rollover_once(fallback_store.clone()).await,
    );

    if audit_fallback_archive_auto_delete_enabled && should_sweep_archive(last_archive_sweep) {
        record_audit_fallback_archive_sweep_result(
            fallback_store.archive_dir(),
            audit_fallback_archive_retention,
            sweep_audit_fallback_archive_once(
                fallback_store.clone(),
                audit_fallback_archive_retention,
            )
            .await,
        );
    }
}

pub async fn run_audit_fallback_rollover_once(
    fallback_store: LocalAuditFallbackStore,
) -> Result<RolloverOutcome, LocalAuditStoreError> {
    tokio::task::spawn_blocking(move || fallback_store.rollover())
        .await
        .map_err(|_| LocalAuditStoreError::Io(std::io::Error::other("join failed")))?
}

pub async fn sweep_audit_fallback_archive_once(
    fallback_store: LocalAuditFallbackStore,
    audit_fallback_archive_retention: Duration,
) -> Result<ArchiveSweepOutcome, LocalAuditStoreError> {
    tokio::task::spawn_blocking(move || {
        fallback_store.sweep_archive(audit_fallback_archive_retention)
    })
    .await
    .map_err(|_| LocalAuditStoreError::Io(std::io::Error::other("join failed")))?
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
        AuditRecordError::PrimaryAndFallbackFailed { .. } => "primary_and_fallback_failed",
        AuditRecordError::ResendReadFailed(_) => "resend_read_failed",
        AuditRecordError::ResendMarkSentFailed(_) => "resend_mark_sent_failed",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditFallbackSizeAlert {
    pub size_bytes: u64,
    pub threshold_bytes: u64,
}

pub fn audit_fallback_size_alert(
    path: &Path,
    threshold_bytes: u64,
) -> Result<Option<AuditFallbackSizeAlert>, std::io::Error> {
    let Some(size_bytes) = audit_fallback_file_size(path)? else {
        return Ok(None);
    };

    if size_bytes >= threshold_bytes {
        Ok(Some(AuditFallbackSizeAlert {
            size_bytes,
            threshold_bytes,
        }))
    } else {
        Ok(None)
    }
}

pub fn audit_fallback_file_size(path: &Path) -> Result<Option<u64>, std::io::Error> {
    match std::fs::metadata(path) {
        Ok(metadata) => {
            if metadata.is_file() {
                Ok(Some(metadata.len()))
            } else {
                Ok(None)
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn record_audit_fallback_size_alert(path: &Path, threshold_bytes: u64) {
    match audit_fallback_size_alert(path, threshold_bytes) {
        Ok(Some(alert)) => {
            tracing::warn!(
                path = %path.display(),
                size_bytes = alert.size_bytes,
                threshold_bytes = alert.threshold_bytes,
                "audit fallback log size threshold exceeded"
            );
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!(
                path = %path.display(),
                error_kind = ?error.kind(),
                "audit fallback log size check failed"
            );
        }
    }
}

fn record_audit_fallback_rollover_result(
    path: &Path,
    result: Result<RolloverOutcome, LocalAuditStoreError>,
) {
    match result {
        Ok(RolloverOutcome::Skipped) => {}
        Ok(RolloverOutcome::Sealed(archive)) => {
            tracing::info!(
                path = %path.display(),
                archive_path = %archive.archive_path.display(),
                sha256_hex = %archive.sha256_hex,
                line_count = archive.line_count,
                first_occurred_at = archive.first_occurred_at.as_deref(),
                last_occurred_at = archive.last_occurred_at.as_deref(),
                size_bytes = archive.size_bytes,
                "audit fallback log rolled over"
            );
        }
        Err(error) => {
            tracing::error!(
                path = %path.display(),
                error_kind = local_audit_store_error_kind(&error),
                "audit fallback rollover failed"
            );
        }
    }
}

fn record_audit_fallback_archive_sweep_result(
    archive_dir: &Path,
    retention: Duration,
    result: Result<ArchiveSweepOutcome, LocalAuditStoreError>,
) {
    match result {
        Ok(outcome) => {
            for archive in outcome.deleted_archives {
                tracing::info!(
                    archive_dir = %archive_dir.display(),
                    archive_path = %archive.archive_path.display(),
                    sha256_hex = archive.sha256_hex.as_deref(),
                    line_count = ?archive.line_count,
                    size_bytes = archive.size_bytes,
                    retention_days = retention.as_secs() / (24 * 60 * 60),
                    "audit fallback archive deleted"
                );
            }
        }
        Err(error) => {
            tracing::error!(
                archive_dir = %archive_dir.display(),
                error_kind = local_audit_store_error_kind(&error),
                "audit fallback archive sweep failed"
            );
        }
    }
}

fn should_sweep_archive(last_archive_sweep: &mut Option<Instant>) -> bool {
    let now = Instant::now();

    match last_archive_sweep {
        Some(last_sweep) if now.duration_since(*last_sweep) < AUDIT_ARCHIVE_SWEEP_INTERVAL => false,
        _ => {
            *last_archive_sweep = Some(now);
            true
        }
    }
}

fn local_audit_store_error_kind(error: &LocalAuditStoreError) -> &'static str {
    match error {
        LocalAuditStoreError::Io(_) => "io",
        LocalAuditStoreError::Json(_) => "json",
        LocalAuditStoreError::TimestampFormat(_) => "timestamp_format",
        LocalAuditStoreError::ArchivePathUnavailable { .. } => "archive_path_unavailable",
        LocalAuditStoreError::GzipWriteFailed { .. } => "gzip_write_failed",
        LocalAuditStoreError::HashReadFailed { .. } => "hash_read_failed",
        LocalAuditStoreError::CurrentFileRemoveFailed { .. } => "current_file_remove_failed",
        LocalAuditStoreError::ArchiveDeleteFailed { .. } => "archive_delete_failed",
        LocalAuditStoreError::LockPoisoned => "lock_poisoned",
        LocalAuditStoreError::InvalidLine { .. } => "invalid_line",
        LocalAuditStoreError::Event(_) => "event",
    }
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
        let parsed = super::parse_restore_test_sample(row)?;

        Ok(super::build_restore_test_decrypt_input(parsed))
    }

    pub fn restore_test_metadata(
        sample_count: u64,
        error_code: Option<&'static str>,
        failed_version: Option<u32>,
    ) -> AuditMetadata {
        super::restore_test_metadata(sample_count, error_code, failed_version)
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
        super::run_jwks_refresh_loop(
            cache,
            http_client,
            jwks_url,
            interval_duration,
            shutdown_receiver,
        )
        .await;
    }
}

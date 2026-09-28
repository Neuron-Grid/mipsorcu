use std::path::PathBuf;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

use crate::audit::{AuditRecorder, LocalAuditFallbackStore};
use crate::incident::{
    AnyNotificationSink, ComponentName, DummyNotificationSink, IncidentCategory,
    IncidentDispatchOutcome, IncidentDispatcher, IncidentId, IncidentNotification,
    IncidentRetryPolicy, IncidentSeverity, IncidentSummary,
};
use crate::server::supabase::{SupabaseAuditAppender, SupabaseClient};
use crate::types::SourceEventAt;

use super::{
    EntrypointCommand, drain_incident_aggregate_flush, parse_entrypoint_command, server_env_filter,
    spawn_incident_aggregate_flush_loop,
};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn temp_path(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    std::env::temp_dir().join(format!("mipsorcu-runtime-{test_name}-{unique}"))
}

fn incident_dispatcher_for_runtime_test(
    sink: DummyNotificationSink,
    window: Duration,
) -> Arc<IncidentDispatcher<AnyNotificationSink, SupabaseAuditAppender>> {
    let http_client = reqwest::Client::new();
    let supabase_client = Arc::new(SupabaseClient::new(
        http_client,
        "http://127.0.0.1:1".to_owned(),
        "service-role-key",
        "publishable-key",
    ));
    let audit_appender = SupabaseAuditAppender::new(supabase_client);
    let audit_recorder = Arc::new(AuditRecorder::new(
        audit_appender,
        LocalAuditFallbackStore::new(temp_path("incident-aggregate")),
    ));
    Arc::new(
        IncidentDispatcher::new(Arc::new(AnyNotificationSink::Dummy(sink)), audit_recorder)
            .with_rate_limit_window(window)
            .with_retry_policy(IncidentRetryPolicy {
                max_attempts: 1,
                initial_backoff: Duration::ZERO,
                max_total_backoff: Duration::ZERO,
            }),
    )
}

fn incident_notification(incident_id: &str) -> IncidentNotification {
    let timestamp =
        SourceEventAt::parse("2026-06-01T02:00:00Z").expect("test timestamp must be valid");
    IncidentNotification::new(
        IncidentId::parse(incident_id).expect("test incident id must be valid"),
        timestamp.clone(),
        IncidentCategory::SchedulerFailure,
        IncidentSeverity::High,
        IncidentSummary::new("scheduler job failed three consecutive times")
            .expect("test incident summary must be valid"),
        vec![ComponentName::scheduler()],
        timestamp,
    )
    .expect("test incident notification must be valid")
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

#[tokio::test]
async fn incident_aggregate_flush_loop_handle_is_created_when_dispatcher_configured() {
    let dispatcher =
        incident_dispatcher_for_runtime_test(DummyNotificationSink::new(), Duration::from_secs(60));
    let (shutdown_sender, _shutdown_receiver) = watch::channel(false);
    let handle = spawn_incident_aggregate_flush_loop(Some(&dispatcher), &shutdown_sender);

    assert!(handle.is_some());
    shutdown_sender
        .send(true)
        .expect("shutdown signal should send");
    handle
        .expect("incident aggregate flush loop handle should exist")
        .await
        .expect("incident aggregate flush loop should not panic");
}

#[test]
fn incident_aggregate_flush_loop_handle_is_not_created_without_dispatcher() {
    let (shutdown_sender, _shutdown_receiver) = watch::channel(false);

    assert!(spawn_incident_aggregate_flush_loop(None, &shutdown_sender).is_none());
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn incident_aggregate_drain_waits_for_loop_and_runs_final_flush() {
    let observed_sink = DummyNotificationSink::new();
    let dispatcher =
        incident_dispatcher_for_runtime_test(observed_sink.clone(), Duration::from_secs(10));
    let loop_waited = Arc::new(AtomicBool::new(false));
    let handle = tokio::spawn({
        let loop_waited = loop_waited.clone();
        async move {
            tokio::task::yield_now().await;
            loop_waited.store(true, Ordering::SeqCst);
        }
    });

    assert_eq!(
        dispatcher
            .dispatch(incident_notification(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            ))
            .await,
        IncidentDispatchOutcome::Sent
    );
    assert_eq!(
        dispatcher
            .dispatch(incident_notification(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            ))
            .await,
        IncidentDispatchOutcome::Suppressed
    );
    assert_eq!(observed_sink.notification_count(), 1);

    tokio::time::advance(Duration::from_secs(10)).await;
    drain_incident_aggregate_flush(Some(dispatcher), Some(handle)).await;

    assert!(loop_waited.load(Ordering::SeqCst));
    assert_eq!(observed_sink.notification_count(), 2);
}

#[derive(Clone, Default)]
struct CapturedLogs {
    bytes: Arc<Mutex<Vec<u8>>>,
}

struct CapturedLogWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl CapturedLogs {
    fn contents(&self) -> String {
        let bytes = self
            .bytes
            .lock()
            .expect("captured log buffer lock should be available");
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = CapturedLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CapturedLogWriter {
            bytes: self.bytes.clone(),
        }
    }
}

impl std::io::Write for CapturedLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut bytes = self
            .bytes
            .lock()
            .expect("captured log buffer lock should be available");
        bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// filter を通して、mipsorcu 自身（本 module の target）と依存 crate 相当の target の
/// event を 1 件ずつ出し、出力されたログを返す。
fn logs_emitted_through(filter: tracing_subscriber::EnvFilter) -> String {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(logs.clone())
        .with_env_filter(filter)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!("mipsorcu info event");
        tracing::info!(target: "dependency_crate", "dependency info event");
        tracing::warn!(target: "dependency_crate", "dependency warn event");
        tracing::error!(target: "dependency_crate", "dependency error event");
    });

    logs.contents()
}

fn assert_server_default_log_filter(logs: &str) {
    assert!(logs.contains("mipsorcu info event"));
    assert!(!logs.contains("dependency info event"));
    assert!(!logs.contains("dependency warn event"));
    assert!(logs.contains("dependency error event"));
}

#[test]
fn server_log_filter_emits_mipsorcu_info_when_rust_log_is_unset() {
    assert_server_default_log_filter(&logs_emitted_through(server_env_filter(None)));
}

#[test]
fn server_log_filter_treats_empty_or_blank_rust_log_as_unset() {
    for value in ["", "   "] {
        assert_server_default_log_filter(&logs_emitted_through(server_env_filter(Some(value))));
    }
}

#[test]
fn server_log_filter_follows_rust_log_when_set() {
    let warn_logs = logs_emitted_through(server_env_filter(Some("warn")));
    assert!(!warn_logs.contains("mipsorcu info event"));
    assert!(!warn_logs.contains("dependency info event"));
    assert!(warn_logs.contains("dependency warn event"));
    assert!(warn_logs.contains("dependency error event"));

    let info_logs = logs_emitted_through(server_env_filter(Some("info")));
    assert!(info_logs.contains("mipsorcu info event"));
    assert!(info_logs.contains("dependency info event"));
}

#[test]
fn server_log_filter_keeps_ignoring_invalid_rust_log_directives() {
    let logs = logs_emitted_through(server_env_filter(Some("mipsorcu=not-a-level")));
    assert!(!logs.contains("mipsorcu info event"));
    assert!(!logs.contains("dependency warn event"));
    assert!(logs.contains("dependency error event"));
}

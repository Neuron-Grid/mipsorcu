//! Task 13: OTLP / Splunk HEC exporter の integration test。
//!
//! wiremock で mock HTTP collector を立ち上げ、`OtlpSiemSink` と `SplunkHecSiemSink` が
//! 正しい Authorization ヘッダと JSON body を送信し、エラー時に明確な error code を
//! 返すことを検証する。秘密 token は `SecretString` に閉じ込めるため、テスト実行時の
//! tracing 出力にも露出してはならない。

use mipsorcu::audit::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditResult, DecryptMetadata, RequestId,
};
use mipsorcu::siem::{OtlpSiemSink, SiemEvent, SiemSink, SiemSinkError, SplunkHecSiemSink};
use mipsorcu::types::{KeyVersion, OwnerUserId, SecretId, SourceEventAt};
use wiremock::matchers::{header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_OWNER_USER_ID: &str = "F47AC10B-58CC-4372-A567-0E02B2C3D479";
const TEST_SECRET_ID: &str = "A1B2C3D4-E5F6-4789-9ABC-DEF012345678";

fn make_audit_event() -> AuditEvent {
    let audit_event_id = AuditEventId::generate().expect("audit event id");
    let request_id = RequestId::generate().expect("request id");
    let owner_user_id = OwnerUserId::parse(TEST_OWNER_USER_ID).expect("owner");
    let secret_id = SecretId::parse(TEST_SECRET_ID).expect("secret id");
    let source_event_at = SourceEventAt::now_utc().expect("source event at");
    let metadata = DecryptMetadata::success()
        .with_source_event_at(source_event_at)
        .build()
        .expect("metadata");
    AuditEvent::new(AuditEventParts {
        audit_event_id,
        request_id,
        actor_user_id: Some(owner_user_id),
        actor_device_id: None,
        action: AuditAction::Decrypt,
        target_secret_id: Some(secret_id),
        result: AuditResult::Success,
        key_version: Some(KeyVersion::new(1).expect("key version")),
        metadata_json: metadata,
    })
    .expect("audit event")
}

fn make_siem_event() -> SiemEvent {
    SiemEvent::from_audit_event(&make_audit_event())
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .build()
        .expect("http client builds in test")
}

#[tokio::test]
async fn otlp_sink_posts_log_record_to_collector() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/logs"))
        .and(header("content-type", "application/json"))
        .and(header("authorization", "Bearer test-otlp-token"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let endpoint = format!("{}/v1/logs", server.uri());
    let token = mipsorcu::types::SecretString::new("test-otlp-token").expect("token");
    let sink = OtlpSiemSink::new(http_client(), endpoint, Some(token));
    let event = make_siem_event();

    sink.send_event(&event).await.expect("post should succeed");
}

#[tokio::test]
async fn otlp_sink_returns_backend_failed_on_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/logs"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let endpoint = format!("{}/v1/logs", server.uri());
    let sink = OtlpSiemSink::new(http_client(), endpoint, None);
    let event = make_siem_event();

    let error = sink
        .send_event(&event)
        .await
        .expect_err("503 should map to BackendFailed");

    match error {
        SiemSinkError::BackendFailed { code } => {
            assert_eq!(code, "siem_otlp_http_503");
        }
        SiemSinkError::InvalidResponse { reason } => panic!("unexpected InvalidResponse: {reason}"),
    }
}

#[tokio::test]
async fn otlp_sink_maps_transport_failure_when_endpoint_unreachable() {
    // wiremock サーバを立てずに、存在しない localhost ポートへ送る。
    let endpoint = "http://127.0.0.1:1/v1/logs".to_owned();
    let sink = OtlpSiemSink::new(http_client(), endpoint, None);
    let event = make_siem_event();

    let error = sink
        .send_event(&event)
        .await
        .expect_err("unreachable endpoint should fail");

    match error {
        SiemSinkError::BackendFailed { code } => {
            assert_eq!(code, "siem_otlp_transport");
        }
        SiemSinkError::InvalidResponse { reason } => panic!("unexpected InvalidResponse: {reason}"),
    }
}

#[tokio::test]
async fn splunk_hec_sink_posts_event_with_splunk_auth_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .and(header("content-type", "application/json"))
        .and(header("authorization", "Splunk hec-secret-token"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let endpoint = format!("{}/services/collector/event", server.uri());
    let token = mipsorcu::types::SecretString::new("hec-secret-token").expect("hec token");
    let sink = SplunkHecSiemSink::new(http_client(), endpoint, token);
    let event = make_siem_event();

    sink.send_event(&event).await.expect("splunk hec post ok");
}

#[tokio::test]
async fn splunk_hec_sink_returns_backend_failed_on_4xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let endpoint = format!("{}/services/collector/event", server.uri());
    let token = mipsorcu::types::SecretString::new("rejected-token").expect("token");
    let sink = SplunkHecSiemSink::new(http_client(), endpoint, token);
    let event = make_siem_event();

    let error = sink
        .send_event(&event)
        .await
        .expect_err("401 should map to BackendFailed");
    match error {
        SiemSinkError::BackendFailed { code } => {
            assert_eq!(code, "siem_splunk_http_401");
        }
        SiemSinkError::InvalidResponse { reason } => panic!("unexpected InvalidResponse: {reason}"),
    }
}

#[tokio::test]
async fn splunk_hec_sink_does_not_leak_token_in_debug_render() {
    let token = mipsorcu::types::SecretString::new("ultra-secret-hec").expect("token");
    let debug_render = format!("{token:?}");
    assert!(
        !debug_render.contains("ultra-secret-hec"),
        "secret token must be redacted in Debug"
    );
    assert!(debug_render.contains("<redacted>"));
}

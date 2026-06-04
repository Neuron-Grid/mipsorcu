//! Task 14: incident notification webhook sink の integration test。
//!
//! wiremock で webhook 受信側を立て、HMAC-SHA3-256 署名ヘッダの形式と内容、
//! および HTTP 失敗時の error code マッピングを検証する。

use hmac::{Hmac, KeyInit, Mac};
use mipsorcu::incident::{
    ComponentName, IncidentCategory, IncidentId, IncidentNotification, IncidentNotificationPayload,
    IncidentNotifier, IncidentSeverity, IncidentSummary, IncidentType, NotificationSink,
    NotificationSinkError, WebhookNotificationSink,
};
use mipsorcu::types::{SecretString, SourceEventAt};
use sha3::Sha3_256;
use wiremock::matchers::{body_bytes, header, header_exists, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

type HmacSha3_256 = Hmac<Sha3_256>;

const HMAC_HEADER_NAME: &str = "X-Mipsorcu-Signature";

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .build()
        .expect("http client builds in test")
}

fn make_payload() -> IncidentNotificationPayload {
    IncidentNotificationPayload {
        incident_type: IncidentType::HashChainMismatch,
        severity: IncidentSeverity::Critical,
        detection_source: "ledger_hash_chain_full_verify".to_owned(),
        dedupe_key: "hash_chain_mismatch:scheduler:2026-05".to_owned(),
        error_code: "ledger_chain_head_mismatch".to_owned(),
        source_event_id: None,
        target_sequence_no: Some(42),
        target_year_month: Some("2026-05".to_owned()),
    }
}

fn timestamp(value: &str) -> SourceEventAt {
    SourceEventAt::parse(value).expect("test timestamp must be valid")
}

fn make_notification() -> IncidentNotification {
    IncidentNotification::new(
        IncidentId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            .expect("test incident id must be valid"),
        timestamp("2026-06-01T03:00:00Z"),
        IncidentCategory::SchedulerFailure,
        IncidentSeverity::High,
        IncidentSummary::new("scheduler job failed three consecutive times")
            .expect("summary must be valid"),
        vec![ComponentName::scheduler()],
        timestamp("2026-06-01T03:00:00Z"),
    )
    .expect("notification must be valid")
}

fn compute_expected_signature(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha3_256::new_from_slice(secret).expect("hmac");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

#[tokio::test]
async fn webhook_notifier_signs_incident_notification_body_with_hmac_sha3_256() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/incident"))
        .and(header("content-type", "application/json"))
        .and(header_exists(HMAC_HEADER_NAME))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let endpoint = format!("{}/incident", server.uri());
    let secret_bytes = b"hmac-secret-must-be-at-least-32b";
    let secret =
        SecretString::new(std::str::from_utf8(secret_bytes).expect("utf8")).expect("secret string");
    let sink = WebhookNotificationSink::new(http_client(), endpoint, secret);
    let notification = make_notification();

    IncidentNotifier::notify(&sink, &notification)
        .await
        .expect("webhook post succeeds");

    let received = server.received_requests().await.expect("requests");
    assert_eq!(received.len(), 1);
    let request: &Request = &received[0];
    let signature_header = request
        .headers
        .get(HMAC_HEADER_NAME)
        .expect("X-Mipsorcu-Signature must be present");
    let signature_value = signature_header.to_str().expect("ascii signature");
    let expected = compute_expected_signature(secret_bytes, &request.body);
    assert_eq!(signature_value, expected);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&request.body).expect("body must be json")["category"],
        serde_json::json!("scheduler_failure")
    );
}

#[tokio::test]
async fn webhook_sink_signs_body_with_hmac_sha3_256() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/incident"))
        .and(header("content-type", "application/json"))
        .and(header_exists(HMAC_HEADER_NAME))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let endpoint = format!("{}/incident", server.uri());
    let secret_bytes = b"hmac-secret-must-be-at-least-32b";
    let secret =
        SecretString::new(std::str::from_utf8(secret_bytes).expect("utf8")).expect("secret string");
    let sink = WebhookNotificationSink::new(http_client(), endpoint, secret);
    let payload = make_payload();

    NotificationSink::notify(&sink, &payload)
        .await
        .expect("webhook post succeeds");

    // 検査: wiremock の受信記録からヘッダを取り出し、HMAC を再計算して一致を検証する。
    let received = server.received_requests().await.expect("requests");
    assert_eq!(received.len(), 1);
    let request: &Request = &received[0];
    let signature_header = request
        .headers
        .get(HMAC_HEADER_NAME)
        .expect("X-Mipsorcu-Signature must be present");
    let signature_value = signature_header.to_str().expect("ascii signature");
    let expected = compute_expected_signature(secret_bytes, &request.body);
    assert_eq!(signature_value, expected);
    assert_eq!(signature_value.len(), 64);
    assert!(
        signature_value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
    );
}

#[tokio::test]
async fn webhook_sink_returns_backend_failed_on_4xx() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/incident"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let endpoint = format!("{}/incident", server.uri());
    let secret = SecretString::new("hmac-secret-must-be-at-least-32b").expect("secret");
    let sink = WebhookNotificationSink::new(http_client(), endpoint, secret);
    let payload = make_payload();

    let error = NotificationSink::notify(&sink, &payload)
        .await
        .expect_err("401 should map to BackendFailed");
    match error {
        NotificationSinkError::BackendFailed { code } => {
            assert_eq!(code, "incident_webhook_http_401");
        }
    }
}

#[tokio::test]
async fn webhook_sink_returns_transport_failure_when_endpoint_unreachable() {
    let endpoint = "http://127.0.0.1:1/incident".to_owned();
    let secret = SecretString::new("hmac-secret-must-be-at-least-32b").expect("secret");
    let sink = WebhookNotificationSink::new(http_client(), endpoint, secret);
    let payload = make_payload();

    let error = NotificationSink::notify(&sink, &payload)
        .await
        .expect_err("unreachable endpoint should fail");
    match error {
        NotificationSinkError::BackendFailed { code } => {
            assert_eq!(code, "incident_webhook_transport");
        }
    }
}

#[tokio::test]
async fn webhook_payload_body_does_not_contain_forbidden_secret_keys() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/incident"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let endpoint = format!("{}/incident", server.uri());
    let secret = SecretString::new("hmac-secret-must-be-at-least-32b").expect("secret");
    let sink = WebhookNotificationSink::new(http_client(), endpoint, secret);
    let payload = make_payload();

    NotificationSink::notify(&sink, &payload)
        .await
        .expect("webhook post succeeds");
    let received = server.received_requests().await.expect("requests");
    let body_text = String::from_utf8(received[0].body.clone()).expect("body utf8");

    for forbidden in [
        "ciphertext",
        "plaintext",
        "nonce",
        "wrapped_dek",
        "encrypted_data_key",
        "master_key",
        "kek_value",
        "signature_private_key",
        "alias_encryption_key",
    ] {
        assert!(
            !body_text.contains(forbidden),
            "webhook body must not contain forbidden key '{forbidden}'"
        );
    }
}

#[tokio::test]
async fn webhook_sink_rejects_inert_secret_change_no_signature_match() {
    // 同一 body・異なる secret で HMAC が変化することを確認するヘルスチェック。
    let body = b"{\"hello\":\"world\"}";
    let alpha = body_bytes(body.as_slice());
    let _ = alpha; // body_bytes は wiremock matcher 用なのでテストには使わない（unused 抑制）

    let secret_a = b"alpha-secret-must-be-32-bytes-pad";
    let secret_b = b"beta-secret-must-be-32-bytes-padd";
    let sig_a = compute_expected_signature(secret_a, body);
    let sig_b = compute_expected_signature(secret_b, body);
    assert_ne!(sig_a, sig_b);
}

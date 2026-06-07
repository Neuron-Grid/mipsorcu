//! Incident notification の webhook sink 実装。
//!
//! 実装方針: `reqwest` で webhook URL に JSON POST する。
//! 受信側との完全性保証のため、body 全文に対し HMAC-SHA3-256 を計算して
//! `X-Mipsorcu-Signature` ヘッダに hex 文字列で載せる。プロジェクトの
//! SHA3 統一方針（ADR-0050）に従い、HMAC は SHA3-256 を使用する。
//!
//! 信頼境界ノート: payload は `IncidentNotificationPayload`（非秘密 DTO）から
//! `serde_json::to_vec` した body のみ。秘密フィールドは型レベルで含み得ない。
//! 共有秘密は `SecretString` に閉じ込め、`Display` / `serde::Serialize` を
//! 経由した漏洩を構造的に防ぐ。TLS 検証は呼び出し側の `reqwest::Client` が
//! 保持する。

use std::time::Instant;

use hmac::{KeyInit, Mac, SimpleHmac};
use sha3::Sha3_256;

use crate::types::SecretString;
use crate::types::SourceEventAt;

use super::IncidentNotification;
use super::dto::{IncidentNotifierKind, NotificationReceipt};
use super::sink::{IncidentError, IncidentNotifier, NotificationSink, NotificationSinkError};
use super::types::IncidentNotificationPayload;

type HmacSha3_256 = SimpleHmac<Sha3_256>;

const SIGNATURE_HEADER: &str = "X-Mipsorcu-Signature";

/// HMAC-SHA3-256 署名つきの webhook 通知 sink。
#[derive(Clone)]
pub struct WebhookNotificationSink {
    client: reqwest::Client,
    endpoint: String,
    secret: SecretString,
}

impl WebhookNotificationSink {
    pub fn new(client: reqwest::Client, endpoint: impl Into<String>, secret: SecretString) -> Self {
        Self {
            client,
            endpoint: endpoint.into(),
            secret,
        }
    }
}

impl NotificationSink for WebhookNotificationSink {
    fn sink_name(&self) -> &'static str {
        "webhook"
    }

    async fn notify(
        &self,
        payload: &IncidentNotificationPayload,
    ) -> Result<(), NotificationSinkError> {
        let body =
            serde_json::to_vec(payload).map_err(|_| NotificationSinkError::BackendFailed {
                code: "incident_webhook_serialize_failed".to_owned(),
            })?;
        self.post_body(body).await
    }
}

impl IncidentNotifier for WebhookNotificationSink {
    fn notifier_kind(&self) -> IncidentNotifierKind {
        IncidentNotifierKind::Webhook
    }

    async fn notify(
        &self,
        notification: &IncidentNotification,
    ) -> Result<NotificationReceipt, IncidentError> {
        let started_at = Instant::now();
        let body =
            notification
                .canonical_json_bytes()
                .map_err(|_| IncidentError::InvalidPayload {
                    code: "incident_webhook_serialize_failed".to_owned(),
                })?;
        self.post_body(body).await.map_err(IncidentError::from)?;
        let delivered_at = SourceEventAt::now_utc().map_err(|_| IncidentError::BackendFailed {
            code: "incident_webhook_timestamp_failed".to_owned(),
        })?;
        Ok(NotificationReceipt::new(
            IncidentNotifierKind::Webhook,
            delivered_at,
            started_at
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        ))
    }
}

impl WebhookNotificationSink {
    async fn post_body(&self, body: Vec<u8>) -> Result<(), NotificationSinkError> {
        let signature_hex = compute_signature_hex(self.secret.as_bytes(), &body)?;
        let response = self
            .client
            .post(self.endpoint.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(SIGNATURE_HEADER, signature_hex)
            .body(body)
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(error_kind = "transport", "incident webhook post failed");
                let _ = error;
                NotificationSinkError::BackendFailed {
                    code: "incident_webhook_transport".to_owned(),
                }
            })?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        Err(NotificationSinkError::BackendFailed {
            code: format!("incident_webhook_http_{}", status.as_u16()),
        })
    }
}

fn compute_signature_hex(secret: &[u8], body: &[u8]) -> Result<String, NotificationSinkError> {
    let mut mac =
        HmacSha3_256::new_from_slice(secret).map_err(|_| NotificationSinkError::BackendFailed {
            code: "incident_webhook_secret_invalid".to_owned(),
        })?;
    mac.update(body);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// runtime で選択される通知 sink を 1 つの enum に閉じ込め、
/// `IncidentDispatcher` で `dummy` / `webhook` の動的選択を可能にする。
#[derive(Clone)]
pub enum AnyNotificationSink {
    Dummy(super::dummy::DummyNotificationSink),
    Webhook(WebhookNotificationSink),
}

impl AnyNotificationSink {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Dummy(_) => "dummy",
            Self::Webhook(_) => "webhook",
        }
    }
}

impl NotificationSink for AnyNotificationSink {
    fn sink_name(&self) -> &'static str {
        match self {
            Self::Dummy(sink) => sink.sink_name(),
            Self::Webhook(sink) => sink.sink_name(),
        }
    }

    async fn notify(
        &self,
        payload: &IncidentNotificationPayload,
    ) -> Result<(), NotificationSinkError> {
        match self {
            Self::Dummy(sink) => NotificationSink::notify(sink, payload).await,
            Self::Webhook(sink) => NotificationSink::notify(sink, payload).await,
        }
    }
}

impl IncidentNotifier for AnyNotificationSink {
    fn notifier_kind(&self) -> IncidentNotifierKind {
        match self {
            Self::Dummy(sink) => sink.notifier_kind(),
            Self::Webhook(sink) => sink.notifier_kind(),
        }
    }

    async fn notify(
        &self,
        notification: &IncidentNotification,
    ) -> Result<NotificationReceipt, IncidentError> {
        match self {
            Self::Dummy(sink) => IncidentNotifier::notify(sink, notification).await,
            Self::Webhook(sink) => IncidentNotifier::notify(sink, notification).await,
        }
    }
}

pub type WebhookIncidentNotifier = WebhookNotificationSink;

#[cfg(test)]
#[path = "../../tests/unit/incident/webhook/tests.rs"]
mod tests;

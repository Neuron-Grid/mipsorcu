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

use hmac::{Hmac, KeyInit, Mac};
use sha3::Sha3_256;

use crate::types::SecretString;

use super::sink::{NotificationSink, NotificationSinkError};
use super::types::IncidentNotificationPayload;

type HmacSha3_256 = Hmac<Sha3_256>;

const SIGNATURE_HEADER: &str = "X-Mipsorcu-Signature";

/// HMAC-SHA3-256 署名つきの webhook 通知 sink。
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
/// `IncidentRecorder<S: NotificationSink>` のジェネリック境界を維持したまま
/// 動的選択を可能にする dispatcher。
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
            Self::Dummy(sink) => sink.notify(payload).await,
            Self::Webhook(sink) => sink.notify(payload).await,
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/incident/webhook/tests.rs"]
mod tests;

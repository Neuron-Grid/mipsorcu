//! Splunk HTTP Event Collector (HEC) ベースの SIEM exporter 実装。
//!
//! 実装方針: `reqwest` で `/services/collector/event` に JSON POST する最小実装。
//! HEC token は `Authorization: Splunk <token>` ヘッダで授受する。
//!
//! 信頼境界ノート: 送信 body は `SiemEvent` から HEC event 形式への構造変換のみ。
//! 秘密フィールドは型レベルで含み得ない。Token は `SecretString` に格納し、
//! `Display` / `serde::Serialize` を経由した漏洩を構造的に防ぐ。

use serde_json::{Value, json};

use crate::types::SecretString;

use super::event::SiemEvent;
use super::sink::{SiemSink, SiemSinkError};

/// Splunk HEC への SIEM exporter。
pub struct SplunkHecSiemSink {
    client: reqwest::Client,
    endpoint: String,
    token: SecretString,
    source: String,
    sourcetype: String,
    host: String,
}

impl SplunkHecSiemSink {
    /// 新規構築。`endpoint` は HEC URL (例: `https://splunk:8088/services/collector/event`)。
    pub fn new(client: reqwest::Client, endpoint: impl Into<String>, token: SecretString) -> Self {
        Self {
            client,
            endpoint: endpoint.into(),
            token,
            source: "mipsorcu/sbc".to_owned(),
            sourcetype: "mipsorcu:audit".to_owned(),
            host: "mipsorcu".to_owned(),
        }
    }

    fn build_payload(&self, event: &SiemEvent) -> Value {
        let event_value = serde_json::to_value(event).unwrap_or(Value::Null);
        let time_epoch_seconds = source_event_at_to_unix_seconds(event.source_event_at());
        json!({
            "time": time_epoch_seconds,
            "host": self.host,
            "source": self.source,
            "sourcetype": self.sourcetype,
            "event": event_value,
        })
    }
}

/// RFC3339 文字列を unix epoch 秒（f64）に変換する。失敗時は 0。
fn source_event_at_to_unix_seconds(value: &str) -> f64 {
    match time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339) {
        Ok(parsed) => {
            let seconds = parsed.unix_timestamp() as f64;
            let nanos = f64::from(parsed.nanosecond());
            seconds + nanos / 1_000_000_000.0
        }
        Err(_) => 0.0,
    }
}

impl SiemSink for SplunkHecSiemSink {
    async fn send_event(&self, event: &SiemEvent) -> Result<(), SiemSinkError> {
        let body = serde_json::to_vec(&self.build_payload(event)).unwrap_or_default();
        let response = self
            .client
            .post(self.endpoint.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Splunk {}", self.token.expose_secret()),
            )
            .body(body)
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(error_kind = "transport", "splunk hec siem post failed");
                let _ = error;
                SiemSinkError::BackendFailed {
                    code: "siem_splunk_transport".to_owned(),
                }
            })?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        Err(SiemSinkError::BackendFailed {
            code: format!("siem_splunk_http_{}", status.as_u16()),
        })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/siem/splunk_hec/tests.rs"]
mod tests;

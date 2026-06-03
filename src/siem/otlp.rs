//! OTLP/HTTP/JSON ベースの SIEM exporter 実装。
//!
//! 実装方針: `opentelemetry-otlp` クレートは導入せず、既存の `reqwest` /
//! `serde_json` で OTLP/HTTP/JSON `/v1/logs` 仕様に従う最小スキーマを直接
//! POST する。これにより:
//!
//! - 追加依存ゼロ（reqwest と serde_json は既存依存）
//! - attack surface 最小（TLS 設定は `build_outbound_http_client` を継承）
//! - wiremock による integration test 容易性
//!
//! 信頼境界ノート: 送信 body は `SiemEvent` から OTLP `LogRecord` への
//! 構造変換のみで、秘密フィールド（ciphertext / plaintext / wrapped_dek /
//! kek_value / master_key / signature_private_key 等）を型レベルで持ち得ない。
//! Authorization token は `SecretString` に閉じ込め、`Display` / `serde::Serialize` を
//! 経由した漏洩を構造的に防ぐ。

use serde_json::{Value, json};

use crate::types::SecretString;

use super::event::SiemEvent;
use super::sink::{ForwardReceipt, SiemExporterKind, SiemSink, SiemSinkError, validate_batch_size};

/// OTLP/HTTP/JSON `/v1/logs` への SIEM exporter。
pub struct OtlpSiemSink {
    client: reqwest::Client,
    endpoint: String,
    auth_token: Option<SecretString>,
    service_name: String,
}

impl OtlpSiemSink {
    /// 新規構築。`endpoint` は `https://collector.example/v1/logs` のような完全 URL。
    pub fn new(
        client: reqwest::Client,
        endpoint: impl Into<String>,
        auth_token: Option<SecretString>,
    ) -> Self {
        Self {
            client,
            endpoint: endpoint.into(),
            auth_token,
            service_name: "mipsorcu-sbc".to_owned(),
        }
    }

    fn build_log_record(event: &SiemEvent) -> Value {
        let event_value = serde_json::to_value(event).unwrap_or(Value::Null);
        let severity_text = if event.result() == "success" {
            "INFO"
        } else {
            "ERROR"
        };
        let time_unix_nano = source_event_at_to_unix_nano(event.source_event_at());

        let mut attributes = vec![
            otlp_attribute("event.id", event.event_id()),
            otlp_attribute("event.type", event.event_type()),
            otlp_attribute("event.result", event.result()),
            otlp_attribute("event.request_id", event.request_id()),
            otlp_attribute("event.source_event_at", event.source_event_at()),
        ];
        if let Some(actor) = event.actor_user_id() {
            attributes.push(otlp_attribute("event.actor_user_id", actor));
        }
        if let Some(device) = event.actor_device_id() {
            attributes.push(otlp_attribute("event.actor_device_id", device));
        }
        if let Some(secret_id) = event.target_secret_id() {
            attributes.push(otlp_attribute("event.target_secret_id", secret_id));
        }
        if let Some(key_version) = event.key_version() {
            attributes.push(json!({
                "key": "event.key_version",
                "value": {"intValue": key_version},
            }));
        }
        // body には canonical JSON 全文を入れる。受信側 collector でフィルタ・整形しやすい。
        let body_string = serde_json::to_string(&event_value).unwrap_or_default();
        json!({
            "timeUnixNano": time_unix_nano,
            "severityText": severity_text,
            "body": {"stringValue": body_string},
            "attributes": attributes,
        })
    }

    fn build_request_body(&self, batch: &[SiemEvent]) -> Result<Vec<u8>, SiemSinkError> {
        validate_batch_size(batch.len())?;
        let log_records: Vec<Value> = batch.iter().map(Self::build_log_record).collect();
        let payload = json!({
            "resourceLogs": [{
                "resource": {
                    "attributes": [
                        otlp_attribute("service.name", &self.service_name),
                    ],
                },
                "scopeLogs": [{
                    "scope": {"name": "mipsorcu.audit"},
                    "logRecords": log_records,
                }],
            }],
        });
        serde_json::to_vec(&payload).map_err(|_| SiemSinkError::BackendFailed {
            code: "siem_otlp_serialize".to_owned(),
        })
    }
}

fn otlp_attribute(key: &str, value: &str) -> Value {
    json!({
        "key": key,
        "value": {"stringValue": value},
    })
}

/// RFC3339 文字列を unix nano 文字列に変換する。失敗時は "0"（collector が
/// 受信時刻で補完する）。秘密情報は時刻文字列に含まれない。
fn source_event_at_to_unix_nano(value: &str) -> String {
    match time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339) {
        Ok(parsed) => {
            // unix_timestamp は秒の i64、nanosecond は 0..=999_999_999 の u32。
            let seconds = parsed.unix_timestamp();
            let nanos = i64::from(parsed.nanosecond());
            let total = seconds.saturating_mul(1_000_000_000).saturating_add(nanos);
            total.to_string()
        }
        Err(_) => "0".to_owned(),
    }
}

impl SiemSink for OtlpSiemSink {
    fn exporter_kind(&self) -> SiemExporterKind {
        SiemExporterKind::Otlp
    }

    async fn send_batch(&self, batch: &[SiemEvent]) -> Result<ForwardReceipt, SiemSinkError> {
        let body = self.build_request_body(batch)?;
        let mut request = self
            .client
            .post(self.endpoint.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(token) = self.auth_token.as_ref() {
            request = request.header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", token.expose_secret()),
            );
        }

        let response = request.send().await.map_err(|error| {
            tracing::warn!(error_kind = "transport", "otlp siem post failed");
            // error 値そのものを log/Display しない（reqwest の Display は URL を含む可能性）。
            let _ = error;
            SiemSinkError::BackendFailed {
                code: "siem_otlp_transport".to_owned(),
            }
        })?;
        let status = response.status();
        if status.is_success() {
            return Ok(ForwardReceipt::new(self.exporter_kind(), batch.len()));
        }
        Err(SiemSinkError::BackendFailed {
            code: format!("siem_otlp_http_{}", status.as_u16()),
        })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/siem/otlp/tests.rs"]
mod tests;

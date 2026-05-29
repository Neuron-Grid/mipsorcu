//! 署名済み S3 HTTP リクエストの実行（reqwest を使用）。
//!
//! sigv4 計算は `sigv4` モジュールに委譲し、本モジュールは URL 構築・ヘッダ
//! 組み立て・status code 分類・retry のみ担当する。
//!
//! セキュリティ: response body 全文・`Authorization` ヘッダ値・credentials は
//! ログ出力しない。

use reqwest::Method;
use sha2::Digest;
use time::OffsetDateTime;
use time::format_description::FormatItem;
use time::macros::format_description;

use super::config::S3ArchiveBackendConfig;
use super::error::S3BackendError;
use super::object_lock::retain_until_date;
use super::sigv4::{SignRequestInput, percent_encode_path_segment, sign};

const AMZ_DATE_FORMAT: &[FormatItem<'static>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");
const DATE_STAMP_FORMAT: &[FormatItem<'static>] = format_description!("[year][month][day]");

const HEADER_HOST: &str = "host";
const HEADER_X_AMZ_DATE: &str = "x-amz-date";
const HEADER_X_AMZ_CONTENT_SHA256: &str = "x-amz-content-sha256";
const HEADER_X_AMZ_SECURITY_TOKEN: &str = "x-amz-security-token";
const HEADER_X_AMZ_OBJECT_LOCK_MODE: &str = "x-amz-object-lock-mode";
const HEADER_X_AMZ_OBJECT_LOCK_RETAIN_UNTIL_DATE: &str = "x-amz-object-lock-retain-until-date";
const HEADER_CONTENT_TYPE: &str = "content-type";
const HEADER_IF_NONE_MATCH: &str = "if-none-match";

const CONTENT_TYPE_JSON: &str = "application/json";

/// PUT object のレスポンス分類。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PutOutcome {
    Created,
}

/// HEAD/GET object のレスポンス分類。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum HeadOutcome {
    Found,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ListObjectsV2Output {
    pub keys: Vec<String>,
    pub next_continuation_token: Option<String>,
}

pub(super) struct S3HttpClient<'a> {
    pub config: &'a S3ArchiveBackendConfig,
    pub http: &'a reqwest::Client,
}

impl<'a> S3HttpClient<'a> {
    pub async fn put_object(
        &self,
        object_key: &str,
        body: Vec<u8>,
        now: OffsetDateTime,
    ) -> Result<PutOutcome, S3BackendError> {
        let (url, host) = self.build_url_and_host(object_key)?;
        let canonical_uri = self.canonical_uri(object_key);
        let amz_date = format_amz_date(now)?;
        let date_stamp = format_date_stamp(now)?;
        let retain_until = retain_until_date(now, self.config.retention_days())?;
        let payload_hash = hex::encode(sha2::Sha256::digest(&body));

        let mut headers: Vec<(String, String)> = vec![
            (HEADER_HOST.to_owned(), host),
            (HEADER_X_AMZ_DATE.to_owned(), amz_date.clone()),
            (HEADER_X_AMZ_CONTENT_SHA256.to_owned(), payload_hash),
            (HEADER_CONTENT_TYPE.to_owned(), CONTENT_TYPE_JSON.to_owned()),
            (
                HEADER_X_AMZ_OBJECT_LOCK_MODE.to_owned(),
                self.config.object_lock_mode().as_header_value().to_owned(),
            ),
            (
                HEADER_X_AMZ_OBJECT_LOCK_RETAIN_UNTIL_DATE.to_owned(),
                retain_until,
            ),
        ];
        if self.config.forbid_overwrite() {
            headers.push((HEADER_IF_NONE_MATCH.to_owned(), "*".to_owned()));
        }
        if let Some(token) = self.config.session_token() {
            headers.push((
                HEADER_X_AMZ_SECURITY_TOKEN.to_owned(),
                token.expose().to_owned(),
            ));
        }

        let signed = sign(SignRequestInput {
            method: "PUT",
            canonical_uri: &canonical_uri,
            canonical_query_string: "",
            headers: &headers,
            payload: &body,
            region: self.config.region(),
            access_key_id: self.config.access_key_id(),
            secret_access_key: self.config.secret_access_key().expose(),
            amz_date: &amz_date,
            date_stamp: &date_stamp,
        })?;

        let mut request = self.http.request(Method::PUT, &url);
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        request = request
            .header("Authorization", signed.authorization_header)
            .body(body);

        let response = request
            .send()
            .await
            .map_err(|error| classify_reqwest_error(&error))?;

        let status = response.status();
        if status.is_success() {
            return Ok(PutOutcome::Created);
        }
        classify_failure_status(status.as_u16())
    }

    pub async fn head_object(
        &self,
        object_key: &str,
        now: OffsetDateTime,
    ) -> Result<HeadOutcome, S3BackendError> {
        let (url, host) = self.build_url_and_host(object_key)?;
        let canonical_uri = self.canonical_uri(object_key);
        let amz_date = format_amz_date(now)?;
        let date_stamp = format_date_stamp(now)?;

        // HEAD/GET の空 body の SHA-256 は固定。
        let payload_hash = hex::encode(sha2::Sha256::digest([]));

        let mut headers: Vec<(String, String)> = vec![
            (HEADER_HOST.to_owned(), host),
            (HEADER_X_AMZ_DATE.to_owned(), amz_date.clone()),
            (HEADER_X_AMZ_CONTENT_SHA256.to_owned(), payload_hash.clone()),
        ];
        if let Some(token) = self.config.session_token() {
            headers.push((
                HEADER_X_AMZ_SECURITY_TOKEN.to_owned(),
                token.expose().to_owned(),
            ));
        }

        let signed = sign(SignRequestInput {
            method: "HEAD",
            canonical_uri: &canonical_uri,
            canonical_query_string: "",
            headers: &headers,
            payload: &[],
            region: self.config.region(),
            access_key_id: self.config.access_key_id(),
            secret_access_key: self.config.secret_access_key().expose(),
            amz_date: &amz_date,
            date_stamp: &date_stamp,
        })?;

        let mut request = self.http.request(Method::HEAD, &url);
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        request = request.header("Authorization", signed.authorization_header);

        let response = request
            .send()
            .await
            .map_err(|error| classify_reqwest_error(&error))?;

        let status = response.status().as_u16();
        if response.status().is_success() {
            return Ok(HeadOutcome::Found);
        }
        if status == 404 {
            return Ok(HeadOutcome::NotFound);
        }
        classify_failure_status(status).map(|_| HeadOutcome::Found)
    }

    pub async fn list_objects_v2(
        &self,
        continuation_token: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<ListObjectsV2Output, S3BackendError> {
        let (url, host, canonical_uri, canonical_query_string) =
            self.build_list_url_and_signing_parts(continuation_token)?;
        let amz_date = format_amz_date(now)?;
        let date_stamp = format_date_stamp(now)?;
        let payload_hash = hex::encode(sha2::Sha256::digest([]));

        let mut headers: Vec<(String, String)> = vec![
            (HEADER_HOST.to_owned(), host),
            (HEADER_X_AMZ_DATE.to_owned(), amz_date.clone()),
            (HEADER_X_AMZ_CONTENT_SHA256.to_owned(), payload_hash),
        ];
        if let Some(token) = self.config.session_token() {
            headers.push((
                HEADER_X_AMZ_SECURITY_TOKEN.to_owned(),
                token.expose().to_owned(),
            ));
        }

        let signed = sign(SignRequestInput {
            method: "GET",
            canonical_uri: &canonical_uri,
            canonical_query_string: &canonical_query_string,
            headers: &headers,
            payload: &[],
            region: self.config.region(),
            access_key_id: self.config.access_key_id(),
            secret_access_key: self.config.secret_access_key().expose(),
            amz_date: &amz_date,
            date_stamp: &date_stamp,
        })?;

        let mut request = self.http.request(Method::GET, &url);
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        request = request.header("Authorization", signed.authorization_header);

        let response = request
            .send()
            .await
            .map_err(|error| classify_reqwest_error(&error))?;

        let status = response.status().as_u16();
        if response.status().is_success() {
            let text = response
                .text()
                .await
                .map_err(|error| S3BackendError::ResponseRead(error.to_string()))?;
            return parse_list_objects_v2_response(&text);
        }
        match status {
            401 | 403 => Err(S3BackendError::Unauthenticated),
            408 | 429 => Err(S3BackendError::ServerError { status }),
            500..=599 => Err(S3BackendError::ServerError { status }),
            _ => Err(S3BackendError::Unexpected { status }),
        }
    }

    pub async fn get_object_bytes(
        &self,
        object_key: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, S3BackendError> {
        let (url, host) = self.build_url_and_host(object_key)?;
        let canonical_uri = self.canonical_uri(object_key);
        let amz_date = format_amz_date(now)?;
        let date_stamp = format_date_stamp(now)?;
        let payload_hash = hex::encode(sha2::Sha256::digest([]));

        let mut headers: Vec<(String, String)> = vec![
            (HEADER_HOST.to_owned(), host),
            (HEADER_X_AMZ_DATE.to_owned(), amz_date.clone()),
            (HEADER_X_AMZ_CONTENT_SHA256.to_owned(), payload_hash.clone()),
        ];
        if let Some(token) = self.config.session_token() {
            headers.push((
                HEADER_X_AMZ_SECURITY_TOKEN.to_owned(),
                token.expose().to_owned(),
            ));
        }

        let signed = sign(SignRequestInput {
            method: "GET",
            canonical_uri: &canonical_uri,
            canonical_query_string: "",
            headers: &headers,
            payload: &[],
            region: self.config.region(),
            access_key_id: self.config.access_key_id(),
            secret_access_key: self.config.secret_access_key().expose(),
            amz_date: &amz_date,
            date_stamp: &date_stamp,
        })?;

        let mut request = self.http.request(Method::GET, &url);
        for (name, value) in &headers {
            request = request.header(name.as_str(), value.as_str());
        }
        request = request.header("Authorization", signed.authorization_header);

        let response = request
            .send()
            .await
            .map_err(|error| classify_reqwest_error(&error))?;

        let status = response.status().as_u16();
        if response.status().is_success() {
            let bytes = response
                .bytes()
                .await
                .map_err(|error| S3BackendError::ResponseRead(error.to_string()))?;
            return Ok(Some(bytes.to_vec()));
        }
        if status == 404 {
            return Ok(None);
        }
        classify_failure_status(status).map(|_| None)
    }

    fn build_list_url_and_signing_parts(
        &self,
        continuation_token: Option<&str>,
    ) -> Result<(String, String, String, String), S3BackendError> {
        let endpoint = self.config.endpoint_url().trim_end_matches('/');
        let parsed = parse_endpoint(endpoint)?;
        let canonical_query_string = match continuation_token {
            Some(token) => format!(
                "continuation-token={}&list-type=2",
                percent_encode_query_value(token)
            ),
            None => "list-type=2".to_owned(),
        };

        if self.config.path_style() {
            let canonical_uri = format!("/{}", self.config.bucket());
            let url = format!(
                "{endpoint}/{bucket}?{query}",
                bucket = self.config.bucket(),
                query = canonical_query_string
            );
            Ok((url, parsed.host, canonical_uri, canonical_query_string))
        } else {
            let host_with_bucket = format!("{}.{}", self.config.bucket(), parsed.host);
            let url = format!(
                "{scheme}://{host}/?{query}",
                scheme = parsed.scheme,
                host = host_with_bucket,
                query = canonical_query_string
            );
            Ok((
                url,
                host_with_bucket,
                "/".to_owned(),
                canonical_query_string,
            ))
        }
    }

    fn build_url_and_host(&self, object_key: &str) -> Result<(String, String), S3BackendError> {
        let endpoint = self.config.endpoint_url().trim_end_matches('/');
        let parsed = parse_endpoint(endpoint)?;
        let encoded_key = percent_encode_path_segment(object_key);

        if self.config.path_style() {
            let url = format!("{endpoint}/{}/{encoded_key}", self.config.bucket());
            Ok((url, parsed.host))
        } else {
            // virtual-hosted style: bucket.{host}
            let host_with_bucket = format!("{}.{}", self.config.bucket(), parsed.host);
            let url = format!(
                "{scheme}://{host}/{encoded_key}",
                scheme = parsed.scheme,
                host = host_with_bucket,
            );
            Ok((url, host_with_bucket))
        }
    }

    fn canonical_uri(&self, object_key: &str) -> String {
        let encoded_key = percent_encode_path_segment(object_key);
        if self.config.path_style() {
            format!("/{}/{encoded_key}", self.config.bucket())
        } else {
            format!("/{encoded_key}")
        }
    }
}

struct ParsedEndpoint {
    scheme: String,
    host: String,
}

fn parse_endpoint(endpoint: &str) -> Result<ParsedEndpoint, S3BackendError> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or(S3BackendError::InvalidConfig(
            "endpoint_url must include scheme (http:// or https://)",
        ))?;
    if !matches!(scheme, "http" | "https") {
        return Err(S3BackendError::InvalidConfig(
            "endpoint_url scheme must be http or https",
        ));
    }
    if rest.contains('?') {
        return Err(S3BackendError::InvalidConfig(
            "endpoint_url must not include query",
        ));
    }
    if rest.contains('#') {
        return Err(S3BackendError::InvalidConfig(
            "endpoint_url must not include fragment",
        ));
    }
    let (host_with_port, path) = match rest.split_once('/') {
        Some((host_with_port, path)) => (host_with_port, Some(path)),
        None => (rest, None),
    };
    if host_with_port.is_empty() {
        return Err(S3BackendError::InvalidConfig("endpoint_url host is empty"));
    }
    if host_with_port.contains('@') {
        return Err(S3BackendError::InvalidConfig(
            "endpoint_url must not include userinfo",
        ));
    }
    if path.is_some_and(|path| !path.is_empty()) {
        return Err(S3BackendError::InvalidConfig(
            "endpoint_url path must be empty or /",
        ));
    }
    Ok(ParsedEndpoint {
        scheme: scheme.to_owned(),
        host: host_with_port.to_owned(),
    })
}

fn format_amz_date(now: OffsetDateTime) -> Result<String, S3BackendError> {
    now.to_offset(time::UtcOffset::UTC)
        .format(&AMZ_DATE_FORMAT)
        .map_err(|_| S3BackendError::InvalidConfig("failed to format x-amz-date"))
}

fn format_date_stamp(now: OffsetDateTime) -> Result<String, S3BackendError> {
    now.to_offset(time::UtcOffset::UTC)
        .format(&DATE_STAMP_FORMAT)
        .map_err(|_| S3BackendError::InvalidConfig("failed to format date stamp"))
}

fn parse_list_objects_v2_response(xml: &str) -> Result<ListObjectsV2Output, S3BackendError> {
    let keys = extract_xml_tags(xml, "Key");
    let next_continuation_token = extract_xml_tags(xml, "NextContinuationToken")
        .into_iter()
        .next();
    Ok(ListObjectsV2Output {
        keys,
        next_continuation_token,
    })
}

fn extract_xml_tags(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut rest = xml;
    let mut values = Vec::new();
    while let Some(start) = rest.find(&open) {
        let after_open = &rest[start + open.len()..];
        let Some(end) = after_open.find(&close) else {
            break;
        };
        values.push(unescape_minimal_xml(&after_open[..end]));
        rest = &after_open[end + close.len()..];
    }
    values
}

fn unescape_minimal_xml(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn percent_encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~') {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

fn classify_failure_status(status: u16) -> Result<PutOutcome, S3BackendError> {
    match status {
        401 | 403 => Err(S3BackendError::Unauthenticated),
        412 => Err(S3BackendError::OverwriteRejected),
        404 => Err(S3BackendError::NotFound),
        408 | 429 => Err(S3BackendError::ServerError { status }),
        500..=599 => Err(S3BackendError::ServerError { status }),
        _ => Err(S3BackendError::Unexpected { status }),
    }
}

fn classify_reqwest_error(error: &reqwest::Error) -> S3BackendError {
    // ネットワーク・接続・タイムアウトは retriable として扱う。
    if error.is_timeout() || error.is_connect() || error.is_request() {
        // error.to_string() は機微情報を含まない（URL や status のみ）。
        S3BackendError::Network(error.to_string())
    } else if let Some(status) = error.status() {
        match classify_failure_status(status.as_u16()) {
            Err(classified) => classified,
            Ok(_) => S3BackendError::Unexpected {
                status: status.as_u16(),
            },
        }
    } else {
        S3BackendError::Network(error.to_string())
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/archive/s3/client/tests.rs"]
mod tests;

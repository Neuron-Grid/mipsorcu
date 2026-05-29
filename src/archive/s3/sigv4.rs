//! AWS Signature Version 4 署名計算。
//!
//! 暗号 primitive は RustCrypto `hmac` + 既存 `sha2` を使用し、自作しない。
//! 署名対象の組み立てロジックのみ自前実装する。
//!
//! 仕様: <https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html>

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

use super::error::S3BackendError;

type HmacSha256 = Hmac<Sha256>;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const AWS4_REQUEST: &str = "aws4_request";
const SERVICE_S3: &str = "s3";

/// 1 リクエストに対する署名済み情報。
#[derive(Debug, Clone)]
pub struct SignedRequest {
    /// HTTP `Authorization` ヘッダ値。
    pub authorization_header: String,
    /// `x-amz-content-sha256` ヘッダ値（hex SHA-256）。
    pub content_sha256_hex: String,
    /// `x-amz-date` ヘッダ値（`yyyymmddThhmmssZ`）。
    pub amz_date: String,
    /// canonical_request（テスト・デバッグ用、ログ出力不可）。
    #[cfg(test)]
    pub canonical_request: String,
}

/// 署名入力。`headers` は **小文字キー** で渡す（`host`, `x-amz-date`, ...）。
/// 渡したヘッダ全てが SignedHeaders に含まれる。
pub struct SignRequestInput<'a> {
    pub method: &'a str,
    pub canonical_uri: &'a str,
    pub canonical_query_string: &'a str,
    pub headers: &'a [(String, String)],
    pub payload: &'a [u8],
    pub region: &'a str,
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub amz_date: &'a str,
    pub date_stamp: &'a str,
}

pub fn sign(input: SignRequestInput<'_>) -> Result<SignedRequest, S3BackendError> {
    let content_sha256_hex = hex::encode(Sha256::digest(input.payload));

    let mut sorted_headers: Vec<(String, String)> = input
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), trim_header_value(value)))
        .collect();
    sorted_headers.sort_by(|left, right| left.0.cmp(&right.0));

    let canonical_headers: String = sorted_headers
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();

    let signed_headers: String = sorted_headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request = format!(
        "{method}\n{uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        method = input.method,
        uri = input.canonical_uri,
        query = input.canonical_query_string,
        canonical_headers = canonical_headers,
        signed_headers = signed_headers,
        payload_hash = content_sha256_hex,
    );

    let credential_scope = format!(
        "{date}/{region}/{service}/{terminator}",
        date = input.date_stamp,
        region = input.region,
        service = SERVICE_S3,
        terminator = AWS4_REQUEST,
    );

    let string_to_sign = format!(
        "{algorithm}\n{amz_date}\n{scope}\n{hashed_canonical_request}",
        algorithm = ALGORITHM,
        amz_date = input.amz_date,
        scope = credential_scope,
        hashed_canonical_request = hex::encode(Sha256::digest(canonical_request.as_bytes())),
    );

    let signing_key = derive_signing_key(
        input.secret_access_key,
        input.date_stamp,
        input.region,
        SERVICE_S3,
    )?;
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

    let authorization_header = format!(
        "{algorithm} Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        algorithm = ALGORITHM,
        access_key = input.access_key_id,
        scope = credential_scope,
    );

    Ok(SignedRequest {
        authorization_header,
        content_sha256_hex,
        amz_date: input.amz_date.to_owned(),
        #[cfg(test)]
        canonical_request,
    })
}

fn derive_signing_key(
    secret_access_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Result<Vec<u8>, S3BackendError> {
    let k_secret = format!("AWS4{secret_access_key}");
    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes())?;
    let k_region = hmac_sha256(&k_date, region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, service.as_bytes())?;
    hmac_sha256(&k_service, AWS4_REQUEST.as_bytes())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<Vec<u8>, S3BackendError> {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .map_err(|_| S3BackendError::InvalidConfig("hmac key construction failed"))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn trim_header_value(value: &str) -> String {
    // sigv4 spec: trim leading/trailing whitespace and collapse internal runs
    // of whitespace, but preserve embedded whitespace within quoted strings.
    // For headers we send (host / x-amz-*), values never contain quoted strings
    // so the simpler form below is correct.
    let trimmed = value.trim();
    let mut collapsed = String::with_capacity(trimmed.len());
    let mut last_was_space = false;
    for character in trimmed.chars() {
        if character.is_ascii_whitespace() {
            if !last_was_space {
                collapsed.push(' ');
                last_was_space = true;
            }
        } else {
            collapsed.push(character);
            last_was_space = false;
        }
    }
    collapsed
}

/// canonical URI 用に object key をエスケープする。
///
/// `/` はパス区切り文字として保持し、それ以外の非予約文字以外を
/// パーセントエンコードする。S3 sigv4 仕様: <https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html>
pub fn percent_encode_path_segment(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for byte in key.as_bytes() {
        if is_unreserved(*byte) || *byte == b'/' {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

#[cfg(test)]
#[path = "../../../tests/unit/archive/s3/sigv4/tests.rs"]
mod tests;

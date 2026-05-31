//! RFC 3161 互換 TSA backend（ADR-0040、task-11）。
//!
//! `Rfc3161TimestampingService` は単一の TSA URL に対して 1 回の timestamp 取得 /
//! 検証を行う。複数 TSA URL の順次 fallback と retry は
//! [`super::sender::RetryingTimestampingService`] が担う。
//!
//! 設計上の制約:
//! - imprint は SHA3-256（ADR-0040 / ADR-0050）。`MessageImprint.hashedMessage` に
//!   既存 `DigestHash`（32 バイト SHA3-256）をそのまま載せる。RFC 3161 ASN.1 構造は
//!   監査済み `x509-tsp` / `cms` クレートが提供し、自前で組み立てない。
//! - nonce は 16 バイト CSPRNG。certReq=true で TSA 証明書を response に含めさせる。
//! - TLS 検証は呼び出し側が構築した reqwest client（rustls, 検証 ON）に従い、本 backend
//!   で **bypass しない**。
//! - credential（Basic 認証）は [`SecretString`](crate::SecretString) に閉じ、
//!   ログ・stdout・stderr に出さない。
//! - **verify は bounded（v0.2.0）**: PKIStatus / TSTInfo 解析 / MessageImprint
//!   （algorithm + value）一致まで。TSA 署名の暗号検証は `known-limitations-v0.2.0.md`
//!   記載のとおり後続で扱う（自前 crypto を持ち込まない方針）。
//!
//! 信頼境界ノート: `request_timestamp` / `verify_timestamp` は `&DigestHash` と
//! token のみを受け取り、平文・鍵・JWT を構造的に扱えない。

use cmpv2::status::PkiStatus;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::{Int, OctetString};
use der::oid::ObjectIdentifier;
use der::{Any, Decode as _, Encode as _};
use spki::AlgorithmIdentifier;
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion, TstInfo};

use crate::SecretString;
use crate::ledger::DigestHash;

use super::service::{
    TimestampVerification, TimestampVerificationFailureKind, TimestampingProviderKind,
    TimestampingService, TimestampingServiceError, TimestampingToken, VerifiedTimestamp,
};

/// SHA3-256 の OID（NIST、ADR-0050 でハッシュを SHA3 に統一）。
const SHA3_256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");
/// id-signedData（RFC 5652 §3）。TimeStampToken の `ContentInfo.contentType`。
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// id-ct-TSTInfo（RFC 3161）。SignedData の eContentType。
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// RFC 3161 要求の Content-Type。
const CONTENT_TYPE_QUERY: &str = "application/timestamp-query";

/// nonce のバイト長（CSPRNG）。
const NONCE_LENGTH: usize = 16;

/// TSA Basic 認証 credential。`password` は `SecretString` に閉じる。
#[derive(Clone)]
pub struct TsaCredentials {
    username: String,
    password: SecretString,
}

impl TsaCredentials {
    pub fn new(username: impl Into<String>, password: SecretString) -> Self {
        Self {
            username: username.into(),
            password,
        }
    }
}

impl std::fmt::Debug for TsaCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TsaCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// 単一 TSA URL に対する RFC 3161 backend。
pub struct Rfc3161TimestampingService {
    http: reqwest::Client,
    tsa_url: String,
    credentials: Option<TsaCredentials>,
}

impl Rfc3161TimestampingService {
    pub fn new(
        http: reqwest::Client,
        tsa_url: impl Into<String>,
        credentials: Option<TsaCredentials>,
    ) -> Self {
        Self {
            http,
            tsa_url: tsa_url.into(),
            credentials,
        }
    }

    pub fn tsa_url(&self) -> &str {
        &self.tsa_url
    }
}

impl std::fmt::Debug for Rfc3161TimestampingService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Rfc3161TimestampingService")
            .field("tsa_url", &self.tsa_url)
            .field("has_credentials", &self.credentials.is_some())
            .finish()
    }
}

impl TimestampingService for Rfc3161TimestampingService {
    async fn request_timestamp(
        &self,
        digest_hash: &DigestHash,
    ) -> Result<TimestampingToken, TimestampingServiceError> {
        let mut nonce_bytes = [0u8; NONCE_LENGTH];
        getrandom::fill(&mut nonce_bytes).map_err(|_| TimestampingServiceError::BackendFailed {
            code: "rfc3161_nonce_csprng_failed".to_owned(),
        })?;
        // 先頭バイトを 0x01..=0x7f に正規化し、最小形式の正の DER INTEGER を保証する。
        nonce_bytes[0] = (nonce_bytes[0] & 0x7f) | 0x01;

        let request_der = build_timestamp_request(digest_hash, &nonce_bytes)?;

        let mut builder = self
            .http
            .post(&self.tsa_url)
            .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE_QUERY)
            .body(request_der);
        if let Some(credentials) = &self.credentials {
            builder = builder.basic_auth(
                &credentials.username,
                Some(credentials.password.expose_secret()),
            );
        }

        let response =
            builder
                .send()
                .await
                .map_err(|error| TimestampingServiceError::BackendFailed {
                    code: classify_reqwest_error(&error),
                })?;
        let status = response.status();
        if !status.is_success() {
            return Err(TimestampingServiceError::BackendFailed {
                code: format!("rfc3161_http_status_{}", status.as_u16()),
            });
        }
        let response_bytes =
            response
                .bytes()
                .await
                .map_err(|_| TimestampingServiceError::BackendFailed {
                    code: "rfc3161_response_read_failed".to_owned(),
                })?;

        // 取得直後の整合性: PKIStatus granted・imprint 一致・nonce echo を確認する。
        let parsed = match parse_timestamp_response(&response_bytes) {
            ParseOutcome::Granted(parsed) => parsed,
            ParseOutcome::NotGranted => {
                return Err(TimestampingServiceError::BackendFailed {
                    code: "rfc3161_status_not_granted".to_owned(),
                });
            }
            ParseOutcome::Malformed => {
                return Err(TimestampingServiceError::InvalidResponse {
                    reason: "TSA response is not a well-formed RFC 3161 token",
                });
            }
        };
        if parsed.imprint_oid != SHA3_256_OID || parsed.imprint_hash != digest_hash.as_bytes() {
            return Err(TimestampingServiceError::InvalidResponse {
                reason: "TSA imprint does not match the requested digest hash",
            });
        }
        match parsed.nonce.as_deref() {
            Some(echoed) if echoed == nonce_bytes => {}
            _ => {
                return Err(TimestampingServiceError::InvalidResponse {
                    reason: "TSA response nonce is missing or does not match the request",
                });
            }
        }

        TimestampingToken::new(response_bytes.to_vec())
    }

    async fn verify_timestamp(
        &self,
        token: &TimestampingToken,
        expected_hash: &DigestHash,
    ) -> Result<TimestampVerification, TimestampingServiceError> {
        Ok(verify_token_against_hash(token, expected_hash))
    }

    fn provider_kind(&self) -> TimestampingProviderKind {
        TimestampingProviderKind::Rfc3161
    }
}

/// SHA3-256 imprint・nonce・certReq=true を持つ RFC 3161 `TimeStampReq` を DER 化する。
///
/// ASN.1 構造の組み立て・DER 符号化は `x509-tsp` / `der` に委ね、自前で行わない。
fn build_timestamp_request(
    digest_hash: &DigestHash,
    nonce_bytes: &[u8],
) -> Result<Vec<u8>, TimestampingServiceError> {
    let hashed_message = OctetString::new(digest_hash.as_bytes().to_vec()).map_err(|_| {
        TimestampingServiceError::InvalidResponse {
            reason: "failed to build message imprint octet string",
        }
    })?;
    let hash_algorithm = AlgorithmIdentifier::<Any> {
        oid: SHA3_256_OID,
        parameters: None,
    };
    let message_imprint = MessageImprint {
        hash_algorithm,
        hashed_message,
    };
    let nonce = Int::new(nonce_bytes).map_err(|_| TimestampingServiceError::InvalidResponse {
        reason: "failed to build nonce integer",
    })?;
    let request = TimeStampReq {
        version: TspVersion::V1,
        message_imprint,
        req_policy: None,
        nonce: Some(nonce),
        cert_req: true,
        extensions: None,
    };
    request
        .to_der()
        .map_err(|_| TimestampingServiceError::InvalidResponse {
            reason: "failed to DER-encode TimeStampReq",
        })
}

/// 保管済み token（RFC 3161 `TimeStampResp` の DER）を `expected_hash` に対して
/// bounded 検証する。
///
/// v0.2.0 の検証範囲: PKIStatus granted / TSTInfo 解析 / MessageImprint の
/// algorithm + value 一致まで。TSA 署名の暗号検証は本関数では行わない
/// （`known-limitations-v0.2.0.md` 参照）。
fn verify_token_against_hash(
    token: &TimestampingToken,
    expected_hash: &DigestHash,
) -> TimestampVerification {
    let parsed = match parse_timestamp_response(token.as_bytes()) {
        ParseOutcome::Granted(parsed) => parsed,
        ParseOutcome::NotGranted => {
            return TimestampVerification::Invalid {
                failure_kind: TimestampVerificationFailureKind::NotGranted,
            };
        }
        ParseOutcome::Malformed => {
            return TimestampVerification::Invalid {
                failure_kind: TimestampVerificationFailureKind::Malformed,
            };
        }
    };
    if parsed.imprint_oid != SHA3_256_OID || parsed.imprint_hash != expected_hash.as_bytes() {
        return TimestampVerification::Invalid {
            failure_kind: TimestampVerificationFailureKind::ImprintMismatch,
        };
    }
    TimestampVerification::Valid(VerifiedTimestamp {
        tsa_serial_hex: parsed.serial_hex,
        gen_time: Some(parsed.gen_time),
    })
}

/// `parse_timestamp_response` の結果。
enum ParseOutcome {
    /// PKIStatus granted で TST を解析できた。
    Granted(ParsedTst),
    /// PKIStatus が granted / grantedWithMods でない。
    NotGranted,
    /// 応答が RFC 3161 token として解析不能。
    Malformed,
}

/// TST から取り出した非秘密メタデータ（所有値）。
struct ParsedTst {
    imprint_oid: ObjectIdentifier,
    imprint_hash: Vec<u8>,
    nonce: Option<Vec<u8>>,
    serial_hex: String,
    gen_time: String,
}

/// RFC 3161 `TimeStampResp` の DER から TST メタデータを取り出す。
///
/// `TimeStampResp -> PKIStatus -> TimeStampToken(ContentInfo) -> SignedData ->
/// eContent(OCTET STRING) -> TSTInfo` の順に辿る。各構造の解析は監査済みクレートに
/// 委ねる。
fn parse_timestamp_response(der_bytes: &[u8]) -> ParseOutcome {
    let Ok(response) = TimeStampResp::from_der(der_bytes) else {
        return ParseOutcome::Malformed;
    };
    if !matches!(
        response.status.status,
        PkiStatus::Accepted | PkiStatus::GrantedWithMods
    ) {
        return ParseOutcome::NotGranted;
    }
    let Some(token) = response.time_stamp_token else {
        return ParseOutcome::Malformed;
    };
    parse_timestamp_token(token).map_or(ParseOutcome::Malformed, ParseOutcome::Granted)
}

/// TimeStampToken（CMS `ContentInfo`）から TSTInfo メタデータを抽出する。
fn parse_timestamp_token(token: ContentInfo) -> Option<ParsedTst> {
    if token.content_type != ID_SIGNED_DATA {
        return None;
    }
    let signed_data: SignedData = token.content.decode_as().ok()?;
    if signed_data.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return None;
    }
    let econtent = signed_data.encap_content_info.econtent?;
    let tst_info_octets: OctetString = econtent.decode_as().ok()?;
    let tst_info = TstInfo::from_der(tst_info_octets.as_bytes()).ok()?;

    Some(ParsedTst {
        imprint_oid: tst_info.message_imprint.hash_algorithm.oid,
        imprint_hash: tst_info.message_imprint.hashed_message.as_bytes().to_vec(),
        nonce: tst_info.nonce.as_ref().map(|n| n.as_bytes().to_vec()),
        serial_hex: hex::encode(tst_info.serial_number.as_bytes()),
        gen_time: tst_info.gen_time.to_date_time().to_string(),
    })
}

/// reqwest エラーを監査・ログ用の固定コードに丸める（URL・ヘッダ等を漏らさない）。
fn classify_reqwest_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "rfc3161_request_timeout".to_owned()
    } else if error.is_connect() {
        "rfc3161_connect_failed".to_owned()
    } else if error.is_body() || error.is_decode() {
        "rfc3161_response_read_failed".to_owned()
    } else {
        "rfc3161_request_failed".to_owned()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/timestamping/rfc3161/tests.rs"]
mod tests;

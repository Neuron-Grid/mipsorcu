//! RFC 3161 backend の emulated mock TSA 統合テスト（Task 11）。
//!
//! `wiremock` で RFC 3161 互換の mock TSA を立て、`Rfc3161TimestampingService` の
//! obtain（HTTP round-trip + nonce echo + imprint 整合）と bounded verify を検証する。
//! 複数 URL の順次 fallback、PKIStatus rejection、Basic 認証ヘッダ送出も確認する。
//!
//! mock TSA は受信した `TimeStampReq` の imprint と nonce をそのまま echo した
//! `TimeStampResp` を返す。署名は付さない（v0.2.0 の bounded verify は署名暗号検証を
//! 行わないため、構造的に妥当な未署名 token で obtain/verify 経路を網羅できる）。

use std::time::Duration;

use cmpv2::status::{PkiStatus, PkiStatusInfo};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfos};
use der::asn1::{GeneralizedTime, Int, OctetString, SetOfVec};
use der::oid::ObjectIdentifier;
use der::{Any, DateTime, Decode as _, Encode as _};
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion, TstInfo};

use wiremock::matchers::{header_exists, method};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use mipsorcu::{
    DigestHash, LedgerHash, LedgerSequenceNo, LedgerSignatureKeyVersion, MonthlyDigestPeriod,
    RetryingTimestampingService, Rfc3161TimestampingService, SecretString, SourceEventAt,
    TimestampVerification, TimestampingRetryPolicy, TimestampingService, TimestampingServiceError,
    TsaCredentials, build_monthly_digest_canonical_form,
};

const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const ID_CT_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

fn test_digest_hash() -> DigestHash {
    let period = MonthlyDigestPeriod::parse("2026-05").unwrap();
    let canonical = build_monthly_digest_canonical_form(
        &period,
        LedgerSequenceNo::new(1).unwrap(),
        LedgerSequenceNo::new(42).unwrap(),
        LedgerHash::from_bytes(&[0xaa; 32]).unwrap(),
        LedgerHash::from_bytes(&[0xbb; 32]).unwrap(),
        42,
        &SourceEventAt::parse("2026-06-01T00:00:00Z").unwrap(),
        LedgerSignatureKeyVersion::new(1).unwrap(),
    )
    .unwrap();
    DigestHash::from_canonical_bytes(&canonical)
}

/// 受信 imprint / nonce を echo した（未署名の）`TimeStampResp` DER を組み立てる。
fn build_timestamp_response(
    message_imprint: MessageImprint,
    nonce: Option<&[u8]>,
    serial: &[u8],
    granted: bool,
) -> Vec<u8> {
    let tst_info = TstInfo {
        version: TspVersion::V1,
        policy: ObjectIdentifier::new_unwrap("1.2.3.4.1"),
        message_imprint,
        serial_number: Int::new(serial).unwrap(),
        gen_time: GeneralizedTime::from_date_time(DateTime::new(2026, 5, 31, 12, 0, 0).unwrap()),
        accuracy: None,
        ordering: false,
        nonce: nonce.map(|bytes| Int::new(bytes).unwrap()),
        tsa: None,
        extensions: None,
    };
    let tst_der = tst_info.to_der().unwrap();
    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: SetOfVec::new(),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: ObjectIdentifier::new_unwrap(ID_CT_TST_INFO),
            econtent: Some(Any::encode_from(&OctetString::new(tst_der).unwrap()).unwrap()),
        },
        certificates: None,
        crls: None,
        signer_infos: SignerInfos(SetOfVec::new()),
    };
    let content_info = ContentInfo {
        content_type: ObjectIdentifier::new_unwrap(ID_SIGNED_DATA),
        content: Any::encode_from(&signed_data).unwrap(),
    };
    let response = TimeStampResp {
        status: PkiStatusInfo {
            status: if granted {
                PkiStatus::Accepted
            } else {
                PkiStatus::Rejection
            },
            status_string: None,
            fail_info: None,
        },
        time_stamp_token: granted.then_some(content_info),
    };
    response.to_der().unwrap()
}

/// RFC 3161 互換 mock TSA。受信 `TimeStampReq` の imprint / nonce を echo する。
struct MockTsa {
    granted: bool,
}

impl Respond for MockTsa {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let parsed = TimeStampReq::from_der(&request.body)
            .expect("mock TSA received an invalid TimeStampReq");
        let nonce = parsed.nonce.as_ref().map(|n| n.as_bytes().to_vec());
        let der = build_timestamp_response(
            parsed.message_imprint,
            nonce.as_deref(),
            &[0x2a],
            self.granted,
        );
        ResponseTemplate::new(200)
            .insert_header("content-type", "application/timestamp-reply")
            .set_body_bytes(der)
    }
}

fn fast_policy() -> TimestampingRetryPolicy {
    TimestampingRetryPolicy {
        max_attempts_per_url: 2,
        base_delay: Duration::from_millis(1),
        max_total: Duration::from_secs(30),
    }
}

#[tokio::test]
async fn obtain_then_verify_against_mock_tsa_succeeds() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(MockTsa { granted: true })
        .mount(&mock)
        .await;

    let service = Rfc3161TimestampingService::new(reqwest::Client::new(), mock.uri(), None);
    let digest = test_digest_hash();

    let token = service
        .request_timestamp(&digest)
        .await
        .expect("obtain should succeed against the mock TSA");

    match service.verify_timestamp(&token, &digest).await.unwrap() {
        TimestampVerification::Valid(meta) => {
            assert_eq!(meta.tsa_serial_hex, "2a");
            assert!(meta.gen_time.is_some());
        }
        other => panic!("expected Valid, got {other:?}"),
    }
}

#[tokio::test]
async fn falls_back_from_failing_tsa_to_working_tsa() {
    let bad = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&bad)
        .await;
    let good = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(MockTsa { granted: true })
        .mount(&good)
        .await;

    let http = reqwest::Client::new();
    let service = RetryingTimestampingService::new(
        vec![
            Rfc3161TimestampingService::new(http.clone(), bad.uri(), None),
            Rfc3161TimestampingService::new(http.clone(), good.uri(), None),
        ],
        fast_policy(),
    );
    let digest = test_digest_hash();

    let token = service
        .request_timestamp(&digest)
        .await
        .expect("should fall back to the working TSA");
    assert!(matches!(
        service.verify_timestamp(&token, &digest).await.unwrap(),
        TimestampVerification::Valid(_)
    ));
}

#[tokio::test]
async fn rejected_status_returns_backend_failure() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(MockTsa { granted: false })
        .mount(&mock)
        .await;

    let service = Rfc3161TimestampingService::new(reqwest::Client::new(), mock.uri(), None);
    let error = service
        .request_timestamp(&test_digest_hash())
        .await
        .expect_err("rejected PKIStatus must fail obtain");
    assert!(matches!(
        error,
        TimestampingServiceError::BackendFailed { .. }
    ));
}

#[tokio::test]
async fn sends_basic_auth_header_when_credentials_configured() {
    // mock は Authorization ヘッダが存在する POST のみに応答する。credential が
    // 送出されていなければ 404 となり obtain は失敗する。
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header_exists("authorization"))
        .respond_with(MockTsa { granted: true })
        .mount(&mock)
        .await;

    let credentials = TsaCredentials::new("tsa-user", SecretString::new("tsa-pass").unwrap());
    let service =
        Rfc3161TimestampingService::new(reqwest::Client::new(), mock.uri(), Some(credentials));

    assert!(
        service.request_timestamp(&test_digest_hash()).await.is_ok(),
        "request must carry the Authorization header to match the mock"
    );
}

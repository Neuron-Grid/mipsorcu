//! RFC 3161 backend の parse / bounded verify ユニットテスト。
//!
//! 署名検証は bounded（v0.2.0）であり、ここでは未署名でも構造的に妥当な
//! `TimeStampResp` を組み立てて parse 経路（ContentInfo -> SignedData ->
//! eContent OCTET STRING -> TSTInfo）と imprint 一致判定を検証する。

use super::*;

use cmpv2::status::{PkiStatus, PkiStatusInfo};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfos};
use der::asn1::{GeneralizedTime, Int, OctetString, SetOfVec};
use der::{Any, DateTime};

use crate::ledger::{
    DigestHash, LedgerHash, LedgerSequenceNo, LedgerSignatureKeyVersion, MonthlyDigestPeriod,
    build_monthly_digest_canonical_form,
};
use crate::types::SourceEventAt;

fn test_digest_hash(seed: u8) -> DigestHash {
    let period = MonthlyDigestPeriod::parse("2026-05").unwrap();
    let start_hash = LedgerHash::from_bytes(&[seed; 32]).unwrap();
    let end_hash = LedgerHash::from_bytes(&[seed ^ 0xff; 32]).unwrap();
    let generated_at = SourceEventAt::parse("2026-06-01T00:00:00Z").unwrap();
    let key_version = LedgerSignatureKeyVersion::new(1).unwrap();
    let canonical = build_monthly_digest_canonical_form(
        &period,
        LedgerSequenceNo::new(1).unwrap(),
        LedgerSequenceNo::new(42).unwrap(),
        start_hash,
        end_hash,
        42,
        &generated_at,
        key_version,
    )
    .unwrap();
    DigestHash::from_canonical_bytes(&canonical)
}

/// 構造的に妥当な `TimeStampResp` DER を組み立てる（署名なし: bounded verify 用）。
fn build_response(
    imprint_oid: ObjectIdentifier,
    imprint_hash: &[u8],
    nonce: &[u8],
    serial: &[u8],
    granted: bool,
) -> Vec<u8> {
    let message_imprint = MessageImprint {
        hash_algorithm: AlgorithmIdentifier::<Any> {
            oid: imprint_oid,
            parameters: None,
        },
        hashed_message: OctetString::new(imprint_hash.to_vec()).unwrap(),
    };
    let tst_info = TstInfo {
        version: TspVersion::V1,
        policy: ObjectIdentifier::new_unwrap("1.2.3.4.1"),
        message_imprint,
        serial_number: Int::new(serial).unwrap(),
        gen_time: GeneralizedTime::from_date_time(DateTime::new(2026, 5, 31, 12, 0, 0).unwrap()),
        accuracy: None,
        ordering: false,
        nonce: Some(Int::new(nonce).unwrap()),
        tsa: None,
        extensions: None,
    };
    let tst_der = tst_info.to_der().unwrap();
    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: SetOfVec::new(),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: ID_CT_TST_INFO,
            econtent: Some(Any::encode_from(&OctetString::new(tst_der).unwrap()).unwrap()),
        },
        certificates: None,
        crls: None,
        signer_infos: SignerInfos(SetOfVec::new()),
    };
    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,
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
        time_stamp_token: Some(content_info),
    };
    response.to_der().unwrap()
}

#[test]
fn verify_valid_token_returns_valid_with_serial_and_gen_time() {
    let digest = test_digest_hash(0xaa);
    let der = build_response(
        SHA3_256_OID,
        digest.as_bytes(),
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        &[0x2a],
        true,
    );
    let token = TimestampingToken::new(der).unwrap();
    match verify_token_against_hash(&token, &digest) {
        TimestampVerification::Valid(meta) => {
            assert_eq!(meta.tsa_serial_hex, "2a");
            assert_eq!(meta.gen_time.as_deref(), Some("2026-05-31T12:00:00Z"));
        }
        other => panic!("expected Valid, got {other:?}"),
    }
}

#[test]
fn verify_wrong_hash_returns_imprint_mismatch() {
    let issued_for = test_digest_hash(0xaa);
    let other = test_digest_hash(0xbb);
    let der = build_response(
        SHA3_256_OID,
        issued_for.as_bytes(),
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        &[0x2a],
        true,
    );
    let token = TimestampingToken::new(der).unwrap();
    assert_eq!(
        verify_token_against_hash(&token, &other),
        TimestampVerification::Invalid {
            failure_kind: TimestampVerificationFailureKind::ImprintMismatch,
        }
    );
}

#[test]
fn verify_non_sha3_imprint_returns_imprint_mismatch() {
    let digest = test_digest_hash(0xaa);
    // SHA-256 OID（2.16.840.1.101.3.4.2.1）— SHA3-256 ではないので拒否される。
    let sha256_oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    let der = build_response(
        sha256_oid,
        digest.as_bytes(),
        &[1, 2, 3, 4, 5, 6, 7, 8],
        &[0x2a],
        true,
    );
    let token = TimestampingToken::new(der).unwrap();
    assert_eq!(
        verify_token_against_hash(&token, &digest),
        TimestampVerification::Invalid {
            failure_kind: TimestampVerificationFailureKind::ImprintMismatch,
        }
    );
}

#[test]
fn verify_rejected_status_returns_not_granted() {
    let digest = test_digest_hash(0xaa);
    let der = build_response(
        SHA3_256_OID,
        digest.as_bytes(),
        &[1, 2, 3, 4],
        &[0x2a],
        false,
    );
    let token = TimestampingToken::new(der).unwrap();
    assert_eq!(
        verify_token_against_hash(&token, &digest),
        TimestampVerification::Invalid {
            failure_kind: TimestampVerificationFailureKind::NotGranted,
        }
    );
}

#[test]
fn verify_garbage_returns_malformed() {
    let digest = test_digest_hash(0xaa);
    let token = TimestampingToken::new(vec![0x00, 0x01, 0x02, 0x03]).unwrap();
    assert_eq!(
        verify_token_against_hash(&token, &digest),
        TimestampVerification::Invalid {
            failure_kind: TimestampVerificationFailureKind::Malformed,
        }
    );
}

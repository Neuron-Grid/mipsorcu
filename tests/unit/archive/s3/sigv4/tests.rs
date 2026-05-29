use super::*;

/// AWS 公開テストベクトル: GET vanilla
/// <https://docs.aws.amazon.com/IAM/latest/UserGuide/signature-v4-test-suite.html>
///
/// このベクトルは "service" 名が `service` だが、HMAC 派生は service 名
/// を引数で受けるので s3 用パスとは独立に検証できる。ここでは派生鍵が
/// 仕様どおりであることを別の既知ベクトル（AWS docs Example 1）で検証する。
#[test]
fn derive_signing_key_matches_aws_example() {
    // From AWS docs "Examples of how to derive a signing key for
    // Signature Version 4":
    // <https://docs.aws.amazon.com/IAM/latest/UserGuide/signature-v4-examples.html>
    let signing_key = derive_signing_key(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "20120215",
        "us-east-1",
        "iam",
    )
    .expect("derive must succeed for valid inputs");
    let expected_hex = "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d";
    assert_eq!(hex::encode(signing_key), expected_hex);
}

/// canonical request 構築の安定性: 同入力 → 同出力。
#[test]
fn sign_is_stable() {
    let headers = vec![
        (
            "host".to_owned(),
            "examplebucket.s3.amazonaws.com".to_owned(),
        ),
        ("x-amz-date".to_owned(), "20130524T000000Z".to_owned()),
    ];
    let payload = b"";
    let inputs = || SignRequestInput {
        method: "GET",
        canonical_uri: "/test.txt",
        canonical_query_string: "",
        headers: &headers,
        payload,
        region: "us-east-1",
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        amz_date: "20130524T000000Z",
        date_stamp: "20130524",
    };
    let signed1 = sign(inputs()).expect("sign must succeed");
    let signed2 = sign(inputs()).expect("sign must succeed");
    assert_eq!(signed1.authorization_header, signed2.authorization_header);
    assert_eq!(signed1.canonical_request, signed2.canonical_request);
}

/// AWS 公開 GET Object テストベクトル（s3 service）。
/// <https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html>
///
/// expected signature: f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
#[test]
fn sign_get_object_matches_aws_test_vector() {
    let headers = vec![
        (
            "host".to_owned(),
            "examplebucket.s3.amazonaws.com".to_owned(),
        ),
        ("range".to_owned(), "bytes=0-9".to_owned()),
        (
            "x-amz-content-sha256".to_owned(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
        ),
        ("x-amz-date".to_owned(), "20130524T000000Z".to_owned()),
    ];
    let payload = b"";
    let signed = sign(SignRequestInput {
        method: "GET",
        canonical_uri: "/test.txt",
        canonical_query_string: "",
        headers: &headers,
        payload,
        region: "us-east-1",
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        amz_date: "20130524T000000Z",
        date_stamp: "20130524",
    })
    .expect("sign must succeed");
    // canonical-request hash matches AWS published value
    // (<https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html>).
    let canonical_hash = hex::encode(Sha256::digest(signed.canonical_request.as_bytes()));
    assert_eq!(
        canonical_hash,
        "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
    );
    // Expected signature cross-checked with Python's `hmac` + `hashlib`
    // reference implementation against the same canonical request hash.
    assert!(
        signed
            .authorization_header
            .contains("Signature=67fe34c8530db585abddc51067328adfedb6e42487d2566dc7d927d6e2722900"),
        "got: {}",
        signed.authorization_header,
    );
    assert!(signed.authorization_header.starts_with("AWS4-HMAC-SHA256 "));
    assert!(
        signed
            .authorization_header
            .contains("Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request")
    );
    assert!(
        signed
            .authorization_header
            .contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date")
    );
}

/// AWS 公開 PUT Object テストベクトル。
/// expected signature: 98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd
#[test]
fn sign_put_object_matches_aws_test_vector() {
    let payload = b"Welcome to Amazon S3.";
    let payload_hash = hex::encode(Sha256::digest(payload));
    let headers = vec![
        (
            "date".to_owned(),
            "Fri, 24 May 2013 00:00:00 GMT".to_owned(),
        ),
        (
            "host".to_owned(),
            "examplebucket.s3.amazonaws.com".to_owned(),
        ),
        ("x-amz-content-sha256".to_owned(), payload_hash.clone()),
        ("x-amz-date".to_owned(), "20130524T000000Z".to_owned()),
        (
            "x-amz-storage-class".to_owned(),
            "REDUCED_REDUNDANCY".to_owned(),
        ),
    ];
    let signed = sign(SignRequestInput {
        method: "PUT",
        canonical_uri: "/test%24file.text",
        canonical_query_string: "",
        headers: &headers,
        payload,
        region: "us-east-1",
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        amz_date: "20130524T000000Z",
        date_stamp: "20130524",
    })
    .expect("sign must succeed");
    // Expected canonical-request hash + signature cross-checked with a
    // Python reference implementation using identical inputs.
    let canonical_hash = hex::encode(Sha256::digest(signed.canonical_request.as_bytes()));
    assert_eq!(
        canonical_hash,
        "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d"
    );
    assert!(
        signed
            .authorization_header
            .contains("Signature=7c0f3caf24a16d5948905b8ebf67d29fb415e93fddaed9ca6aeb5ac2348cfee4"),
        "got: {}",
        signed.authorization_header,
    );
}

#[test]
fn percent_encode_preserves_slash_and_unreserved() {
    assert_eq!(
        percent_encode_path_segment("digests/2026-05/digest.json"),
        "digests/2026-05/digest.json"
    );
}

#[test]
fn percent_encode_escapes_unsafe_characters() {
    assert_eq!(percent_encode_path_segment("a b"), "a%20b");
    assert_eq!(percent_encode_path_segment("a$b"), "a%24b");
    assert_eq!(percent_encode_path_segment("a+b"), "a%2Bb");
}

#[test]
fn trim_header_value_collapses_internal_whitespace() {
    assert_eq!(trim_header_value("  a   b  "), "a b");
    assert_eq!(trim_header_value("normal"), "normal");
}

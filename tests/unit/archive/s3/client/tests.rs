use super::*;
use crate::archive::s3::object_lock::S3ObjectLockMode;

fn make_config(path_style: bool) -> S3ArchiveBackendConfig {
    S3ArchiveBackendConfig::new(
        "https://s3.example.com".to_owned(),
        "us-east-1".to_owned(),
        "mipsorcu-archive".to_owned(),
        "AKIA".to_owned(),
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
        None,
        S3ObjectLockMode::Compliance,
        30,
    )
    .unwrap()
    .with_path_style(path_style)
}

#[test]
fn build_url_path_style_includes_bucket() {
    let config = make_config(true);
    let http = reqwest::Client::new();
    let client = S3HttpClient {
        config: &config,
        http: &http,
    };
    let (url, host) = client
        .build_url_and_host("digests/2026-05/digest.json")
        .unwrap();
    assert_eq!(
        url,
        "https://s3.example.com/mipsorcu-archive/digests/2026-05/digest.json"
    );
    assert_eq!(host, "s3.example.com");
}

#[test]
fn build_url_virtual_hosted_style_includes_bucket_in_host() {
    let config = make_config(false);
    let http = reqwest::Client::new();
    let client = S3HttpClient {
        config: &config,
        http: &http,
    };
    let (url, host) = client
        .build_url_and_host("digests/2026-05/digest.json")
        .unwrap();
    assert_eq!(
        url,
        "https://mipsorcu-archive.s3.example.com/digests/2026-05/digest.json"
    );
    assert_eq!(host, "mipsorcu-archive.s3.example.com");
}

#[test]
fn canonical_uri_path_style_includes_bucket() {
    let config = make_config(true);
    let http = reqwest::Client::new();
    let client = S3HttpClient {
        config: &config,
        http: &http,
    };
    assert_eq!(
        client.canonical_uri("digests/2026-05/digest.json"),
        "/mipsorcu-archive/digests/2026-05/digest.json"
    );
}

#[test]
fn classify_failure_status_maps_codes() {
    assert!(matches!(
        classify_failure_status(401),
        Err(S3BackendError::Unauthenticated)
    ));
    assert!(matches!(
        classify_failure_status(403),
        Err(S3BackendError::Unauthenticated)
    ));
    assert!(matches!(
        classify_failure_status(412),
        Err(S3BackendError::OverwriteRejected)
    ));
    assert!(matches!(
        classify_failure_status(404),
        Err(S3BackendError::NotFound)
    ));
    assert!(matches!(
        classify_failure_status(503),
        Err(S3BackendError::ServerError { status: 503 })
    ));
    assert!(matches!(
        classify_failure_status(429),
        Err(S3BackendError::ServerError { status: 429 })
    ));
    assert!(matches!(
        classify_failure_status(418),
        Err(S3BackendError::Unexpected { status: 418 })
    ));
}

#[test]
fn parse_endpoint_requires_scheme() {
    assert!(parse_endpoint("s3.example.com").is_err());
    let parsed = parse_endpoint("https://s3.example.com").unwrap();
    assert_eq!(parsed.scheme, "https");
    assert_eq!(parsed.host, "s3.example.com");
}

#[test]
fn parse_endpoint_rejects_unsupported_or_ambiguous_values() {
    for endpoint in [
        "ftp://s3.example.com",
        "https://user:pass@s3.example.com",
        "https://s3.example.com/archive",
        "https://s3.example.com?debug=true",
        "https://s3.example.com#fragment",
    ] {
        assert!(
            parse_endpoint(endpoint).is_err(),
            "endpoint must be rejected: {endpoint}"
        );
    }
}

#[test]
fn parse_list_objects_v2_response_extracts_keys_and_token() {
    let xml = r#"<ListBucketResult><Contents><Key>digests/2026-05/digest.json</Key></Contents><Contents><Key>digests/2026-06/digest.json</Key></Contents><NextContinuationToken>next-token</NextContinuationToken></ListBucketResult>"#;
    let parsed = parse_list_objects_v2_response(xml).unwrap();
    assert_eq!(
        parsed.keys,
        vec![
            "digests/2026-05/digest.json".to_owned(),
            "digests/2026-06/digest.json".to_owned()
        ]
    );
    assert_eq!(
        parsed.next_continuation_token.as_deref(),
        Some("next-token")
    );
}

#[test]
fn parse_list_objects_v2_response_unescapes_xml_values() {
    let xml = r#"<ListBucketResult><Contents><Key>digests/a&amp;b/digest.json</Key></Contents></ListBucketResult>"#;
    let parsed = parse_list_objects_v2_response(xml).unwrap();
    assert_eq!(parsed.keys, vec!["digests/a&b/digest.json".to_owned()]);
}

#[test]
fn parse_endpoint_handles_port() {
    let parsed = parse_endpoint("http://localhost:9000").unwrap();
    assert_eq!(parsed.host, "localhost:9000");
}

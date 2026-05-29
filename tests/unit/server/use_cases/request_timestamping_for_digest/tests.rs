use super::*;

#[test]
fn error_as_error_code_backend_failed_returns_dynamic_code() {
    let error = RequestTimestampingError::BackendFailed {
        code: "boom".to_owned(),
    };
    assert_eq!(error.as_error_code(), "boom");
}

#[test]
fn error_as_error_code_ledger_append_failed_returns_static_code() {
    let error = RequestTimestampingError::LedgerAppendFailed {
        code: "digest_timestamped_append_failed",
    };
    assert_eq!(error.as_error_code(), "digest_timestamped_append_failed");
}

#[test]
fn error_display_includes_backend_failed_code() {
    let error = RequestTimestampingError::BackendFailed {
        code: "network".to_owned(),
    };
    assert_eq!(format!("{error}"), "timestamping backend failed: network");
}

#[test]
fn error_display_includes_ledger_append_failed_code() {
    let error = RequestTimestampingError::LedgerAppendFailed {
        code: "digest_timestamped_append_failed",
    };
    assert_eq!(
        format!("{error}"),
        "timestamping ledger append failed: digest_timestamped_append_failed"
    );
}

#[test]
fn backend_error_code_maps_backend_failed_to_default() {
    let error = TimestampingServiceError::BackendFailed {
        code: "network".to_owned(),
    };
    assert_eq!(
        backend_error_code(&error),
        "digest_timestamping_backend_failed"
    );
}

#[test]
fn backend_error_code_passes_through_digest_timestamping_prefix() {
    let error = TimestampingServiceError::BackendFailed {
        code: "digest_timestamping_rate_limited".to_owned(),
    };
    assert_eq!(
        backend_error_code(&error),
        "digest_timestamping_rate_limited"
    );
}

#[test]
fn backend_error_code_maps_invalid_response() {
    let error = TimestampingServiceError::InvalidResponse {
        reason: "empty token",
    };
    assert_eq!(
        backend_error_code(&error),
        "digest_timestamping_invalid_response"
    );
}

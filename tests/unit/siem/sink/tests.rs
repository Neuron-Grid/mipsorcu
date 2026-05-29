use super::*;

#[test]
fn error_display_backend_failed() {
    let error = SiemSinkError::BackendFailed {
        code: "network".to_owned(),
    };
    assert_eq!(format!("{error}"), "siem backend failed: network");
}

#[test]
fn error_display_invalid_response() {
    let error = SiemSinkError::InvalidResponse {
        reason: "rejected by server",
    };
    assert_eq!(
        format!("{error}"),
        "siem invalid response: rejected by server"
    );
}

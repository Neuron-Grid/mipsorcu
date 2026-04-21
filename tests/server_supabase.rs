use mipsorcu::server::supabase::SupabaseRpcError;

#[test]
fn supabase_error_display_does_not_expose_response_body() {
    let error = SupabaseRpcError::NonSuccessStatus {
        status: 400,
        body: "secret internal upstream details".to_owned(),
    };

    let rendered = error.to_string();

    assert!(rendered.contains("status 400"));
    assert!(rendered.contains("response body length"));
    assert!(!rendered.contains("secret internal upstream details"));
}

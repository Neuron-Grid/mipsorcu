use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use mipsorcu::server::supabase::{
    IntegrityCheckViolationSummary, LedgerAppendRpcFailure, RegisterPublicKeyError,
    SupabaseAuditAppender, SupabaseClient, SupabaseRpcError, classify_append_ledger_error,
    classify_register_public_key_error,
};
use mipsorcu::{
    AuditAction, AuditAppendError, AuditEvent, AuditEventAppender, AuditEventId, AuditEventParts,
    AuditMetadata, AuditResult, DeviceId, KeyVersion, LedgerChainHead, LedgerEntryDraft,
    LedgerEntryDraftParts, LedgerEntryId, LedgerEntryType, LedgerHash, LedgerPayload, LedgerResult,
    LedgerSequenceNo, LedgerSignatureKeyVersion, LedgerSigningKey, LedgerTargetSecretVersionId,
    OwnerUserId, RawJwt, RequestId, SecretAlias, SecretId, SourceEventAt,
};
use serde_json::{Value, json};

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

type ProbeServer = (
    String,
    mpsc::Receiver<CapturedRequest>,
    thread::JoinHandle<std::io::Result<()>>,
);

const AUDIT_EVENT_ID: &str = "11111111-1111-4111-8111-111111111111";
const REQUEST_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const TARGET_SECRET_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const DEVICE_ID: &str = "sbc-device-1";
const SOURCE_EVENT_AT: &str = "2026-04-08T12:00:00Z";

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

#[test]
fn supabase_error_debug_does_not_expose_response_body() {
    let error = SupabaseRpcError::NonSuccessStatus {
        status: 403,
        body: "secret internal upstream details".to_owned(),
    };

    let rendered = format!("{error:?}");

    assert!(rendered.contains("NonSuccessStatus"));
    assert!(rendered.contains("403"));
    assert!(rendered.contains("body_len"));
    assert!(!rendered.contains("secret internal upstream details"));
}

#[test]
fn supabase_client_debug_redacts_api_keys() {
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        "http://127.0.0.1:54321",
        "service-role-secret",
        "publishable-key-secret",
    );

    let rendered = format!("{client:?}");

    assert!(rendered.contains("SupabaseClient"));
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("service-role-secret"));
    assert!(!rendered.contains("publishable-key-secret"));
}

#[tokio::test(flavor = "current_thread")]
async fn audit_appender_maps_conflict_response_to_idempotency_conflict() {
    let (base_url, receiver, server_thread) =
        spawn_capture_server(409, r#"{"details":"audit_event_id_conflict"}"#)
            .expect("capture server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );
    let appender = SupabaseAuditAppender::new(Arc::new(client));

    let event = sample_audit_event();
    let result = appender.append_audit_event(&event).await;
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");

    assert!(matches!(result, Err(AuditAppendError::IdempotencyConflict)));
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/rest/v1/rpc/rpc_append_audit_event");
    assert_eq!(
        request.headers.get("authorization"),
        Some(&"Bearer service-role-secret".to_owned())
    );
    assert_eq!(
        request.headers.get("apikey"),
        Some(&"service-role-secret".to_owned())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn audit_appender_keeps_non_conflict_responses_as_external_dependency_failure() {
    let (base_url, receiver, server_thread) =
        spawn_capture_server(409, r#"{"message":"different_conflict"}"#)
            .expect("capture server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );
    let appender = SupabaseAuditAppender::new(Arc::new(client));

    let event = sample_audit_event();
    let result = appender.append_audit_event(&event).await;
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");

    assert!(matches!(
        result,
        Err(AuditAppendError::ExternalDependencyFailed {
            code: "supabase_rpc_failed"
        })
    ));
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/rest/v1/rpc/rpc_append_audit_event");
}

#[tokio::test(flavor = "current_thread")]
async fn current_secret_version_read_uses_expected_columns_and_publishable_auth() {
    let (base_url, receiver, server_thread) =
        spawn_capture_server(200, "[]").expect("capture server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );
    let secret_id =
        SecretId::parse("550e8400-e29b-41d4-a716-446655440000").expect("secret id must be valid");
    let raw_jwt = RawJwt::new("sample-user-jwt").expect("raw jwt must be valid");

    let rows = client
        .fetch_current_secret_version_for_user(&secret_id, &raw_jwt)
        .await
        .expect("current secret version read should succeed");
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");

    assert!(rows.is_empty());
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.path,
        "/rest/v1/secret_versions?select=id,secret_id,version,ciphertext,encrypted_data_key,key_version,algorithm,classification,nonce_or_iv,aad_context,created_by_user_id,created_at,secrets!inner(current_version_id,owner_user_id,classification)&secret_id=eq.550e8400-e29b-41d4-a716-446655440000"
    );
    assert_eq!(
        request.headers.get("authorization"),
        Some(&"Bearer sample-user-jwt".to_owned())
    );
    assert_eq!(
        request.headers.get("apikey"),
        Some(&"publishable-key".to_owned())
    );
    assert!(
        !request
            .headers
            .values()
            .any(|value| value.contains("service-role-secret"))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn secret_alias_resolution_uses_publishable_auth_and_rls_read() {
    let (base_url, receiver, server_thread) =
        spawn_capture_server(200, "[]").expect("capture server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );
    let alias_normalized =
        mipsorcu::AliasNormalized::new("Prod.API_1").expect("alias should normalize");
    let raw_jwt = RawJwt::new("sample-user-jwt").expect("raw jwt must be valid");

    let rows = client
        .resolve_secret_alias_for_user(&alias_normalized, &raw_jwt)
        .await
        .expect("alias read should succeed");
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");

    assert!(rows.is_empty());
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.path,
        "/rest/v1/secret_aliases?select=secret_id,owner_user_id,alias_normalized&alias_normalized=eq.prod.api_1"
    );
    assert_eq!(
        request.headers.get("authorization"),
        Some(&"Bearer sample-user-jwt".to_owned())
    );
    assert_eq!(
        request.headers.get("apikey"),
        Some(&"publishable-key".to_owned())
    );
    assert!(
        !request
            .headers
            .values()
            .any(|value| value.contains("service-role-secret"))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn create_secret_alias_uses_service_role_rpc_and_parses_response() {
    let response_body = serde_json::to_string(&json!([{
        "secret_id": TARGET_SECRET_ID,
        "alias": "Prod.API_1",
        "alias_normalized": "prod.api_1",
    }]))
    .expect("alias response should serialize");
    let (base_url, receiver, server_thread) =
        spawn_capture_server(200, &response_body).expect("capture server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );
    let secret_id = SecretId::parse(TARGET_SECRET_ID).expect("secret id must be valid");
    let owner_user_id = OwnerUserId::parse(OWNER_USER_ID).expect("owner id must be valid");
    let alias = SecretAlias::new("Prod.API_1").expect("alias must be valid");

    let outcome = client
        .call_create_secret_alias(&secret_id, &owner_user_id, &alias)
        .await
        .expect("create alias RPC should succeed");
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");

    assert_eq!(outcome.secret_id().as_canonical_string(), TARGET_SECRET_ID);
    assert_eq!(outcome.alias().as_str(), "Prod.API_1");
    assert_eq!(outcome.alias_normalized().as_str(), "prod.api_1");
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/rest/v1/rpc/rpc_create_secret_alias");
    assert_eq!(
        request.headers.get("authorization"),
        Some(&"Bearer service-role-secret".to_owned())
    );
    assert_eq!(
        request.headers.get("apikey"),
        Some(&"service-role-secret".to_owned())
    );

    let body: Value = serde_json::from_str(&request.body).expect("request body should be JSON");
    assert_eq!(body["p_secret_id"], TARGET_SECRET_ID);
    assert_eq!(body["p_owner_user_id"], OWNER_USER_ID);
    assert_eq!(body["p_alias"], "Prod.API_1");
    assert_eq!(body["p_alias_normalized"], "prod.api_1");
}

#[test]
fn classify_create_secret_alias_error_maps_duplicate_marker() {
    let error = SupabaseRpcError::NonSuccessStatus {
        status: 409,
        body: r#"{"message":"secret_alias_duplicate"}"#.to_owned(),
    };

    assert_eq!(
        mipsorcu::server::supabase::classify_create_secret_alias_error(&error),
        mipsorcu::server::supabase::CreateSecretAliasRpcError::Duplicate
    );
}

#[tokio::test(flavor = "current_thread")]
async fn integrity_check_uses_service_role_rpc_and_parses_summary() {
    let response_body = serde_json::to_string(&json!([{
        "checked_secret_count": 2,
        "checked_secret_version_count": 4,
        "checked_audit_event_count": 6,
        "violation_count": 0,
        "violation_summary": IntegrityCheckViolationSummary::zero(),
    }]))
    .expect("integrity response should serialize");
    let (base_url, receiver, server_thread) =
        spawn_capture_server(200, &response_body).expect("capture server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let summary = client
        .call_integrity_check()
        .await
        .expect("integrity check RPC should succeed");
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");

    assert_eq!(summary.checked_secret_count, 2);
    assert_eq!(summary.checked_secret_version_count, 4);
    assert_eq!(summary.checked_audit_event_count, 6);
    assert_eq!(summary.violation_count, 0);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/rest/v1/rpc/rpc_integrity_check");
    assert_eq!(
        request.headers.get("authorization"),
        Some(&"Bearer service-role-secret".to_owned())
    );
    assert_eq!(
        request.headers.get("apikey"),
        Some(&"service-role-secret".to_owned())
    );
}

#[tokio::test(flavor = "current_thread")]
async fn append_ledger_entry_uses_service_role_rpc_and_sql_parameter_names() {
    let entry = sample_signed_ledger_entry().expect("ledger entry should build");
    let response_body = serde_json::to_string(&json!([{
        "ledger_entry_id": entry.ledger_entry_id().as_canonical_string(),
        "sequence_no": entry.sequence_no().get(),
        "entry_hash": entry.entry_hash().to_bytea_hex(),
        "chain_last_sequence_no": entry.sequence_no().get(),
        "chain_last_entry_hash": entry.entry_hash().to_bytea_hex(),
        "replayed": false
    }]))
    .expect("ledger response should serialize");
    let (base_url, receiver, server_thread) =
        spawn_capture_server(200, &response_body).expect("capture server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let outcome = client
        .call_append_ledger_entry(&entry)
        .await
        .expect("ledger append RPC should succeed");
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");
    let body: Value = serde_json::from_str(&request.body).expect("request body should be JSON");

    assert_eq!(outcome.ledger_entry_id(), entry.ledger_entry_id());
    assert_eq!(outcome.sequence_no(), entry.sequence_no());
    assert_eq!(outcome.entry_hash(), entry.entry_hash());
    assert_eq!(
        outcome.chain_head(),
        LedgerChainHead::new(entry.sequence_no().get(), entry.entry_hash())
            .expect("chain head should be valid")
    );
    assert!(!outcome.replayed());
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/rest/v1/rpc/rpc_append_ledger_entry");
    assert_eq!(
        request.headers.get("authorization"),
        Some(&"Bearer service-role-secret".to_owned())
    );
    assert_eq!(
        request.headers.get("apikey"),
        Some(&"service-role-secret".to_owned())
    );

    assert_eq!(
        body["p_ledger_entry_id"],
        entry.ledger_entry_id().as_canonical_string()
    );
    assert_eq!(body["p_sequence_no"], entry.sequence_no().get());
    assert_eq!(body["p_entry_type"], "secret_created");
    assert_eq!(body["p_source_event_at"], SOURCE_EVENT_AT);
    assert_eq!(body["p_request_id"], REQUEST_ID);
    assert!(body["p_source_event_id"].is_null());
    assert_eq!(body["p_target_secret_id"], TARGET_SECRET_ID);
    assert_eq!(
        body["p_target_secret_version_id"],
        "11111111-2222-4333-8444-555555555555"
    );
    assert_eq!(body["p_actor_user_id"], OWNER_USER_ID);
    assert_eq!(body["p_actor_device_id"], DEVICE_ID);
    assert_eq!(body["p_result"], "success");
    assert!(body["p_error_code"].is_null());
    assert_eq!(body["p_payload"]["algorithm"], "xchacha20-poly1305");
    assert_eq!(body["p_canonicalization_version"], 1);
    assert_eq!(
        body["p_previous_entry_hash"],
        LedgerHash::genesis().to_bytea_hex()
    );
    assert_bytea_hex(&body["p_previous_entry_hash"], 64);
    assert_eq!(body["p_entry_hash"], entry.entry_hash().to_bytea_hex());
    assert_bytea_hex(&body["p_entry_hash"], 64);
    assert_eq!(body["p_hash_algorithm"], "sha-256");
    assert_eq!(body["p_signature"], entry.signature().to_bytea_hex());
    assert_bytea_hex(&body["p_signature"], 128);
    assert_eq!(body["p_signature_algorithm"], "ed25519");
    assert_eq!(body["p_signature_key_version"], 1);
}

#[test]
fn ledger_append_error_classification_uses_body_without_exposing_it() {
    let body = r#"{"message":"ledger_sequence_mismatch with upstream details"}"#.to_owned();
    let error = SupabaseRpcError::NonSuccessStatus { status: 409, body };

    assert_eq!(
        classify_append_ledger_error(&error),
        LedgerAppendRpcFailure::SequenceMismatch
    );
    assert_eq!(
        classify_append_ledger_error(&error).as_error_code(),
        "ledger_sequence_mismatch"
    );
    assert!(!format!("{error:?}").contains("with upstream details"));
    assert!(!error.to_string().contains("with upstream details"));
}

#[tokio::test(flavor = "current_thread")]
async fn readiness_probe_retries_with_publishable_key_after_unauthorized_head() {
    let (base_url, receiver, server_thread) =
        spawn_probe_server(vec![401, 200]).expect("probe server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let reachable = client.probe_readiness().await;
    let first_request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("first request should be captured");
    let second_request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("second request should be captured");
    let join_result = server_thread
        .join()
        .expect("probe server thread should not panic");
    join_result.expect("probe server should exit cleanly");

    assert!(reachable);
    assert_eq!(first_request.method, "HEAD");
    assert_eq!(first_request.path, "/rest/v1/");
    assert!(!first_request.headers.contains_key("authorization"));
    assert!(!first_request.headers.contains_key("apikey"));

    assert_eq!(second_request.method, "HEAD");
    assert_eq!(second_request.path, "/rest/v1/");
    assert!(!second_request.headers.contains_key("authorization"));
    assert_eq!(
        second_request.headers.get("apikey"),
        Some(&"publishable-key".to_owned())
    );
    assert!(
        !second_request
            .headers
            .values()
            .any(|value| value.contains("service-role-secret"))
    );
}

#[tokio::test(flavor = "current_thread")]
async fn readiness_probe_succeeds_without_auth_when_head_is_public() {
    let (base_url, receiver, server_thread) =
        spawn_probe_server(vec![200]).expect("probe server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let reachable = client.probe_readiness().await;
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("probe server thread should not panic");
    join_result.expect("probe server should exit cleanly");

    assert!(reachable);
    assert_eq!(request.method, "HEAD");
    assert_eq!(request.path, "/rest/v1/");
    assert!(!request.headers.contains_key("authorization"));
    assert!(!request.headers.contains_key("apikey"));
}

#[tokio::test(flavor = "current_thread")]
async fn readiness_probe_does_not_retry_on_non_auth_failure() {
    let (base_url, receiver, server_thread) =
        spawn_probe_server(vec![404]).expect("probe server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let reachable = client.probe_readiness().await;
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("probe server thread should not panic");
    join_result.expect("probe server should exit cleanly");

    assert!(!reachable);
    assert_eq!(request.method, "HEAD");
    assert_eq!(request.path, "/rest/v1/");
    assert!(
        receiver
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err()
    );
}

fn spawn_capture_server(
    status: u16,
    body: &str,
) -> Result<ProbeServer, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let body = body.to_owned();
    let thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept()?;
        let request = read_http_request(&mut stream)?;
        sender.send(request).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "captured request receiver was dropped",
            )
        })?;
        write_http_response(&mut stream, status, &body)?;

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn sample_audit_event() -> AuditEvent {
    AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::parse(AUDIT_EVENT_ID).expect("audit event id must be valid"),
        request_id: RequestId::parse(REQUEST_ID).expect("request id must be valid"),
        actor_user_id: Some(
            OwnerUserId::parse(OWNER_USER_ID).expect("owner user id must be valid"),
        ),
        actor_device_id: Some(DeviceId::new(DEVICE_ID).expect("device id must be valid")),
        action: AuditAction::Decrypt,
        target_secret_id: Some(
            SecretId::parse(TARGET_SECRET_ID).expect("target secret id must be valid"),
        ),
        result: AuditResult::Failure,
        key_version: Some(KeyVersion::new(1).expect("key version must be valid")),
        metadata_json: AuditMetadata::new(json!({
            "attempted_secret_id": TARGET_SECRET_ID,
            "source_event_at": SOURCE_EVENT_AT
        }))
        .expect("metadata must be valid"),
    })
    .expect("audit event must be valid")
}

fn sample_signed_ledger_entry() -> Result<mipsorcu::SignedLedgerEntry, Box<dyn std::error::Error>> {
    let payload = LedgerPayload::new(
        LedgerEntryType::SecretCreated,
        json!({
            "algorithm": "xchacha20-poly1305",
            "classification": "confidential",
            "key_version": 1,
            "version": 1
        }),
    )?;
    let draft = LedgerEntryDraft::new(LedgerEntryDraftParts {
        ledger_entry_id: LedgerEntryId::parse("22222222-2222-4222-8222-222222222222")?,
        sequence_no: LedgerSequenceNo::new(1)?,
        entry_type: LedgerEntryType::SecretCreated,
        source_event_at: SourceEventAt::parse(SOURCE_EVENT_AT)?,
        request_id: RequestId::parse(REQUEST_ID)?,
        source_event_id: None,
        target_secret_id: Some(SecretId::parse(TARGET_SECRET_ID)?),
        target_secret_version_id: Some(LedgerTargetSecretVersionId::parse(
            "11111111-2222-4333-8444-555555555555",
        )?),
        actor_user_id: Some(OwnerUserId::parse(OWNER_USER_ID)?),
        actor_device_id: Some(DeviceId::new(DEVICE_ID)?),
        result: LedgerResult::Success,
        error_code: None,
        payload,
        previous_entry_hash: LedgerHash::genesis(),
        signature_key_version: LedgerSignatureKeyVersion::new(1)?,
    })?;
    let signing_key =
        LedgerSigningKey::from_secret_key_bytes(LedgerSignatureKeyVersion::new(1)?, &[9u8; 32])?;

    Ok(draft.sign(&signing_key)?)
}

fn assert_bytea_hex(value: &Value, expected_hex_chars: usize) {
    let text = value.as_str().expect("bytea param should be a string");
    let hex = text
        .strip_prefix("\\x")
        .expect("bytea param should use postgres hex text prefix");

    assert_eq!(hex.len(), expected_hex_chars);
    assert!(
        hex.chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    );
}

fn spawn_probe_server(statuses: Vec<u16>) -> Result<ProbeServer, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    let thread = thread::spawn(move || {
        for status in statuses {
            let (mut stream, _) = listener.accept()?;
            let request = read_http_request(&mut stream)?;
            sender.send(request).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "captured request receiver was dropped",
                )
            })?;
            write_http_response(&mut stream, status, "{}")?;
        }

        Ok(())
    });

    Ok((format!("http://{addr}"), receiver, thread))
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<CapturedRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];

    let header_end = loop {
        let bytes_read = stream.read(&mut chunk)?;
        if bytes_read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before headers were complete",
            ));
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);

        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
    };

    let headers = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let request_line = headers.lines().next().unwrap_or_default();
    let method = request_line
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let headers = headers
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect::<HashMap<_, _>>();
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    let mut body = buffer.get(body_start..).unwrap_or_default().to_vec();

    while body.len() < content_length {
        let bytes_read = stream.read(&mut chunk)?;
        if bytes_read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..bytes_read]);
    }
    body.truncate(content_length);

    Ok(CapturedRequest {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

#[tokio::test(flavor = "current_thread")]
async fn register_ledger_signing_public_key_sends_bytea_params_and_returns_replayed_false() {
    let signing_key = ledger_signing_key_for_tests();
    let verification_key = signing_key.verification_key();
    let response_body = serde_json::to_string(&json!([{
        "out_key_version": 1,
        "public_key": format!("\\x{}", hex::encode(verification_key.as_bytes())),
        "algorithm": "ed25519",
        "status": "active",
        "created_at": "2026-05-09T12:00:00Z",
        "retired_at": null,
        "replayed": false
    }]))
    .expect("register response should serialize");
    let (base_url, receiver, server_thread) =
        spawn_capture_server(200, &response_body).expect("capture server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let outcome = client
        .register_ledger_signing_public_key(&verification_key)
        .await
        .expect("register RPC should succeed");
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");
    let body: Value = serde_json::from_str(&request.body).expect("request body should be JSON");

    assert!(!outcome.replayed());
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.path,
        "/rest/v1/rpc/rpc_register_ledger_signing_public_key"
    );
    assert_eq!(
        request.headers.get("authorization"),
        Some(&"Bearer service-role-secret".to_owned())
    );
    assert_eq!(
        request.headers.get("apikey"),
        Some(&"service-role-secret".to_owned())
    );
    assert_eq!(body["p_key_version"], 1);
    assert_bytea_hex(&body["p_public_key"], 64);
}

#[tokio::test(flavor = "current_thread")]
async fn register_ledger_signing_public_key_replays_idempotently() {
    let signing_key = ledger_signing_key_for_tests();
    let verification_key = signing_key.verification_key();
    let response_body = serde_json::to_string(&json!([{
        "out_key_version": 1,
        "public_key": format!("\\x{}", hex::encode(verification_key.as_bytes())),
        "algorithm": "ed25519",
        "status": "active",
        "created_at": "2026-05-09T12:00:00Z",
        "retired_at": null,
        "replayed": true
    }]))
    .expect("register response should serialize");
    let (base_url, receiver, server_thread) =
        spawn_capture_server(200, &response_body).expect("capture server should start");
    let client = SupabaseClient::new(
        reqwest::Client::new(),
        base_url,
        "service-role-secret",
        "publishable-key",
    );

    let outcome = client
        .register_ledger_signing_public_key(&verification_key)
        .await
        .expect("register RPC should succeed");
    let request = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("request should be captured");
    let join_result = server_thread
        .join()
        .expect("capture server thread should not panic");
    join_result.expect("capture server should exit cleanly");

    assert!(outcome.replayed());
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.path,
        "/rest/v1/rpc/rpc_register_ledger_signing_public_key"
    );
}

#[test]
fn classify_register_public_key_error_maps_conflict() {
    let body = r#"{"message":"ledger_signing_public_key_conflict with details"}"#.to_owned();
    let error = SupabaseRpcError::NonSuccessStatus { status: 409, body };

    assert_eq!(
        classify_register_public_key_error(&error),
        RegisterPublicKeyError::Conflict
    );
    assert_eq!(
        classify_register_public_key_error(&error).as_error_code(),
        "ledger_signing_public_key_conflict"
    );
}

#[test]
fn classify_register_public_key_error_maps_retired() {
    let body = r#"{"details":"ledger_signing_public_key_retired for this key"}"#.to_owned();
    let error = SupabaseRpcError::NonSuccessStatus { status: 409, body };

    assert_eq!(
        classify_register_public_key_error(&error),
        RegisterPublicKeyError::Retired
    );
    assert_eq!(
        classify_register_public_key_error(&error).as_error_code(),
        "ledger_signing_public_key_retired"
    );
}

#[test]
fn classify_register_public_key_error_maps_invalid_rpc_input() {
    let body = r#"{"hint":"invalid_rpc_input: bad key version"}"#.to_owned();
    let error = SupabaseRpcError::NonSuccessStatus { status: 400, body };

    assert_eq!(
        classify_register_public_key_error(&error),
        RegisterPublicKeyError::InvalidRpcInput
    );
    assert_eq!(
        classify_register_public_key_error(&error).as_error_code(),
        "invalid_rpc_input"
    );
}

#[test]
fn classify_register_public_key_error_falls_back_to_register_failed_for_unknown_body() {
    let body = r#"{"message":"some other database error"}"#.to_owned();
    let error = SupabaseRpcError::NonSuccessStatus { status: 500, body };

    assert_eq!(
        classify_register_public_key_error(&error),
        RegisterPublicKeyError::RegisterFailed
    );
}

#[test]
fn classify_register_public_key_error_falls_back_to_register_failed_for_unknown_status_body() {
    let body = r#"{"code":"50001"}"#.to_owned();
    let error = SupabaseRpcError::NonSuccessStatus { status: 500, body };

    assert_eq!(
        classify_register_public_key_error(&error),
        RegisterPublicKeyError::RegisterFailed
    );
}

#[test]
fn register_public_key_error_debug_and_error_code_do_not_expose_body() {
    let body =
        r#"{"message":"ledger_signing_public_key_conflict with secret upstream state"}"#.to_owned();
    let error = SupabaseRpcError::NonSuccessStatus { status: 409, body };
    let classification = classify_register_public_key_error(&error);

    assert_eq!(
        classification.as_error_code(),
        "ledger_signing_public_key_conflict"
    );
    assert!(!format!("{error:?}").contains("secret upstream state"));
    assert!(!error.to_string().contains("secret upstream state"));
}

#[test]
fn ledger_verifying_key_debug_redacts_raw_public_key_bytes() {
    let signing_key = ledger_signing_key_for_tests();
    let verification_key = signing_key.verification_key();
    let rendered = format!("{verification_key:?}");

    assert!(rendered.contains("LedgerVerifyingKey"));
    assert!(rendered.contains("key_version"));
    // Raw public key bytes must not appear in Debug output
    let hex_encoded = hex::encode(verification_key.as_bytes());
    assert!(!rendered.contains(&hex_encoded));
}

fn ledger_signing_key_for_tests() -> LedgerSigningKey {
    LedgerSigningKey::from_secret_key_bytes(
        LedgerSignatureKeyVersion::new(1).expect("key version must be valid"),
        &[9u8; 32],
    )
    .expect("ledger signing key must be valid")
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

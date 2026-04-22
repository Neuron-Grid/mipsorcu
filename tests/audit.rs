use std::cell::RefCell;
use std::error::Error;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use mipsorcu::{
    AuditAction, AuditAppendError, AuditEvent, AuditEventAppender, AuditEventError, AuditEventId,
    AuditEventParts, AuditMetadata, AuditRecordError, AuditRecordOutcome, AuditRecorder,
    AuditResult, DeviceId, FORBIDDEN_AUDIT_METADATA_KEYS, KeyVersion, LocalAuditFallbackStore,
    OwnerUserId, RequestId, RolloverOutcome, SecretId, SourceEventAt,
};
use serde_json::{Value, json};

const AUDIT_EVENT_ID: &str = "11111111-1111-4111-8111-111111111111";
const AUDIT_EVENT_ID_2: &str = "22222222-2222-4222-8222-222222222222";
const REQUEST_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OWNER_USER_ID: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const TARGET_SECRET_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const DEVICE_ID: &str = "sbc-device-1";
const SOURCE_EVENT_AT: &str = "2026-04-08T12:00:00Z";

type TestResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone)]
enum AppendBehavior {
    AlwaysOk,
    AlwaysErr,
    Outcomes(Vec<Result<(), AuditAppendError>>),
}

#[derive(Debug)]
struct FakeAppender {
    behavior: RefCell<AppendBehavior>,
    appended_event_ids: RefCell<Vec<String>>,
}

impl FakeAppender {
    fn always_ok() -> Self {
        Self {
            behavior: RefCell::new(AppendBehavior::AlwaysOk),
            appended_event_ids: RefCell::new(Vec::new()),
        }
    }

    fn always_err() -> Self {
        Self {
            behavior: RefCell::new(AppendBehavior::AlwaysErr),
            appended_event_ids: RefCell::new(Vec::new()),
        }
    }

    fn outcomes(outcomes: Vec<Result<(), AuditAppendError>>) -> Self {
        Self {
            behavior: RefCell::new(AppendBehavior::Outcomes(outcomes)),
            appended_event_ids: RefCell::new(Vec::new()),
        }
    }

    fn appended_event_ids(&self) -> Vec<String> {
        self.appended_event_ids.borrow().clone()
    }
}

impl AuditEventAppender for FakeAppender {
    fn append_audit_event(&self, event: &AuditEvent) -> Result<(), AuditAppendError> {
        self.appended_event_ids
            .borrow_mut()
            .push(event.audit_event_id().as_canonical_string());

        match &mut *self.behavior.borrow_mut() {
            AppendBehavior::AlwaysOk => Ok(()),
            AppendBehavior::AlwaysErr => Err(AuditAppendError::ExternalDependencyFailed {
                code: "network_unavailable",
            }),
            AppendBehavior::Outcomes(outcomes) => {
                if outcomes.is_empty() {
                    Ok(())
                } else {
                    outcomes.remove(0)
                }
            }
        }
    }
}

fn temp_jsonl_path(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    std::env::temp_dir().join(format!("mipsorcu-{test_name}-{unique}.jsonl"))
}

fn metadata() -> Result<AuditMetadata, AuditEventError> {
    AuditMetadata::new(json!({
        "error_code": "decrypt_failed",
        "elapsed_ms": 12,
        "source_event_at": SOURCE_EVENT_AT,
        "nested": {
            "retryable": true
        }
    }))
}

fn sample_event_with_ids(audit_event_id: &str, request_id: &str) -> TestResult<AuditEvent> {
    Ok(AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::parse(audit_event_id)?,
        request_id: RequestId::parse(request_id)?,
        actor_user_id: Some(OwnerUserId::parse(OWNER_USER_ID)?),
        actor_device_id: Some(DeviceId::new(DEVICE_ID)?),
        action: AuditAction::Decrypt,
        target_secret_id: Some(SecretId::parse(TARGET_SECRET_ID)?),
        result: AuditResult::Failure,
        key_version: Some(KeyVersion::new(1)?),
        metadata_json: metadata()?,
    })?)
}

fn sample_event() -> TestResult<AuditEvent> {
    sample_event_with_ids(AUDIT_EVENT_ID, REQUEST_ID)
}

fn read_json_lines(path: &PathBuf) -> TestResult<Vec<Value>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let text = fs::read_to_string(path)?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

fn read_gzip_text(path: &PathBuf) -> TestResult<String> {
    let file = fs::File::open(path)?;
    let mut decoder = GzDecoder::new(file);
    let mut text = String::new();
    decoder.read_to_string(&mut text)?;

    Ok(text)
}

fn archive_file_names(path: &PathBuf) -> TestResult<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let mut names = fs::read_dir(path)?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .map_err(Into::into)
        })
        .collect::<TestResult<Vec<_>>>()?;
    names.sort();

    Ok(names)
}

#[test]
fn audit_event_accepts_valid_decrypt_failure_event() -> TestResult<()> {
    let event = sample_event()?;

    assert_eq!(event.action(), AuditAction::Decrypt);
    assert_eq!(event.result(), AuditResult::Failure);
    assert_eq!(
        event.actor_device_id().map(DeviceId::as_str),
        Some(DEVICE_ID)
    );
    assert_eq!(event.key_version().map(KeyVersion::get), Some(1));

    Ok(())
}

#[test]
fn audit_event_rejects_unknown_action_and_result() {
    assert!(matches!(
        AuditAction::parse("unknown"),
        Err(AuditEventError::UnknownAction { .. })
    ));
    assert!(matches!(
        AuditResult::parse("maybe"),
        Err(AuditEventError::UnknownResult { .. })
    ));
}

#[test]
fn audit_event_rejects_write_success_actions_outside_write_rpc() -> TestResult<()> {
    for action in [
        AuditAction::EncryptCreate,
        AuditAction::EncryptRotate,
        AuditAction::VersionPurge,
    ] {
        let result = AuditEvent::new(AuditEventParts {
            audit_event_id: AuditEventId::parse(AUDIT_EVENT_ID)?,
            request_id: RequestId::parse(REQUEST_ID)?,
            actor_user_id: Some(OwnerUserId::parse(OWNER_USER_ID)?),
            actor_device_id: Some(DeviceId::new(DEVICE_ID)?),
            action,
            target_secret_id: Some(SecretId::parse(TARGET_SECRET_ID)?),
            result: AuditResult::Success,
            key_version: Some(KeyVersion::new(1)?),
            metadata_json: AuditMetadata::new(json!({
                "source_event_at": SOURCE_EVENT_AT
            }))?,
        });

        assert!(matches!(
            result,
            Err(AuditEventError::WriteSuccessActionNotAllowed { .. })
        ));
    }

    Ok(())
}

#[test]
fn audit_event_rejects_missing_source_event_at() -> TestResult<()> {
    let result = AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::parse(AUDIT_EVENT_ID)?,
        request_id: RequestId::parse(REQUEST_ID)?,
        actor_user_id: Some(OwnerUserId::parse(OWNER_USER_ID)?),
        actor_device_id: Some(DeviceId::new(DEVICE_ID)?),
        action: AuditAction::Decrypt,
        target_secret_id: Some(SecretId::parse(TARGET_SECRET_ID)?),
        result: AuditResult::Failure,
        key_version: Some(KeyVersion::new(1)?),
        metadata_json: AuditMetadata::empty(),
    });

    assert!(matches!(result, Err(AuditEventError::MissingSourceEventAt)));

    Ok(())
}

#[test]
fn device_id_rejects_whitespace_actor_device_id() {
    assert!(DeviceId::new("   ").is_err());
}

#[test]
fn key_version_zero_cannot_be_constructed() {
    assert!(KeyVersion::new(0).is_err());
}

#[test]
fn metadata_rejects_non_object_and_forbidden_keys_recursively() {
    assert!(matches!(
        AuditMetadata::new(json!("not-object")),
        Err(AuditEventError::MetadataMustBeObject)
    ));
    assert!(matches!(
        AuditMetadata::new(json!({ "plaintext": "do-not-store" })),
        Err(AuditEventError::ForbiddenMetadataKey { key }) if key == "plaintext"
    ));
    assert!(matches!(
        AuditMetadata::new(json!({
            "safe": [
                {
                    "encrypted_data_key": "do-not-store"
                }
            ]
        })),
        Err(AuditEventError::ForbiddenMetadataKey { key }) if key == "encrypted_data_key"
    ));
    assert!(matches!(
        AuditMetadata::new(json!({
            "safe": [
                {
                    "plain_text": "do-not-store"
                }
            ]
        })),
        Err(AuditEventError::ForbiddenMetadataKey { key }) if key == "plain_text"
    ));
    assert!(matches!(
        AuditMetadata::new(json!({
            "safe": {
                "DeCrYpTeD_dAtA": "do-not-store"
            }
        })),
        Err(AuditEventError::ForbiddenMetadataKey { key }) if key == "DeCrYpTeD_dAtA"
    ));
    assert!(AuditMetadata::new(json!({ "error_code": "denied" })).is_ok());
}

#[test]
fn metadata_adds_attempted_secret_id_as_canonical_uuid() -> TestResult<()> {
    let secret_id = SecretId::parse(TARGET_SECRET_ID)?;
    let metadata = AuditMetadata::new(json!({ "error_code": "write_rpc_failed" }))?
        .with_attempted_secret_id(&secret_id)?;

    assert_eq!(metadata.as_value()["error_code"], "write_rpc_failed");
    assert_eq!(
        metadata.as_value()["attempted_secret_id"],
        secret_id.as_canonical_string()
    );
    assert!(AuditMetadata::new(metadata.as_value().clone()).is_ok());

    Ok(())
}

#[test]
fn forbidden_audit_metadata_keys_match_reserved_key_expectations() {
    assert!(FORBIDDEN_AUDIT_METADATA_KEYS.contains(&"plain_text"));
    assert!(FORBIDDEN_AUDIT_METADATA_KEYS.contains(&"decrypted_data"));
    assert!(!FORBIDDEN_AUDIT_METADATA_KEYS.contains(&"attempted_secret_id"));
    assert!(!FORBIDDEN_AUDIT_METADATA_KEYS.contains(&"source_event_at"));
    assert!(
        AuditMetadata::new(json!({
            "attempted_secret_id": TARGET_SECRET_ID,
            "error_code": "write_rpc_failed"
        }))
        .is_ok()
    );
}

#[test]
fn metadata_rejects_non_canonical_source_event_at_forms() -> TestResult<()> {
    let metadata = AuditMetadata::new(json!({
        "error_code": "write_rpc_failed",
        "source_event_at": SOURCE_EVENT_AT
    }))?;

    assert_eq!(
        metadata.as_value()["source_event_at"],
        Value::String(SOURCE_EVENT_AT.to_owned())
    );
    assert!(matches!(
        AuditMetadata::new(json!({
            "source_event_at": "2026-04-08T12:00:00+00:00"
        })),
        Err(AuditEventError::InvalidSourceEventAt)
    ));
    assert!(matches!(
        AuditMetadata::new(json!({
            "source_event_at": "2026-04-08T12:00:00 UTC"
        })),
        Err(AuditEventError::InvalidSourceEventAt)
    ));
    assert!(matches!(
        AuditMetadata::new(json!({
            "source_event_at": 42
        })),
        Err(AuditEventError::InvalidSourceEventAt)
    ));

    Ok(())
}

#[test]
fn fallback_json_keeps_null_target_and_attempted_secret_metadata() -> TestResult<()> {
    let path = temp_jsonl_path("attempted-secret-null-target");
    let recorder = AuditRecorder::new(
        FakeAppender::always_err(),
        LocalAuditFallbackStore::new(path.clone()),
    );
    let secret_id = SecretId::parse(TARGET_SECRET_ID)?;
    let event = AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::parse(AUDIT_EVENT_ID)?,
        request_id: RequestId::parse(REQUEST_ID)?,
        actor_user_id: Some(OwnerUserId::parse(OWNER_USER_ID)?),
        actor_device_id: Some(DeviceId::new(DEVICE_ID)?),
        action: AuditAction::EncryptCreate,
        target_secret_id: None,
        result: AuditResult::Failure,
        key_version: None,
        metadata_json: AuditMetadata::empty()
            .with_attempted_secret_id(&secret_id)?
            .with_source_event_at(SourceEventAt::parse(SOURCE_EVENT_AT)?)?,
    })?;

    let outcome = recorder.record(&event)?;

    assert_eq!(outcome, AuditRecordOutcome::FallbackSucceeded);
    let lines = read_json_lines(&path)?;
    assert_eq!(lines.len(), 1);
    let line = lines[0].as_object().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "fallback line should be a JSON object",
        )
    })?;
    assert!(line.contains_key("target_secret_id"));
    assert!(line["target_secret_id"].is_null());
    assert_eq!(
        line["metadata_json"]["attempted_secret_id"],
        TARGET_SECRET_ID
    );

    Ok(())
}

#[test]
fn recorder_does_not_write_fallback_when_appender_succeeds() -> TestResult<()> {
    let path = temp_jsonl_path("success-no-fallback");
    let recorder = AuditRecorder::new(
        FakeAppender::always_ok(),
        LocalAuditFallbackStore::new(path.clone()),
    );

    let outcome = recorder.record(&sample_event()?)?;

    assert_eq!(outcome, AuditRecordOutcome::PrimarySucceeded);
    assert!(!path.exists());

    Ok(())
}

#[test]
fn recorder_returns_idempotency_conflict_without_writing_fallback() -> TestResult<()> {
    let path = temp_jsonl_path("idempotency-conflict-no-fallback");
    let recorder = AuditRecorder::new(
        FakeAppender::outcomes(vec![Err(AuditAppendError::IdempotencyConflict)]),
        LocalAuditFallbackStore::new(path.clone()),
    );

    let error = recorder
        .record(&sample_event()?)
        .expect_err("idempotency conflict should not write fallback");

    assert!(matches!(error, AuditRecordError::IdempotencyConflict));
    assert!(!path.exists());

    Ok(())
}

#[test]
fn recorder_writes_pending_json_line_when_appender_fails() -> TestResult<()> {
    let path = temp_jsonl_path("pending-on-failure");
    let recorder = AuditRecorder::new(
        FakeAppender::always_err(),
        LocalAuditFallbackStore::new(path.clone()),
    );
    let event = sample_event()?;
    let expected_source_event_at = event
        .metadata_json()
        .as_value()
        .get("source_event_at")
        .and_then(Value::as_str)
        .ok_or_else(|| std::io::Error::other("source_event_at must exist"))?
        .to_owned();

    let outcome = recorder.record(&event)?;

    assert_eq!(outcome, AuditRecordOutcome::FallbackSucceeded);
    let lines = read_json_lines(&path)?;
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["audit_event_id"], AUDIT_EVENT_ID);
    assert_eq!(lines[0]["request_id"], REQUEST_ID);
    assert_eq!(lines[0]["actor_user_id"], OWNER_USER_ID);
    assert_eq!(lines[0]["actor_device_id"], DEVICE_ID);
    assert_eq!(lines[0]["action"], "decrypt");
    assert_eq!(lines[0]["target_secret_id"], TARGET_SECRET_ID);
    assert_eq!(lines[0]["result"], "failure");
    assert_eq!(lines[0]["key_version"], 1);
    assert_eq!(lines[0]["delivery_status"], "pending");
    assert!(lines[0]["occurred_at"].as_str().is_some());
    assert!(lines[0]["metadata_json"].is_object());
    assert_eq!(
        lines[0]["metadata_json"]["source_event_at"],
        Value::String(expected_source_event_at.clone())
    );
    assert!(SourceEventAt::parse(&expected_source_event_at).is_ok());

    Ok(())
}

#[test]
fn resend_pending_returns_idempotency_conflict_without_sent_marker() -> TestResult<()> {
    let path = temp_jsonl_path("resend-idempotency-conflict");
    let store = LocalAuditFallbackStore::new(path.clone());
    let event = sample_event()?;
    let expected_source_event_at = event
        .metadata_json()
        .as_value()
        .get("source_event_at")
        .and_then(Value::as_str)
        .ok_or_else(|| std::io::Error::other("source_event_at must exist"))?
        .to_owned();
    store.append_pending(&event)?;
    let recorder = AuditRecorder::new(
        FakeAppender::outcomes(vec![Err(AuditAppendError::IdempotencyConflict)]),
        store.clone(),
    );

    let error = recorder
        .resend_pending()
        .expect_err("idempotency conflict should stop resend");

    assert!(matches!(error, AuditRecordError::IdempotencyConflict));
    let lines = read_json_lines(&path)?;
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["delivery_status"], "pending");
    assert_eq!(
        lines[0]["metadata_json"]["source_event_at"],
        Value::String(expected_source_event_at)
    );
    assert_eq!(store.pending_events()?.len(), 1);

    Ok(())
}

#[test]
fn recorder_returns_primary_and_fallback_failed_when_both_paths_fail() -> TestResult<()> {
    let path = temp_jsonl_path("fallback-directory");
    fs::create_dir_all(&path)?;
    let recorder = AuditRecorder::new(
        FakeAppender::always_err(),
        LocalAuditFallbackStore::new(path.clone()),
    );

    let error = recorder
        .record(&sample_event()?)
        .expect_err("primary and fallback should both fail");

    assert!(matches!(
        error,
        AuditRecordError::PrimaryAndFallbackFailed { .. }
    ));

    fs::remove_dir_all(path)?;

    Ok(())
}

#[test]
fn pending_tracking_uses_audit_event_id_not_request_id() -> TestResult<()> {
    let path = temp_jsonl_path("audit-event-id-not-request-id");
    let store = LocalAuditFallbackStore::new(path);
    let first = sample_event_with_ids(AUDIT_EVENT_ID, REQUEST_ID)?;
    let second = sample_event_with_ids(AUDIT_EVENT_ID_2, REQUEST_ID)?;

    store.append_pending(&first)?;
    store.append_pending(&second)?;

    let pending_ids = store
        .pending_events()?
        .into_iter()
        .map(|event| event.audit_event_id().as_canonical_string())
        .collect::<Vec<_>>();

    assert_eq!(pending_ids, vec![AUDIT_EVENT_ID, AUDIT_EVENT_ID_2]);

    Ok(())
}

#[test]
fn resend_success_appends_sent_marker_without_deleting_pending_line() -> TestResult<()> {
    let path = temp_jsonl_path("resend-success");
    let store = LocalAuditFallbackStore::new(path.clone());
    let event = sample_event()?;
    let expected_source_event_at = event
        .metadata_json()
        .as_value()
        .get("source_event_at")
        .and_then(Value::as_str)
        .ok_or_else(|| std::io::Error::other("source_event_at must exist"))?
        .to_owned();
    store.append_pending(&event)?;
    let recorder = AuditRecorder::new(FakeAppender::always_ok(), store.clone());

    let summary = recorder.resend_pending()?;

    assert_eq!(summary.attempted, 1);
    assert_eq!(summary.sent, 1);
    assert_eq!(summary.failed, 0);

    let lines = read_json_lines(&path)?;
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["delivery_status"], "pending");
    assert_eq!(lines[1]["delivery_status"], "sent");
    assert_eq!(
        lines[0]["metadata_json"]["source_event_at"],
        Value::String(expected_source_event_at.clone())
    );
    assert_eq!(
        lines[1]["metadata_json"]["source_event_at"],
        Value::String(expected_source_event_at)
    );
    assert_eq!(store.pending_events()?.len(), 0);

    let second_summary = recorder.resend_pending()?;
    assert_eq!(second_summary.attempted, 0);

    Ok(())
}

#[test]
fn resend_marks_only_successful_events_as_sent() -> TestResult<()> {
    let path = temp_jsonl_path("partial-resend");
    let store = LocalAuditFallbackStore::new(path.clone());
    store.append_pending(&sample_event_with_ids(AUDIT_EVENT_ID, REQUEST_ID)?)?;
    store.append_pending(&sample_event_with_ids(AUDIT_EVENT_ID_2, REQUEST_ID)?)?;
    let appender = FakeAppender::outcomes(vec![
        Ok(()),
        Err(AuditAppendError::ExternalDependencyFailed { code: "still_down" }),
    ]);
    let recorder = AuditRecorder::new(appender, store.clone());

    let summary = recorder.resend_pending()?;

    assert_eq!(summary.attempted, 2);
    assert_eq!(summary.sent, 1);
    assert_eq!(summary.failed, 1);

    let lines = read_json_lines(&path)?;
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[2]["audit_event_id"], AUDIT_EVENT_ID);
    assert_eq!(lines[2]["delivery_status"], "sent");

    let pending_ids = store
        .pending_events()?
        .into_iter()
        .map(|event| event.audit_event_id().as_canonical_string())
        .collect::<Vec<_>>();
    assert_eq!(pending_ids, vec![AUDIT_EVENT_ID_2]);

    Ok(())
}

#[test]
fn pending_events_reject_missing_source_event_at_without_regenerating_it() -> TestResult<()> {
    let path = temp_jsonl_path("missing-source-event-at");
    let store = LocalAuditFallbackStore::new(path.clone());
    fs::write(
        &path,
        format!(
            r#"{{"audit_event_id":"{AUDIT_EVENT_ID}","request_id":"{REQUEST_ID}","actor_user_id":"{OWNER_USER_ID}","actor_device_id":"{DEVICE_ID}","action":"decrypt","target_secret_id":"{TARGET_SECRET_ID}","result":"failure","key_version":1,"metadata_json":{{"error_code":"decrypt_failed"}},"occurred_at":"{SOURCE_EVENT_AT}","delivery_status":"pending"}}"#
        ),
    )?;

    let error = store
        .pending_events()
        .expect_err("missing source_event_at should fail closed");

    assert!(matches!(
        error,
        mipsorcu::LocalAuditStoreError::InvalidLine { reason, .. }
            if reason == "metadata_json.source_event_at is missing"
    ));

    Ok(())
}

#[test]
fn rollover_skips_when_pending_event_remains() -> TestResult<()> {
    let path = temp_jsonl_path("rollover-pending");
    let archive_dir = temp_jsonl_path("rollover-pending-archive");
    let store = LocalAuditFallbackStore::with_rollover_config(path.clone(), archive_dir.clone(), 1);
    store.append_pending(&sample_event()?)?;

    assert!(!store.should_rollover()?);

    let outcome = store.rollover()?;

    assert_eq!(outcome, RolloverOutcome::Skipped);
    assert_eq!(read_json_lines(&path)?.len(), 1);
    assert!(archive_file_names(&archive_dir)?.is_empty());

    Ok(())
}

#[test]
fn rollover_seals_all_sent_current_file_and_resets_current_file() -> TestResult<()> {
    let path = temp_jsonl_path("rollover-all-sent");
    let archive_dir = temp_jsonl_path("rollover-all-sent-archive");
    let store = LocalAuditFallbackStore::with_rollover_config(path.clone(), archive_dir.clone(), 1);
    let event = sample_event()?;
    store.append_pending(&event)?;
    store.mark_sent(&event)?;

    assert!(store.should_rollover()?);

    let outcome = store.rollover()?;
    let RolloverOutcome::Sealed(archive) = outcome else {
        panic!("rollover should seal the all-sent fallback file");
    };

    assert_eq!(archive.line_count, 2);
    assert_eq!(archive.sha256_hex.len(), 64);
    assert!(
        archive
            .sha256_hex
            .chars()
            .all(|value| value.is_ascii_hexdigit())
    );
    assert!(archive.first_occurred_at.is_some());
    assert!(archive.last_occurred_at.is_some());
    assert!(archive.size_bytes > 0);
    assert!(archive.archive_path.exists());
    assert_eq!(fs::read_to_string(&path)?, "");

    let archive_name = archive
        .archive_path
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .ok_or_else(|| std::io::Error::other("archive filename should be present"))?;
    assert!(archive_name.starts_with("audit-fallback-"));
    assert!(archive_name.ends_with(".jsonl.sealed.gz"));
    assert_eq!(
        archive_name.len(),
        "audit-fallback-YYYYMMDDTHHMMSSZ.jsonl.sealed.gz".len()
    );

    let decoded = read_gzip_text(&archive.archive_path)?;
    assert_eq!(decoded.lines().count(), 2);
    assert_eq!(store.pending_events()?.len(), 0);

    Ok(())
}

#[test]
fn pending_events_ignores_sealed_archives_after_rollover() -> TestResult<()> {
    let path = temp_jsonl_path("rollover-archive-ignored");
    let archive_dir = temp_jsonl_path("rollover-archive-ignored-archive");
    let store = LocalAuditFallbackStore::with_rollover_config(path.clone(), archive_dir, 1);
    let first = sample_event_with_ids(AUDIT_EVENT_ID, REQUEST_ID)?;
    let second = sample_event_with_ids(AUDIT_EVENT_ID_2, REQUEST_ID)?;
    store.append_pending(&first)?;
    store.mark_sent(&first)?;
    assert!(matches!(store.rollover()?, RolloverOutcome::Sealed(_)));

    store.append_pending(&second)?;

    let pending_ids = store
        .pending_events()?
        .into_iter()
        .map(|event| event.audit_event_id().as_canonical_string())
        .collect::<Vec<_>>();

    assert_eq!(pending_ids, vec![AUDIT_EVENT_ID_2]);

    Ok(())
}

#[test]
fn rollover_skips_after_partial_resend_leaves_pending_event() -> TestResult<()> {
    let path = temp_jsonl_path("rollover-partial-resend");
    let archive_dir = temp_jsonl_path("rollover-partial-resend-archive");
    let store = LocalAuditFallbackStore::with_rollover_config(path.clone(), archive_dir.clone(), 1);
    store.append_pending(&sample_event_with_ids(AUDIT_EVENT_ID, REQUEST_ID)?)?;
    store.append_pending(&sample_event_with_ids(AUDIT_EVENT_ID_2, REQUEST_ID)?)?;
    let appender = FakeAppender::outcomes(vec![
        Ok(()),
        Err(AuditAppendError::ExternalDependencyFailed { code: "still_down" }),
    ]);
    let recorder = AuditRecorder::new(appender, store.clone());

    let summary = recorder.resend_pending()?;
    let outcome = store.rollover()?;

    assert_eq!(summary.attempted, 2);
    assert_eq!(summary.sent, 1);
    assert_eq!(summary.failed, 1);
    assert_eq!(outcome, RolloverOutcome::Skipped);
    assert!(!store.should_rollover()?);
    assert_eq!(archive_file_names(&archive_dir)?.len(), 0);

    let pending_ids = store
        .pending_events()?
        .into_iter()
        .map(|event| event.audit_event_id().as_canonical_string())
        .collect::<Vec<_>>();
    assert_eq!(pending_ids, vec![AUDIT_EVENT_ID_2]);

    Ok(())
}

#[test]
fn debug_and_error_messages_do_not_expose_secret_metadata_values() -> TestResult<()> {
    let metadata = AuditMetadata::new(json!({
        "error_code": "safe",
        "source_event_at": SOURCE_EVENT_AT,
        "nested": {
            "token_hint": "never-log-this-value"
        }
    }))?;
    let event = AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::parse(AUDIT_EVENT_ID)?,
        request_id: RequestId::parse(REQUEST_ID)?,
        actor_user_id: Some(OwnerUserId::parse(OWNER_USER_ID)?),
        actor_device_id: Some(DeviceId::new(DEVICE_ID)?),
        action: AuditAction::Decrypt,
        target_secret_id: Some(SecretId::parse(TARGET_SECRET_ID)?),
        result: AuditResult::Failure,
        key_version: Some(KeyVersion::new(1)?),
        metadata_json: metadata,
    })?;
    let debug_output = format!("{event:?}");

    assert!(!debug_output.contains("never-log-this-value"));
    assert!(!debug_output.contains("plaintext"));
    assert!(!debug_output.contains("master_key"));
    assert!(!debug_output.contains("data_key"));
    assert!(!debug_output.contains("jwt"));
    assert!(!debug_output.contains("service_role_key"));
    assert!(!debug_output.contains("ciphertext"));
    assert!(!debug_output.contains("encrypted_data_key"));

    let error = AuditMetadata::new(json!({
        "safe": {
            "jwt": "secret-token-value"
        }
    }))
    .expect_err("forbidden metadata key should be rejected");
    let error_output = error.to_string();

    assert!(!error_output.contains("secret-token-value"));

    Ok(())
}

#[test]
fn fake_appender_records_attempted_audit_event_ids() -> TestResult<()> {
    let appender = FakeAppender::always_err();
    let event = sample_event()?;

    let _ = appender.append_audit_event(&event);

    assert_eq!(appender.appended_event_ids(), vec![AUDIT_EVENT_ID]);

    Ok(())
}

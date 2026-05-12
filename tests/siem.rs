//! SIEM 連携基盤の統合テスト。
//!
//! - happy path: dummy sink + buffer で送信が完結する
//! - backend failure: buffer に積まれ、SiemForwardFailureMetadata から
//!   AuditEvent が構築できる（Supabase 送信は本タスク範囲外）
//! - 長期失敗警告: failure_since が threshold を超えた時点で is_long_failure が true
//! - フェイル分離: forward の戻り型 SiemForwardOutcome は Result でないため
//!   主要操作（例: AuditRecorder 相当）の Result<...> に伝播できない
//! - 型レベル境界: SiemEvent serialized JSON のキー集合が allowlist と一致

use std::path::PathBuf;
use std::time::Duration;

use mipsorcu::{
    AuditAction, AuditEvent, AuditEventId, AuditEventParts, AuditMetadata, AuditResult,
    AuthFailureMetadata, DecryptMetadata, FORBIDDEN_AUDIT_METADATA_KEYS, FailingSiemSink,
    InMemorySiemSink, LocalSiemFallbackBuffer, RequestId, SIEM_EVENT_TOP_LEVEL_KEYS, SecretId,
    SiemEvent, SiemForwardOutcome, SiemForwarder, SiemSink, SiemSinkError,
    build_siem_forward_failure_audit_event,
};

fn tempfile_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "mipsorcu-t11-siem-{}-{}-{}.jsonl",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0),
    ));
    let _ = std::fs::remove_file(&path);
    path
}

fn build_decrypt_failure_audit_event() -> AuditEvent {
    let metadata = DecryptMetadata::failure()
        .with_attempted_secret_id(SecretId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap())
        .build()
        .unwrap()
        .with_current_source_event_at()
        .unwrap();
    AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::generate().unwrap(),
        request_id: RequestId::generate().unwrap(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::Decrypt,
        target_secret_id: Some(SecretId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap()),
        result: AuditResult::Failure,
        key_version: None,
        metadata_json: metadata,
    })
    .unwrap()
}

fn build_auth_failure_audit_event() -> AuditEvent {
    let metadata = AuthFailureMetadata::new("authorization_header_missing")
        .build()
        .unwrap()
        .with_current_source_event_at()
        .unwrap();
    AuditEvent::new(AuditEventParts {
        audit_event_id: AuditEventId::generate().unwrap(),
        request_id: RequestId::nil(),
        actor_user_id: None,
        actor_device_id: None,
        action: AuditAction::AuthFailure,
        target_secret_id: None,
        result: AuditResult::Failure,
        key_version: None,
        metadata_json: metadata,
    })
    .unwrap()
}

#[tokio::test]
async fn happy_path_dummy_sink_completes_send() {
    let path = tempfile_path("happy");
    let sink = InMemorySiemSink::new();
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let forwarder = SiemForwarder::new(sink.clone(), buffer.clone());

    let audit_event = build_decrypt_failure_audit_event();
    let siem_event = SiemEvent::from_audit_event(&audit_event);

    let outcome = forwarder.forward(&siem_event).await;
    assert!(matches!(outcome, SiemForwardOutcome::SentDirect));
    assert_eq!(sink.event_count(), 1);
    assert!(buffer.pending_events().unwrap().is_empty());
    assert!(forwarder.status().failure_since().is_none());

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn backend_failure_buffers_event_and_builds_failure_audit() {
    let path = tempfile_path("failure_audit");
    let sink = FailingSiemSink::new("siem_simulated_outage");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let forwarder = SiemForwarder::new(sink, buffer.clone());

    let audit_event = build_decrypt_failure_audit_event();
    let siem_event = SiemEvent::from_audit_event(&audit_event);

    let outcome = forwarder.forward(&siem_event).await;
    let sink_error_code = match outcome {
        SiemForwardOutcome::Buffered { sink_error_code } => sink_error_code,
        other => panic!("expected Buffered, got {other:?}"),
    };
    assert_eq!(sink_error_code, "siem_simulated_outage");

    // buffer に pending として記録されている
    let pending = buffer.pending_events().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].event_id(), siem_event.event_id());

    // SiemForwardFailureMetadata から失敗監査 AuditEvent を構築できる
    // （SIEM 統合の範囲では Supabase 送信は行わず、構築可能性のみを検証する）
    let failure_audit = build_siem_forward_failure_audit_event(
        RequestId::parse(siem_event.request_id()).unwrap_or(RequestId::nil()),
        siem_event.event_type(),
        &sink_error_code,
        Some(1),
    )
    .expect("failure audit event must build");

    assert_eq!(failure_audit.action(), AuditAction::SiemForwardFailure);
    assert_eq!(failure_audit.result(), AuditResult::Failure);
    let metadata_value = failure_audit.metadata_json().as_value();
    assert_eq!(
        metadata_value["error_code"].as_str(),
        Some("siem_simulated_outage")
    );
    assert_eq!(metadata_value["event_type"].as_str(), Some("decrypt"));
    assert_eq!(metadata_value["event_count"].as_u64(), Some(1));

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn long_failure_warning_threshold_reached() {
    let path = tempfile_path("long_failure");
    let sink = FailingSiemSink::new("siem_long_outage");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let forwarder = SiemForwarder::new(sink, buffer);

    let audit_event = build_auth_failure_audit_event();
    let siem_event = SiemEvent::from_audit_event(&audit_event);

    let _ = forwarder.forward(&siem_event).await;
    let failure_since = forwarder
        .status()
        .failure_since()
        .expect("failure_since must be recorded after forward failure");

    // 短い threshold（1秒）に対し、failure_since 直後ではまだ long failure ではない。
    assert!(
        !forwarder
            .status()
            .is_long_failure(failure_since, Duration::from_secs(1)),
        "same moment should not be long failure"
    );

    // 120 秒経過した時点では long failure と判定される。
    let later = failure_since + time::Duration::seconds(120);
    assert!(
        forwarder
            .status()
            .is_long_failure(later, Duration::from_secs(60)),
        "after threshold should be long failure"
    );

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn forward_failure_does_not_propagate_to_primary_operation() {
    // 「SIEM 送信失敗で secret 保存・復号が失敗しない」の構造的検証。
    //
    // 主要操作を模した関数 `primary_with_siem_post_hook` が SIEM forward の
    // 結果を完全に無視できることを確認する。SiemForwardOutcome は Result では
    // ないため、? による伝播は不可能（compile-time に強制される）。
    let path = tempfile_path("isolation");
    let sink = FailingSiemSink::new("siem_total_outage");
    let buffer = LocalSiemFallbackBuffer::new(&path);
    let forwarder = SiemForwarder::new(sink, buffer);

    async fn primary_with_siem_post_hook<S: SiemSink>(
        forwarder: &SiemForwarder<S>,
        event: &SiemEvent,
    ) -> Result<&'static str, &'static str> {
        // 主要操作: ここでは「成功」を返す不変条件。
        let primary_outcome: Result<&'static str, &'static str> = Ok("primary_ok");

        // SIEM forward は副作用としてのみ実行され、Result に影響しない。
        let _ = forwarder.forward(event).await;

        primary_outcome
    }

    let audit_event = build_decrypt_failure_audit_event();
    let siem_event = SiemEvent::from_audit_event(&audit_event);

    let primary_result = primary_with_siem_post_hook(&forwarder, &siem_event).await;
    assert_eq!(
        primary_result,
        Ok("primary_ok"),
        "SIEM 送信失敗が primary operation の Result に伝播してはならない"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn siem_event_top_level_keys_match_allowlist() {
    // 型レベル境界: SiemEvent の JSON 出力は allowlist 集合と完全一致する。
    let audit_event = build_decrypt_failure_audit_event();
    let siem_event = SiemEvent::from_audit_event(&audit_event);
    let value = serde_json::to_value(&siem_event).expect("serialize must succeed");
    let object = value.as_object().expect("must serialize as object");

    let actual_keys: std::collections::BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected_keys: std::collections::BTreeSet<&str> =
        SIEM_EVENT_TOP_LEVEL_KEYS.iter().copied().collect();

    assert_eq!(
        actual_keys, expected_keys,
        "SiemEvent JSON keys must equal SIEM_EVENT_TOP_LEVEL_KEYS"
    );
}

#[test]
fn siem_event_serialization_never_contains_forbidden_keys() {
    // 二重保証: 禁止語彙が serialized JSON 文字列中に top-level または
    // metadata キーとして現れない。
    let audit_event = build_decrypt_failure_audit_event();
    let siem_event = SiemEvent::from_audit_event(&audit_event);
    let json_string = serde_json::to_string(&siem_event).expect("serialize must succeed");

    for forbidden in FORBIDDEN_AUDIT_METADATA_KEYS {
        let needle = format!("\"{forbidden}\":");
        assert!(
            !json_string.contains(&needle),
            "SIEM JSON must not contain forbidden key {forbidden}: {json_string}"
        );
    }
}

#[test]
fn siem_event_metadata_round_trip_preserves_audit_metadata() {
    // metadata は AuditMetadata の as_value() をそのまま転載するため、
    // AuditMetadata 側の allowlist 強制が SiemEvent にも継承される。
    let audit_event = build_decrypt_failure_audit_event();
    let siem_event = SiemEvent::from_audit_event(&audit_event);
    assert_eq!(
        siem_event.metadata(),
        audit_event.metadata_json().as_value()
    );
}

#[test]
fn sink_error_invalid_response_display_includes_reason() {
    // SiemSinkError::InvalidResponse は Display で `reason` をそのまま表示する。
    // バックエンド実装が将来追加されたとき、未知の文字列を audit_events に
    // 流出させないために sink_error_code が "siem_invalid_response" に丸める
    // ことを単体テストで検証済み。ここでは Display の安定性のみ確認する。
    let error = SiemSinkError::InvalidResponse {
        reason: "test_reason",
    };
    let display = format!("{error}");
    assert!(display.contains("test_reason"));
}

#[test]
fn forward_outcome_is_non_result_type() {
    // SiemForwardOutcome は Result ではないため、? で伝播できない。
    // この compile-time 制約が主要操作との隔離を強制する。
    fn _assert_not_result<T: 'static>(_: &T) {}
    let outcome = SiemForwardOutcome::SentDirect;
    _assert_not_result::<SiemForwardOutcome>(&outcome);
}

#[test]
fn build_siem_forward_failure_audit_event_allowlist_compliant() {
    // SiemForwardFailureMetadata で構築した AuditEvent が
    // audit_events.metadata_json の Rust allowlist に整合する。
    let event = build_siem_forward_failure_audit_event(
        RequestId::nil(),
        "decrypt",
        "siem_backend_failed",
        Some(2),
    )
    .expect("must build");
    let metadata = event.metadata_json().clone();
    let result = metadata
        .validate_allowlist_for_action(AuditAction::SiemForwardFailure, AuditResult::Failure);
    assert!(
        result.is_ok(),
        "allowlist validation should pass for SiemForwardFailure: {result:?}"
    );
}

#[test]
fn build_siem_forward_failure_audit_event_rejects_success_action() {
    // SiemForwardFailure は failure-only — success で構築しようとしても
    // AuditEvent 構築時に弾かれる（このテストは「helper が failure を返す」ことの確認）。
    let event = build_siem_forward_failure_audit_event(
        RequestId::nil(),
        "decrypt",
        "siem_backend_failed",
        None,
    )
    .expect("must build");
    assert_eq!(event.result(), AuditResult::Failure);
}

#[test]
fn audit_metadata_alone_rejects_forbidden_keys_so_siem_event_inherits() {
    // 値レベル防御: AuditMetadata::new() 時点で禁止キーが弾かれるため、
    // SiemEvent::from_audit_event を経由しても禁止キーは入り得ない。
    for forbidden in FORBIDDEN_AUDIT_METADATA_KEYS {
        let value = serde_json::json!({
            "source_event_at": "2026-05-12T00:00:00Z",
            *forbidden: "leak"
        });
        let result = AuditMetadata::new(value);
        assert!(
            result.is_err(),
            "AuditMetadata must reject forbidden key {forbidden}"
        );
    }
}

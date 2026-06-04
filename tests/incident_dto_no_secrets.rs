use mipsorcu::{
    ComponentName, IncidentCategory, IncidentId, IncidentNotification, IncidentSeverity,
    IncidentSummary, SourceEventAt, TriageUrl,
};
use serde_json::Value;

fn timestamp(value: &str) -> SourceEventAt {
    SourceEventAt::parse(value).expect("test timestamp must be valid")
}

#[test]
fn incident_notification_uses_expected_top_level_keys_and_canonical_order() {
    let notification = IncidentNotification::new(
        IncidentId::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
        timestamp("2026-06-01T02:00:00Z"),
        IncidentCategory::SchedulerFailure,
        IncidentSeverity::High,
        IncidentSummary::new("scheduler job failed three consecutive times").unwrap(),
        vec![ComponentName::scheduler(), ComponentName::ledger()],
        timestamp("2026-06-01T02:00:00Z"),
    )
    .unwrap()
    .with_correlation_id("scheduler:monthly_digest_generate:scheduler_job_timeout")
    .unwrap()
    .with_triage_url(
        TriageUrl::parse("https://runbooks.example.test/incidents/scheduler").unwrap(),
    );

    let body = notification.canonical_json_bytes().unwrap();
    let body_text = std::str::from_utf8(&body).unwrap();
    assert!(
        body_text
            .starts_with(r#"{"incident_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","detected_at":"#)
    );

    let parsed: Value = serde_json::from_slice(&body).unwrap();
    let keys = parsed
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        vec![
            "affected_components",
            "category",
            "correlation_id",
            "detected_at",
            "incident_id",
            "severity",
            "source_event_at",
            "summary",
            "triage_url",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>()
    );
    assert_eq!(
        parsed["affected_components"],
        serde_json::json!(["ledger", "scheduler"])
    );
}

#[test]
fn incident_notification_rejects_secret_like_text_and_invalid_url() {
    assert!(IncidentSummary::new("plaintext leaked").is_err());
    assert!(ComponentName::new("wrapped_dek").is_err());
    assert!(TriageUrl::parse("file:///tmp/runbook").is_err());
    assert!(TriageUrl::parse("https://runbooks.example.test/incidents").is_ok());
}

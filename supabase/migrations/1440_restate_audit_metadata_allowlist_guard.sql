-- Section 1440: restate the audit metadata key allowlist guard as a single,
-- self-contained definition (bug-05 regression-guard staleness).
--
-- Rationale:
--   Section 1400 redefined audit_metadata_has_unknown_key_for_action by renaming
--   the 1390 body to _before_1400 and delegating every non-incident_notification
--   action to it. That delegating definition carries NO -- ACTION_ALLOWLIST_*
--   markers, so the Rust/SQL parity test (tests/audit_metadata_forbidden_keys_parity.rs)
--   kept reading 1390 (a stale, one-generation-old definition). The values matched
--   by coincidence, but the guard could no longer detect a future SQL-only drift
--   in the incident_notification allowlist.
--
--   This migration restores the invariant "one file = the complete allowlist" by
--   re-stating the full per-action allowlist (all 38 actions) as the effective
--   latest definition, with the -- ACTION_ALLOWLIST_START/END markers preserved.
--   `create or replace` is forward-compatible with databases that already applied
--   1390/1400, and supersedes the 1400 delegating version in place.
--
-- Invariant (see docs/coding-rules.md §14):
--   A migration that re-defines a metadata/value guard function MUST restate the
--   complete allowlist/value set and keep its -- *_ALLOWLIST_START/END markers.
--   The parity test auto-discovers the latest definition and asserts (meta-test)
--   that the latest definition still carries the markers.
--
-- This change does NOT alter any allowed key or value. The set is byte-identical to
-- the 1390 body and the 1400 incident_notification arrays (verified). It only moves
-- the effective latest definition back into a single, marker-bearing file, so no ADR
-- is required (set is unchanged).

create or replace function public.audit_metadata_has_unknown_key_for_action(
    p_action text,
    p_result text,
    p_metadata_json jsonb
)
returns boolean
language plpgsql
stable
set search_path = public, pg_temp
as $$
declare
    v_key text;
    v_allowed_keys text[];
    v_violation_summary_keys text[];
begin
    if jsonb_typeof(p_metadata_json) <> 'object' then
        return true;
    end if;

    -- ACTION_ALLOWLIST_START
    case p_action
        when 'encrypt_create', 'encrypt_rotate', 'version_purge' then
            v_allowed_keys := array['version', 'secret_version_id', 'source_event_at'];
        when 'decrypt' then
            if p_result = 'failure' then
                v_allowed_keys := array['attempted_secret_id', 'source_event_at'];
            else
                v_allowed_keys := array['source_event_at'];
            end if;
        when 'integrity_check' then
            v_allowed_keys := array['check_name', 'checked_secret_count', 'checked_secret_version_count', 'checked_audit_event_count', 'duration_ms', 'violation_count', 'violation_summary', 'trigger', 'error_code', 'source_event_at'];
            v_violation_summary_keys := array['current_version_invalid', 'version_invalid', 'retention_exceeded', 'ciphertext_empty', 'encrypted_data_key_empty', 'nonce_length_invalid', 'algorithm_invalid', 'nonce_duplicate', 'aad_keys_invalid', 'aad_row_mismatch', 'created_at_mismatch', 'audit_action_invalid', 'audit_result_invalid', 'audit_metadata_not_object', 'audit_metadata_forbidden_key', 'audit_source_event_at_invalid'];
        when 'restore_test' then
            v_allowed_keys := array['phase', 'sample_count', 'trigger', 'duration_ms', 'error_code', 'failed_version', 'reason', 'source_event_at'];
        when 'auth_failure' then
            v_allowed_keys := array['error_code', 'source_event_at'];
        when 'key_rotation_start' then
            v_allowed_keys := array['old_key_version', 'new_key_version', 'source_event_at'];
        when 'key_rotation_reencrypt' then
            v_allowed_keys := array['old_key_version', 'new_key_version', 'batch_size', 'processed_count', 'remaining_count', 'source_event_at'];
        when 'key_rotation_complete' then
            v_allowed_keys := array['old_key_version', 'new_key_version', 'remaining_count', 'source_event_at'];
        when 'key_rotation_envelope_migrated' then
            v_allowed_keys := array['batch_size', 'success_count', 'failure_count', 'source_event_at'];
        when 'key_rotation_envelope_failed' then
            v_allowed_keys := array['secret_version_id', 'version', 'error_code', 'source_event_at'];
        when 'signature_key_created' then
            v_allowed_keys := array['created_at', 'public_key_fingerprint', 'signature_key_version', 'source_event_at'];
        when 'signature_key_activated' then
            v_allowed_keys := array['activated_at', 'public_key_fingerprint', 'signature_key_version', 'source_event_at'];
        when 'signature_key_retired' then
            v_allowed_keys := array['public_key_fingerprint', 'retired_at', 'signature_key_version', 'source_event_at'];
        when 'monthly_digest_generate' then
            v_allowed_keys := array['error_code', 'target_year_month', 'source_event_at', 'start_sequence_no', 'end_sequence_no', 'entry_count', 'signature_key_version', 'digest_hash'];
        when 'monthly_digest_verify' then
            v_allowed_keys := array['error_code', 'target_year_month', 'verify_result', 'source_event_at'];
        when 'archive_export' then
            v_allowed_keys := array['archive_key', 'digest_hash', 'target_year_month', 'error_code', 'source_event_at'];
        when 'digest_timestamping' then
            v_allowed_keys := array['digest_hash', 'timestamp_token_hash', 'target_year_month', 'error_code', 'source_event_at'];
        when 'siem_forward_failure' then
            v_allowed_keys := array['error_code', 'event_type', 'event_count', 'source_event_at'];
        when 'siem_event_forwarded' then
            v_allowed_keys := array['exporter_kind', 'batch_size', 'source_event_at'];
        when 'siem_event_failed' then
            v_allowed_keys := array['exporter_kind', 'error_code', 'buffered', 'batch_size', 'source_event_at'];
        when 'siem_buffer_flushed' then
            v_allowed_keys := array['flushed_count', 'buffer_remaining_bytes', 'source_event_at'];
        when 'audit_report_generate' then
            v_allowed_keys := array['error_code', 'format', 'period_end', 'period_start', 'source_event_at'];
        when 'audit_ui_read' then
            v_allowed_keys := array['endpoint', 'method', 'resource', 'result_count', 'period_start', 'period_end', 'start_sequence_no', 'end_sequence_no', 'target_year_month', 'error_code', 'source_event_at'];
        when 'scheduler_job' then
            v_allowed_keys := array['duration_ms', 'error_code', 'job_name', 'target_year_month', 'trigger', 'source_event_at'];
        when 'scheduler_job_started' then
            v_allowed_keys := array['job_name', 'scheduled_at', 'started_at', 'source_event_at'];
        when 'scheduler_job_completed' then
            v_allowed_keys := array['completed_at', 'duration_ms', 'job_name', 'result_summary', 'started_at', 'source_event_at'];
        when 'scheduler_job_failed' then
            v_allowed_keys := array['error_code', 'failed_at', 'job_name', 'retry_count', 'started_at', 'source_event_at'];
        when 'scheduler_job_skipped' then
            v_allowed_keys := array['job_name', 'reason', 'skipped_at', 'source_event_at'];
        when 'incident_detected' then
            v_allowed_keys := array['incident_type', 'severity', 'detection_source', 'dedupe_key', 'notification_sink', 'notification_result', 'error_code', 'source_event_at', 'source_event_id', 'target_sequence_no', 'target_year_month'];
        when 'incident_notification_sent' then
            v_allowed_keys := array['incident_id', 'category', 'notifier_kind', 'duration_ms', 'source_event_at'];
        when 'incident_notification_failed' then
            v_allowed_keys := array['incident_id', 'category', 'notifier_kind', 'error_code', 'retry_count', 'source_event_at'];
        when 'incident_notification_suppressed' then
            v_allowed_keys := array['incident_id', 'category', 'reason', 'suppressed_count', 'window_remaining_sec', 'source_event_at'];
        when 'secret_alias_create' then
            v_allowed_keys := array['alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version', 'error_code', 'source_event_at'];
        when 'secret_alias_update' then
            v_allowed_keys := array['old_alias_fingerprint', 'new_alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version', 'error_code', 'source_event_at'];
        when 'secret_alias_delete' then
            v_allowed_keys := array['alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version', 'error_code', 'source_event_at'];
        when 'secret_alias_list' then
            v_allowed_keys := array['result_count', 'error_code', 'source_event_at'];
        else
            return true;
    end case;
    -- ACTION_ALLOWLIST_END

    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        if not (v_key = any(v_allowed_keys)) then
            return true;
        end if;
    end loop;

    if p_action = 'integrity_check'
        and p_metadata_json ? 'violation_summary'
        and jsonb_typeof(p_metadata_json -> 'violation_summary') = 'object'
    then
        for v_key in select jsonb_object_keys(p_metadata_json -> 'violation_summary')
        loop
            if not (v_key = any(v_violation_summary_keys)) then
                return true;
            end if;
        end loop;
    end if;

    return false;
end;
$$;

comment on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb)
is 'Returns true when audit metadata contains a key outside the per-action allowlist. Section 1440 restates the complete allowlist (all 38 actions) with -- ACTION_ALLOWLIST_START/END markers preserved, superseding the 1400 delegating definition so the Rust/SQL parity test always reads the effective latest definition. Re-defining migrations must restate the full allowlist and keep these markers (docs/coding-rules.md §14).';

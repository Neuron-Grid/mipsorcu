-- Section 1450: restate the audit metadata required-key guard as a single,
-- self-contained definition (bug-05 secondary regression-guard gap).
--
-- Rationale:
--   audit_metadata_has_missing_required_key_for_action is defined across a deep
--   _before_NNNN delegation chain (1400 -> 1390 -> 1380 -> 1360, with 1230/1330
--   bodies folded underneath). No single migration carried the complete required
--   key set and none carried any marker, so unlike the unknown-key allowlist
--   (restated with markers in 1440), the required-key set had NO executable
--   Rust/SQL parity guard in cargo -- only the pure-Rust contract
--   (tests/audit_metadata_required_keys_contract.rs) plus pgTAP. A future SQL-only
--   drift in the required keys for an incident_notification action could pass
--   `cargo test` undetected (bug-05, "二次的ギャップ").
--
--   This migration restores the invariant "one file = the complete required-key
--   definition" by re-stating the full per-action required-key set (all 38 actions)
--   as the effective latest definition, with -- REQUIRED_KEY_START/END markers
--   preserved. `create or replace` is forward-compatible with databases that
--   already applied 1230/1330/1360/1380/1390/1400, and supersedes the 1400
--   delegating version in place. The _before_NNNN chain is left intact (still
--   referenced by superseded versions in already-applied environments); 1450 just
--   makes the effective top definition complete and marker-bearing.
--
-- Invariant (see docs/coding-rules.md §14, ADR-0044):
--   A migration that re-defines a metadata/value guard function MUST restate the
--   complete allowlist/required/value set and keep its -- *_START/END markers.
--   The parity test auto-discovers the latest definition and asserts (meta-test)
--   that the latest definition still carries the markers.
--
-- This change does NOT alter any required key. The effective set is byte-identical
-- to the chain (1360 base incl. monthly_digest result branches and the
-- integrity_check violation_summary required keys; 1380 envelope + scheduler_job_*;
-- 1390 siem_event_*/siem_buffer_flushed; 1400 incident_notification_*; 1360
-- secret_alias_* result branches), so no ADR is required (set is unchanged).

create or replace function public.audit_metadata_has_missing_required_key_for_action(
    p_action text,
    p_result text,
    p_metadata_json jsonb,
    p_require_source_event_at boolean default true
)
returns boolean
language plpgsql
stable
set search_path = public, pg_temp
as $$
declare
    v_required_keys text[];
    v_summary_required_keys text[];
begin
    if jsonb_typeof(p_metadata_json) <> 'object' then
        return true;
    end if;

    -- REQUIRED_KEY_START
    case p_action
        when 'encrypt_create', 'encrypt_rotate', 'version_purge' then
            v_required_keys := array['version', 'secret_version_id'];
        when 'decrypt' then
            v_required_keys := array[]::text[];
        when 'integrity_check' then
            v_required_keys := array['check_name', 'checked_secret_count', 'checked_secret_version_count', 'checked_audit_event_count', 'duration_ms', 'violation_count', 'violation_summary', 'trigger'];
            v_summary_required_keys := array['current_version_invalid', 'version_invalid', 'retention_exceeded', 'ciphertext_empty', 'encrypted_data_key_empty', 'nonce_length_invalid', 'algorithm_invalid', 'nonce_duplicate', 'aad_keys_invalid', 'aad_row_mismatch', 'created_at_mismatch', 'audit_action_invalid', 'audit_result_invalid', 'audit_metadata_not_object', 'audit_metadata_forbidden_key', 'audit_source_event_at_invalid'];
        when 'restore_test' then
            v_required_keys := array['phase', 'sample_count', 'trigger', 'duration_ms'];
        when 'auth_failure' then
            v_required_keys := array['error_code'];
        when 'key_rotation_start' then
            v_required_keys := array['old_key_version', 'new_key_version'];
        when 'key_rotation_reencrypt' then
            v_required_keys := array['old_key_version', 'new_key_version', 'batch_size', 'processed_count', 'remaining_count'];
        when 'key_rotation_complete' then
            v_required_keys := array['old_key_version', 'new_key_version', 'remaining_count'];
        when 'key_rotation_envelope_migrated' then
            v_required_keys := array['batch_size', 'success_count', 'failure_count'];
        when 'key_rotation_envelope_failed' then
            v_required_keys := array['secret_version_id', 'version', 'error_code'];
        when 'signature_key_created' then
            v_required_keys := array['signature_key_version', 'public_key_fingerprint', 'created_at'];
        when 'signature_key_activated' then
            v_required_keys := array['signature_key_version', 'public_key_fingerprint', 'activated_at'];
        when 'signature_key_retired' then
            v_required_keys := array['signature_key_version', 'public_key_fingerprint', 'retired_at'];
        when 'monthly_digest_generate' then
            if p_result = 'success' then
                v_required_keys := array['target_year_month', 'start_sequence_no', 'end_sequence_no', 'entry_count', 'signature_key_version', 'digest_hash'];
            else
                v_required_keys := array['target_year_month', 'error_code'];
            end if;
        when 'monthly_digest_verify' then
            if p_result = 'success' then
                v_required_keys := array['target_year_month', 'verify_result'];
            else
                v_required_keys := array['target_year_month', 'verify_result', 'error_code'];
            end if;
        when 'archive_export', 'digest_timestamping' then
            v_required_keys := array['target_year_month'];
        when 'siem_forward_failure' then
            v_required_keys := array['error_code'];
        when 'siem_event_forwarded' then
            v_required_keys := array['exporter_kind', 'batch_size'];
        when 'siem_event_failed' then
            v_required_keys := array['exporter_kind', 'error_code', 'buffered', 'batch_size'];
        when 'siem_buffer_flushed' then
            v_required_keys := array['flushed_count', 'buffer_remaining_bytes'];
        when 'audit_report_generate' then
            v_required_keys := array['format', 'period_end', 'period_start'];
        when 'audit_ui_read' then
            v_required_keys := array['endpoint', 'method', 'resource'];
        when 'scheduler_job' then
            v_required_keys := array['job_name', 'trigger', 'duration_ms'];
        when 'scheduler_job_started' then
            v_required_keys := array['job_name', 'scheduled_at', 'started_at'];
        when 'scheduler_job_completed' then
            v_required_keys := array['job_name', 'started_at', 'completed_at', 'duration_ms', 'result_summary'];
        when 'scheduler_job_failed' then
            v_required_keys := array['job_name', 'started_at', 'failed_at', 'error_code', 'retry_count'];
        when 'scheduler_job_skipped' then
            v_required_keys := array['job_name', 'skipped_at', 'reason'];
        when 'incident_detected' then
            v_required_keys := array['incident_type', 'severity', 'detection_source', 'dedupe_key', 'notification_sink', 'notification_result', 'error_code'];
        when 'incident_notification_sent' then
            v_required_keys := array['incident_id', 'category', 'notifier_kind', 'duration_ms'];
        when 'incident_notification_failed' then
            v_required_keys := array['incident_id', 'category', 'notifier_kind', 'error_code', 'retry_count'];
        when 'incident_notification_suppressed' then
            v_required_keys := array['incident_id', 'category', 'reason', 'suppressed_count', 'window_remaining_sec'];
        when 'secret_alias_create' then
            if p_result = 'success' then
                v_required_keys := array['alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version'];
            else
                v_required_keys := array[]::text[];
            end if;
        when 'secret_alias_update' then
            if p_result = 'success' then
                v_required_keys := array['old_alias_fingerprint', 'new_alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version'];
            else
                v_required_keys := array[]::text[];
            end if;
        when 'secret_alias_delete' then
            if p_result = 'success' then
                v_required_keys := array['alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version'];
            else
                v_required_keys := array[]::text[];
            end if;
        when 'secret_alias_list' then
            if p_result = 'success' then
                v_required_keys := array['result_count'];
            else
                v_required_keys := array[]::text[];
            end if;
        else
            return true;
    end case;
    -- REQUIRED_KEY_END

    if p_require_source_event_at then
        v_required_keys := v_required_keys || array['source_event_at'];
    end if;

    if not (p_metadata_json ?& v_required_keys) then
        return true;
    end if;

    if p_action = 'integrity_check' then
        if jsonb_typeof(p_metadata_json -> 'violation_summary') <> 'object' then
            return true;
        end if;

        if not ((p_metadata_json -> 'violation_summary') ?& v_summary_required_keys) then
            return true;
        end if;
    end if;

    return false;
end;
$$;

comment on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean)
is 'Returns true when audit metadata is missing a required key for the given action/result. Section 1450 restates the complete required-key set (all 38 actions, incl. monthly_digest/secret_alias result branches and the integrity_check violation_summary required keys) with -- REQUIRED_KEY_START/END markers preserved, superseding the 1400 delegating definition so the Rust/SQL parity test always reads the effective latest definition. Re-defining migrations must restate the full required-key set and keep these markers (docs/coding-rules.md §14).';

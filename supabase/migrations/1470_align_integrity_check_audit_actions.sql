-- Section 1470: align the rpc_integrity_check audit action vocabulary with the
-- current audit_events vocabulary.
--
-- rpc_integrity_check() was defined only in 0900, where v_audit_actions listed the
-- 10 actions that existed at that time. Later migrations (1000 through 1400)
-- extended the audit_events_action_allowed CHECK constraint and the Rust
-- AuditAction enum to 38 actions, but the integrity check kept the 10-action list,
-- so every legitimate event of the newer actions was counted as
-- audit_action_invalid and the integrity check could not succeed on a database
-- that contained any of them.
--
-- This migration re-states rpc_integrity_check() with the complete 38-action
-- vocabulary between standalone -- INTEGRITY_CHECK_AUDIT_ACTIONS_START/END marker
-- lines. The Rust parity test (tests/audit_metadata_forbidden_keys_parity.rs)
-- reads the latest marker block and compares it with AuditAction and with the
-- latest audit_events_action_allowed CHECK constraint. A migration that re-defines
-- rpc_integrity_check() must restate the complete vocabulary and keep the markers.
--
-- Everything else is unchanged from 0900: the returned columns, the
-- violation_summary keys, every other check, SECURITY DEFINER, the fixed
-- search_path and the EXECUTE grants.

create or replace function public.rpc_integrity_check()
returns table (
    checked_secret_count integer,
    checked_secret_version_count integer,
    checked_audit_event_count integer,
    violation_count integer,
    violation_summary jsonb
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_aad_keys constant text[] := array[
        'aad_version',
        'secret_id',
        'version',
        'owner_user_id',
        'classification',
        'created_at'
    ];
    v_audit_actions constant text[] := array[
        -- INTEGRITY_CHECK_AUDIT_ACTIONS_START
        'encrypt_create',
        'encrypt_rotate',
        'decrypt',
        'version_purge',
        'integrity_check',
        'restore_test',
        'auth_failure',
        'key_rotation_start',
        'key_rotation_reencrypt',
        'key_rotation_complete',
        'key_rotation_envelope_migrated',
        'key_rotation_envelope_failed',
        'signature_key_created',
        'signature_key_activated',
        'signature_key_retired',
        'monthly_digest_generate',
        'monthly_digest_verify',
        'archive_export',
        'digest_timestamping',
        'siem_forward_failure',
        'siem_event_forwarded',
        'siem_event_failed',
        'siem_buffer_flushed',
        'audit_report_generate',
        'audit_ui_read',
        'scheduler_job',
        'scheduler_job_started',
        'scheduler_job_completed',
        'scheduler_job_failed',
        'scheduler_job_skipped',
        'incident_detected',
        'incident_notification_sent',
        'incident_notification_failed',
        'incident_notification_suppressed',
        'secret_alias_create',
        'secret_alias_update',
        'secret_alias_delete',
        'secret_alias_list'
        -- INTEGRITY_CHECK_AUDIT_ACTIONS_END
    ];
    v_current_version_invalid integer;
    v_version_invalid integer;
    v_retention_exceeded integer;
    v_ciphertext_empty integer;
    v_encrypted_data_key_empty integer;
    v_nonce_length_invalid integer;
    v_algorithm_invalid integer;
    v_nonce_duplicate integer;
    v_aad_keys_invalid integer;
    v_aad_row_mismatch integer;
    v_created_at_mismatch integer;
    v_audit_action_invalid integer;
    v_audit_result_invalid integer;
    v_audit_metadata_not_object integer;
    v_audit_metadata_forbidden_key integer;
    v_audit_source_event_at_invalid integer;
begin
    -- Base row counts only; do not return row identifiers or secret material.
    select count(*)::integer into checked_secret_count from public.secrets;
    select count(*)::integer into checked_secret_version_count from public.secret_versions;
    select count(*)::integer into checked_audit_event_count from public.audit_events;

    -- secret/current-version invariants.
    select count(*)::integer
    into v_current_version_invalid
    from public.secrets s
    left join public.secret_versions sv
        on sv.id = s.current_version_id
        and sv.secret_id = s.id
    where s.current_version_id is null
        or sv.id is null;

    -- secret_versions storage invariants.
    select count(*)::integer
    into v_version_invalid
    from public.secret_versions sv
    where sv.version <= 0;

    select count(*)::integer
    into v_retention_exceeded
    from (
        select sv.secret_id
        from public.secret_versions sv
        group by sv.secret_id
        having count(*) > 4
    ) retained;

    select count(*)::integer
    into v_ciphertext_empty
    from public.secret_versions sv
    where octet_length(sv.ciphertext) = 0;

    select count(*)::integer
    into v_encrypted_data_key_empty
    from public.secret_versions sv
    where octet_length(sv.encrypted_data_key) = 0;

    select count(*)::integer
    into v_nonce_length_invalid
    from public.secret_versions sv
    where octet_length(sv.nonce_or_iv) <> 24;

    select count(*)::integer
    into v_algorithm_invalid
    from public.secret_versions sv
    where sv.algorithm <> 'xchacha20-poly1305';

    select count(*)::integer
    into v_nonce_duplicate
    from (
        select sv.secret_id, sv.nonce_or_iv
        from public.secret_versions sv
        group by sv.secret_id, sv.nonce_or_iv
        having count(*) > 1
    ) duplicate_nonces;

    -- AAD v1 shape and row-binding invariants.
    select count(*)::integer
    into v_aad_keys_invalid
    from public.secret_versions sv
    where jsonb_typeof(sv.aad_context) is distinct from 'object'
        or not (sv.aad_context ?& v_aad_keys)
        or sv.aad_context - v_aad_keys <> '{}'::jsonb
        or jsonb_typeof(sv.aad_context -> 'aad_version') is distinct from 'number'
        or jsonb_typeof(sv.aad_context -> 'secret_id') is distinct from 'string'
        or jsonb_typeof(sv.aad_context -> 'version') is distinct from 'number'
        or jsonb_typeof(sv.aad_context -> 'owner_user_id') is distinct from 'string'
        or jsonb_typeof(sv.aad_context -> 'classification') is distinct from 'string'
        or jsonb_typeof(sv.aad_context -> 'created_at') is distinct from 'string'
        or sv.aad_context ->> 'aad_version' <> '1';

    select count(*)::integer
    into v_aad_row_mismatch
    from public.secret_versions sv
    inner join public.secrets s
        on s.id = sv.secret_id
    where jsonb_typeof(sv.aad_context) = 'object'
        and sv.aad_context ?& v_aad_keys
        and sv.aad_context - v_aad_keys = '{}'::jsonb
        and (
            sv.aad_context ->> 'secret_id' <> sv.secret_id::text
            or sv.aad_context ->> 'version' <> sv.version::text
            or sv.aad_context ->> 'owner_user_id' <> s.owner_user_id::text
            or sv.aad_context ->> 'owner_user_id' <> sv.created_by_user_id::text
            or sv.aad_context ->> 'classification' <> s.classification
            or sv.aad_context ->> 'classification' <> sv.classification
        );

    select count(*)::integer
    into v_created_at_mismatch
    from public.secret_versions sv
    where jsonb_typeof(sv.aad_context) = 'object'
        and jsonb_typeof(sv.aad_context -> 'created_at') = 'string'
        and not (
            sv.aad_context ->> 'created_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$'
            and case
                when sv.aad_context ->> 'created_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$'
                    then (sv.aad_context ->> 'created_at')::timestamptz = sv.created_at
                else false
            end
        );

    -- audit_events shape invariants. The summary remains aggregate-only.
    select count(*)::integer
    into v_audit_action_invalid
    from public.audit_events ae
    where not (ae.action = any(v_audit_actions));

    select count(*)::integer
    into v_audit_result_invalid
    from public.audit_events ae
    where ae.result not in ('success', 'failure');

    select count(*)::integer
    into v_audit_metadata_not_object
    from public.audit_events ae
    where jsonb_typeof(ae.metadata_json) is distinct from 'object';

    select count(*)::integer
    into v_audit_metadata_forbidden_key
    from public.audit_events ae
    where public.audit_metadata_has_forbidden_key(ae.metadata_json);

    select count(*)::integer
    into v_audit_source_event_at_invalid
    from public.audit_events ae
    where jsonb_typeof(ae.metadata_json) = 'object'
        and not public.audit_metadata_source_event_at_is_valid(ae.metadata_json);

    -- Result assembly: fixed keys consumed by Rust audit metadata builders/tests.
    violation_summary := jsonb_build_object(
        'current_version_invalid', v_current_version_invalid,
        'version_invalid', v_version_invalid,
        'retention_exceeded', v_retention_exceeded,
        'ciphertext_empty', v_ciphertext_empty,
        'encrypted_data_key_empty', v_encrypted_data_key_empty,
        'nonce_length_invalid', v_nonce_length_invalid,
        'algorithm_invalid', v_algorithm_invalid,
        'nonce_duplicate', v_nonce_duplicate,
        'aad_keys_invalid', v_aad_keys_invalid,
        'aad_row_mismatch', v_aad_row_mismatch,
        'created_at_mismatch', v_created_at_mismatch,
        'audit_action_invalid', v_audit_action_invalid,
        'audit_result_invalid', v_audit_result_invalid,
        'audit_metadata_not_object', v_audit_metadata_not_object,
        'audit_metadata_forbidden_key', v_audit_metadata_forbidden_key,
        'audit_source_event_at_invalid', v_audit_source_event_at_invalid
    );

    violation_count := v_current_version_invalid
        + v_version_invalid
        + v_retention_exceeded
        + v_ciphertext_empty
        + v_encrypted_data_key_empty
        + v_nonce_length_invalid
        + v_algorithm_invalid
        + v_nonce_duplicate
        + v_aad_keys_invalid
        + v_aad_row_mismatch
        + v_created_at_mismatch
        + v_audit_action_invalid
        + v_audit_result_invalid
        + v_audit_metadata_not_object
        + v_audit_metadata_forbidden_key
        + v_audit_source_event_at_invalid;

    return next;
end;
$$;

revoke execute on function public.rpc_integrity_check() from public, anon, authenticated;

grant execute on function public.rpc_integrity_check() to service_role;

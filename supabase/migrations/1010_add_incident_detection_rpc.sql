-- T14: Incident detection recording RPC.
--
-- Trust boundary: incident metadata and ledger payloads contain only short
-- non-secret identifiers, aggregate references, and notification status. The
-- RPC does not accept arbitrary audit metadata JSON from callers.

create or replace function public.incident_type_allowed(p_incident_type text)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select p_incident_type in (
        'hash_chain_mismatch',
        'signature_mismatch',
        'monthly_digest_mismatch',
        'digest_timestamping_mismatch',
        'archive_export_mismatch',
        'sequence_gap',
        'unknown_signature_key',
        'non_auditor_ledger_read',
        'ledger_secret_leak_suspected',
        'siem_long_failure',
        'audit_ui_forbidden_operation'
    );
$$;

create or replace function public.incident_severity_allowed(p_severity text)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select p_severity in ('critical', 'high', 'medium', 'low');
$$;

create or replace function public.incident_notification_result_allowed(p_notification_result text)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select p_notification_result in ('sent', 'failed', 'suppressed', 'not_configured');
$$;

alter table public.audit_events
    drop constraint audit_events_action_allowed,
    add constraint audit_events_action_allowed check (
        action in (
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
            'monthly_digest_generate',
            'monthly_digest_verify',
            'archive_export',
            'digest_timestamping',
            'siem_forward_failure',
            'audit_report_generate',
            'scheduler_job',
            'incident_detected'
        )
    );

alter table public.audit_events
    add constraint audit_events_incident_detected_failure_only check (
        action <> 'incident_detected' or result = 'failure'
    );

comment on constraint audit_events_incident_detected_failure_only on public.audit_events is
    'Incident detection audit events are failure-only because they record detected anomalies.';

create or replace function public.rpc_append_audit_event(
    p_audit_event_id uuid,
    p_request_id uuid,
    p_actor_user_id uuid default null,
    p_actor_device_id text default null,
    p_action text default null,
    p_target_secret_id uuid default null,
    p_result text default null,
    p_key_version integer default null,
    p_metadata_json jsonb default '{}'::jsonb
)
returns uuid
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_existing_audit_event record;
    v_allowlist_mode text;
begin
    if p_audit_event_id is null
        or p_request_id is null
        or p_action is null
        or p_result is null
        or p_metadata_json is null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_action not in (
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
        'monthly_digest_generate',
        'monthly_digest_verify',
        'archive_export',
        'digest_timestamping',
        'siem_forward_failure',
        'audit_report_generate',
        'scheduler_job',
        'incident_detected'
    ) then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_result not in ('success', 'failure') then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_result = 'success'
        and p_action in ('encrypt_create', 'encrypt_rotate', 'version_purge')
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_action in ('auth_failure', 'siem_forward_failure', 'incident_detected')
        and p_result <> 'failure'
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_action in ('monthly_digest_generate', 'monthly_digest_verify')
        and p_result <> 'failure'
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_action = 'auth_failure'
        and (
            p_actor_user_id is not null
            or p_actor_device_id is not null
            or p_target_secret_id is not null
            or p_key_version is not null
        )
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_actor_device_id is not null and btrim(p_actor_device_id) = '' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_key_version is not null and p_key_version <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if jsonb_typeof(p_metadata_json) <> 'object' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if public.audit_metadata_has_forbidden_key(p_metadata_json)
        or not public.audit_metadata_source_event_at_is_valid(p_metadata_json)
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    v_allowlist_mode := public.audit_metadata_allowlist_mode();

    if public.audit_metadata_has_schema_violation_for_action(p_action, p_result, p_metadata_json, true) then
        if v_allowlist_mode = 'strict' then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        else
            raise notice 'audit_metadata_schema_warning: action=%, result=%, schema_violation_present',
                p_action, p_result;
        end if;
    end if;

    insert into public.audit_events (
        id,
        request_id,
        actor_user_id,
        actor_device_id,
        action,
        target_secret_id,
        result,
        key_version,
        metadata_json
    )
    values (
        p_audit_event_id,
        p_request_id,
        p_actor_user_id,
        p_actor_device_id,
        p_action,
        p_target_secret_id,
        p_result,
        p_key_version,
        p_metadata_json
    )
    on conflict (id) do nothing;

    select *
    into v_existing_audit_event
    from public.audit_events ae
    where ae.id = p_audit_event_id;

    if not found then
        raise exception 'audit_event_id_conflict' using errcode = '23505';
    end if;

    if v_existing_audit_event.request_id <> p_request_id
        or v_existing_audit_event.actor_user_id is distinct from p_actor_user_id
        or v_existing_audit_event.actor_device_id is distinct from p_actor_device_id
        or v_existing_audit_event.action <> p_action
        or v_existing_audit_event.target_secret_id is distinct from p_target_secret_id
        or v_existing_audit_event.result <> p_result
        or v_existing_audit_event.key_version is distinct from p_key_version
        or v_existing_audit_event.metadata_json <> p_metadata_json
    then
        raise exception 'audit_event_id_conflict' using errcode = '23505';
    end if;

    return p_audit_event_id;
end;
$$;

comment on function public.rpc_append_audit_event(
    uuid, uuid, uuid, text, text, uuid, text, integer, jsonb
) is
    'Audit append RPC for non-write-path audit events and failure events. Updated in T14 to add incident_detected action.';

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

    case p_action
        when 'encrypt_create', 'encrypt_rotate', 'version_purge' then
            v_required_keys := array['version', 'secret_version_id'];
        when 'decrypt' then
            v_required_keys := array[]::text[];
        when 'integrity_check' then
            v_required_keys := array[
                'check_name',
                'checked_secret_count',
                'checked_secret_version_count',
                'checked_audit_event_count',
                'duration_ms',
                'violation_count',
                'violation_summary',
                'trigger'
            ];
            v_summary_required_keys := array[
                'current_version_invalid',
                'version_invalid',
                'retention_exceeded',
                'ciphertext_empty',
                'encrypted_data_key_empty',
                'nonce_length_invalid',
                'algorithm_invalid',
                'nonce_duplicate',
                'aad_keys_invalid',
                'aad_row_mismatch',
                'created_at_mismatch',
                'audit_action_invalid',
                'audit_result_invalid',
                'audit_metadata_not_object',
                'audit_metadata_forbidden_key',
                'audit_source_event_at_invalid'
            ];
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
        when 'monthly_digest_generate', 'monthly_digest_verify' then
            v_required_keys := array[]::text[];
        when 'archive_export', 'digest_timestamping' then
            v_required_keys := array['target_year_month'];
        when 'siem_forward_failure' then
            v_required_keys := array['error_code'];
        when 'audit_report_generate' then
            v_required_keys := array['format', 'period_end', 'period_start'];
        when 'scheduler_job' then
            v_required_keys := array['job_name', 'trigger', 'duration_ms'];
        when 'incident_detected' then
            v_required_keys := array[
                'incident_type',
                'severity',
                'detection_source',
                'dedupe_key',
                'notification_sink',
                'notification_result',
                'error_code'
            ];
        else
            return true;
    end case;

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
        when 'monthly_digest_generate', 'monthly_digest_verify' then
            v_allowed_keys := array['error_code', 'target_year_month', 'source_event_at'];
        when 'archive_export' then
            v_allowed_keys := array['archive_key', 'digest_hash', 'target_year_month', 'error_code', 'source_event_at'];
        when 'digest_timestamping' then
            v_allowed_keys := array['digest_hash', 'timestamp_token_hash', 'target_year_month', 'error_code', 'source_event_at'];
        when 'siem_forward_failure' then
            v_allowed_keys := array['error_code', 'event_type', 'event_count', 'source_event_at'];
        when 'audit_report_generate' then
            v_allowed_keys := array['error_code', 'format', 'period_end', 'period_start', 'source_event_at'];
        when 'scheduler_job' then
            v_allowed_keys := array['duration_ms', 'error_code', 'job_name', 'target_year_month', 'trigger', 'source_event_at'];
        when 'incident_detected' then
            v_allowed_keys := array[
                'incident_type',
                'severity',
                'detection_source',
                'dedupe_key',
                'notification_sink',
                'notification_result',
                'error_code',
                'source_event_at',
                'source_event_id',
                'target_sequence_no',
                'target_year_month'
            ];
        else
            return true;
    end case;

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
is 'Returns true when audit metadata contains a key outside the allowlist for the given action. Updated in T14 to include incident_detected.';

create or replace function public.audit_metadata_has_invalid_value_for_action(
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
    v_val jsonb;
    v_text text;
begin
    if jsonb_typeof(p_metadata_json) <> 'object' then
        return true;
    end if;

    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        continue when not v_key = any(array[
            'checked_secret_count',
            'checked_secret_version_count',
            'checked_audit_event_count',
            'duration_ms',
            'violation_count',
            'sample_count',
            'processed_count',
            'remaining_count',
            'event_count'
        ]);

        v_val := p_metadata_json -> v_key;
        if jsonb_typeof(v_val) <> 'number' or v_val::text !~ '^(0|[1-9][0-9]*)$' then
            return true;
        end if;
    end loop;

    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        continue when not v_key = any(array[
            'version',
            'old_key_version',
            'new_key_version',
            'failed_version',
            'batch_size',
            'target_sequence_no'
        ]);

        v_val := p_metadata_json -> v_key;
        if v_key = 'failed_version' and v_val = 'null'::jsonb then
            continue;
        end if;
        if jsonb_typeof(v_val) <> 'number' or v_val::text !~ '^[1-9][0-9]*$' then
            return true;
        end if;
    end loop;

    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        continue when not v_key = any(array[
            'secret_version_id',
            'attempted_secret_id',
            'source_event_id'
        ]);

        v_val := p_metadata_json -> v_key;
        if jsonb_typeof(v_val) <> 'string' then
            return true;
        end if;
        v_text := p_metadata_json ->> v_key;
        if v_text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
            return true;
        end if;
    end loop;

    if p_metadata_json ? 'attempted_secret_id'
        and not (p_action = 'decrypt' and p_result = 'failure')
    then
        return true;
    end if;

    if p_metadata_json ? 'source_event_id' and p_action <> 'incident_detected' then
        return true;
    end if;

    if p_metadata_json ? 'error_code' then
        if p_result <> 'failure'
            or jsonb_typeof(p_metadata_json -> 'error_code') <> 'string'
        then
            return true;
        end if;
        v_text := p_metadata_json ->> 'error_code';
        if btrim(v_text) = '' or length(v_text) > 64 then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'job_name' then
        if jsonb_typeof(p_metadata_json -> 'job_name') <> 'string' then
            return true;
        end if;
        v_text := p_metadata_json ->> 'job_name';
        if btrim(v_text) = '' or length(v_text) > 96 then
            return true;
        end if;
    end if;

    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        continue when not v_key = any(array[
            'detection_source',
            'dedupe_key',
            'notification_sink'
        ]);

        v_val := p_metadata_json -> v_key;
        if jsonb_typeof(v_val) <> 'string' then
            return true;
        end if;
        v_text := v_val #>> '{}';
        if btrim(v_text) = '' or length(v_text) > 128 then
            return true;
        end if;
    end loop;

    if p_metadata_json ? 'incident_type' then
        if jsonb_typeof(p_metadata_json -> 'incident_type') <> 'string'
            or not public.incident_type_allowed(p_metadata_json ->> 'incident_type')
        then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'severity' then
        if jsonb_typeof(p_metadata_json -> 'severity') <> 'string'
            or not public.incident_severity_allowed(p_metadata_json ->> 'severity')
        then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'notification_result' then
        if jsonb_typeof(p_metadata_json -> 'notification_result') <> 'string'
            or not public.incident_notification_result_allowed(p_metadata_json ->> 'notification_result')
        then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'target_year_month' then
        if jsonb_typeof(p_metadata_json -> 'target_year_month') <> 'string' then
            return true;
        end if;
        v_text := p_metadata_json ->> 'target_year_month';
        if v_text !~ '^\d{4}-(0[1-9]|1[0-2])$' then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'format' then
        if jsonb_typeof(p_metadata_json -> 'format') <> 'string'
            or p_metadata_json ->> 'format' not in ('json', 'markdown')
        then
            return true;
        end if;
    end if;

    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        continue when not v_key = any(array['period_start', 'period_end']);

        v_val := p_metadata_json -> v_key;
        if jsonb_typeof(v_val) <> 'string'
            or not public.audit_metadata_source_event_at_is_valid(
                jsonb_build_object('source_event_at', v_val #>> '{}')
            )
        then
            return true;
        end if;
    end loop;

    if p_metadata_json ? 'archive_key' then
        if p_result = 'failure'
            or jsonb_typeof(p_metadata_json -> 'archive_key') <> 'string'
        then
            return true;
        end if;
        v_text := p_metadata_json ->> 'archive_key';
        if btrim(v_text) = '' or length(v_text) > 256 then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'check_name' then
        if jsonb_typeof(p_metadata_json -> 'check_name') <> 'string'
            or p_metadata_json ->> 'check_name' <> 'mvp_integrity_check'
        then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'phase' then
        if jsonb_typeof(p_metadata_json -> 'phase') <> 'string'
            or p_metadata_json ->> 'phase' <> 'verify'
        then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'reason' then
        if jsonb_typeof(p_metadata_json -> 'reason') <> 'string'
            or p_metadata_json ->> 'reason' <> 'no_current_secret_versions'
        then
            return true;
        end if;
    end if;

    if p_result = 'success' and p_metadata_json ? 'failed_version' then
        return true;
    end if;

    if p_metadata_json ? 'trigger' then
        if jsonb_typeof(p_metadata_json -> 'trigger') <> 'string' then
            return true;
        end if;
        if p_metadata_json ->> 'trigger' not in ('startup', 'background', 'cli') then
            return true;
        end if;
    end if;

    if p_action = 'integrity_check' and p_metadata_json ? 'violation_summary' then
        if jsonb_typeof(p_metadata_json -> 'violation_summary') <> 'object' then
            return true;
        end if;

        for v_key, v_val in select * from jsonb_each(p_metadata_json -> 'violation_summary')
        loop
            if jsonb_typeof(v_val) <> 'number' or v_val::text !~ '^(0|[1-9][0-9]*)$' then
                return true;
            end if;
        end loop;
    end if;

    return false;
end;
$$;

comment on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) is
    'Returns true if metadata_json contains invalid values per action schema. Updated in T14 to validate incident_detected metadata.';

create or replace function public.ledger_entry_type_allowed(p_entry_type text)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select p_entry_type in (
        'secret_created',
        'secret_version_created',
        'secret_decrypted',
        'secret_version_purged',
        'integrity_check_completed',
        'restore_test_completed',
        'key_rotation_started',
        'key_rotation_reencrypted',
        'key_rotation_completed',
        'key_rotation_aborted',
        'ledger_verified',
        'ledger_verification_failed',
        'audit_fallback_resent',
        'monthly_digest',
        'archive_exported',
        'digest_timestamped',
        'scheduler_job_completed',
        'incident_detected'
    );
$$;

create or replace function public.ledger_payload_allowed_keys(p_entry_type text)
returns text[]
language sql
stable
set search_path = public, pg_temp
as $$
    select case p_entry_type
        when 'secret_created' then array['algorithm', 'classification', 'key_version', 'version']::text[]
        when 'secret_version_created' then array['algorithm', 'classification', 'key_version', 'version']::text[]
        when 'secret_decrypted' then array['algorithm', 'key_version', 'version']::text[]
        when 'secret_version_purged' then array['key_version', 'retention_limit', 'version']::text[]
        when 'integrity_check_completed' then array['checked_audit_event_count', 'checked_secret_count', 'checked_secret_version_count', 'duration_ms', 'violation_count']::text[]
        when 'restore_test_completed' then array['duration_ms', 'failure_count', 'sample_count', 'success_count', 'trigger']::text[]
        when 'key_rotation_started' then array['new_key_version', 'old_key_version']::text[]
        when 'key_rotation_reencrypted' then array['batch_size', 'new_key_version', 'old_key_version', 'processed_count', 'remaining_count']::text[]
        when 'key_rotation_completed' then array['new_key_version', 'old_key_version', 'remaining_count']::text[]
        when 'key_rotation_aborted' then array['new_key_version', 'old_key_version', 'reason_code']::text[]
        when 'ledger_verified' then array['checked_count', 'duration_ms', 'end_sequence_no', 'start_sequence_no']::text[]
        when 'ledger_verification_failed' then array['end_sequence_no', 'error_code', 'failed_count', 'start_sequence_no']::text[]
        when 'audit_fallback_resent' then array['duration_ms', 'failed_count', 'resent_count']::text[]
        when 'monthly_digest' then array['digest_hash', 'end_sequence_no', 'entry_count', 'start_sequence_no', 'target_year_month']::text[]
        when 'archive_exported' then array['archive_key', 'digest_hash', 'target_year_month']::text[]
        when 'digest_timestamped' then array['digest_hash', 'target_year_month', 'timestamp_token_hash']::text[]
        when 'scheduler_job_completed' then array['duration_ms', 'job_name', 'target_year_month', 'trigger']::text[]
        when 'incident_detected' then array['dedupe_key', 'detection_source', 'incident_type', 'notification_result', 'notification_sink', 'severity', 'target_sequence_no', 'target_year_month']::text[]
        else null::text[]
    end;
$$;

create or replace function public.ledger_payload_schema_is_valid(
    p_entry_type text,
    p_payload jsonb
)
returns boolean
language plpgsql
stable
set search_path = public, pg_temp
as $$
declare
    v_key text;
    v_value jsonb;
    v_text text;
    v_integer bigint;
    v_old_key_version bigint;
    v_new_key_version bigint;
begin
    if p_payload is null or jsonb_typeof(p_payload) <> 'object' then
        return false;
    end if;

    if not public.ledger_entry_type_allowed(p_entry_type) then
        return false;
    end if;

    if public.ledger_payload_has_unknown_key(p_entry_type, p_payload) then
        return false;
    end if;

    if exists (
        select 1
        from jsonb_each(p_payload) as fields(key, value)
        where jsonb_typeof(fields.value) in ('object', 'array')
    ) then
        return false;
    end if;

    if p_entry_type = 'incident_detected'
        and not (
            p_payload ?& array[
                'incident_type',
                'severity',
                'detection_source',
                'dedupe_key',
                'notification_sink',
                'notification_result'
            ]
        )
    then
        return false;
    end if;

    for v_key, v_value in
        select fields.key, fields.value
        from jsonb_each(p_payload) as fields(key, value)
    loop
        if v_key in ('version', 'key_version', 'old_key_version', 'new_key_version', 'retention_limit', 'start_sequence_no', 'end_sequence_no', 'target_sequence_no') then
            if jsonb_typeof(v_value) <> 'number' or (v_value #>> '{}') !~ '^[0-9]+$' then
                return false;
            end if;
            v_integer := (v_value #>> '{}')::bigint;
            if v_integer <= 0 then
                return false;
            end if;
            if v_key = 'retention_limit' and v_integer <> 4 then
                return false;
            end if;
        elsif v_key in ('batch_size', 'checked_audit_event_count', 'checked_count', 'checked_secret_count', 'checked_secret_version_count', 'duration_ms', 'entry_count', 'failed_count', 'failure_count', 'processed_count', 'remaining_count', 'resent_count', 'sample_count', 'success_count', 'violation_count') then
            if jsonb_typeof(v_value) <> 'number' or (v_value #>> '{}') !~ '^[0-9]+$' then
                return false;
            end if;
            v_integer := (v_value #>> '{}')::bigint;
            if v_integer < 0 then
                return false;
            end if;
        elsif v_key = 'algorithm' then
            if jsonb_typeof(v_value) <> 'string' or v_value #>> '{}' <> 'xchacha20-poly1305' then
                return false;
            end if;
        elsif v_key = 'classification' then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;
            v_text := v_value #>> '{}';
            if btrim(v_text) = '' or length(v_text) > 128 then
                return false;
            end if;
        elsif v_key = 'trigger' then
            if jsonb_typeof(v_value) <> 'string' or (v_value #>> '{}') not in ('background', 'cli', 'scheduled', 'startup') then
                return false;
            end if;
        elsif v_key in ('error_code', 'reason_code', 'archive_key', 'job_name') then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;
            v_text := v_value #>> '{}';
            if btrim(v_text) = '' or length(v_text) > 128 then
                return false;
            end if;
        elsif v_key in ('detection_source', 'dedupe_key', 'notification_sink') then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;
            v_text := v_value #>> '{}';
            if btrim(v_text) = '' or length(v_text) > 128 then
                return false;
            end if;
        elsif v_key = 'incident_type' then
            if jsonb_typeof(v_value) <> 'string' or not public.incident_type_allowed(v_value #>> '{}') then
                return false;
            end if;
        elsif v_key = 'severity' then
            if jsonb_typeof(v_value) <> 'string' or not public.incident_severity_allowed(v_value #>> '{}') then
                return false;
            end if;
        elsif v_key = 'notification_result' then
            if jsonb_typeof(v_value) <> 'string' or not public.incident_notification_result_allowed(v_value #>> '{}') then
                return false;
            end if;
        elsif v_key in ('digest_hash', 'timestamp_token_hash') then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;
            v_text := v_value #>> '{}';
            if v_text !~ '^[0-9a-f]{64}$' then
                return false;
            end if;
        elsif v_key = 'target_year_month' then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;
            v_text := v_value #>> '{}';
            if v_text !~ '^\d{4}-(0[1-9]|1[0-2])$' then
                return false;
            end if;
        else
            return false;
        end if;
    end loop;

    if p_payload ? 'old_key_version' and p_payload ? 'new_key_version' then
        v_old_key_version := (p_payload ->> 'old_key_version')::bigint;
        v_new_key_version := (p_payload ->> 'new_key_version')::bigint;
        if v_old_key_version = v_new_key_version then
            return false;
        end if;
    end if;

    return true;
exception
    when numeric_value_out_of_range then
        return false;
end;
$$;

comment on function public.ledger_payload_schema_is_valid(text, jsonb)
is 'Validates type, length, vocabulary, and numeric range for ledger payload fields. Updated in T14 to add incident_detected.';

create or replace function public.rpc_append_audit_event_with_ledger(
    p_audit_event_id uuid,
    p_request_id uuid,
    p_actor_user_id uuid default null,
    p_actor_device_id text default null,
    p_action text default null,
    p_target_secret_id uuid default null,
    p_result text default null,
    p_key_version integer default null,
    p_metadata_json jsonb default '{}'::jsonb,
    p_ledger_entry_id uuid default null,
    p_sequence_no bigint default null,
    p_entry_type text default null,
    p_source_event_at text default null,
    p_source_event_id uuid default null,
    p_target_secret_version_id uuid default null,
    p_error_code text default null,
    p_payload jsonb default '{}'::jsonb,
    p_canonicalization_version integer default null,
    p_previous_entry_hash bytea default null,
    p_entry_hash bytea default null,
    p_hash_algorithm text default null,
    p_signature bytea default null,
    p_signature_algorithm text default null,
    p_signature_key_version integer default null
)
returns table (
    ledger_entry_id uuid,
    sequence_no bigint,
    entry_hash bytea,
    chain_last_sequence_no bigint,
    chain_last_entry_hash bytea,
    replayed boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if p_audit_event_id is null
        or p_request_id is null
        or p_action is null
        or p_result is null
        or p_source_event_id is distinct from p_audit_event_id
        or p_source_event_at is null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_source_event_at is distinct from p_metadata_json ->> 'source_event_at' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if (p_action = 'decrypt' and p_entry_type <> 'secret_decrypted')
        or (p_action = 'restore_test' and p_entry_type <> 'restore_test_completed')
        or (p_action = 'integrity_check' and p_entry_type <> 'integrity_check_completed')
        or (p_action = 'key_rotation_start' and p_entry_type <> 'key_rotation_started')
        or (p_action = 'key_rotation_reencrypt' and p_entry_type <> 'key_rotation_reencrypted')
        or (p_action = 'key_rotation_complete' and p_entry_type <> 'key_rotation_completed')
        or (p_action = 'incident_detected' and p_entry_type <> 'incident_detected')
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    perform public.rpc_append_audit_event(
        p_audit_event_id,
        p_request_id,
        p_actor_user_id,
        p_actor_device_id,
        p_action,
        p_target_secret_id,
        p_result,
        p_key_version,
        p_metadata_json
    );

    return query
    select *
    from public.rpc_append_ledger_entry(
        p_ledger_entry_id,
        p_sequence_no,
        p_entry_type,
        p_source_event_at,
        p_request_id,
        p_source_event_id,
        p_target_secret_id,
        p_target_secret_version_id,
        p_actor_user_id,
        p_actor_device_id,
        p_result,
        p_error_code,
        p_payload,
        p_canonicalization_version,
        p_previous_entry_hash,
        p_entry_hash,
        p_hash_algorithm,
        p_signature,
        p_signature_algorithm,
        p_signature_key_version
    );
end;
$$;

comment on function public.rpc_append_audit_event_with_ledger(
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb,
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) is
    'Appends a non-write-path audit event and its signed Ledger Phase 1 entry in one transaction. Updated in T14 for incident_detected.';

create or replace function public.rpc_record_incident(
    p_audit_event_id uuid,
    p_request_id uuid,
    p_incident_type text,
    p_severity text,
    p_detection_source text,
    p_dedupe_key text,
    p_notification_sink text,
    p_notification_result text,
    p_error_code text,
    p_source_event_at text,
    p_ledger_entry jsonb,
    p_incident_source_event_id uuid default null,
    p_target_sequence_no bigint default null,
    p_target_year_month text default null,
    p_dedupe_window_seconds integer default 3600
)
returns table (
    audit_event_id uuid,
    ledger_entry_id uuid,
    suppressed boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_metadata_json jsonb;
    v_expected_payload jsonb;
    v_ledger_payload jsonb;
    v_ledger_entry_id uuid;
    v_suppressed boolean;
begin
    if p_audit_event_id is null
        or p_request_id is null
        or p_incident_type is null
        or p_severity is null
        or p_detection_source is null
        or p_dedupe_key is null
        or p_notification_sink is null
        or p_notification_result is null
        or p_error_code is null
        or p_source_event_at is null
        or p_ledger_entry is null
        or p_dedupe_window_seconds is null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if jsonb_typeof(p_ledger_entry) <> 'object' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if not public.incident_type_allowed(p_incident_type)
        or not public.incident_severity_allowed(p_severity)
        or not public.incident_notification_result_allowed(p_notification_result)
        or not public.audit_metadata_source_event_at_is_valid(
            jsonb_build_object('source_event_at', p_source_event_at)
        )
        or p_target_sequence_no is not null and p_target_sequence_no <= 0
        or p_dedupe_window_seconds < 1
        or p_dedupe_window_seconds > 604800
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if btrim(p_detection_source) = ''
        or length(p_detection_source) > 128
        or btrim(p_dedupe_key) = ''
        or length(p_dedupe_key) > 128
        or btrim(p_notification_sink) = ''
        or length(p_notification_sink) > 128
        or btrim(p_error_code) = ''
        or length(p_error_code) > 64
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_target_year_month is not null
        and p_target_year_month !~ '^\d{4}-(0[1-9]|1[0-2])$'
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    v_metadata_json := jsonb_build_object(
        'incident_type', p_incident_type,
        'severity', p_severity,
        'detection_source', p_detection_source,
        'dedupe_key', p_dedupe_key,
        'notification_sink', p_notification_sink,
        'notification_result', p_notification_result,
        'error_code', p_error_code,
        'source_event_at', p_source_event_at
    );

    v_expected_payload := jsonb_build_object(
        'incident_type', p_incident_type,
        'severity', p_severity,
        'detection_source', p_detection_source,
        'dedupe_key', p_dedupe_key,
        'notification_sink', p_notification_sink,
        'notification_result', p_notification_result
    );

    if p_incident_source_event_id is not null then
        v_metadata_json := v_metadata_json || jsonb_build_object(
            'source_event_id',
            p_incident_source_event_id::text
        );
    end if;

    if p_target_sequence_no is not null then
        v_metadata_json := v_metadata_json || jsonb_build_object(
            'target_sequence_no',
            p_target_sequence_no
        );
        v_expected_payload := v_expected_payload || jsonb_build_object(
            'target_sequence_no',
            p_target_sequence_no
        );
    end if;

    if p_target_year_month is not null then
        v_metadata_json := v_metadata_json || jsonb_build_object(
            'target_year_month',
            p_target_year_month
        );
        v_expected_payload := v_expected_payload || jsonb_build_object(
            'target_year_month',
            p_target_year_month
        );
    end if;

    if public.audit_metadata_has_forbidden_key(v_metadata_json)
        or public.audit_metadata_has_schema_violation_for_action(
            'incident_detected',
            'failure',
            v_metadata_json,
            true
        )
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    v_ledger_payload := p_ledger_entry -> 'p_payload';
    v_ledger_entry_id := (p_ledger_entry ->> 'p_ledger_entry_id')::uuid;

    if public.ledger_payload_has_forbidden_key(p_ledger_entry)
        or exists (
            select 1
            from jsonb_object_keys(p_ledger_entry) as keys(key)
            where keys.key <> all(array[
                'p_ledger_entry_id',
                'p_sequence_no',
                'p_entry_type',
                'p_source_event_at',
                'p_request_id',
                'p_source_event_id',
                'p_target_secret_id',
                'p_target_secret_version_id',
                'p_actor_user_id',
                'p_actor_device_id',
                'p_result',
                'p_error_code',
                'p_payload',
                'p_canonicalization_version',
                'p_previous_entry_hash',
                'p_entry_hash',
                'p_hash_algorithm',
                'p_signature',
                'p_signature_algorithm',
                'p_signature_key_version'
            ])
        )
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if v_ledger_entry_id is null
        or coalesce((p_ledger_entry ->> 'p_sequence_no')::bigint <= 0, true)
        or p_ledger_entry ->> 'p_entry_type' is distinct from 'incident_detected'
        or p_ledger_entry ->> 'p_source_event_at' is distinct from p_source_event_at
        or (p_ledger_entry ->> 'p_request_id')::uuid is distinct from p_request_id
        or nullif(p_ledger_entry ->> 'p_source_event_id', '')::uuid is distinct from p_audit_event_id
        or p_ledger_entry ->> 'p_result' is distinct from 'failure'
        or nullif(p_ledger_entry ->> 'p_error_code', '') is distinct from p_error_code
        or v_ledger_payload is distinct from v_expected_payload
        or (p_ledger_entry ->> 'p_canonicalization_version')::integer is distinct from 1
        or octet_length(decode(substr(p_ledger_entry ->> 'p_previous_entry_hash', 3), 'hex')) is distinct from 32
        or octet_length(decode(substr(p_ledger_entry ->> 'p_entry_hash', 3), 'hex')) is distinct from 32
        or p_ledger_entry ->> 'p_hash_algorithm' is distinct from 'sha-256'
        or octet_length(decode(substr(p_ledger_entry ->> 'p_signature', 3), 'hex')) is distinct from 64
        or p_ledger_entry ->> 'p_signature_algorithm' is distinct from 'ed25519'
        or coalesce((p_ledger_entry ->> 'p_signature_key_version')::integer <= 0, true)
        or not public.ledger_payload_is_valid('incident_detected', v_ledger_payload)
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    perform pg_advisory_xact_lock(hashtextextended(
        'incident_detected:' || p_incident_type || ':' || p_dedupe_key,
        0
    ));

    select exists (
        select 1
        from public.audit_events ae
        where ae.id <> p_audit_event_id
            and ae.action = 'incident_detected'
            and ae.result = 'failure'
            and ae.metadata_json ->> 'incident_type' = p_incident_type
            and ae.metadata_json ->> 'dedupe_key' = p_dedupe_key
            and (ae.metadata_json ->> 'source_event_at')::timestamptz
                >= p_source_event_at::timestamptz - make_interval(secs => p_dedupe_window_seconds)
    )
    into v_suppressed;

    if v_suppressed then
        audit_event_id := p_audit_event_id;
        ledger_entry_id := null;
        suppressed := true;
        return next;
        return;
    end if;

    perform public.rpc_append_audit_event(
        p_audit_event_id,
        p_request_id,
        null,
        null,
        'incident_detected',
        null,
        'failure',
        null,
        v_metadata_json
    );

    select appended.ledger_entry_id
    into v_ledger_entry_id
    from public.rpc_append_ledger_entry_from_jsonb(p_ledger_entry) as appended;

    audit_event_id := p_audit_event_id;
    ledger_entry_id := v_ledger_entry_id;
    suppressed := false;
    return next;
exception
    when invalid_text_representation
        or invalid_parameter_value
        or numeric_value_out_of_range
        or null_value_not_allowed
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
end;
$$;

comment on function public.rpc_record_incident(
    uuid,
    uuid,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    jsonb,
    uuid,
    bigint,
    text,
    integer
) is
    'Records a T14 incident detection as failure-only audit_events and incident_detected ledger_entries rows with debounce. Notification delivery itself remains outside this SQL RPC.';

create or replace function public.rpc_incident_recently_seen(
    p_incident_type text,
    p_dedupe_key text,
    p_source_event_at text,
    p_dedupe_window_seconds integer default 3600
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if p_incident_type is null
        or p_dedupe_key is null
        or p_source_event_at is null
        or p_dedupe_window_seconds is null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if not public.incident_type_allowed(p_incident_type)
        or not public.audit_metadata_source_event_at_is_valid(
            jsonb_build_object('source_event_at', p_source_event_at)
        )
        or p_dedupe_window_seconds < 1
        or p_dedupe_window_seconds > 604800
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if btrim(p_dedupe_key) = '' or length(p_dedupe_key) > 128 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return exists (
        select 1
        from public.audit_events ae
        where ae.action = 'incident_detected'
            and ae.result = 'failure'
            and ae.metadata_json ->> 'incident_type' = p_incident_type
            and ae.metadata_json ->> 'dedupe_key' = p_dedupe_key
            and (ae.metadata_json ->> 'source_event_at')::timestamptz
                >= p_source_event_at::timestamptz - make_interval(secs => p_dedupe_window_seconds)
    );
exception
    when invalid_text_representation
        or invalid_parameter_value
        or numeric_value_out_of_range
        or null_value_not_allowed
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
end;
$$;

comment on function public.rpc_incident_recently_seen(text, text, text, integer) is
    'Checks T14 incident debounce state before external notification delivery. Returns only a boolean and exposes no incident payload.';

revoke execute on function public.incident_type_allowed(text) from public, anon, authenticated;
revoke execute on function public.incident_severity_allowed(text) from public, anon, authenticated;
revoke execute on function public.incident_notification_result_allowed(text) from public, anon, authenticated;

revoke execute on function public.rpc_record_incident(
    uuid,
    uuid,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    jsonb,
    uuid,
    bigint,
    text,
    integer
) from public, anon, authenticated;
revoke execute on function public.rpc_record_incident(
    uuid,
    uuid,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    jsonb,
    uuid,
    bigint,
    text,
    integer
) from public;
revoke execute on function public.rpc_incident_recently_seen(text, text, text, integer) from public, anon, authenticated;
revoke execute on function public.rpc_incident_recently_seen(text, text, text, integer) from public;
grant execute on function public.rpc_record_incident(
    uuid,
    uuid,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    jsonb,
    uuid,
    bigint,
    text,
    integer
) to service_role;
grant execute on function public.rpc_incident_recently_seen(text, text, text, integer) to service_role;

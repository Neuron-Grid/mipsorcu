-- Section 1210: extend audit actions for encrypted secret aliases

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
            'signature_key_created',
            'signature_key_activated',
            'signature_key_retired',
            'monthly_digest_generate',
            'monthly_digest_verify',
            'archive_export',
            'digest_timestamping',
            'siem_forward_failure',
            'audit_report_generate',
            'scheduler_job',
            'incident_detected',
            'secret_alias_create',
            'secret_alias_update',
            'secret_alias_delete',
            'secret_alias_list'
        )
    );

-- Keep the forbidden-key marker in the latest audit metadata migration so
-- Rust/SQL parity tests can use this file as the single current SQL source.
-- FORBIDDEN_AUDIT_METADATA_KEYS_START
-- 'authorization'
-- 'authorization_header'
-- 'bearer_token'
-- 'ciphertext'
-- 'data_key'
-- 'decrypt_result'
-- 'decrypted'
-- 'decrypted_data'
-- 'encrypted_data_key'
-- 'jwt'
-- 'jwt_full'
-- 'master_key'
-- 'passphrase'
-- 'password'
-- 'plain_text'
-- 'plaintext'
-- 'raw_jwt'
-- 'request_body'
-- 'request_body_full'
-- 'response_body'
-- 'response_body_full'
-- 'secret_key'
-- 'secret_value'
-- 'service_role'
-- 'service_role_key'
-- 'token'
-- FORBIDDEN_AUDIT_METADATA_KEYS_END

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
        when 'signature_key_created' then
            v_required_keys := array['signature_key_version', 'public_key_fingerprint', 'created_at'];
        when 'signature_key_activated' then
            v_required_keys := array['signature_key_version', 'public_key_fingerprint', 'activated_at'];
        when 'signature_key_retired' then
            v_required_keys := array['signature_key_version', 'public_key_fingerprint', 'retired_at'];
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
            v_required_keys := array['incident_type', 'severity', 'detection_source', 'dedupe_key', 'notification_sink', 'notification_result', 'error_code'];
        when 'secret_alias_create' then
            v_required_keys := array['alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version'];
        when 'secret_alias_update' then
            v_required_keys := array['old_alias_fingerprint', 'new_alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version'];
        when 'secret_alias_delete' then
            v_required_keys := array['alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version'];
        when 'secret_alias_list' then
            v_required_keys := array['result_count'];
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
        when 'signature_key_created' then
            v_allowed_keys := array['created_at', 'public_key_fingerprint', 'signature_key_version', 'source_event_at'];
        when 'signature_key_activated' then
            v_allowed_keys := array['activated_at', 'public_key_fingerprint', 'signature_key_version', 'source_event_at'];
        when 'signature_key_retired' then
            v_allowed_keys := array['public_key_fingerprint', 'retired_at', 'signature_key_version', 'source_event_at'];
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
            v_allowed_keys := array['incident_type', 'severity', 'detection_source', 'dedupe_key', 'notification_sink', 'notification_result', 'error_code', 'source_event_at', 'source_event_id', 'target_sequence_no', 'target_year_month'];
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
is 'Returns true when audit metadata contains a key outside the allowlist for the given action. Extended for encrypted secret alias actions.';

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

    for v_key, v_val in
        select fields.key, fields.value
        from jsonb_each(p_metadata_json) as fields(key, value)
    loop
        if v_key in ('version', 'old_key_version', 'new_key_version', 'batch_size', 'target_sequence_no', 'signature_key_version', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version') then
            if jsonb_typeof(v_val) <> 'number' or (v_val #>> '{}') !~ '^[0-9]+$' or (v_val #>> '{}')::bigint <= 0 then
                return true;
            end if;
        elsif v_key in ('checked_secret_count', 'checked_secret_version_count', 'checked_audit_event_count', 'duration_ms', 'violation_count', 'sample_count', 'processed_count', 'remaining_count', 'event_count', 'result_count') then
            if jsonb_typeof(v_val) <> 'number' or (v_val #>> '{}') !~ '^[0-9]+$' then
                return true;
            end if;
        elsif v_key = 'error_code' then
            if p_result <> 'failure' or jsonb_typeof(v_val) <> 'string' or btrim(v_val #>> '{}') = '' or length(v_val #>> '{}') > 64 then
                return true;
            end if;
        elsif v_key in ('source_event_at', 'created_at', 'activated_at', 'retired_at', 'period_start', 'period_end') then
            if jsonb_typeof(v_val) <> 'string' or not public.audit_metadata_source_event_at_is_valid(jsonb_build_object('source_event_at', v_val #>> '{}')) then
                return true;
            end if;
        elsif v_key in ('public_key_fingerprint', 'digest_hash', 'timestamp_token_hash', 'alias_fingerprint', 'old_alias_fingerprint', 'new_alias_fingerprint') then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') !~ '^[0-9a-f]{64}$' then
                return true;
            end if;
        elsif v_key in ('secret_version_id', 'attempted_secret_id') then
            if v_key = 'attempted_secret_id'
                and not (p_action = 'decrypt' and p_result = 'failure') then
                return true;
            end if;
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') !~ '^[0-9a-fA-F-]{36}$' then
                return true;
            end if;
        elsif v_key = 'source_event_id' then
            if p_action <> 'incident_detected' or jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') !~ '^[0-9a-fA-F-]{36}$' then
                return true;
            end if;
        elsif v_key = 'trigger' then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') not in ('background', 'cli', 'startup') then
                return true;
            end if;
        elsif v_key in ('job_name', 'event_type', 'detection_source', 'dedupe_key', 'notification_sink') then
            if jsonb_typeof(v_val) <> 'string' or btrim(v_val #>> '{}') = '' or length(v_val #>> '{}') > 128 then
                return true;
            end if;
        elsif v_key = 'target_year_month' then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') !~ '^\d{4}-(0[1-9]|1[0-2])$' then
                return true;
            end if;
        elsif v_key = 'format' then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') not in ('json', 'markdown') then
                return true;
            end if;
        elsif v_key = 'check_name' then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') <> 'mvp_integrity_check' then
                return true;
            end if;
        elsif v_key = 'phase' then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') <> 'verify' then
                return true;
            end if;
        elsif v_key = 'reason' then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') <> 'no_current_secret_versions' then
                return true;
            end if;
        elsif v_key = 'failed_version' then
            if p_result = 'success' then
                return true;
            end if;
            if v_val <> 'null'::jsonb and (jsonb_typeof(v_val) <> 'number' or (v_val #>> '{}') !~ '^[0-9]+$' or (v_val #>> '{}')::bigint <= 0) then
                return true;
            end if;
        elsif v_key = 'archive_key' then
            if p_result = 'failure' or jsonb_typeof(v_val) <> 'string' or btrim(v_val #>> '{}') = '' or length(v_val #>> '{}') > 256 then
                return true;
            end if;
        elsif v_key = 'incident_type' then
            if jsonb_typeof(v_val) <> 'string' or not public.incident_type_allowed(v_val #>> '{}') then
                return true;
            end if;
        elsif v_key = 'severity' then
            if jsonb_typeof(v_val) <> 'string' or not public.incident_severity_allowed(v_val #>> '{}') then
                return true;
            end if;
        elsif v_key = 'notification_result' then
            if jsonb_typeof(v_val) <> 'string' or not public.incident_notification_result_allowed(v_val #>> '{}') then
                return true;
            end if;
        elsif v_key = 'violation_summary' then
            if jsonb_typeof(v_val) <> 'object' then
                return true;
            end if;
        end if;
    end loop;

    return false;
exception
    when numeric_value_out_of_range then
        return true;
end;
$$;

comment on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) is
    'Returns true if metadata_json contains invalid values per action schema. Extended for encrypted secret alias actions.';

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
        'signature_key_created',
        'signature_key_activated',
        'signature_key_retired',
        'monthly_digest_generate',
        'monthly_digest_verify',
        'archive_export',
        'digest_timestamping',
        'siem_forward_failure',
        'audit_report_generate',
        'scheduler_job',
        'incident_detected',
        'secret_alias_create',
        'secret_alias_update',
        'secret_alias_delete',
        'secret_alias_list'
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

    if p_action in ('signature_key_created', 'signature_key_activated', 'signature_key_retired')
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
    'Audit append RPC for non-write-path audit events and failure events. Extended for encrypted secret alias actions.';

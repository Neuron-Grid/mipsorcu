-- T13: 定期実行スケジューラの audit / ledger 記録サポート。
--
-- 信頼境界: scheduler metadata / ledger payload は非秘密の job 名、期間、duration、
-- error_code のみに限定する。平文・鍵・JWT・Authorization header は含めない。
--
-- FORBIDDEN_AUDIT_METADATA_KEYS_START
-- 'authorization', 'authorization_header', 'bearer_token', 'ciphertext',
-- 'data_key', 'decrypt_result', 'decrypted', 'decrypted_data',
-- 'encrypted_data_key', 'jwt', 'jwt_full', 'master_key', 'passphrase',
-- 'password', 'plain_text', 'plaintext', 'raw_jwt', 'request_body',
-- 'request_body_full', 'response_body', 'response_body_full', 'secret_key',
-- 'secret_value', 'service_role', 'service_role_key', 'token'
-- FORBIDDEN_AUDIT_METADATA_KEYS_END

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. audit_events.action に scheduler_job を追加
-- ─────────────────────────────────────────────────────────────────────────────

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
            'scheduler_job'
        )
    );

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. rpc_append_audit_event の action allowlist を更新
-- ─────────────────────────────────────────────────────────────────────────────

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
        'scheduler_job'
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

    if p_action in ('auth_failure', 'siem_forward_failure') and p_result <> 'failure' then
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
    'Audit append RPC for non-write-path audit events and failure events. Updated in T13 to add scheduler_job action.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. audit metadata allowlist / required keys に scheduler_job を追加
-- ─────────────────────────────────────────────────────────────────────────────

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
is 'Returns true when audit metadata contains a key outside the allowlist for the given action. Updated in T13 to include scheduler_job.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. ledger entry_type / payload allowlist に scheduler_job_completed を追加
-- ─────────────────────────────────────────────────────────────────────────────

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
        'scheduler_job_completed'
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

    for v_key, v_value in
        select fields.key, fields.value
        from jsonb_each(p_payload) as fields(key, value)
    loop
        if v_key in ('version', 'key_version', 'old_key_version', 'new_key_version', 'retention_limit', 'start_sequence_no', 'end_sequence_no') then
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
is 'Validates type, length, vocabulary, and numeric range for ledger payload fields. Updated in T13 to add scheduler_job_completed.';

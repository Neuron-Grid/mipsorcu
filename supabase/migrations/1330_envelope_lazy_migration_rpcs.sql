-- Task 07: lazy migration from legacy encrypted_data_key rows to v0.2 envelope rows.
-- The trusted SBC performs all plaintext/DEK handling; these RPCs only move
-- ciphertext, nonce, wrapped DEK, and non-secret audit/ledger metadata.

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
            'audit_report_generate',
            'audit_ui_read',
            'scheduler_job',
            'incident_detected',
            'secret_alias_create',
            'secret_alias_update',
            'secret_alias_delete',
            'secret_alias_list'
        )
    ),
    drop constraint if exists audit_events_key_rotation_envelope_migrated_success_only,
    add constraint audit_events_key_rotation_envelope_migrated_success_only check (
        action <> 'key_rotation_envelope_migrated' or result = 'success'
    ),
    drop constraint if exists audit_events_key_rotation_envelope_failed_failure_only,
    add constraint audit_events_key_rotation_envelope_failed_failure_only check (
        action <> 'key_rotation_envelope_failed' or result = 'failure'
    );

drop function if exists public.audit_metadata_has_missing_required_key_for_action_before_1330(text, text, jsonb, boolean);
alter function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean)
    rename to audit_metadata_has_missing_required_key_for_action_before_1330;

create function public.audit_metadata_has_missing_required_key_for_action(
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
begin
    if jsonb_typeof(p_metadata_json) <> 'object' then
        return true;
    end if;

    if p_action = 'key_rotation_envelope_migrated' then
        v_required_keys := array['batch_size', 'success_count', 'failure_count'];
    elsif p_action = 'key_rotation_envelope_failed' then
        v_required_keys := array['secret_version_id', 'version', 'error_code'];
    else
        return public.audit_metadata_has_missing_required_key_for_action_before_1330(
            p_action,
            p_result,
            p_metadata_json,
            p_require_source_event_at
        );
    end if;

    if p_require_source_event_at then
        v_required_keys := v_required_keys || array['source_event_at'];
    end if;

    return not (p_metadata_json ?& v_required_keys);
end;
$$;

comment on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean)
is 'Returns true when audit metadata is missing a required key for the given action/result, including Task 07 envelope migration actions.';

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
        when 'audit_ui_read' then
            v_allowed_keys := array['endpoint', 'method', 'resource', 'result_count', 'period_start', 'period_end', 'start_sequence_no', 'end_sequence_no', 'target_year_month', 'error_code', 'source_event_at'];
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
is 'Returns true when audit metadata contains a key outside the per-action allowlist, including Task 07 envelope migration actions.';

drop function if exists public.audit_metadata_has_invalid_value_for_action_before_1330(text, text, jsonb);
alter function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb)
    rename to audit_metadata_has_invalid_value_for_action_before_1330;

create function public.audit_metadata_has_invalid_value_for_action(
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
    v_value jsonb;
begin
    if jsonb_typeof(p_metadata_json) <> 'object' then
        return true;
    end if;

    if p_action not in ('key_rotation_envelope_migrated', 'key_rotation_envelope_failed') then
        return public.audit_metadata_has_invalid_value_for_action_before_1330(
            p_action,
            p_result,
            p_metadata_json
        );
    end if;

    if p_action = 'key_rotation_envelope_migrated' then
        if p_result <> 'success' then
            return true;
        end if;

        v_value := p_metadata_json -> 'batch_size';
        if jsonb_typeof(v_value) <> 'number'
            or (v_value #>> '{}') !~ '^[0-9]+$'
            or (v_value #>> '{}')::bigint <= 0
        then
            return true;
        end if;

        foreach v_value in array array[p_metadata_json -> 'success_count', p_metadata_json -> 'failure_count']
        loop
            if jsonb_typeof(v_value) <> 'number' or (v_value #>> '{}') !~ '^[0-9]+$' then
                return true;
            end if;
        end loop;
    else
        if p_result <> 'failure' then
            return true;
        end if;

        v_value := p_metadata_json -> 'secret_version_id';
        if jsonb_typeof(v_value) <> 'string'
            or (v_value #>> '{}') !~ '^[0-9a-fA-F-]{36}$'
        then
            return true;
        end if;

        v_value := p_metadata_json -> 'version';
        if jsonb_typeof(v_value) <> 'number'
            or (v_value #>> '{}') !~ '^[0-9]+$'
            or (v_value #>> '{}')::bigint <= 0
        then
            return true;
        end if;

        v_value := p_metadata_json -> 'error_code';
        if jsonb_typeof(v_value) <> 'string'
            or btrim(v_value #>> '{}') = ''
            or length(v_value #>> '{}') > 64
        then
            return true;
        end if;
    end if;

    v_value := p_metadata_json -> 'source_event_at';
    if jsonb_typeof(v_value) <> 'string'
        or not public.audit_metadata_source_event_at_is_valid(
            jsonb_build_object('source_event_at', v_value #>> '{}')
        )
    then
        return true;
    end if;

    return false;
exception
    when numeric_value_out_of_range then
        return true;
end;
$$;

comment on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb)
is 'Returns true when audit metadata values are invalid, including Task 07 envelope migration actions.';

create or replace function public.audit_metadata_has_schema_violation_for_action(
    p_action text,
    p_result text,
    p_metadata_json jsonb,
    p_require_source_event_at boolean default true
)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select public.audit_metadata_has_unknown_key_for_action(p_action, p_result, p_metadata_json)
        or public.audit_metadata_has_missing_required_key_for_action(
            p_action,
            p_result,
            p_metadata_json,
            p_require_source_event_at
        )
        or public.audit_metadata_has_invalid_value_for_action(p_action, p_result, p_metadata_json);
$$;

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
        'envelope_migration_batch_completed',
        'signature_key_created',
        'signature_key_activated',
        'signature_key_retired',
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
        when 'envelope_migration_batch_completed' then array['batch_size', 'success_count', 'failure_count']::text[]
        when 'signature_key_created' then array['created_at', 'public_key_fingerprint', 'signature_key_version']::text[]
        when 'signature_key_activated' then array['activated_at', 'public_key_fingerprint', 'signature_key_version']::text[]
        when 'signature_key_retired' then array['public_key_fingerprint', 'retired_at', 'signature_key_version']::text[]
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

create or replace function public.rpc_envelope_migration_status(p_secret_id uuid default null)
returns table (
    total_legacy_rows bigint,
    last_run_at text,
    last_batch_size bigint,
    last_success_count bigint,
    last_failure_count bigint
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_last_metadata jsonb;
begin
    select count(*)
    into total_legacy_rows
    from public.secret_versions sv
    where (sv.dek_wrap_algorithm is null or sv.dek_wrap_algorithm = 'legacy-master-key-v1')
        and (p_secret_id is null or sv.secret_id = p_secret_id);

    select ae.metadata_json
    into v_last_metadata
    from public.audit_events ae
    where ae.action = 'key_rotation_envelope_migrated'
        and ae.result = 'success'
    order by ae.occurred_at desc, ae.id desc
    limit 1;

    last_run_at := v_last_metadata ->> 'source_event_at';
    last_batch_size := nullif(v_last_metadata ->> 'batch_size', '')::bigint;
    last_success_count := nullif(v_last_metadata ->> 'success_count', '')::bigint;
    last_failure_count := nullif(v_last_metadata ->> 'failure_count', '')::bigint;

    return next;
end;
$$;

comment on function public.rpc_envelope_migration_status(uuid)
is 'Returns Task 07 envelope lazy migration progress without exposing plaintext or key material.';

create or replace function public.rpc_list_envelope_migration_batch(
    p_limit integer,
    p_secret_id uuid default null
)
returns table (
    id uuid,
    secret_id uuid,
    version integer,
    ciphertext bytea,
    encrypted_data_key bytea,
    key_version integer,
    algorithm text,
    classification text,
    nonce_or_iv bytea,
    aad_context jsonb,
    created_at timestamptz,
    owner_user_id uuid
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if p_limit is null or p_limit <= 0 or p_limit > 1000 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return query
    select
        sv.id,
        sv.secret_id,
        sv.version,
        sv.ciphertext,
        sv.encrypted_data_key,
        sv.key_version,
        sv.algorithm,
        s.classification,
        sv.nonce_or_iv,
        sv.aad_context,
        sv.created_at,
        s.owner_user_id
    from public.secret_versions sv
    join public.secrets s on s.id = sv.secret_id
    where (sv.dek_wrap_algorithm is null or sv.dek_wrap_algorithm = 'legacy-master-key-v1')
        and sv.encrypted_data_key is not null
        and (p_secret_id is null or sv.secret_id = p_secret_id)
    order by sv.created_at, sv.id
    limit p_limit;
end;
$$;

comment on function public.rpc_list_envelope_migration_batch(integer, uuid)
is 'Lists legacy envelope rows for SBC-side lazy migration. Returns ciphertext and wrapped legacy DEK only; no plaintext key material is exposed.';

create or replace function public.rpc_apply_envelope_migration_batch(
    p_request_id uuid,
    p_rows jsonb default '[]'::jsonb,
    p_failure_rows jsonb default '[]'::jsonb,
    p_audit_event_id uuid default gen_random_uuid(),
    p_source_event_at text default null,
    p_ledger_entry jsonb default null
)
returns table (
    success_count bigint,
    failure_count bigint,
    remaining_legacy_rows bigint,
    retry_secret_version_ids uuid[]
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_row jsonb;
    v_id uuid;
    v_secret_id uuid;
    v_version integer;
    v_key_version integer;
    v_ciphertext bytea;
    v_nonce_or_iv bytea;
    v_wrapped_dek bytea;
    v_kek_version integer;
    v_error_code text;
    v_failure_metadata jsonb;
    v_batch_metadata jsonb;
    v_batch_size bigint;
    v_source_event_id uuid;
    v_payload jsonb;
begin
    retry_secret_version_ids := array[]::uuid[];

    if p_request_id is null
        or p_audit_event_id is null
        or p_source_event_at is null
        or not public.audit_metadata_source_event_at_is_valid(jsonb_build_object('source_event_at', p_source_event_at))
        or p_rows is null
        or p_failure_rows is null
        or jsonb_typeof(p_rows) <> 'array'
        or jsonb_typeof(p_failure_rows) <> 'array'
        or jsonb_array_length(p_rows) + jsonb_array_length(p_failure_rows) = 0
        or jsonb_array_length(p_rows) + jsonb_array_length(p_failure_rows) > 1000
        or p_ledger_entry is null
        or jsonb_typeof(p_ledger_entry) <> 'object'
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if exists (
        select 1
        from (
            select item.value ->> 'id' as row_id
            from jsonb_array_elements(p_rows) as item(value)
            union all
            select item.value ->> 'id' as row_id
            from jsonb_array_elements(p_failure_rows) as item(value)
        ) ids
        group by row_id
        having count(*) > 1
    ) then
        raise exception 'duplicate_input_row' using errcode = '23505';
    end if;

    for v_row in select item.value from jsonb_array_elements(p_rows) as item(value)
    loop
        if jsonb_typeof(v_row) <> 'object'
            or not (v_row ?& array['id', 'secret_id', 'version', 'key_version', 'ciphertext', 'nonce_or_iv', 'wrapped_dek', 'dek_wrap_algorithm', 'kek_version'])
            or exists (
                select 1
                from jsonb_object_keys(v_row) as keys(key)
                where keys.key <> all(array['id', 'secret_id', 'version', 'key_version', 'ciphertext', 'nonce_or_iv', 'wrapped_dek', 'dek_wrap_algorithm', 'kek_version'])
            )
            or jsonb_typeof(v_row -> 'id') <> 'string'
            or jsonb_typeof(v_row -> 'secret_id') <> 'string'
            or jsonb_typeof(v_row -> 'version') <> 'number'
            or jsonb_typeof(v_row -> 'key_version') <> 'number'
            or jsonb_typeof(v_row -> 'ciphertext') <> 'string'
            or jsonb_typeof(v_row -> 'nonce_or_iv') <> 'string'
            or jsonb_typeof(v_row -> 'wrapped_dek') <> 'string'
            or jsonb_typeof(v_row -> 'dek_wrap_algorithm') <> 'string'
            or jsonb_typeof(v_row -> 'kek_version') <> 'number'
        then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;

        if (v_row ->> 'ciphertext') !~ '^\\x([0-9A-Fa-f]{2})+$'
            or (v_row ->> 'nonce_or_iv') !~ '^\\x([0-9A-Fa-f]{2}){24}$'
            or (v_row ->> 'wrapped_dek') !~ '^\\x([0-9A-Fa-f]{2}){25,}$'
        then
            raise exception 'invalid_bytea_encoding' using errcode = '22023';
        end if;

        v_id := (v_row ->> 'id')::uuid;
        v_secret_id := (v_row ->> 'secret_id')::uuid;
        v_version := (v_row ->> 'version')::integer;
        v_key_version := (v_row ->> 'key_version')::integer;
        v_kek_version := (v_row ->> 'kek_version')::integer;
        v_ciphertext := decode(substr(v_row ->> 'ciphertext', 3), 'hex');
        v_nonce_or_iv := decode(substr(v_row ->> 'nonce_or_iv', 3), 'hex');
        v_wrapped_dek := decode(substr(v_row ->> 'wrapped_dek', 3), 'hex');

        if v_secret_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
            raise exception 'invalid_secret_id' using errcode = '22023';
        end if;
        if v_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
            raise exception 'invalid_secret_version_id' using errcode = '22023';
        end if;
        if v_version <= 0 or v_key_version <= 0 or v_kek_version <= 0 then
            raise exception 'invalid_version' using errcode = '22023';
        end if;
        if v_row ->> 'dek_wrap_algorithm' <> 'envvar-xchacha-v2' then
            raise exception 'invalid_dek_wrap_algorithm' using errcode = '22023';
        end if;
        if left(v_row ->> 'ciphertext', 2) <> '\x'
            or left(v_row ->> 'nonce_or_iv', 2) <> '\x'
            or left(v_row ->> 'wrapped_dek', 2) <> '\x'
        then
            raise exception 'invalid_bytea_prefix' using errcode = '22023';
        end if;
        if octet_length(v_ciphertext) = 0
            or octet_length(v_nonce_or_iv) <> 24
            or octet_length(v_wrapped_dek) <= 24
        then
            raise exception 'invalid_bytea_length' using errcode = '22023';
        end if;

        begin
            perform 1
            from public.secret_versions sv
            where sv.id = v_id
                and sv.secret_id = v_secret_id
                and sv.version = v_version
                and (sv.dek_wrap_algorithm is null or sv.dek_wrap_algorithm = 'legacy-master-key-v1')
            for update nowait;

            if not found then
                v_error_code := 'row_conflict';
            else
                update public.secret_versions
                set
                    ciphertext = v_ciphertext,
                    nonce_or_iv = v_nonce_or_iv,
                    encrypted_data_key = null,
                    wrapped_dek = v_wrapped_dek,
                    dek_wrap_algorithm = 'envvar-xchacha-v2',
                    kek_version = v_kek_version,
                    key_version = v_kek_version
                where id = v_id;

                success_count := coalesce(success_count, 0) + 1;
            end if;
        exception
            when unique_violation then
                v_error_code := 'nonce_reuse_detected';
            when lock_not_available then
                v_error_code := coalesce(v_error_code, 'row_locked');
        end;

        if v_error_code is not null then
            if v_error_code = 'nonce_reuse_detected' then
                retry_secret_version_ids := array_append(retry_secret_version_ids, v_id);
            else
                v_failure_metadata := jsonb_build_object(
                    'secret_version_id', v_id::text,
                    'version', v_version,
                    'error_code', v_error_code,
                    'source_event_at', p_source_event_at
                );
                if public.audit_metadata_has_forbidden_key(v_failure_metadata)
                    or public.audit_metadata_has_schema_violation_for_action('key_rotation_envelope_failed', 'failure', v_failure_metadata, true)
                then
                    raise exception 'invalid_audit_metadata' using errcode = '22023';
                end if;

                insert into public.audit_events (
                    id,
                    request_id,
                    action,
                    target_secret_id,
                    result,
                    key_version,
                    metadata_json
                )
                values (
                    gen_random_uuid(),
                    p_request_id,
                    'key_rotation_envelope_failed',
                    v_secret_id,
                    'failure',
                    v_key_version,
                    v_failure_metadata
                );
                failure_count := coalesce(failure_count, 0) + 1;
            end if;
            v_error_code := null;
        end if;
    end loop;

    for v_row in select item.value from jsonb_array_elements(p_failure_rows) as item(value)
    loop
        if jsonb_typeof(v_row) <> 'object'
            or not (v_row ?& array['id', 'secret_id', 'version', 'key_version', 'error_code'])
            or exists (
                select 1
                from jsonb_object_keys(v_row) as keys(key)
                where keys.key <> all(array['id', 'secret_id', 'version', 'key_version', 'error_code'])
            )
            or jsonb_typeof(v_row -> 'id') <> 'string'
            or jsonb_typeof(v_row -> 'secret_id') <> 'string'
            or jsonb_typeof(v_row -> 'version') <> 'number'
            or jsonb_typeof(v_row -> 'key_version') <> 'number'
            or jsonb_typeof(v_row -> 'error_code') <> 'string'
        then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;

        v_id := (v_row ->> 'id')::uuid;
        v_secret_id := (v_row ->> 'secret_id')::uuid;
        v_version := (v_row ->> 'version')::integer;
        v_key_version := (v_row ->> 'key_version')::integer;
        v_error_code := v_row ->> 'error_code';

        if v_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
            raise exception 'invalid_secret_version_id' using errcode = '22023';
        end if;
        if v_secret_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
            raise exception 'invalid_secret_id' using errcode = '22023';
        end if;
        if v_version <= 0 or v_key_version <= 0 then
            raise exception 'invalid_version' using errcode = '22023';
        end if;
        if v_error_code !~ '^[a-z0-9_]{1,64}$' then
            raise exception 'invalid_error_code' using errcode = '22023';
        end if;

        v_failure_metadata := jsonb_build_object(
            'secret_version_id', v_id::text,
            'version', v_version,
            'error_code', v_error_code,
            'source_event_at', p_source_event_at
        );
        if public.audit_metadata_has_forbidden_key(v_failure_metadata)
            or public.audit_metadata_has_schema_violation_for_action('key_rotation_envelope_failed', 'failure', v_failure_metadata, true)
        then
            raise exception 'invalid_audit_metadata' using errcode = '22023';
        end if;

        insert into public.audit_events (
            id,
            request_id,
            action,
            target_secret_id,
            result,
            key_version,
            metadata_json
        )
        values (
            gen_random_uuid(),
            p_request_id,
            'key_rotation_envelope_failed',
            v_secret_id,
            'failure',
            v_key_version,
            v_failure_metadata
        );
        failure_count := coalesce(failure_count, 0) + 1;
    end loop;

    success_count := coalesce(success_count, 0);
    failure_count := coalesce(failure_count, 0);
    v_batch_size := success_count + failure_count;
    v_batch_metadata := jsonb_build_object(
        'batch_size', v_batch_size,
        'success_count', success_count,
        'failure_count', failure_count,
        'source_event_at', p_source_event_at
    );
    if public.audit_metadata_has_forbidden_key(v_batch_metadata)
        or public.audit_metadata_has_schema_violation_for_action('key_rotation_envelope_migrated', 'success', v_batch_metadata, true)
    then
        raise exception 'invalid_audit_metadata' using errcode = '22023';
    end if;

    insert into public.audit_events (
        id,
        request_id,
        action,
        result,
        metadata_json
    )
    values (
        p_audit_event_id,
        p_request_id,
        'key_rotation_envelope_migrated',
        'success',
        v_batch_metadata
    );

    v_payload := p_ledger_entry -> 'p_payload';
    if not public.ledger_payload_is_valid('envelope_migration_batch_completed', v_payload) then
        raise exception 'invalid_ledger_entry' using errcode = '22023';
    end if;

    perform public.rpc_append_ledger_entry_from_jsonb(p_ledger_entry);

    select count(*)
    into remaining_legacy_rows
    from public.secret_versions sv
    where sv.dek_wrap_algorithm is null or sv.dek_wrap_algorithm = 'legacy-master-key-v1';

    return next;
exception
    when invalid_text_representation
        or numeric_value_out_of_range
        or null_value_not_allowed
        or string_data_right_truncation
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
end;
$$;

comment on function public.rpc_apply_envelope_migration_batch(uuid, jsonb, jsonb, uuid, text, jsonb)
is 'Applies one Task 07 envelope lazy migration batch. Plaintext and DEK plaintext never enter SQL.';

revoke execute on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_schema_violation_for_action(text, text, jsonb, boolean) from public, anon, authenticated;
revoke execute on function public.rpc_envelope_migration_status(uuid) from public, anon, authenticated;
revoke execute on function public.rpc_list_envelope_migration_batch(integer, uuid) from public, anon, authenticated;
revoke execute on function public.rpc_apply_envelope_migration_batch(uuid, jsonb, jsonb, uuid, text, jsonb) from public, anon, authenticated;

grant execute on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean) to service_role;
grant execute on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb) to service_role;
grant execute on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) to service_role;
grant execute on function public.audit_metadata_has_schema_violation_for_action(text, text, jsonb, boolean) to service_role;
grant execute on function public.rpc_envelope_migration_status(uuid) to service_role;
grant execute on function public.rpc_list_envelope_migration_batch(integer, uuid) to service_role;
grant execute on function public.rpc_apply_envelope_migration_batch(uuid, jsonb, jsonb, uuid, text, jsonb) to service_role;

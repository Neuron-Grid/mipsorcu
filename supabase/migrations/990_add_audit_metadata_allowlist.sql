-- T04 audit metadata validation.
-- 時刻源と責務:
-- - audit_events.occurred_at は DB 側で発生時刻として now() を記録する既存責務を維持する。
-- - metadata_json.source_event_at は producer である SBC がイベント生成時に一度だけ決定し、
--   fallback / 再送 / sent マーカーでも同じ値を保持する。SQL 側は canonical UTC RFC3339（末尾 Z）
--   であることを検証し、値を再生成しない。
-- - secret_versions.created_at は SBC が決定した p_created_at を保存し、DB now() で置き換えない。

create or replace function public.audit_metadata_allowlist_mode()
returns text
language sql
stable
set search_path = public, pg_temp
as $$
    select case
        when current_setting('mipsorcu.audit_metadata_allowlist_mode', true) in ('warning', 'strict')
            then current_setting('mipsorcu.audit_metadata_allowlist_mode', true)
        else 'strict'
    end;
$$;

comment on function public.audit_metadata_allowlist_mode() is
    'Feature flag for audit metadata allowlist validation. Values: strict (reject unknown keys) or warning (log only). Defaults to strict for Phase 2; operators may temporarily set warning during controlled migration windows only. See docs/adr/0027-adr-audit-events-metadata-json-action-allowlist.md for staged migration plan.';


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
            v_allowed_keys := array[
                'version',
                'secret_version_id',
                'source_event_at'
            ];
        when 'decrypt' then
            if p_result = 'failure' then
                v_allowed_keys := array[
                    'attempted_secret_id',
                    'source_event_at'
                ];
            else
                v_allowed_keys := array[
                    'source_event_at'
                ];
            end if;
        when 'integrity_check' then
            v_allowed_keys := array[
                'check_name',
                'checked_secret_count',
                'checked_secret_version_count',
                'checked_audit_event_count',
                'duration_ms',
                'violation_count',
                'violation_summary',
                'trigger',
                'error_code',
                'source_event_at'
            ];
            v_violation_summary_keys := array[
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
            v_allowed_keys := array[
                'phase',
                'sample_count',
                'trigger',
                'duration_ms',
                'error_code',
                'failed_version',
                'reason',
                'source_event_at'
            ];
        when 'auth_failure' then
            v_allowed_keys := array[
                'error_code',
                'source_event_at'
            ];
        when 'key_rotation_start' then
            v_allowed_keys := array[
                'old_key_version',
                'new_key_version',
                'source_event_at'
            ];
        when 'key_rotation_reencrypt' then
            v_allowed_keys := array[
                'old_key_version',
                'new_key_version',
                'batch_size',
                'processed_count',
                'remaining_count',
                'source_event_at'
            ];
        when 'key_rotation_complete' then
            v_allowed_keys := array[
                'old_key_version',
                'new_key_version',
                'remaining_count',
                'source_event_at'
            ];
        else
            -- 未知action: fail-closed
            return true;
    end case;
    -- ACTION_ALLOWLIST_END

    -- トップレベルキー検証
    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        if not v_key = any(v_allowed_keys) then
            return true;
        end if;
    end loop;

    -- violation_summary サブオブジェクトキー検証
    if p_action = 'integrity_check' and p_metadata_json ? 'violation_summary' then
        if jsonb_typeof(p_metadata_json -> 'violation_summary') <> 'object' then
            return true;
        end if;

        for v_key in select jsonb_object_keys(p_metadata_json -> 'violation_summary')
        loop
            if not v_key = any(v_violation_summary_keys) then
                return true;
            end if;
        end loop;
    end if;

    return false;
end;
$$;

comment on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb) is
    'Returns true if metadata_json contains keys not in the allowlist for the given action and result. Enforces the action-specific schema from docs/audit_metadata_schema.md. Coexists with audit_metadata_has_forbidden_key as defense-in-depth.';

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
            v_required_keys := array[
                'phase',
                'sample_count',
                'trigger',
                'duration_ms'
            ];
        when 'auth_failure' then
            v_required_keys := array['error_code'];
        when 'key_rotation_start' then
            v_required_keys := array['old_key_version', 'new_key_version'];
        when 'key_rotation_reencrypt' then
            v_required_keys := array[
                'old_key_version',
                'new_key_version',
                'batch_size',
                'processed_count',
                'remaining_count'
            ];
        when 'key_rotation_complete' then
            v_required_keys := array[
                'old_key_version',
                'new_key_version',
                'remaining_count'
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

comment on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean) is
    'Returns true if metadata_json is missing action-specific required keys. The require_source_event_at flag distinguishes append-audit RPCs (producer time required) from write RPC internal success audit metadata (producer time optional unless ledger-linked).';

-- ------------------------------------------------------------------------------
-- 値型検証: count/duration 系, version/key_version 系, violation_summary values,
-- trigger の enum 制約を検証する。
-- ------------------------------------------------------------------------------
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

    -- count/duration 系: JSON integer かつ >= 0
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
            'remaining_count'
        ]);

        v_val := p_metadata_json -> v_key;
        if jsonb_typeof(v_val) <> 'number' then
            return true;
        end if;
        if v_val::text !~ '^(0|[1-9][0-9]*)$' then
            return true;
        end if;
    end loop;

    -- version / key_version / batch_size 系: JSON integer かつ > 0
    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        continue when not v_key = any(array[
            'version',
            'old_key_version',
            'new_key_version',
            'failed_version',
            'batch_size'
        ]);

        v_val := p_metadata_json -> v_key;
        if v_key = 'failed_version' and v_val = 'null'::jsonb then
            continue;
        end if;
        if jsonb_typeof(v_val) <> 'number' then
            return true;
        end if;
        if v_val::text !~ '^[1-9][0-9]*$' then
            return true;
        end if;
    end loop;

    -- UUID v4 形式（ハイフン付き小文字）
    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        continue when not v_key = any(array[
            'secret_version_id',
            'attempted_secret_id'
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

    -- attempted_secret_id は decrypt failure metadata 専用の予約キー。
    if p_metadata_json ? 'attempted_secret_id'
        and not (p_action = 'decrypt' and p_result = 'failure')
    then
        return true;
    end if;

    -- error_code は failure metadata 専用。値は非空・最大64文字。
    if p_metadata_json ? 'error_code' then
        if p_result <> 'failure' then
            return true;
        end if;
        if jsonb_typeof(p_metadata_json -> 'error_code') <> 'string' then
            return true;
        end if;
        v_text := p_metadata_json ->> 'error_code';
        if btrim(v_text) = '' or length(v_text) > 64 then
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

    -- trigger: enum validation
    if p_metadata_json ? 'trigger' then
        if jsonb_typeof(p_metadata_json -> 'trigger') <> 'string' then
            return true;
        end if;
        if p_metadata_json ->> 'trigger' not in ('startup', 'background', 'cli') then
            return true;
        end if;
    end if;

    -- violation_summary values: JSON integer かつ >= 0
    if p_action = 'integrity_check' and p_metadata_json ? 'violation_summary' then
        if jsonb_typeof(p_metadata_json -> 'violation_summary') <> 'object' then
            return true;
        end if;

        for v_key, v_val in select * from jsonb_each(p_metadata_json -> 'violation_summary')
        loop
            if jsonb_typeof(v_val) <> 'number' then
                return true;
            end if;
            if v_val::text !~ '^(0|[1-9][0-9]*)$' then
                return true;
            end if;
        end loop;
    end if;

    return false;
end;
$$;

comment on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) is
    'Returns true if metadata_json contains values with invalid types, formats, or out-of-range values per action schema. Checks integers, UUID v4 strings, fixed values, trigger enum, error_code placement, attempted_secret_id reservation, and violation_summary value types.';

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

comment on function public.audit_metadata_has_schema_violation_for_action(text, text, jsonb, boolean) is
    'Action-specific audit metadata schema validation wrapper. In warning mode callers log violations only; in strict mode callers reject them as invalid_rpc_input.';

-- ------------------------------------------------------------------------------
-- RPC: rpc_append_audit_event
-- allowlist チェックを追加。denylist・source_event_at 検証と共存。
-- ------------------------------------------------------------------------------
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
        'key_rotation_complete'
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

    if p_action = 'auth_failure' and p_result <> 'failure' then
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

    -- allowlist / schema validation (段階的移行対応)
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
    'Audit append RPC for non-write-path audit events and failure events. Added allowlist validation (Phase 2). Caller supplies a stable audit_event_id so fallback resend remains idempotent.';

-- ------------------------------------------------------------------------------
-- RPC: rpc_write_secret_version
-- 内部生成の audit metadata に対して allowlist 検証を追加
-- ------------------------------------------------------------------------------
create or replace function public.rpc_write_secret_version(
    p_request_id uuid,
    p_action text,
    p_secret_id uuid,
    p_owner_user_id uuid,
    p_classification text,
    p_created_by_device_id text,
    p_created_at timestamptz,
    p_version integer,
    p_ciphertext bytea,
    p_encrypted_data_key bytea,
    p_key_version integer,
    p_algorithm text,
    p_nonce_or_iv bytea,
    p_aad_context jsonb,
    p_secret_version_id uuid default gen_random_uuid(),
    p_ledger_entries jsonb default null
)
returns table (
    secret_id uuid,
    secret_version_id uuid,
    version integer,
    purged_version_ids uuid[]
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_current_secret public.secrets%rowtype;
    v_current_version integer;
    v_secret_version_id uuid;
    v_purged_version_ids uuid[] := array[]::uuid[];
    v_purged record;
    v_secret_version_from_aad integer;
    v_aad_created_at timestamptz;
    v_audit_metadata jsonb;
    v_write_ledger_entry jsonb;
    v_purge_ledger_entry jsonb;
    v_purge_ledger_count integer;
    v_constraint_name text;
    v_allowlist_mode text;
begin
    if p_request_id is null
        or p_action is null
        or p_secret_id is null
        or p_owner_user_id is null
        or p_classification is null
        or p_created_by_device_id is null
        or p_created_at is null
        or p_version is null
        or p_ciphertext is null
        or p_encrypted_data_key is null
        or p_key_version is null
        or p_algorithm is null
        or p_nonce_or_iv is null
        or p_aad_context is null
        or p_secret_version_id is null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_action not in ('encrypt_create', 'encrypt_rotate') then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_secret_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_secret_version_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_ledger_entries is not null and jsonb_typeof(p_ledger_entries) <> 'array' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if btrim(p_classification) = '' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if btrim(p_created_by_device_id) = '' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_version <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if octet_length(p_ciphertext) = 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if octet_length(p_encrypted_data_key) <> 73 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_key_version <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_algorithm <> 'xchacha20-poly1305' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if octet_length(p_nonce_or_iv) <> 24 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if jsonb_typeof(p_aad_context) is distinct from 'object' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if not (
        p_aad_context ?& array[
            'aad_version',
            'secret_id',
            'version',
            'owner_user_id',
            'classification',
            'created_at'
        ]
    )
        or p_aad_context - array[
            'aad_version',
            'secret_id',
            'version',
            'owner_user_id',
            'classification',
            'created_at'
        ] <> '{}'::jsonb
    then
        raise exception 'aad_context_mismatch' using errcode = '22023';
    end if;

    if jsonb_typeof(p_aad_context -> 'aad_version') is distinct from 'number'
        or jsonb_typeof(p_aad_context -> 'secret_id') is distinct from 'string'
        or jsonb_typeof(p_aad_context -> 'version') is distinct from 'number'
        or jsonb_typeof(p_aad_context -> 'owner_user_id') is distinct from 'string'
        or jsonb_typeof(p_aad_context -> 'classification') is distinct from 'string'
        or jsonb_typeof(p_aad_context -> 'created_at') is distinct from 'string'
        or p_aad_context ->> 'version' !~ '^[1-9][0-9]*$'
        or p_aad_context ->> 'created_at' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$'
    then
        raise exception 'aad_context_mismatch' using errcode = '22023';
    end if;

    begin
        v_secret_version_from_aad := (p_aad_context ->> 'version')::integer;
        v_aad_created_at := (p_aad_context ->> 'created_at')::timestamptz;
    exception
        when others then
            raise exception 'aad_context_mismatch' using errcode = '22023';
    end;

    if p_aad_context ->> 'aad_version' <> '1'
        or p_aad_context ->> 'secret_id' <> p_secret_id::text
        or v_secret_version_from_aad <> p_version
        or p_aad_context ->> 'owner_user_id' <> p_owner_user_id::text
        or p_aad_context ->> 'classification' <> p_classification
        or v_aad_created_at <> p_created_at
    then
        raise exception 'aad_context_mismatch' using errcode = '22023';
    end if;

    select *
    into v_current_secret
    from public.secrets s
    where s.id = p_secret_id
    for update;

    if not found then
        if p_action <> 'encrypt_create' or p_version <> 1 then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;

        insert into public.secrets (
            id,
            owner_user_id,
            classification,
            created_at,
            updated_at
        )
        values (
            p_secret_id,
            p_owner_user_id,
            p_classification,
            p_created_at,
            now()
        );
    else
        if p_action <> 'encrypt_rotate' then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;

        if v_current_secret.owner_user_id <> p_owner_user_id then
            raise exception 'owner_mismatch' using errcode = '42501';
        end if;

        if v_current_secret.classification <> p_classification then
            raise exception 'classification_immutable' using errcode = '23514';
        end if;

        select sv.version
        into v_current_version
        from public.secret_versions sv
        where sv.secret_id = p_secret_id
            and sv.id = v_current_secret.current_version_id;

        if v_current_version is null then
            raise exception 'db_integrity_violation' using errcode = '23514';
        end if;

        if p_version <> v_current_version + 1 then
            raise exception 'not_next_version' using errcode = '23514';
        end if;
    end if;

    begin
        insert into public.secret_versions (
            id,
            secret_id,
            version,
            ciphertext,
            encrypted_data_key,
            key_version,
            algorithm,
            classification,
            nonce_or_iv,
            aad_context,
            created_by_user_id,
            created_by_device_id,
            created_at
        )
        values (
            p_secret_version_id,
            p_secret_id,
            p_version,
            p_ciphertext,
            p_encrypted_data_key,
            p_key_version,
            p_algorithm,
            p_classification,
            p_nonce_or_iv,
            p_aad_context,
            p_owner_user_id,
            p_created_by_device_id,
            p_created_at
        )
        returning id into v_secret_version_id;
    exception
        when unique_violation then
            get stacked diagnostics v_constraint_name = constraint_name;

            if v_constraint_name = 'secret_versions_secret_nonce_unique' then
                raise exception 'nonce_reuse_detected' using errcode = '23505';
            end if;

            raise;
    end;

    update public.secrets
    set current_version_id = v_secret_version_id
    where id = p_secret_id;

    if p_ledger_entries is not null then
        select entries.entry
        into v_write_ledger_entry
        from jsonb_array_elements(p_ledger_entries) as entries(entry)
        where entries.entry ->> 'p_entry_type' = case
            when p_action = 'encrypt_create' then 'secret_created'
            else 'secret_version_created'
        end;

        if not found or (
            select count(*)::integer
            from jsonb_array_elements(p_ledger_entries) as entries(entry)
            where entries.entry ->> 'p_entry_type' in (
                'secret_created',
                'secret_version_created'
            )
        ) <> 1 then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;

        if v_write_ledger_entry ->> 'p_request_id' <> p_request_id::text
            or v_write_ledger_entry ->> 'p_source_event_id' is null
            or v_write_ledger_entry ->> 'p_target_secret_id' <> p_secret_id::text
            or v_write_ledger_entry ->> 'p_target_secret_version_id' <> v_secret_version_id::text
            or v_write_ledger_entry ->> 'p_actor_user_id' <> p_owner_user_id::text
            or v_write_ledger_entry ->> 'p_actor_device_id' <> p_created_by_device_id
            or v_write_ledger_entry ->> 'p_result' <> 'success'
            or v_write_ledger_entry ->> 'p_error_code' is not null
            or v_write_ledger_entry -> 'p_payload' ->> 'classification' <> p_classification
            or v_write_ledger_entry -> 'p_payload' ->> 'algorithm' <> p_algorithm
            or (v_write_ledger_entry -> 'p_payload' ->> 'version')::integer <> p_version
            or (v_write_ledger_entry -> 'p_payload' ->> 'key_version')::integer <> p_key_version
        then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;
    end if;

    v_audit_metadata := jsonb_build_object(
        'version',
        p_version,
        'secret_version_id',
        v_secret_version_id
    );

    if v_write_ledger_entry is not null then
        v_audit_metadata := v_audit_metadata || jsonb_build_object(
            'source_event_at',
            v_write_ledger_entry ->> 'p_source_event_at'
        );
    end if;

    if public.audit_metadata_has_forbidden_key(v_audit_metadata)
        or not public.audit_metadata_source_event_at_is_valid(v_audit_metadata)
    then
        raise exception 'invalid_audit_metadata' using errcode = '22023';
    end if;

    -- allowlist / schema validation for internal audit metadata (段階的移行対応)
    v_allowlist_mode := public.audit_metadata_allowlist_mode();

    if public.audit_metadata_has_schema_violation_for_action(p_action, 'success', v_audit_metadata, false) then
        if v_allowlist_mode = 'strict' then
            raise exception 'invalid_audit_metadata' using errcode = '22023';
        else
            raise notice 'audit_metadata_schema_warning: action=%, result=success, schema_violation_present',
                p_action;
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
        coalesce((v_write_ledger_entry ->> 'p_source_event_id')::uuid, gen_random_uuid()),
        p_request_id,
        p_owner_user_id,
        p_created_by_device_id,
        p_action,
        p_secret_id,
        'success',
        p_key_version,
        v_audit_metadata
    );

    if v_write_ledger_entry is not null then
        perform *
        from public.rpc_append_ledger_entry_from_jsonb(v_write_ledger_entry);
    end if;

    for v_purged in
        delete from public.secret_versions sv
        using (
            select ranked.id
            from (
                select
                    retained.id,
                    row_number() over (
                        partition by retained.secret_id
                        order by retained.version desc
                    ) as retained_rank
                from public.secret_versions retained
                where retained.secret_id = p_secret_id
            ) ranked
            where ranked.retained_rank > 4
        ) purge_candidates
        where sv.id = purge_candidates.id
        returning sv.id, sv.version, sv.key_version
    loop
        v_purged_version_ids := array_append(v_purged_version_ids, v_purged.id);

        v_purge_ledger_entry := null;
        if p_ledger_entries is not null then
            select entries.entry
            into v_purge_ledger_entry
            from jsonb_array_elements(p_ledger_entries) as entries(entry)
            where entries.entry ->> 'p_entry_type' = 'secret_version_purged'
                and entries.entry ->> 'p_target_secret_version_id' = v_purged.id::text;

            if not found
                or v_purge_ledger_entry ->> 'p_request_id' <> p_request_id::text
                or v_purge_ledger_entry ->> 'p_source_event_id' is null
                or v_purge_ledger_entry ->> 'p_target_secret_id' <> p_secret_id::text
                or v_purge_ledger_entry ->> 'p_actor_user_id' <> p_owner_user_id::text
                or v_purge_ledger_entry ->> 'p_actor_device_id' <> p_created_by_device_id
                or v_purge_ledger_entry ->> 'p_result' <> 'success'
                or v_purge_ledger_entry ->> 'p_error_code' is not null
                or (v_purge_ledger_entry -> 'p_payload' ->> 'version')::integer <> v_purged.version
                or (v_purge_ledger_entry -> 'p_payload' ->> 'key_version')::integer <> v_purged.key_version
                or (v_purge_ledger_entry -> 'p_payload' ->> 'retention_limit')::integer <> 4
            then
                raise exception 'invalid_rpc_input' using errcode = '22023';
            end if;
        end if;

        v_audit_metadata := jsonb_build_object(
            'version',
            v_purged.version,
            'secret_version_id',
            v_purged.id
        );

        if v_purge_ledger_entry is not null then
            v_audit_metadata := v_audit_metadata || jsonb_build_object(
                'source_event_at',
                v_purge_ledger_entry ->> 'p_source_event_at'
            );
        end if;

        if public.audit_metadata_has_forbidden_key(v_audit_metadata)
            or not public.audit_metadata_source_event_at_is_valid(v_audit_metadata)
        then
            raise exception 'invalid_audit_metadata' using errcode = '22023';
        end if;

        -- allowlist / schema validation for purge audit metadata (段階的移行対応)
        if public.audit_metadata_has_schema_violation_for_action('version_purge', 'success', v_audit_metadata, false) then
            if v_allowlist_mode = 'strict' then
                raise exception 'invalid_audit_metadata' using errcode = '22023';
            else
                raise notice 'audit_metadata_schema_warning: action=version_purge, result=success, schema_violation_present';
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
            coalesce((v_purge_ledger_entry ->> 'p_source_event_id')::uuid, gen_random_uuid()),
            p_request_id,
            p_owner_user_id,
            p_created_by_device_id,
            'version_purge',
            p_secret_id,
            'success',
            v_purged.key_version,
            v_audit_metadata
        );

        if v_purge_ledger_entry is not null then
            perform *
            from public.rpc_append_ledger_entry_from_jsonb(v_purge_ledger_entry);
        end if;
    end loop;

    if p_ledger_entries is not null then
        select count(*)::integer
        into v_purge_ledger_count
        from jsonb_array_elements(p_ledger_entries) as entries(entry)
        where entries.entry ->> 'p_entry_type' = 'secret_version_purged';

        if v_purge_ledger_count <> coalesce(array_length(v_purged_version_ids, 1), 0) then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;
    end if;

    return query
    select
        p_secret_id,
        v_secret_version_id,
        p_version,
        v_purged_version_ids;
end;
$$;

comment on function public.rpc_write_secret_version(
    uuid, text, uuid, uuid, text, text, timestamptz,
    integer, bytea, bytea, integer, text, bytea, jsonb, uuid, jsonb
) is
    'Authoritative production write RPC for encrypt_create and encrypt_rotate. Added allowlist validation for internally-generated audit metadata (Phase 2). Inserts the version, advances current_version_id, appends success audit events, and purges versions beyond retention in one transaction.';

-- ------------------------------------------------------------------------------
-- 権限設定
-- ------------------------------------------------------------------------------
revoke execute on function public.audit_metadata_allowlist_mode() from public, anon, authenticated;
revoke execute on function public.audit_metadata_allowlist_mode() from public;

revoke execute on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb) from public;

revoke execute on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean) from public;

revoke execute on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) from public;

revoke execute on function public.audit_metadata_has_schema_violation_for_action(text, text, jsonb, boolean) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_schema_violation_for_action(text, text, jsonb, boolean) from public;

grant execute on function public.audit_metadata_allowlist_mode() to service_role;
grant execute on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb) to service_role;
grant execute on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean) to service_role;
grant execute on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) to service_role;
grant execute on function public.audit_metadata_has_schema_violation_for_action(text, text, jsonb, boolean) to service_role;

revoke execute on function public.rpc_append_audit_event(
    uuid, uuid, uuid, text, text, uuid, text, integer, jsonb
) from public, anon, authenticated;
revoke execute on function public.rpc_append_audit_event(
    uuid, uuid, uuid, text, text, uuid, text, integer, jsonb
) from public;

grant execute on function public.rpc_append_audit_event(
    uuid, uuid, uuid, text, text, uuid, text, integer, jsonb
) to service_role;

revoke execute on function public.rpc_write_secret_version(
    uuid, text, uuid, uuid, text, text, timestamptz,
    integer, bytea, bytea, integer, text, bytea, jsonb, uuid, jsonb
) from public, anon, authenticated;
revoke execute on function public.rpc_write_secret_version(
    uuid, text, uuid, uuid, text, text, timestamptz,
    integer, bytea, bytea, integer, text, bytea, jsonb, uuid, jsonb
) from public;

grant execute on function public.rpc_write_secret_version(
    uuid, text, uuid, uuid, text, text, timestamptz,
    integer, bytea, bytea, integer, text, bytea, jsonb, uuid, jsonb
) to service_role;

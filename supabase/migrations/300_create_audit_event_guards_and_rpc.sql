create function public.audit_metadata_has_forbidden_key(p_metadata_json jsonb)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    with recursive nodes(value) as (
        values (p_metadata_json)

        union all

        select child_values.value
        from nodes
        cross join lateral (
            select object_values.value
            from jsonb_each(
                case
                    when jsonb_typeof(nodes.value) = 'object' then nodes.value
                    else '{}'::jsonb
                end
            ) as object_values(key, value)

            union all

            select array_values.value
            from jsonb_array_elements(
                case
                    when jsonb_typeof(nodes.value) = 'array' then nodes.value
                    else '[]'::jsonb
                end
            ) as array_values(value)
        ) as child_values(value)
    )
    select exists (
        select 1
        from nodes
        cross join lateral jsonb_object_keys(
            case
                when jsonb_typeof(nodes.value) = 'object' then nodes.value
                else '{}'::jsonb
            end
        ) as metadata_keys(key)
        where jsonb_typeof(nodes.value) = 'object'
            and lower(btrim(metadata_keys.key)) in (
                -- FORBIDDEN_AUDIT_METADATA_KEYS_START
                'authorization',
                'ciphertext',
                'data_key',
                'decrypt_result',
                'decrypted',
                'decrypted_data',
                'encrypted_data_key',
                'jwt',
                'master_key',
                'passphrase',
                'password',
                'plain_text',
                'plaintext',
                'secret_key',
                'secret_value',
                'service_role',
                'service_role_key',
                'token'
                -- FORBIDDEN_AUDIT_METADATA_KEYS_END
            )
    );
$$;

comment on function public.audit_metadata_has_forbidden_key(jsonb) is
    'Recursive guard used by audit constraints and RPCs to reject metadata keys that could carry plaintext, keys, JWTs, or ciphertext material.';

create function public.audit_metadata_source_event_at_is_valid(p_metadata_json jsonb)
returns boolean
language plpgsql
stable
set search_path = public, pg_temp
as $$
declare
    v_source_event_at text;
begin
    if jsonb_typeof(p_metadata_json) <> 'object' then
        return false;
    end if;

    if not (p_metadata_json ? 'source_event_at') then
        return true;
    end if;

    if jsonb_typeof(p_metadata_json -> 'source_event_at') <> 'string' then
        return false;
    end if;

    v_source_event_at := p_metadata_json ->> 'source_event_at';

    if v_source_event_at !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$' then
        return false;
    end if;

    begin
        perform v_source_event_at::timestamptz;
    exception
        when others then
            return false;
    end;

    return true;
end;
$$;

comment on function public.audit_metadata_source_event_at_is_valid(jsonb) is
    'Validates optional top-level metadata_json.source_event_at as canonical RFC 3339 UTC producer time.';

alter table public.audit_events
    add constraint audit_events_metadata_json_no_forbidden_keys
    check (not public.audit_metadata_has_forbidden_key(metadata_json)),
    add constraint audit_events_metadata_json_source_event_at_valid
    check (public.audit_metadata_source_event_at_is_valid(metadata_json));

create function public.rpc_append_audit_event(
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
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb
) is
    'Audit append RPC for non-write-path audit events and failure events. Caller supplies a stable audit_event_id so fallback resend remains idempotent.';

revoke execute on function public.audit_metadata_has_forbidden_key(jsonb) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_forbidden_key(jsonb) from public;
revoke execute on function public.audit_metadata_source_event_at_is_valid(jsonb) from public, anon, authenticated;
revoke execute on function public.audit_metadata_source_event_at_is_valid(jsonb) from public;

revoke execute on function public.rpc_append_audit_event(
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb
) from public, anon, authenticated;
revoke execute on function public.rpc_append_audit_event(
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb
) from public;

grant execute on function public.rpc_append_audit_event(
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb
) to service_role;

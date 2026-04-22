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

alter table public.audit_events
    add constraint audit_events_metadata_json_source_event_at_valid
    check (public.audit_metadata_source_event_at_is_valid(metadata_json));

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

comment on column public.secret_versions.created_at is
    'SBC が AAD 構成時に決定した値を保存する。AAD 束縛されるため DB default 不可。ADR-021 参照。';

comment on column public.secrets.created_at is
    'secret aggregate metadata。AAD 束縛されない。RPC 経由では初回 secret_versions.created_at と同じ SBC 決定値を保存する。DB default は直接 INSERT 防御用の補助。ADR-021 参照。';

comment on column public.secrets.updated_at is
    'secret aggregate metadata。tg_set_updated_at トリガで自動更新する。ADR-021 参照。';

comment on column public.audit_events.occurred_at is
    '監査イベントの DB 確定時刻。fallback 経由では再送時刻になるため、producer 側発生時刻は metadata_json.source_event_at を参照する。ADR-021 参照。';

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

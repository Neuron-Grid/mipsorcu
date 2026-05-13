-- Ledger Phase 1 key rotation integration.
-- The key rotation RPCs remain the transactional boundary for DB mutation and
-- authoritative audit_events writes; signed ledger entries are appended inside
-- that same transaction when provided by the SBC runtime.

drop function public.rpc_apply_key_rotation_batch(uuid, integer, integer, jsonb);

create function public.rpc_apply_key_rotation_batch(
    p_request_id uuid,
    p_old_key_version integer,
    p_new_key_version integer,
    p_rows jsonb,
    p_audit_event_id uuid default gen_random_uuid(),
    p_source_event_at text default null,
    p_ledger_entry jsonb default null
)
returns table (
    processed_count bigint,
    remaining_count bigint
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_batch_size bigint;
    v_processed_count bigint;
    v_remaining_count bigint;
    v_audit_metadata jsonb;
    v_ledger_payload jsonb;
begin
    if p_request_id is null
        or p_old_key_version is null
        or p_old_key_version <= 0
        or p_new_key_version is null
        or p_new_key_version <= 0
        or p_old_key_version = p_new_key_version
        or p_rows is null
        or jsonb_typeof(p_rows) <> 'array'
        or jsonb_array_length(p_rows) = 0
        or jsonb_array_length(p_rows) > 1000
        or p_audit_event_id is null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if exists (
        select 1
        from jsonb_array_elements(p_rows) as rows(row_value)
        where jsonb_typeof(rows.row_value) <> 'object'
            or not (
                rows.row_value ?& array[
                    'id',
                    'encrypted_data_key'
                ]
            )
            or rows.row_value - array[
                'id',
                'encrypted_data_key'
            ] <> '{}'::jsonb
            or jsonb_typeof(rows.row_value -> 'id') <> 'string'
            or jsonb_typeof(rows.row_value -> 'encrypted_data_key') <> 'string'
            or rows.row_value ->> 'id' !~ '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
            or rows.row_value ->> 'encrypted_data_key' !~ '^\\x([0-9A-Fa-f]{2}){73}$'
    ) then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if exists (
        select 1
        from (
            select lower(rows.row_value ->> 'id') as id
            from jsonb_array_elements(p_rows) as rows(row_value)
            group by lower(rows.row_value ->> 'id')
            having count(*) > 1
        ) duplicate_rows
    ) then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_ledger_entry is not null
        and (
            jsonb_typeof(p_ledger_entry) <> 'object'
            or p_source_event_at is null
            or not public.ledger_source_event_at_is_valid(p_source_event_at)
            or p_ledger_entry ->> 'p_entry_type' <> 'key_rotation_reencrypted'
            or (p_ledger_entry ->> 'p_request_id')::uuid is distinct from p_request_id
            or (p_ledger_entry ->> 'p_source_event_id')::uuid is distinct from p_audit_event_id
            or p_ledger_entry ->> 'p_source_event_at' <> p_source_event_at
            or p_ledger_entry ->> 'p_result' <> 'success'
            or nullif(p_ledger_entry ->> 'p_target_secret_id', '') is not null
            or nullif(p_ledger_entry ->> 'p_target_secret_version_id', '') is not null
            or nullif(p_ledger_entry ->> 'p_actor_user_id', '') is not null
            or nullif(p_ledger_entry ->> 'p_actor_device_id', '') is not null
        )
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    v_batch_size := jsonb_array_length(p_rows)::bigint;

    with rotation_rows as (
        select
            (rows.row_value ->> 'id')::uuid as id,
            decode(substr(rows.row_value ->> 'encrypted_data_key', 3), 'hex') as encrypted_data_key
        from jsonb_array_elements(p_rows) as rows(row_value)
    ),
    updated as (
        update public.secret_versions sv
        set
            encrypted_data_key = rotation_rows.encrypted_data_key,
            key_version = p_new_key_version
        from rotation_rows
        where sv.id = rotation_rows.id
            and sv.key_version = p_old_key_version
        returning sv.id
    )
    select count(*)::bigint
    into v_processed_count
    from updated;

    if v_processed_count <> v_batch_size then
        raise exception 'key_rotation_conflict' using errcode = '40001';
    end if;

    select count(*)::bigint
    into v_remaining_count
    from public.secret_versions sv
    where sv.key_version = p_old_key_version;

    v_ledger_payload := jsonb_build_object(
        'old_key_version',
        p_old_key_version,
        'new_key_version',
        p_new_key_version,
        'batch_size',
        v_batch_size,
        'processed_count',
        v_processed_count,
        'remaining_count',
        v_remaining_count
    );

    v_audit_metadata := v_ledger_payload;
    if p_ledger_entry is not null then
        v_audit_metadata := v_audit_metadata || jsonb_build_object(
            'source_event_at',
            p_source_event_at
        );

        if p_ledger_entry -> 'p_payload' <> v_ledger_payload then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;
    end if;

    if public.audit_metadata_has_forbidden_key(v_audit_metadata) then
        raise exception 'invalid_audit_metadata' using errcode = '22023';
    end if;

    insert into public.audit_events (
        id,
        request_id,
        action,
        result,
        key_version,
        metadata_json
    )
    values (
        p_audit_event_id,
        p_request_id,
        'key_rotation_reencrypt',
        'success',
        p_new_key_version,
        v_audit_metadata
    );

    if p_ledger_entry is not null then
        perform public.rpc_append_ledger_entry_from_jsonb(p_ledger_entry);
    end if;

    return query
    select
        v_processed_count,
        v_remaining_count;
end;
$$;

drop function public.rpc_complete_key_rotation(uuid, integer, integer);

create function public.rpc_complete_key_rotation(
    p_request_id uuid,
    p_old_key_version integer,
    p_new_key_version integer,
    p_audit_event_id uuid default gen_random_uuid(),
    p_source_event_at text default null,
    p_ledger_entry jsonb default null
)
returns table (
    remaining_count bigint
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_remaining_count bigint;
    v_audit_metadata jsonb;
    v_ledger_payload jsonb;
begin
    if p_request_id is null
        or p_old_key_version is null
        or p_old_key_version <= 0
        or p_new_key_version is null
        or p_new_key_version <= 0
        or p_old_key_version = p_new_key_version
        or p_audit_event_id is null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_ledger_entry is not null
        and (
            jsonb_typeof(p_ledger_entry) <> 'object'
            or p_source_event_at is null
            or not public.ledger_source_event_at_is_valid(p_source_event_at)
            or p_ledger_entry ->> 'p_entry_type' <> 'key_rotation_completed'
            or (p_ledger_entry ->> 'p_request_id')::uuid is distinct from p_request_id
            or (p_ledger_entry ->> 'p_source_event_id')::uuid is distinct from p_audit_event_id
            or p_ledger_entry ->> 'p_source_event_at' <> p_source_event_at
            or p_ledger_entry ->> 'p_result' <> 'success'
            or nullif(p_ledger_entry ->> 'p_target_secret_id', '') is not null
            or nullif(p_ledger_entry ->> 'p_target_secret_version_id', '') is not null
            or nullif(p_ledger_entry ->> 'p_actor_user_id', '') is not null
            or nullif(p_ledger_entry ->> 'p_actor_device_id', '') is not null
        )
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    select count(*)::bigint
    into v_remaining_count
    from public.secret_versions sv
    where sv.key_version = p_old_key_version;

    if v_remaining_count <> 0 then
        raise exception 'key_rotation_incomplete' using errcode = '23514';
    end if;

    v_ledger_payload := jsonb_build_object(
        'old_key_version',
        p_old_key_version,
        'new_key_version',
        p_new_key_version,
        'remaining_count',
        v_remaining_count
    );

    v_audit_metadata := v_ledger_payload;
    if p_ledger_entry is not null then
        v_audit_metadata := v_audit_metadata || jsonb_build_object(
            'source_event_at',
            p_source_event_at
        );

        if p_ledger_entry -> 'p_payload' <> v_ledger_payload then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;
    end if;

    if public.audit_metadata_has_forbidden_key(v_audit_metadata) then
        raise exception 'invalid_audit_metadata' using errcode = '22023';
    end if;

    insert into public.audit_events (
        id,
        request_id,
        action,
        result,
        key_version,
        metadata_json
    )
    values (
        p_audit_event_id,
        p_request_id,
        'key_rotation_complete',
        'success',
        p_new_key_version,
        v_audit_metadata
    );

    if p_ledger_entry is not null then
        perform public.rpc_append_ledger_entry_from_jsonb(p_ledger_entry);
    end if;

    return query
    select v_remaining_count;
end;
$$;

comment on function public.rpc_apply_key_rotation_batch(
    uuid,
    integer,
    integer,
    jsonb,
    uuid,
    text,
    jsonb
) is
    'Applies a validated encrypted_data_key rewrap batch and records key_rotation_reencrypt audit plus optional Ledger Phase 1 entry in one transaction. Each encrypted_data_key must be the 73-byte SBC envelope.';

comment on function public.rpc_complete_key_rotation(
    uuid,
    integer,
    integer,
    uuid,
    text,
    jsonb
) is
    'Completes Master Key rotation only after no rows remain on the old key version, then records key_rotation_complete audit plus optional Ledger Phase 1 entry.';

revoke execute on function public.rpc_apply_key_rotation_batch(
    uuid,
    integer,
    integer,
    jsonb,
    uuid,
    text,
    jsonb
) from public, anon, authenticated;
revoke execute on function public.rpc_apply_key_rotation_batch(
    uuid,
    integer,
    integer,
    jsonb,
    uuid,
    text,
    jsonb
) from public;

revoke execute on function public.rpc_complete_key_rotation(
    uuid,
    integer,
    integer,
    uuid,
    text,
    jsonb
) from public, anon, authenticated;
revoke execute on function public.rpc_complete_key_rotation(
    uuid,
    integer,
    integer,
    uuid,
    text,
    jsonb
) from public;

grant execute on function public.rpc_apply_key_rotation_batch(
    uuid,
    integer,
    integer,
    jsonb,
    uuid,
    text,
    jsonb
) to service_role;
grant execute on function public.rpc_complete_key_rotation(
    uuid,
    integer,
    integer,
    uuid,
    text,
    jsonb
) to service_role;

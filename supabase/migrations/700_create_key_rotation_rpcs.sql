create or replace function public.rpc_key_rotation_status(p_key_version integer)
returns table (
    key_version integer,
    remaining_count bigint
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if p_key_version is null or p_key_version <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return query
    select
        p_key_version,
        count(*)::bigint
    from public.secret_versions sv
    where sv.key_version = p_key_version;
end;
$$;

create or replace function public.rpc_list_key_rotation_batch(
    p_old_key_version integer,
    p_limit integer
)
returns table (
    id uuid,
    secret_id uuid,
    version integer,
    encrypted_data_key bytea,
    key_version integer
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if p_old_key_version is null
        or p_old_key_version <= 0
        or p_limit is null
        or p_limit <= 0
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return query
    select
        sv.id,
        sv.secret_id,
        sv.version,
        sv.encrypted_data_key,
        sv.key_version
    from public.secret_versions sv
    where sv.key_version = p_old_key_version
    order by sv.secret_id, sv.version, sv.id
    limit p_limit;
end;
$$;

create or replace function public.rpc_apply_key_rotation_batch(
    p_request_id uuid,
    p_old_key_version integer,
    p_new_key_version integer,
    p_rows jsonb
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
            or rows.row_value ->> 'encrypted_data_key' !~ '^\\x([0-9A-Fa-f]{2})+$'
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

    v_audit_metadata := jsonb_build_object(
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

    if public.audit_metadata_has_forbidden_key(v_audit_metadata) then
        raise exception 'invalid_audit_metadata' using errcode = '22023';
    end if;

    insert into public.audit_events (
        request_id,
        action,
        result,
        key_version,
        metadata_json
    )
    values (
        p_request_id,
        'key_rotation_reencrypt',
        'success',
        p_new_key_version,
        v_audit_metadata
    );

    return query
    select
        v_processed_count,
        v_remaining_count;
end;
$$;

create or replace function public.rpc_complete_key_rotation(
    p_request_id uuid,
    p_old_key_version integer,
    p_new_key_version integer
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
begin
    if p_request_id is null
        or p_old_key_version is null
        or p_old_key_version <= 0
        or p_new_key_version is null
        or p_new_key_version <= 0
        or p_old_key_version = p_new_key_version
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

    v_audit_metadata := jsonb_build_object(
        'old_key_version',
        p_old_key_version,
        'new_key_version',
        p_new_key_version,
        'remaining_count',
        v_remaining_count
    );

    if public.audit_metadata_has_forbidden_key(v_audit_metadata) then
        raise exception 'invalid_audit_metadata' using errcode = '22023';
    end if;

    insert into public.audit_events (
        request_id,
        action,
        result,
        key_version,
        metadata_json
    )
    values (
        p_request_id,
        'key_rotation_complete',
        'success',
        p_new_key_version,
        v_audit_metadata
    );

    return query
    select v_remaining_count;
end;
$$;

comment on function public.rpc_key_rotation_status(integer) is
    'Counts rows still wrapped with a given Master Key version.';

comment on function public.rpc_list_key_rotation_batch(integer, integer) is
    'Lists encrypted data keys requiring rewrap for a Master Key rotation batch. Does not expose plaintext.';

comment on function public.rpc_apply_key_rotation_batch(uuid, integer, integer, jsonb) is
    'Applies a validated encrypted_data_key rewrap batch and records key_rotation_reencrypt audit in one transaction.';

comment on function public.rpc_complete_key_rotation(uuid, integer, integer) is
    'Completes Master Key rotation only after no rows remain on the old key version, then records key_rotation_complete audit.';

revoke execute on function public.rpc_key_rotation_status(integer) from public, anon, authenticated;
revoke execute on function public.rpc_key_rotation_status(integer) from public;

revoke execute on function public.rpc_list_key_rotation_batch(integer, integer) from public, anon, authenticated;
revoke execute on function public.rpc_list_key_rotation_batch(integer, integer) from public;

revoke execute on function public.rpc_apply_key_rotation_batch(uuid, integer, integer, jsonb) from public, anon, authenticated;
revoke execute on function public.rpc_apply_key_rotation_batch(uuid, integer, integer, jsonb) from public;

revoke execute on function public.rpc_complete_key_rotation(uuid, integer, integer) from public, anon, authenticated;
revoke execute on function public.rpc_complete_key_rotation(uuid, integer, integer) from public;

grant execute on function public.rpc_key_rotation_status(integer) to service_role;
grant execute on function public.rpc_list_key_rotation_batch(integer, integer) to service_role;
grant execute on function public.rpc_apply_key_rotation_batch(uuid, integer, integer, jsonb) to service_role;
grant execute on function public.rpc_complete_key_rotation(uuid, integer, integer) to service_role;

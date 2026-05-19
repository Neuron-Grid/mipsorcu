-- Section 1240: provide owner-scoped alias update context for SBC-side AAD generation.

create function public.rpc_get_secret_alias_for_update(
    p_owner_user_id uuid,
    p_secret_alias_id uuid
)
returns table (secret_id uuid)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_existing public.secret_aliases%rowtype;
begin
    if p_owner_user_id is null
        or p_secret_alias_id is null
        or p_owner_user_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        or p_secret_alias_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    select *
    into v_existing
    from public.secret_aliases sa
    where sa.id = p_secret_alias_id;

    if not found then
        raise exception 'alias_not_found' using errcode = '02000';
    end if;

    if v_existing.owner_user_id <> p_owner_user_id then
        raise exception 'owner_mismatch' using errcode = '42501';
    end if;

    return query select v_existing.secret_id;
end;
$$;

comment on function public.rpc_get_secret_alias_for_update(uuid, uuid) is
    'Returns owner-scoped secret_id for one alias so the SBC can generate alias update AAD without moving AAD construction into SQL.';

revoke execute on function public.rpc_get_secret_alias_for_update(uuid, uuid)
    from public, anon, authenticated;
grant execute on function public.rpc_get_secret_alias_for_update(uuid, uuid)
    to service_role;

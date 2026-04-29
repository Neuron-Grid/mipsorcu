create or replace function public.rpc_sample_restore_test(p_limit integer)
returns table (
    id uuid,
    secret_id uuid,
    version integer,
    ciphertext bytea,
    encrypted_data_key bytea,
    key_version integer,
    nonce_or_iv bytea,
    aad_context jsonb,
    classification text,
    created_at timestamptz
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if p_limit is null or p_limit <= 0 then
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
        sv.nonce_or_iv,
        sv.aad_context,
        sv.classification,
        sv.created_at
    from public.secret_versions sv
    inner join public.secrets s
        on s.id = sv.secret_id
    where s.current_version_id = sv.id
    order by random()
    limit p_limit;
end;
$$;

comment on function public.rpc_sample_restore_test(integer) is
    'Returns current encrypted rows for restore verification. Service-role only; plaintext recovery remains outside Postgres.';

revoke execute on function public.rpc_sample_restore_test(integer) from public, anon, authenticated;
revoke execute on function public.rpc_sample_restore_test(integer) from public;

grant execute on function public.rpc_sample_restore_test(integer) to service_role;

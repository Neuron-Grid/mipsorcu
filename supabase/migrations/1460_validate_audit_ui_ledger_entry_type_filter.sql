-- Section 1460: validate the Audit UI ledger entry_type filter at the RPC boundary.
-- This keeps the read-only audit UI RPC aligned with the Rust LedgerEntryType enum.

create or replace function public.rpc_audit_ui_ledger_entries(
    p_limit integer,
    p_offset integer,
    p_start_sequence_no bigint default null,
    p_end_sequence_no bigint default null,
    p_entry_type text default null,
    p_result text default null
)
returns setof public.auditor_ledger_entries_view
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
begin
    if p_limit is null or p_limit <= 0 or p_limit > 1000 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_offset is null or p_offset < 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_entry_type is not null and (
        length(p_entry_type) > 64
        or not public.ledger_entry_type_allowed(p_entry_type)
    ) then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_result is not null and p_result not in ('success', 'failure') then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return query
    select v.*
    from public.auditor_ledger_entries_view v
    where (p_start_sequence_no is null or v.sequence_no >= p_start_sequence_no)
        and (p_end_sequence_no is null or v.sequence_no <= p_end_sequence_no)
        and (p_entry_type is null or v.entry_type = p_entry_type)
        and (p_result is null or v.result = p_result)
    order by v.sequence_no desc
    limit p_limit offset p_offset;
end;
$$;

comment on function public.rpc_audit_ui_ledger_entries(integer, integer, bigint, bigint, text, text) is
    'Audit UI read RPC. Filtered (sequence range/entry_type/result) + paginated wrapper over auditor_ledger_entries_view. Non-secret fields only. Section 1460 validates entry_type filter vocabulary.';

revoke execute on function public.rpc_audit_ui_ledger_entries(integer, integer, bigint, bigint, text, text) from public, anon, authenticated;
grant execute on function public.rpc_audit_ui_ledger_entries(integer, integer, bigint, bigint, text, text) to service_role;

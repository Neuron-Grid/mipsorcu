-- Section 1350: monthly digest list RPC
-- Ledger Phase 2 / Task 09 monthly digest production support.
-- Read-only RPC that lists previously recorded monthly_digest ledger entries.
-- Returns non-secret metadata only (year-month, sequence range, entry_count,
-- signature_key_version, generation timestamp). 平文・hash・signature・
-- マスターキー・データキー・JWT を一切含まない。

create or replace function public.rpc_list_monthly_digests()
returns table(
    target_year_month       text,
    start_sequence_no       bigint,
    end_sequence_no         bigint,
    entry_count             bigint,
    signature_key_version   integer,
    digest_generated_at     text
)
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
begin
    return query
    select
        le.payload->>'target_year_month',
        (le.payload->>'start_sequence_no')::bigint,
        (le.payload->>'end_sequence_no')::bigint,
        (le.payload->>'entry_count')::bigint,
        le.signature_key_version,
        le.source_event_at
    from public.ledger_entries le
    where le.entry_type = 'monthly_digest'
    order by le.payload->>'target_year_month';
end;
$$;

comment on function public.rpc_list_monthly_digests()
is 'Lists all monthly_digest ledger entries with non-secret summary fields (year-month, sequence range, entry_count, signature_key_version, digest_generated_at), ordered by year-month. Returns no hash/signature/secret material. Task 09.';

grant execute on function public.rpc_list_monthly_digests()
    to service_role, mipsorcu_auditor;

revoke execute on function public.rpc_list_monthly_digests()
    from anon, authenticated, public;

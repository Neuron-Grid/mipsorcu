create policy secrets_select_own
on public.secrets
for select
to authenticated
using ((select auth.uid()) = owner_user_id);

create policy secret_versions_select_current_own
on public.secret_versions
for select
to authenticated
using (
    exists (
        select 1
        from public.secrets s
        where s.id = secret_versions.secret_id
            and s.owner_user_id = (select auth.uid())
            and s.current_version_id = secret_versions.id
    )
);

revoke all on table public.secrets from anon, authenticated;
revoke all on table public.secret_versions from anon, authenticated;
revoke all on table public.audit_events from anon, authenticated;

grant select on table public.secrets to authenticated;
grant select on table public.secret_versions to authenticated;

alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke all on sequences from anon, authenticated;
alter default privileges in schema public revoke all on functions from anon, authenticated;
revoke execute on all functions in schema public from public;
alter default privileges revoke execute on functions from public;

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

grant execute on function public.rpc_write_secret_version(
    uuid,
    text,
    uuid,
    uuid,
    text,
    text,
    timestamptz,
    integer,
    bytea,
    bytea,
    integer,
    text,
    bytea,
    jsonb
) to service_role;

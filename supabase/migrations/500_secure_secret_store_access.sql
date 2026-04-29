create policy secrets_select_own
on public.secrets
for select
to authenticated
using ((select auth.uid()) = owner_user_id);

comment on policy secrets_select_own on public.secrets is
    'Allows authenticated users to read only their own secret aggregate metadata.';

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

comment on policy secret_versions_select_current_own on public.secret_versions is
    'Allows authenticated users to read only the current version of their own secrets.';

create policy audit_events_deny_all
on public.audit_events
as restrictive
for all
to public
using (false)
with check (false);

comment on policy audit_events_deny_all on public.audit_events is
    'Restrictive deny-all policy for runtime roles; audit reads and writes must not bypass the dedicated RPC boundary.';

revoke all on table public.secrets from anon, authenticated;
revoke all on table public.secret_versions from anon, authenticated;
revoke all on table public.audit_events from anon, authenticated;
revoke all privileges on table public.audit_events from service_role;
revoke select, insert, update, delete, truncate on table public.audit_events from service_role;

grant select on table public.secrets to authenticated;
grant select on table public.secret_versions to authenticated;

alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke all on sequences from anon, authenticated;
alter default privileges in schema public revoke all on functions from anon, authenticated;
revoke execute on all functions in schema public from public;
alter default privileges revoke execute on functions from public;

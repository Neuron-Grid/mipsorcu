comment on table public.audit_events is
    'Append-only audit source of truth. Runtime roles must append through SECURITY DEFINER RPCs; direct DML privileges are revoked and UPDATE/DELETE/TRUNCATE are rejected by trigger.';

revoke all privileges on table public.audit_events from service_role;
revoke select, insert, update, delete, truncate on table public.audit_events from service_role;

create or replace function public.audit_events_immutable()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    raise exception 'audit_events_immutable' using errcode = '42501';
end;
$$;

comment on function public.audit_events_immutable() is
    'Rejects UPDATE, DELETE, and TRUNCATE on audit_events so audit_events remains append-only.';

drop trigger if exists audit_events_immutable_update_delete
on public.audit_events;

create trigger audit_events_immutable_update_delete
before update or delete on public.audit_events
for each row
execute function public.audit_events_immutable();

drop trigger if exists audit_events_immutable_truncate
on public.audit_events;

create trigger audit_events_immutable_truncate
before truncate on public.audit_events
for each statement
execute function public.audit_events_immutable();

revoke execute on function public.audit_events_immutable() from public, anon, authenticated;
revoke execute on function public.audit_events_immutable() from public;

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

grant execute on function public.rpc_sample_restore_test(integer) to service_role;

create function public.tg_set_updated_at()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    new.updated_at := now();
    return new;
end;
$$;

comment on function public.tg_set_updated_at() is
    'Maintains secrets.updated_at for aggregate metadata updates.';

create trigger secrets_set_updated_at
before update on public.secrets
for each row
execute function public.tg_set_updated_at();

comment on trigger secrets_set_updated_at on public.secrets is
    'Updates secrets.updated_at when aggregate metadata changes.';

create function public.tg_prevent_secret_classification_change()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if old.classification is distinct from new.classification then
        raise exception 'classification_immutable' using errcode = '23514';
    end if;

    return new;
end;
$$;

comment on function public.tg_prevent_secret_classification_change() is
    'Rejects classification changes after secret creation.';

create trigger secrets_prevent_classification_change
before update of classification on public.secrets
for each row
execute function public.tg_prevent_secret_classification_change();

comment on trigger secrets_prevent_classification_change on public.secrets is
    'Blocks changes to secrets.classification after creation.';

create function public.tg_prevent_secret_owner_change()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if old.owner_user_id is distinct from new.owner_user_id then
        raise exception 'owner_immutable' using errcode = '23514';
    end if;

    return new;
end;
$$;

comment on function public.tg_prevent_secret_owner_change() is
    'Rejects owner changes after secret creation.';

create trigger secrets_prevent_owner_change
before update of owner_user_id on public.secrets
for each row
execute function public.tg_prevent_secret_owner_change();

comment on trigger secrets_prevent_owner_change on public.secrets is
    'Blocks changes to secrets.owner_user_id after creation.';

create function public.audit_events_immutable()
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
    'Rejects UPDATE, DELETE, and TRUNCATE on audit_events so the audit table remains append-only.';

create trigger audit_events_immutable_update_delete
before update or delete on public.audit_events
for each row
execute function public.audit_events_immutable();

comment on trigger audit_events_immutable_update_delete on public.audit_events is
    'Blocks UPDATE and DELETE against audit_events.';

create trigger audit_events_immutable_truncate
before truncate on public.audit_events
for each statement
execute function public.audit_events_immutable();

comment on trigger audit_events_immutable_truncate on public.audit_events is
    'Blocks TRUNCATE against audit_events.';

revoke execute on function public.tg_set_updated_at() from public, anon, authenticated;
revoke execute on function public.tg_set_updated_at() from public;
revoke execute on function public.tg_prevent_secret_classification_change() from public, anon, authenticated;
revoke execute on function public.tg_prevent_secret_classification_change() from public;
revoke execute on function public.tg_prevent_secret_owner_change() from public, anon, authenticated;
revoke execute on function public.tg_prevent_secret_owner_change() from public;
revoke execute on function public.audit_events_immutable() from public, anon, authenticated;
revoke execute on function public.audit_events_immutable() from public;

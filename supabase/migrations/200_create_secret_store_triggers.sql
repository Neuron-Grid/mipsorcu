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

create trigger secrets_set_updated_at
before update on public.secrets
for each row
execute function public.tg_set_updated_at();

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

create trigger secrets_prevent_classification_change
before update of classification on public.secrets
for each row
execute function public.tg_prevent_secret_classification_change();

revoke execute on function public.tg_set_updated_at() from public, anon, authenticated;
revoke execute on function public.tg_prevent_secret_classification_change() from public, anon, authenticated;

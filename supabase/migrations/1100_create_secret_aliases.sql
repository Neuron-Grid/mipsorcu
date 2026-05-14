-- Section 1100: owner-scoped secret aliases

create table public.secret_aliases (
    id uuid primary key default gen_random_uuid(),
    secret_id uuid not null references public.secrets (id) on delete restrict,
    owner_user_id uuid not null references auth.users (id) on delete restrict,
    alias text not null,
    alias_normalized text not null,
    created_at timestamptz not null default now(),
    constraint secret_aliases_id_uuid_v4 check (
        id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    constraint secret_aliases_alias_not_blank check (btrim(alias) <> ''),
    constraint secret_aliases_alias_normalized_not_blank check (
        btrim(alias_normalized) <> ''
    ),
    constraint secret_aliases_alias_length check (length(btrim(alias)) <= 128),
    constraint secret_aliases_alias_slug check (
        btrim(alias) ~ '^[A-Za-z0-9._-]{1,128}$'
    ),
    constraint secret_aliases_alias_normalized_slug check (
        alias_normalized ~ '^[a-z0-9._-]{1,128}$'
    ),
    constraint secret_aliases_alias_normalized_matches_alias check (
        alias_normalized = lower(btrim(alias))
    ),
    constraint secret_aliases_alias_not_uuid_v4 check (
        alias_normalized !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    constraint secret_aliases_owner_alias_unique unique (
        owner_user_id,
        alias_normalized
    )
);

comment on table public.secret_aliases is
    'Owner-scoped aliases used only to resolve API secret_ref input to the canonical secret_id. Alias values are not AAD, audit, or ledger identifiers.';
comment on column public.secret_aliases.secret_id is
    'Canonical secret id that remains the source of truth for crypto, AAD, audit, and ledger records.';
comment on column public.secret_aliases.owner_user_id is
    'Owner scope for alias uniqueness and RLS-protected alias resolution.';
comment on column public.secret_aliases.alias is
    'Trimmed display/input alias. ASCII slug only; never use as a canonical audit, AAD, or ledger identifier.';
comment on column public.secret_aliases.alias_normalized is
    'lowercase normalized alias used for owner-scoped uniqueness and lookup.';
comment on column public.secret_aliases.created_at is
    'DB-confirmed alias linkage creation time. Not bound into AAD.';

create index secret_aliases_secret_id_idx on public.secret_aliases (secret_id);
create index secret_aliases_owner_user_id_idx on public.secret_aliases (owner_user_id);

alter table public.secret_aliases enable row level security;
alter table public.secret_aliases force row level security;

create policy secret_aliases_select_own
on public.secret_aliases
for select
to authenticated
using ((select auth.uid()) = owner_user_id);

comment on policy secret_aliases_select_own on public.secret_aliases is
    'Allows authenticated users to resolve only aliases owned by their Supabase Auth user id.';

revoke all on table public.secret_aliases from anon, authenticated, service_role;
revoke select, insert, update, delete, truncate on table public.secret_aliases from service_role;
grant select on table public.secret_aliases to authenticated;

create or replace function public.rpc_create_secret_alias(
    p_secret_id uuid,
    p_owner_user_id uuid,
    p_alias text,
    p_alias_normalized text
)
returns table (
    secret_id uuid,
    alias text,
    alias_normalized text
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_secret_owner_user_id uuid;
    v_alias text := btrim(p_alias);
    v_alias_normalized text := lower(btrim(p_alias));
begin
    if p_secret_id is null
        or p_secret_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        or p_owner_user_id is null
        or p_alias is null
        or p_alias_normalized is null
        or v_alias = ''
        or length(v_alias) > 128
        or v_alias !~ '^[A-Za-z0-9._-]{1,128}$'
        or p_alias_normalized <> v_alias_normalized
        or p_alias_normalized !~ '^[a-z0-9._-]{1,128}$'
        or p_alias_normalized ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    then
        raise exception 'secret_alias_invalid'
            using errcode = '22023';
    end if;

    select s.owner_user_id
    into v_secret_owner_user_id
    from public.secrets s
    where s.id = p_secret_id;

    if v_secret_owner_user_id is null then
        raise exception 'secret_alias_secret_not_found'
            using errcode = 'P0002';
    end if;

    if v_secret_owner_user_id <> p_owner_user_id then
        raise exception 'secret_alias_owner_mismatch'
            using errcode = '42501';
    end if;

    if exists (
        select 1
        from public.secret_aliases existing
        where existing.owner_user_id = p_owner_user_id
            and existing.alias_normalized = p_alias_normalized
    ) then
        raise exception 'secret_alias_duplicate'
            using errcode = '23505';
    end if;

    insert into public.secret_aliases (
        secret_id,
        owner_user_id,
        alias,
        alias_normalized
    )
    values (
        p_secret_id,
        p_owner_user_id,
        v_alias,
        p_alias_normalized
    );

    return query
    select p_secret_id, v_alias, p_alias_normalized;
end;
$$;

comment on function public.rpc_create_secret_alias(uuid, uuid, text, text) is
    'Creates an owner-scoped alias for an existing secret. Runtime callers receive only canonical secret_id and alias strings; alias is not recorded in audit or ledger payloads.';

revoke execute on function public.rpc_create_secret_alias(uuid, uuid, text, text)
    from public, anon, authenticated;
grant execute on function public.rpc_create_secret_alias(uuid, uuid, text, text)
    to service_role;

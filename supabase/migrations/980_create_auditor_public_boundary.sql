-- Create auditor role

do $$
begin
    if not exists (
        select 1 from pg_catalog.pg_roles where rolname = 'mipsorcu_auditor'
    ) then
        create role mipsorcu_auditor with nologin inherit;
    end if;
end;
$$;

grant mipsorcu_auditor to postgres;
grant usage on schema extensions to mipsorcu_auditor;

-- Ledger signing public key registry

create table public.ledger_signing_public_keys (
    key_version integer primary key,
    public_key bytea not null,
    algorithm text not null default 'ed25519',
    status text not null default 'active',
    created_at timestamptz not null default now(),
    retired_at timestamptz,
    constraint ledger_signing_public_keys_key_version_positive check (key_version > 0),
    constraint ledger_signing_public_keys_public_key_len check (octet_length(public_key) = 32),
    constraint ledger_signing_public_keys_algorithm_fixed check (algorithm = 'ed25519'),
    constraint ledger_signing_public_keys_status_allowed check (status in ('active', 'retired')),
    constraint ledger_signing_public_keys_active_retired_at_null check (
        status <> 'active' or retired_at is null
    ),
    constraint ledger_signing_public_keys_retired_retired_at_not_null check (
        status <> 'retired' or retired_at is not null
    )
);

comment on table public.ledger_signing_public_keys
is 'Ed25519 public key registry for independent ledger signature verification by auditors. Public keys are non-secret.';
comment on column public.ledger_signing_public_keys.key_version
is 'Signing key version. Matches ledger_entries.signature_key_version. Immutable.';
comment on column public.ledger_signing_public_keys.public_key
is 'Ed25519 public key, 32 bytes. Non-secret, suitable for auditor distribution. Immutable.';
comment on column public.ledger_signing_public_keys.algorithm
is 'Signature algorithm. ed25519 fixed. Immutable.';
comment on column public.ledger_signing_public_keys.status
is 'active or retired. Only active -> retired transition is allowed.';
comment on column public.ledger_signing_public_keys.created_at
is 'Registration timestamp. Immutable.';
comment on column public.ledger_signing_public_keys.retired_at
is 'Retirement timestamp. Null for active keys.';

-- Immutability trigger

create or replace function public.ledger_signing_public_keys_check_mutation()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if tg_op = 'INSERT' then
        return new;
    end if;

    if tg_op = 'UPDATE' then
        if old.status = 'active'
            and new.status = 'retired'
            and old.key_version = new.key_version
            and old.public_key = new.public_key
            and old.algorithm = new.algorithm
            and old.created_at = new.created_at
            and new.retired_at is not null
        then
            return new;
        end if;

        raise exception 'ledger_signing_public_keys_immutable'
            using errcode = '42501';
    end if;

    if tg_op = 'DELETE' then
        raise exception 'ledger_signing_public_keys_no_delete'
            using errcode = '42501';
    end if;

    if tg_op = 'TRUNCATE' then
        raise exception 'ledger_signing_public_keys_no_truncate'
            using errcode = '42501';
    end if;

    return null;
end;
$$;

comment on function public.ledger_signing_public_keys_check_mutation()
is 'Rejects UPDATE (except active->retired), DELETE, and TRUNCATE on ledger_signing_public_keys.';

create trigger ledger_signing_public_keys_update_delete
before update or delete on public.ledger_signing_public_keys
for each row
execute function public.ledger_signing_public_keys_check_mutation();

create trigger ledger_signing_public_keys_truncate
before truncate on public.ledger_signing_public_keys
for each statement
execute function public.ledger_signing_public_keys_check_mutation();

-- RLS on public key table

alter table public.ledger_signing_public_keys enable row level security;
alter table public.ledger_signing_public_keys force row level security;

-- No restrictive deny_all on this table; auditors and service_role need
-- SELECT. INSERT / UPDATE / DELETE are controlled by the trigger above.

create policy ledger_signing_public_keys_select_auditor
    on public.ledger_signing_public_keys
    for select
    to mipsorcu_auditor
    using (true);

create policy ledger_signing_public_keys_select_service_role
    on public.ledger_signing_public_keys
    for select
    to service_role
    using (true);

-- Auditor security-barrier views

-- auditor_secret_inventory_view
create or replace view public.auditor_secret_inventory_view
with (security_barrier = true)
as
select
    s.id as secret_id,
    s.owner_user_id,
    s.classification,
    s.current_version_id,
    s.created_at as secret_created_at,
    s.updated_at as secret_updated_at
from public.secrets s;

comment on view public.auditor_secret_inventory_view
is 'Auditor-facing inventory of secrets (non-secret metadata only). security_barrier prevents leak via joins.';

-- auditor_audit_events_view
create or replace view public.auditor_audit_events_view
with (security_barrier = true)
as
select
    ae.id as audit_event_id,
    ae.request_id,
    ae.actor_user_id,
    ae.actor_device_id,
    ae.action,
    ae.target_secret_id,
    ae.result,
    ae.key_version,
    ae.metadata_json,
    ae.occurred_at
from public.audit_events ae;

comment on view public.auditor_audit_events_view
is 'Auditor-facing audit event log (non-secret metadata only). security_barrier prevents leak via joins.';

-- auditor_ledger_entries_view
create or replace view public.auditor_ledger_entries_view
with (security_barrier = true)
as
select
    le.id as ledger_entry_id,
    le.sequence_no,
    le.entry_type,
    le.source_event_at,
    le.request_id,
    le.source_event_id,
    le.target_secret_id,
    le.target_secret_version_id,
    le.actor_user_id,
    le.actor_device_id,
    le.result,
    le.error_code,
    le.payload,
    le.canonicalization_version,
    le.previous_entry_hash,
    le.entry_hash,
    le.hash_algorithm,
    le.signature,
    le.signature_algorithm,
    le.signature_key_version,
    le.created_at
from public.ledger_entries le;

comment on view public.auditor_ledger_entries_view
is 'Auditor-facing ledger entries (non-secret fields only). security_barrier prevents leak via joins.';

-- auditor_integrity_status_view
create or replace view public.auditor_integrity_status_view
with (security_barrier = true)
as
select
    lcs.chain_id,
    lcs.last_sequence_no,
    lcs.last_entry_hash,
    lcs.updated_at as chain_state_updated_at
from public.ledger_chain_state lcs;

comment on view public.auditor_integrity_status_view
is 'Auditor-facing global chain head state. security_barrier prevents leak via joins.';

-- RPC: rpc_register_ledger_signing_public_key

create or replace function public.rpc_register_ledger_signing_public_key(
    p_key_version integer,
    p_public_key bytea
)
returns table (
    out_key_version integer,
    public_key bytea,
    algorithm text,
    status text,
    created_at timestamptz,
    retired_at timestamptz,
    replayed boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_existing public.ledger_signing_public_keys%rowtype;
begin
    if p_key_version is null or p_key_version <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_public_key is null or octet_length(p_public_key) <> 32 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    select *
    into v_existing
    from public.ledger_signing_public_keys
    where ledger_signing_public_keys.key_version = rpc_register_ledger_signing_public_key.p_key_version;

    if found then
        if v_existing.public_key = p_public_key
            and v_existing.status in ('active', 'retired')
        then
            out_key_version := v_existing.key_version;
            public_key := v_existing.public_key;
            algorithm := v_existing.algorithm;
            status := v_existing.status;
            created_at := v_existing.created_at;
            retired_at := v_existing.retired_at;
            replayed := true;
            return next;
            return;
        end if;

        if v_existing.status = 'retired' then
            raise exception 'ledger_signing_public_key_retired'
                using errcode = '23505';
        end if;

        raise exception 'ledger_signing_public_key_conflict'
            using errcode = '23505';
    end if;

    insert into public.ledger_signing_public_keys (
        key_version,
        public_key,
        algorithm,
        status,
        created_at
    )
    values (
        p_key_version,
        p_public_key,
        'ed25519',
        'active',
        now()
    )
    returning *
    into v_existing;

    out_key_version := v_existing.key_version;
    public_key := v_existing.public_key;
    algorithm := v_existing.algorithm;
    status := v_existing.status;
    created_at := v_existing.created_at;
    retired_at := v_existing.retired_at;
    replayed := false;
    return next;
end;
$$;

comment on function public.rpc_register_ledger_signing_public_key(integer, bytea)
is 'Registers an Ed25519 public key for ledger signature verification. Idempotent for same key_version + public_key.';

-- RPC: rpc_retire_ledger_signing_public_key

create or replace function public.rpc_retire_ledger_signing_public_key(
    p_key_version integer
)
returns table (
    out_key_version integer,
    public_key bytea,
    algorithm text,
    status text,
    created_at timestamptz,
    retired_at timestamptz,
    already_retired boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_row public.ledger_signing_public_keys%rowtype;
begin
    if p_key_version is null or p_key_version <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    select *
    into v_row
    from public.ledger_signing_public_keys
    where ledger_signing_public_keys.key_version = rpc_retire_ledger_signing_public_key.p_key_version;

    if not found then
        raise exception 'ledger_signing_public_key_not_found'
            using errcode = '02000';
    end if;

    if v_row.status = 'retired' then
        out_key_version := v_row.key_version;
        public_key := v_row.public_key;
        algorithm := v_row.algorithm;
        status := v_row.status;
        created_at := v_row.created_at;
        retired_at := v_row.retired_at;
        already_retired := true;
        return next;
        return;
    end if;

    update public.ledger_signing_public_keys
    set status = 'retired',
        retired_at = now()
    where ledger_signing_public_keys.key_version = rpc_retire_ledger_signing_public_key.p_key_version
    returning *
    into v_row;

    out_key_version := v_row.key_version;
    public_key := v_row.public_key;
    algorithm := v_row.algorithm;
    status := v_row.status;
    created_at := v_row.created_at;
    retired_at := v_row.retired_at;
    already_retired := false;
    return next;
end;
$$;

comment on function public.rpc_retire_ledger_signing_public_key(integer)
is 'Retires an active Ed25519 signing public key. Idempotent for already-retired keys.';

-- RPC: rpc_verify_ledger_hash_chain

create or replace function public.rpc_verify_ledger_hash_chain(
    p_start_sequence_no bigint default null,
    p_end_sequence_no bigint default null
)
returns table (
    chain_valid boolean,
    entries_checked bigint,
    first_gap_sequence_no bigint,
    first_gap_detail text,
    first_hash_mismatch_sequence_no bigint,
    first_hash_mismatch_detail text,
    chain_head_sequence_no bigint,
    chain_head_entry_hash bytea
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_curr record;
    v_checked bigint := 0;
    v_chain_head record;
    v_expected_prev_hash bytea;
    v_expected_sequence_no bigint;
    v_last_sequence_no bigint := null;
    v_last_entry_hash bytea := null;
    v_zero_hash bytea := decode(repeat('00', 32), 'hex');
begin
    if p_start_sequence_no is not null and p_start_sequence_no <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_end_sequence_no is not null and p_end_sequence_no <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_start_sequence_no is not null and p_end_sequence_no is not null
        and p_start_sequence_no > p_end_sequence_no then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    select lcs.last_sequence_no, lcs.last_entry_hash
    into v_chain_head
    from public.ledger_chain_state lcs
    where lcs.chain_id = 'global';

    if not found then
        chain_valid := false;
        entries_checked := 0;
        first_gap_sequence_no := null;
        first_gap_detail := 'chain state missing';
        first_hash_mismatch_sequence_no := null;
        first_hash_mismatch_detail := null;
        chain_head_sequence_no := null;
        chain_head_entry_hash := null;
        return next;
        return;
    end if;

    chain_head_sequence_no := v_chain_head.last_sequence_no;
    chain_head_entry_hash := v_chain_head.last_entry_hash;
    v_expected_sequence_no := coalesce(p_start_sequence_no, 1);

    if p_start_sequence_no is not null and p_start_sequence_no > 1 then
        select prec.entry_hash
        into v_expected_prev_hash
        from public.ledger_entries prec
        where prec.sequence_no = p_start_sequence_no - 1;

        if not found then
            chain_valid := false;
            entries_checked := 0;
            first_gap_sequence_no := p_start_sequence_no - 1;
            first_gap_detail := 'sequence ' || (p_start_sequence_no - 1)::text
                || ': preceding ledger entry missing for range start '
                || p_start_sequence_no::text;
            first_hash_mismatch_sequence_no := null;
            first_hash_mismatch_detail := null;
            return next;
            return;
        end if;
    else
        v_expected_prev_hash := v_zero_hash;
    end if;

    for v_curr in
        select
            le.sequence_no,
            le.previous_entry_hash,
            le.entry_hash
        from public.ledger_entries le
        where (
            p_start_sequence_no is null
            or le.sequence_no >= p_start_sequence_no
        )
        and (
            p_end_sequence_no is null
            or le.sequence_no <= p_end_sequence_no
        )
        order by le.sequence_no
    loop
        if v_curr.sequence_no <> v_expected_sequence_no then
            chain_valid := false;
            entries_checked := v_checked;
            first_gap_sequence_no := v_expected_sequence_no;
            first_gap_detail := 'sequence ' || v_expected_sequence_no::text
                || ': expected sequence_no, found '
                || v_curr.sequence_no::text;
            first_hash_mismatch_sequence_no := null;
            first_hash_mismatch_detail := null;
            return next;
            return;
        end if;

        if v_curr.previous_entry_hash is distinct from v_expected_prev_hash then
            if v_expected_prev_hash = v_zero_hash then
                first_hash_mismatch_detail := 'sequence ' || v_curr.sequence_no::text
                    || ': previous_entry_hash does not match genesis zero hash';
            else
                first_hash_mismatch_detail := 'sequence ' || v_curr.sequence_no::text
                    || ': previous_entry_hash does not match preceding entry_hash '
                    || 'at sequence ' || (v_curr.sequence_no - 1)::text;
            end if;
            first_hash_mismatch_sequence_no := v_curr.sequence_no;
            chain_valid := false;
            entries_checked := v_checked;
            return next;
            return;
        end if;

        v_expected_prev_hash := v_curr.entry_hash;
        v_last_sequence_no := v_curr.sequence_no;
        v_last_entry_hash := v_curr.entry_hash;
        v_checked := v_checked + 1;
        v_expected_sequence_no := v_expected_sequence_no + 1;
    end loop;

    if p_end_sequence_no is not null and v_expected_sequence_no <= p_end_sequence_no then
        chain_valid := false;
        entries_checked := v_checked;
        first_gap_sequence_no := v_expected_sequence_no;
        first_gap_detail := 'sequence ' || v_expected_sequence_no::text
            || ': expected sequence_no before range end '
            || p_end_sequence_no::text;
        first_hash_mismatch_sequence_no := null;
        first_hash_mismatch_detail := null;
        return next;
        return;
    end if;

    if p_start_sequence_no is null and p_end_sequence_no is null then
        if v_checked = 0 then
            if v_chain_head.last_sequence_no is distinct from 0 then
                chain_valid := false;
                entries_checked := v_checked;
                first_gap_sequence_no := 1;
                first_gap_detail := 'ledger_chain_state last_sequence_no mismatch: '
                    || 'expected 0 for empty ledger, found '
                    || coalesce(v_chain_head.last_sequence_no::text, 'null');
                first_hash_mismatch_sequence_no := null;
                first_hash_mismatch_detail := null;
                return next;
                return;
            end if;

            if v_chain_head.last_entry_hash is distinct from v_zero_hash then
                chain_valid := false;
                entries_checked := v_checked;
                first_gap_sequence_no := null;
                first_gap_detail := null;
                first_hash_mismatch_sequence_no := 0;
                first_hash_mismatch_detail := 'ledger_chain_state last_entry_hash mismatch: '
                    || 'expected genesis zero hash for empty ledger';
                return next;
                return;
            end if;
        else
            if v_chain_head.last_sequence_no is distinct from v_last_sequence_no then
                chain_valid := false;
                entries_checked := v_checked;
                first_gap_sequence_no := v_last_sequence_no;
                first_gap_detail := 'ledger_chain_state last_sequence_no mismatch: expected '
                    || v_last_sequence_no::text || ', found '
                    || coalesce(v_chain_head.last_sequence_no::text, 'null');
                first_hash_mismatch_sequence_no := null;
                first_hash_mismatch_detail := null;
                return next;
                return;
            end if;

            if v_chain_head.last_entry_hash is distinct from v_last_entry_hash then
                chain_valid := false;
                entries_checked := v_checked;
                first_gap_sequence_no := null;
                first_gap_detail := null;
                first_hash_mismatch_sequence_no := v_last_sequence_no;
                first_hash_mismatch_detail := 'ledger_chain_state last_entry_hash mismatch: '
                    || 'expected entry_hash at sequence '
                    || v_last_sequence_no::text;
                return next;
                return;
            end if;
        end if;
    end if;

    chain_valid := true;
    entries_checked := v_checked;
    first_gap_sequence_no := null;
    first_gap_detail := null;
    first_hash_mismatch_sequence_no := null;
    first_hash_mismatch_detail := null;
    return next;
end;
$$;

comment on function public.rpc_verify_ledger_hash_chain(bigint, bigint)
is 'Verifies sequence_no continuity, previous_entry_hash chain, and full-chain ledger_chain_state consistency. Does not reconstruct canonical payload, recompute entry_hash, or verify Ed25519 signatures (Rust responsibility).';

-- RPC: rpc_verify_ledger_range

create or replace function public.rpc_verify_ledger_range(
    p_start_sequence_no bigint,
    p_end_sequence_no bigint
)
returns table (
    range_valid boolean,
    entries_checked bigint,
    expected_count bigint,
    detail text
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_expected bigint;
    v_actual bigint;
begin
    if p_start_sequence_no is null or p_start_sequence_no <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_end_sequence_no is null or p_end_sequence_no <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_start_sequence_no > p_end_sequence_no then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    v_expected := p_end_sequence_no - p_start_sequence_no + 1;

    select count(*)::bigint
    into v_actual
    from public.ledger_entries le
    where le.sequence_no >= p_start_sequence_no
        and le.sequence_no <= p_end_sequence_no;

    entries_checked := v_actual;
    expected_count := v_expected;

    if v_actual = v_expected then
        range_valid := true;
        detail := 'range [' || p_start_sequence_no::text || ', '
            || p_end_sequence_no::text || '] is complete';
    else
        range_valid := false;
        detail := 'range [' || p_start_sequence_no::text || ', '
            || p_end_sequence_no::text || '] expected '
            || v_expected::text || ' entries, found ' || v_actual::text;
    end if;

    return next;
end;
$$;

comment on function public.rpc_verify_ledger_range(bigint, bigint)
is 'Verifies that a sequence_no range has exactly the expected number of entries with no gaps or extra entries.';

-- RPC: rpc_export_ledger_verification_materials

create or replace function public.rpc_export_ledger_verification_materials(
    p_start_sequence_no bigint default null,
    p_end_sequence_no bigint default null
)
returns table (
    ledger_entry_id uuid,
    sequence_no bigint,
    entry_hash bytea,
    previous_entry_hash bytea,
    signature bytea,
    signature_key_version integer,
    entry_type text,
    source_event_at text,
    request_id uuid,
    source_event_id uuid,
    target_secret_id uuid,
    target_secret_version_id uuid,
    actor_user_id uuid,
    actor_device_id text,
    result text,
    error_code text,
    payload jsonb,
    canonicalization_version integer,
    hash_algorithm text,
    signature_algorithm text,
    pk_key_version integer,
    pk_public_key bytea,
    pk_algorithm text,
    pk_status text,
    pk_created_at timestamptz,
    pk_retired_at timestamptz
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if p_start_sequence_no is not null and p_start_sequence_no <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_end_sequence_no is not null and p_end_sequence_no <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_start_sequence_no is not null and p_end_sequence_no is not null
        and p_start_sequence_no > p_end_sequence_no then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return query
    select
        le.id as ledger_entry_id,
        le.sequence_no,
        le.entry_hash,
        le.previous_entry_hash,
        le.signature,
        le.signature_key_version,
        le.entry_type,
        le.source_event_at,
        le.request_id,
        le.source_event_id,
        le.target_secret_id,
        le.target_secret_version_id,
        le.actor_user_id,
        le.actor_device_id,
        le.result,
        le.error_code,
        le.payload,
        le.canonicalization_version,
        le.hash_algorithm,
        le.signature_algorithm,
        pk.key_version as pk_key_version,
        pk.public_key as pk_public_key,
        pk.algorithm as pk_algorithm,
        pk.status as pk_status,
        pk.created_at as pk_created_at,
        pk.retired_at as pk_retired_at
    from public.ledger_entries le
    left join public.ledger_signing_public_keys pk
        on le.signature_key_version = pk.key_version
    where (
        p_start_sequence_no is null
        or le.sequence_no >= p_start_sequence_no
    )
    and (
        p_end_sequence_no is null
        or le.sequence_no <= p_end_sequence_no
    )
    order by le.sequence_no;
end;
$$;

comment on function public.rpc_export_ledger_verification_materials(bigint, bigint)
is 'Exports complete non-secret ledger canonical fields with LEFT JOINed public key materials for independent auditor verification. Retired keys are included; missing keys produce pk_* IS NULL columns.';

-- GRANT / REVOKE

-- Grant auditor select on views
grant select on public.auditor_secret_inventory_view to mipsorcu_auditor;
grant select on public.auditor_audit_events_view to mipsorcu_auditor;
grant select on public.auditor_ledger_entries_view to mipsorcu_auditor;
grant select on public.auditor_integrity_status_view to mipsorcu_auditor;

-- Grant auditor execute on verification / export RPCs
grant execute on function public.rpc_verify_ledger_hash_chain(bigint, bigint)
    to mipsorcu_auditor;
grant execute on function public.rpc_verify_ledger_range(bigint, bigint)
    to mipsorcu_auditor;
grant execute on function public.rpc_export_ledger_verification_materials(bigint, bigint)
    to mipsorcu_auditor;

-- Grant service_role minimal privileges
grant select on public.ledger_signing_public_keys to service_role;
grant execute on function public.rpc_register_ledger_signing_public_key(integer, bytea)
    to service_role;
grant execute on function public.rpc_retire_ledger_signing_public_key(integer)
    to service_role;
grant execute on function public.rpc_verify_ledger_hash_chain(bigint, bigint)
    to service_role;
grant execute on function public.rpc_verify_ledger_range(bigint, bigint)
    to service_role;
grant execute on function public.rpc_export_ledger_verification_materials(bigint, bigint)
    to service_role;

-- Grant auditor select on public key registry
grant select on public.ledger_signing_public_keys to mipsorcu_auditor;

-- Revoke everything from anon / authenticated for new RPCs
revoke execute on function public.rpc_register_ledger_signing_public_key(integer, bytea)
    from anon, authenticated, public;
revoke execute on function public.rpc_retire_ledger_signing_public_key(integer)
    from anon, authenticated, public;
revoke execute on function public.rpc_verify_ledger_hash_chain(bigint, bigint)
    from anon, authenticated, public;
revoke execute on function public.rpc_verify_ledger_range(bigint, bigint)
    from anon, authenticated, public;
revoke execute on function public.rpc_export_ledger_verification_materials(bigint, bigint)
    from anon, authenticated, public;

-- Revoke table access from anon / authenticated
revoke all on public.ledger_signing_public_keys from anon, authenticated;
revoke all on public.auditor_secret_inventory_view from anon, authenticated;
revoke all on public.auditor_audit_events_view from anon, authenticated;
revoke all on public.auditor_ledger_entries_view from anon, authenticated;
revoke all on public.auditor_integrity_status_view from anon, authenticated;

-- Revoke view access from service_role (service_role uses base tables + RPCs, not views)
revoke all on public.auditor_secret_inventory_view from service_role;
revoke all on public.auditor_audit_events_view from service_role;
revoke all on public.auditor_ledger_entries_view from service_role;
revoke all on public.auditor_integrity_status_view from service_role;

-- Revoke service_role table-level DML on public key table (SELECT only)
revoke insert, update, delete, truncate on public.ledger_signing_public_keys from service_role;

-- Ledger Phase 1 SQL support.
-- The audit_events table remains the primary audit record. ledger_entries adds
-- append-only hash-chain evidence without backfilling audit_events.

create or replace function public.ledger_source_event_at_is_valid(p_source_event_at text)
returns boolean
language plpgsql
stable
set search_path = public, pg_temp
as $$
declare
    v_parsed timestamptz;
begin
    if p_source_event_at is null then
        return false;
    end if;

    if p_source_event_at !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$' then
        return false;
    end if;

    begin
        v_parsed := p_source_event_at::timestamptz;
    exception
        when others then
            return false;
    end;

    return to_char(v_parsed at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') = p_source_event_at
        or (
            p_source_event_at ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+Z$'
            and (v_parsed at time zone 'UTC')::text is not null
        );
end;
$$;

comment on function public.ledger_source_event_at_is_valid(text)
is 'Validates canonical UTC RFC3339 producer timestamps for ledger_entries.source_event_at.';

create or replace function public.ledger_entry_type_allowed(p_entry_type text)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select p_entry_type in (
        'secret_created',
        'secret_version_created',
        'secret_decrypted',
        'secret_version_purged',
        'integrity_check_completed',
        'restore_test_completed',
        'key_rotation_started',
        'key_rotation_reencrypted',
        'key_rotation_completed',
        'key_rotation_aborted',
        'ledger_verified',
        'ledger_verification_failed',
        'audit_fallback_resent'
    );
$$;

comment on function public.ledger_entry_type_allowed(text)
is 'Returns true for Ledger Phase 1 entry_type vocabulary only.';

create or replace function public.ledger_payload_allowed_keys(p_entry_type text)
returns text[]
language sql
stable
set search_path = public, pg_temp
as $$
    select case p_entry_type
        when 'secret_created' then array['algorithm', 'classification', 'key_version', 'version']::text[]
        when 'secret_version_created' then array['algorithm', 'classification', 'key_version', 'version']::text[]
        when 'secret_decrypted' then array['algorithm', 'key_version', 'version']::text[]
        when 'secret_version_purged' then array['key_version', 'retention_limit', 'version']::text[]
        when 'integrity_check_completed' then array[
            'checked_audit_event_count',
            'checked_secret_count',
            'checked_secret_version_count',
            'duration_ms',
            'violation_count'
        ]::text[]
        when 'restore_test_completed' then array[
            'duration_ms',
            'failure_count',
            'sample_count',
            'success_count',
            'trigger'
        ]::text[]
        when 'key_rotation_started' then array['new_key_version', 'old_key_version']::text[]
        when 'key_rotation_reencrypted' then array[
            'batch_size',
            'new_key_version',
            'old_key_version',
            'processed_count',
            'remaining_count'
        ]::text[]
        when 'key_rotation_completed' then array[
            'new_key_version',
            'old_key_version',
            'remaining_count'
        ]::text[]
        when 'key_rotation_aborted' then array[
            'new_key_version',
            'old_key_version',
            'reason_code'
        ]::text[]
        when 'ledger_verified' then array[
            'checked_count',
            'duration_ms',
            'end_sequence_no',
            'start_sequence_no'
        ]::text[]
        when 'ledger_verification_failed' then array[
            'end_sequence_no',
            'error_code',
            'failed_count',
            'start_sequence_no'
        ]::text[]
        when 'audit_fallback_resent' then array[
            'duration_ms',
            'failed_count',
            'resent_count'
        ]::text[]
        else null::text[]
    end;
$$;

comment on function public.ledger_payload_allowed_keys(text)
is 'Returns top-level ledger payload keys allowed for a Ledger Phase 1 entry_type.';

create or replace function public.ledger_payload_has_forbidden_key(p_payload jsonb)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    with recursive nodes(value) as (
        select p_payload
        where p_payload is not null
        union all
        select child.value
        from nodes
        cross join lateral (
            select value
            from jsonb_each(nodes.value)
            where jsonb_typeof(nodes.value) = 'object'
            union all
            select value
            from jsonb_array_elements(nodes.value)
            where jsonb_typeof(nodes.value) = 'array'
        ) as child
    ),
    keys(key_name) as (
        select lower(btrim(obj.key))
        from nodes
        cross join lateral jsonb_each(nodes.value) as obj(key, value)
        where jsonb_typeof(nodes.value) = 'object'
    )
    select exists (
        select 1
        from keys
        where key_name in (
            'authorization',
            'ciphertext',
            'data_key',
            'decrypt_result',
            'decrypted',
            'decrypted_data',
            'encrypted_data_key',
            'jwt',
            'master_key',
            'passphrase',
            'password',
            'plain_text',
            'plaintext',
            'request_body',
            'response_body',
            'secret_key',
            'secret_value',
            'service_role',
            'service_role_key',
            'token'
        )
    );
$$;

comment on function public.ledger_payload_has_forbidden_key(jsonb)
is 'Recursively rejects ledger payload keys that could carry plaintext, decryptable data, credentials, or key material.';

create or replace function public.ledger_payload_has_unknown_key(
    p_entry_type text,
    p_payload jsonb
)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select case
        when p_payload is null then true
        when jsonb_typeof(p_payload) <> 'object' then true
        when public.ledger_payload_allowed_keys(p_entry_type) is null then true
        else exists (
            select 1
            from jsonb_object_keys(p_payload) as payload_keys(key)
            where not (payload_keys.key = any(public.ledger_payload_allowed_keys(p_entry_type)))
        )
    end;
$$;

comment on function public.ledger_payload_has_unknown_key(text, jsonb)
is 'Returns true when a ledger payload includes keys outside the entry_type allowlist.';

create or replace function public.ledger_payload_schema_is_valid(
    p_entry_type text,
    p_payload jsonb
)
returns boolean
language plpgsql
stable
set search_path = public, pg_temp
as $$
declare
    v_key text;
    v_value jsonb;
    v_text text;
    v_integer bigint;
    v_old_key_version bigint;
    v_new_key_version bigint;
begin
    if p_payload is null or jsonb_typeof(p_payload) <> 'object' then
        return false;
    end if;

    if not public.ledger_entry_type_allowed(p_entry_type) then
        return false;
    end if;

    if public.ledger_payload_has_unknown_key(p_entry_type, p_payload) then
        return false;
    end if;

    if exists (
        select 1
        from jsonb_each(p_payload) as fields(key, value)
        where jsonb_typeof(fields.value) in ('object', 'array')
    ) then
        return false;
    end if;

    for v_key, v_value in
        select fields.key, fields.value
        from jsonb_each(p_payload) as fields(key, value)
    loop
        if v_key in (
            'version',
            'key_version',
            'old_key_version',
            'new_key_version',
            'retention_limit',
            'start_sequence_no',
            'end_sequence_no'
        ) then
            if jsonb_typeof(v_value) <> 'number' or (v_value #>> '{}') !~ '^[0-9]+$' then
                return false;
            end if;

            v_integer := (v_value #>> '{}')::bigint;

            if v_integer <= 0 then
                return false;
            end if;

            if v_key = 'retention_limit' and v_integer <> 4 then
                return false;
            end if;
        elsif v_key in (
            'batch_size',
            'checked_audit_event_count',
            'checked_count',
            'checked_secret_count',
            'checked_secret_version_count',
            'duration_ms',
            'failed_count',
            'failure_count',
            'processed_count',
            'remaining_count',
            'resent_count',
            'sample_count',
            'success_count',
            'violation_count'
        ) then
            if jsonb_typeof(v_value) <> 'number' or (v_value #>> '{}') !~ '^[0-9]+$' then
                return false;
            end if;

            v_integer := (v_value #>> '{}')::bigint;

            if v_integer < 0 then
                return false;
            end if;
        elsif v_key = 'algorithm' then
            if jsonb_typeof(v_value) <> 'string' or v_value #>> '{}' <> 'xchacha20-poly1305' then
                return false;
            end if;
        elsif v_key = 'classification' then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;

            v_text := v_value #>> '{}';

            if btrim(v_text) = '' or length(v_text) > 128 then
                return false;
            end if;
        elsif v_key = 'trigger' then
            if jsonb_typeof(v_value) <> 'string' or (v_value #>> '{}') not in (
                'background',
                'cli',
                'scheduled',
                'startup'
            ) then
                return false;
            end if;
        elsif v_key in ('error_code', 'reason_code') then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;

            v_text := v_value #>> '{}';

            if btrim(v_text) = '' or length(v_text) > 128 then
                return false;
            end if;
        else
            return false;
        end if;
    end loop;

    if p_payload ? 'old_key_version' and p_payload ? 'new_key_version' then
        v_old_key_version := (p_payload ->> 'old_key_version')::bigint;
        v_new_key_version := (p_payload ->> 'new_key_version')::bigint;

        if v_old_key_version = v_new_key_version then
            return false;
        end if;
    end if;

    return true;
exception
    when numeric_value_out_of_range then
        return false;
end;
$$;

comment on function public.ledger_payload_schema_is_valid(text, jsonb)
is 'Validates type, length, vocabulary, and numeric range for Ledger Phase 1 payload fields.';

create or replace function public.ledger_payload_is_valid(
    p_entry_type text,
    p_payload jsonb
)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select p_payload is not null
        and jsonb_typeof(p_payload) = 'object'
        and pg_column_size(p_payload) <= 8192
        and public.ledger_entry_type_allowed(p_entry_type)
        and not public.ledger_payload_has_forbidden_key(p_payload)
        and not public.ledger_payload_has_unknown_key(p_entry_type, p_payload)
        and public.ledger_payload_schema_is_valid(p_entry_type, p_payload);
$$;

comment on function public.ledger_payload_is_valid(text, jsonb)
is 'Composite ledger payload guard used by table constraints and rpc_append_ledger_entry.';

create table public.ledger_entries (
    id uuid primary key,
    sequence_no bigint not null,
    entry_type text not null,
    source_event_at text not null,
    request_id uuid not null,
    source_event_id uuid,
    target_secret_id uuid,
    target_secret_version_id uuid,
    actor_user_id uuid,
    actor_device_id text,
    result text not null,
    error_code text,
    payload jsonb not null,
    canonicalization_version integer not null,
    previous_entry_hash bytea not null,
    entry_hash bytea not null,
    hash_algorithm text not null,
    signature bytea not null,
    signature_algorithm text not null,
    signature_key_version integer not null,
    created_at timestamptz not null default now(),
    constraint ledger_entries_id_uuid_v4 check (
        id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    constraint ledger_entries_sequence_no_positive check (sequence_no > 0),
    constraint ledger_entries_sequence_no_unique unique (sequence_no),
    constraint ledger_entries_entry_type_allowed check (
        length(entry_type) <= 64
        and public.ledger_entry_type_allowed(entry_type)
    ),
    constraint ledger_entries_source_event_at_canonical check (
        public.ledger_source_event_at_is_valid(source_event_at)
    ),
    constraint ledger_entries_actor_device_id_non_blank check (
        actor_device_id is null
        or (btrim(actor_device_id) <> '' and length(actor_device_id) <= 128)
    ),
    constraint ledger_entries_result_allowed check (result in ('success', 'failure')),
    constraint ledger_entries_error_code_non_blank check (
        error_code is null
        or (btrim(error_code) <> '' and length(error_code) <= 128)
    ),
    constraint ledger_entries_success_error_code_null check (
        result <> 'success'
        or error_code is null
    ),
    constraint ledger_entries_payload_valid check (
        public.ledger_payload_is_valid(entry_type, payload)
    ),
    constraint ledger_entries_canonicalization_version_v1 check (
        canonicalization_version = 1
    ),
    constraint ledger_entries_previous_entry_hash_len check (
        octet_length(previous_entry_hash) = 32
    ),
    constraint ledger_entries_entry_hash_len check (
        octet_length(entry_hash) = 32
    ),
    constraint ledger_entries_entry_hash_unique unique (entry_hash),
    constraint ledger_entries_hash_algorithm_sha256 check (
        hash_algorithm = 'sha-256'
    ),
    constraint ledger_entries_signature_len check (
        octet_length(signature) = 64
    ),
    constraint ledger_entries_signature_algorithm_ed25519 check (
        signature_algorithm = 'ed25519'
    ),
    constraint ledger_entries_signature_key_version_positive check (
        signature_key_version > 0
    )
);

comment on table public.ledger_entries
is 'Append-only Ledger Phase 1 entries for global hash-chain verification. Does not replace audit_events.';
comment on column public.ledger_entries.id is 'Caller-supplied UUID v4 idempotency key generated by Rust/SBC.';
comment on column public.ledger_entries.sequence_no is 'Caller-supplied expected global sequence number, verified under ledger_chain_state row lock.';
comment on column public.ledger_entries.source_event_at is 'Producer timestamp in canonical UTC RFC3339 text; part of the signed canonical payload.';
comment on column public.ledger_entries.source_event_id is 'Optional audit_events.id UUID snapshot. No FK so audit_events remains append-only and independent.';
comment on column public.ledger_entries.target_secret_id is 'Optional secret UUID snapshot. No FK to keep ledger verification independent of later lifecycle changes.';
comment on column public.ledger_entries.target_secret_version_id is 'Optional secret version UUID snapshot. No FK so four-generation purge cannot break ledger verification.';
comment on column public.ledger_entries.payload is 'Allowlisted, non-secret, flat JSON object. Canonical JSONB serialization is not used for hashing.';
comment on column public.ledger_entries.entry_hash is 'Rust/SBC-computed SHA-256 entry hash. SQL stores and chains it but does not recompute it.';
comment on column public.ledger_entries.signature is 'Rust/SBC-generated Ed25519 signature. SQL stores it but never holds signing private keys.';
comment on column public.ledger_entries.created_at is 'Database insertion timestamp. Not part of the signed canonical ledger payload.';

create index ledger_entries_request_id_idx on public.ledger_entries (request_id);
create index ledger_entries_source_event_id_idx on public.ledger_entries (source_event_id);
create index ledger_entries_target_secret_id_idx on public.ledger_entries (target_secret_id);
create index ledger_entries_target_secret_version_id_idx on public.ledger_entries (target_secret_version_id);
create index ledger_entries_actor_user_id_idx on public.ledger_entries (actor_user_id);
create index ledger_entries_entry_type_source_event_at_idx on public.ledger_entries (entry_type, source_event_at);
create index ledger_entries_signature_key_version_idx on public.ledger_entries (signature_key_version);

create table public.ledger_chain_state (
    chain_id text primary key,
    last_sequence_no bigint not null,
    last_entry_hash bytea not null,
    updated_at timestamptz not null default now(),
    constraint ledger_chain_state_global_only check (chain_id = 'global'),
    constraint ledger_chain_state_last_sequence_no_non_negative check (last_sequence_no >= 0),
    constraint ledger_chain_state_last_entry_hash_len check (octet_length(last_entry_hash) = 32)
);

comment on table public.ledger_chain_state
is 'Single-row global chain head for Ledger Phase 1. Updated only by rpc_append_ledger_entry for new entries.';
comment on column public.ledger_chain_state.chain_id is 'Fixed to global in Ledger Phase 1.';
comment on column public.ledger_chain_state.last_sequence_no is 'Current global chain head sequence. Initial genesis state is 0.';
comment on column public.ledger_chain_state.last_entry_hash is 'Current global chain head hash. Initial genesis previous hash is 32 zero bytes.';

insert into public.ledger_chain_state (
    chain_id,
    last_sequence_no,
    last_entry_hash,
    updated_at
)
values (
    'global',
    0,
    decode(repeat('00', 32), 'hex'),
    now()
);

create or replace function public.ledger_entries_immutable()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    raise exception 'ledger_entries_immutable'
        using errcode = '42501';
end;
$$;

comment on function public.ledger_entries_immutable()
is 'Rejects UPDATE, DELETE, and TRUNCATE on append-only ledger_entries.';

create trigger ledger_entries_no_update_delete
before update or delete on public.ledger_entries
for each row
execute function public.ledger_entries_immutable();

create trigger ledger_entries_no_truncate
before truncate on public.ledger_entries
for each statement
execute function public.ledger_entries_immutable();

create or replace function public.ledger_chain_state_no_delete_truncate()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    raise exception 'ledger_chain_state_mutation_restricted'
        using errcode = '42501';
end;
$$;

comment on function public.ledger_chain_state_no_delete_truncate()
is 'Rejects DELETE and TRUNCATE on ledger_chain_state; chain head UPDATE is reserved for rpc_append_ledger_entry.';

create trigger ledger_chain_state_no_delete
before delete on public.ledger_chain_state
for each row
execute function public.ledger_chain_state_no_delete_truncate();

create trigger ledger_chain_state_no_truncate
before truncate on public.ledger_chain_state
for each statement
execute function public.ledger_chain_state_no_delete_truncate();

alter table public.ledger_entries enable row level security;
alter table public.ledger_entries force row level security;

create policy ledger_entries_deny_all
    on public.ledger_entries
    as restrictive
    for all
    to public
    using (false)
    with check (false);

alter table public.ledger_chain_state enable row level security;
alter table public.ledger_chain_state force row level security;

create policy ledger_chain_state_deny_all
    on public.ledger_chain_state
    as restrictive
    for all
    to public
    using (false)
    with check (false);

create or replace function public.rpc_append_ledger_entry(
    p_ledger_entry_id uuid,
    p_sequence_no bigint,
    p_entry_type text,
    p_source_event_at text,
    p_request_id uuid,
    p_source_event_id uuid,
    p_target_secret_id uuid,
    p_target_secret_version_id uuid,
    p_actor_user_id uuid,
    p_actor_device_id text,
    p_result text,
    p_error_code text,
    p_payload jsonb,
    p_canonicalization_version integer,
    p_previous_entry_hash bytea,
    p_entry_hash bytea,
    p_hash_algorithm text,
    p_signature bytea,
    p_signature_algorithm text,
    p_signature_key_version integer
)
returns table (
    ledger_entry_id uuid,
    sequence_no bigint,
    entry_hash bytea,
    chain_last_sequence_no bigint,
    chain_last_entry_hash bytea,
    replayed boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_existing public.ledger_entries%rowtype;
    v_state public.ledger_chain_state%rowtype;
    v_constraint_name text;
begin
    if p_ledger_entry_id is null
        or p_sequence_no is null
        or p_entry_type is null
        or p_source_event_at is null
        or p_request_id is null
        or p_result is null
        or p_payload is null
        or p_canonicalization_version is null
        or p_previous_entry_hash is null
        or p_entry_hash is null
        or p_hash_algorithm is null
        or p_signature is null
        or p_signature_algorithm is null
        or p_signature_key_version is null
    then
        raise exception 'invalid_rpc_input'
            using errcode = '22023';
    end if;

    if p_sequence_no <= 0
        or octet_length(p_previous_entry_hash) <> 32
        or octet_length(p_entry_hash) <> 32
        or octet_length(p_signature) <> 64
    then
        raise exception 'invalid_rpc_input'
            using errcode = '22023';
    end if;

    select *
    into v_existing
    from public.ledger_entries
    where id = p_ledger_entry_id;

    if found then
        if v_existing.sequence_no is distinct from p_sequence_no
            or v_existing.entry_type is distinct from p_entry_type
            or v_existing.source_event_at is distinct from p_source_event_at
            or v_existing.request_id is distinct from p_request_id
            or v_existing.source_event_id is distinct from p_source_event_id
            or v_existing.target_secret_id is distinct from p_target_secret_id
            or v_existing.target_secret_version_id is distinct from p_target_secret_version_id
            or v_existing.actor_user_id is distinct from p_actor_user_id
            or v_existing.actor_device_id is distinct from p_actor_device_id
            or v_existing.result is distinct from p_result
            or v_existing.error_code is distinct from p_error_code
            or v_existing.payload is distinct from p_payload
            or v_existing.canonicalization_version is distinct from p_canonicalization_version
            or v_existing.previous_entry_hash is distinct from p_previous_entry_hash
            or v_existing.entry_hash is distinct from p_entry_hash
            or v_existing.hash_algorithm is distinct from p_hash_algorithm
            or v_existing.signature is distinct from p_signature
            or v_existing.signature_algorithm is distinct from p_signature_algorithm
            or v_existing.signature_key_version is distinct from p_signature_key_version
        then
            raise exception 'ledger_entry_id_conflict'
                using errcode = '23505';
        end if;

        select *
        into v_state
        from public.ledger_chain_state
        where chain_id = 'global';

        if not found then
            raise exception 'ledger_chain_state_missing'
                using errcode = '23514';
        end if;

        ledger_entry_id := v_existing.id;
        sequence_no := v_existing.sequence_no;
        entry_hash := v_existing.entry_hash;
        chain_last_sequence_no := v_state.last_sequence_no;
        chain_last_entry_hash := v_state.last_entry_hash;
        replayed := true;
        return next;
        return;
    end if;

    if not public.ledger_entry_type_allowed(p_entry_type)
        or length(p_entry_type) > 64
        or not public.ledger_source_event_at_is_valid(p_source_event_at)
        or p_result not in ('success', 'failure')
        or (p_error_code is not null and (btrim(p_error_code) = '' or length(p_error_code) > 128))
        or (p_result = 'success' and p_error_code is not null)
        or (p_actor_device_id is not null and (btrim(p_actor_device_id) = '' or length(p_actor_device_id) > 128))
        or p_canonicalization_version <> 1
        or p_hash_algorithm <> 'sha-256'
        or p_signature_algorithm <> 'ed25519'
        or p_signature_key_version <= 0
        or not public.ledger_payload_is_valid(p_entry_type, p_payload)
    then
        raise exception 'invalid_rpc_input'
            using errcode = '22023';
    end if;

    select *
    into v_state
    from public.ledger_chain_state
    where chain_id = 'global'
    for update;

    if not found then
        raise exception 'ledger_chain_state_missing'
            using errcode = '23514';
    end if;

    if p_sequence_no <> v_state.last_sequence_no + 1 then
        raise exception 'ledger_sequence_mismatch'
            using errcode = '40001';
    end if;

    if p_previous_entry_hash <> v_state.last_entry_hash then
        raise exception 'ledger_previous_hash_mismatch'
            using errcode = '40001';
    end if;

    begin
        insert into public.ledger_entries (
            id,
            sequence_no,
            entry_type,
            source_event_at,
            request_id,
            source_event_id,
            target_secret_id,
            target_secret_version_id,
            actor_user_id,
            actor_device_id,
            result,
            error_code,
            payload,
            canonicalization_version,
            previous_entry_hash,
            entry_hash,
            hash_algorithm,
            signature,
            signature_algorithm,
            signature_key_version
        )
        values (
            p_ledger_entry_id,
            p_sequence_no,
            p_entry_type,
            p_source_event_at,
            p_request_id,
            p_source_event_id,
            p_target_secret_id,
            p_target_secret_version_id,
            p_actor_user_id,
            p_actor_device_id,
            p_result,
            p_error_code,
            p_payload,
            p_canonicalization_version,
            p_previous_entry_hash,
            p_entry_hash,
            p_hash_algorithm,
            p_signature,
            p_signature_algorithm,
            p_signature_key_version
        );
    exception
        when unique_violation then
            get stacked diagnostics v_constraint_name = constraint_name;

            if v_constraint_name = 'ledger_entries_entry_hash_unique' then
                raise exception 'ledger_entry_hash_conflict'
                    using errcode = '23505';
            end if;

            raise exception 'ledger_entry_id_conflict'
                using errcode = '23505';
    end;

    update public.ledger_chain_state
    set last_sequence_no = p_sequence_no,
        last_entry_hash = p_entry_hash,
        updated_at = now()
    where chain_id = 'global';

    ledger_entry_id := p_ledger_entry_id;
    sequence_no := p_sequence_no;
    entry_hash := p_entry_hash;
    chain_last_sequence_no := p_sequence_no;
    chain_last_entry_hash := p_entry_hash;
    replayed := false;
    return next;
end;
$$;

comment on function public.rpc_append_ledger_entry(
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    text,
    text,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
)
is 'Appends or idempotently replays a Ledger Phase 1 global hash-chain entry. Existing id replay is checked before chain-state lock.';

revoke all on public.ledger_entries from anon;
revoke all on public.ledger_entries from authenticated;
revoke all on public.ledger_entries from service_role;
revoke all on public.ledger_chain_state from anon;
revoke all on public.ledger_chain_state from authenticated;
revoke all on public.ledger_chain_state from service_role;
grant select on public.ledger_chain_state to service_role;

revoke execute on function public.ledger_source_event_at_is_valid(text) from public;
revoke execute on function public.ledger_source_event_at_is_valid(text) from anon;
revoke execute on function public.ledger_source_event_at_is_valid(text) from authenticated;

revoke execute on function public.ledger_entry_type_allowed(text) from public;
revoke execute on function public.ledger_entry_type_allowed(text) from anon;
revoke execute on function public.ledger_entry_type_allowed(text) from authenticated;

revoke execute on function public.ledger_payload_allowed_keys(text) from public;
revoke execute on function public.ledger_payload_allowed_keys(text) from anon;
revoke execute on function public.ledger_payload_allowed_keys(text) from authenticated;

revoke execute on function public.ledger_payload_has_forbidden_key(jsonb) from public;
revoke execute on function public.ledger_payload_has_forbidden_key(jsonb) from anon;
revoke execute on function public.ledger_payload_has_forbidden_key(jsonb) from authenticated;

revoke execute on function public.ledger_payload_has_unknown_key(text, jsonb) from public;
revoke execute on function public.ledger_payload_has_unknown_key(text, jsonb) from anon;
revoke execute on function public.ledger_payload_has_unknown_key(text, jsonb) from authenticated;

revoke execute on function public.ledger_payload_schema_is_valid(text, jsonb) from public;
revoke execute on function public.ledger_payload_schema_is_valid(text, jsonb) from anon;
revoke execute on function public.ledger_payload_schema_is_valid(text, jsonb) from authenticated;

revoke execute on function public.ledger_payload_is_valid(text, jsonb) from public;
revoke execute on function public.ledger_payload_is_valid(text, jsonb) from anon;
revoke execute on function public.ledger_payload_is_valid(text, jsonb) from authenticated;

revoke execute on function public.ledger_entries_immutable() from public;
revoke execute on function public.ledger_entries_immutable() from anon;
revoke execute on function public.ledger_entries_immutable() from authenticated;

revoke execute on function public.ledger_chain_state_no_delete_truncate() from public;
revoke execute on function public.ledger_chain_state_no_delete_truncate() from anon;
revoke execute on function public.ledger_chain_state_no_delete_truncate() from authenticated;

revoke execute on function public.rpc_append_ledger_entry(
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    text,
    text,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) from public;
revoke execute on function public.rpc_append_ledger_entry(
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    text,
    text,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) from anon;
revoke execute on function public.rpc_append_ledger_entry(
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    text,
    text,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) from authenticated;
grant execute on function public.rpc_append_ledger_entry(
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    text,
    text,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) to service_role;

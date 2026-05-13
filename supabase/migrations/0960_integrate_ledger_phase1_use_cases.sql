-- Ledger Phase 1 use-case integration helpers.
-- audit_events remains the audit source of truth; these RPCs append ledger
-- entries in the same transaction as the corresponding authoritative audit row.

create or replace function public.rpc_append_ledger_entry_from_jsonb(p_entry jsonb)
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
begin
    if p_entry is null or jsonb_typeof(p_entry) <> 'object' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return query
    select *
    from public.rpc_append_ledger_entry(
        (p_entry ->> 'p_ledger_entry_id')::uuid,
        (p_entry ->> 'p_sequence_no')::bigint,
        p_entry ->> 'p_entry_type',
        p_entry ->> 'p_source_event_at',
        (p_entry ->> 'p_request_id')::uuid,
        nullif(p_entry ->> 'p_source_event_id', '')::uuid,
        nullif(p_entry ->> 'p_target_secret_id', '')::uuid,
        nullif(p_entry ->> 'p_target_secret_version_id', '')::uuid,
        nullif(p_entry ->> 'p_actor_user_id', '')::uuid,
        nullif(p_entry ->> 'p_actor_device_id', ''),
        p_entry ->> 'p_result',
        nullif(p_entry ->> 'p_error_code', ''),
        p_entry -> 'p_payload',
        (p_entry ->> 'p_canonicalization_version')::integer,
        decode(substr(p_entry ->> 'p_previous_entry_hash', 3), 'hex'),
        decode(substr(p_entry ->> 'p_entry_hash', 3), 'hex'),
        p_entry ->> 'p_hash_algorithm',
        decode(substr(p_entry ->> 'p_signature', 3), 'hex'),
        p_entry ->> 'p_signature_algorithm',
        (p_entry ->> 'p_signature_key_version')::integer
    );
exception
    when invalid_text_representation
        or invalid_parameter_value
        or numeric_value_out_of_range
        or null_value_not_allowed
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
end;
$$;

comment on function public.rpc_append_ledger_entry_from_jsonb(jsonb)
is 'Internal Ledger Phase 1 helper that appends one signed ledger entry from Rust RPC JSON parameters.';

create or replace function public.rpc_append_audit_event_with_ledger(
    p_audit_event_id uuid,
    p_request_id uuid,
    p_actor_user_id uuid default null,
    p_actor_device_id text default null,
    p_action text default null,
    p_target_secret_id uuid default null,
    p_result text default null,
    p_key_version integer default null,
    p_metadata_json jsonb default '{}'::jsonb,
    p_ledger_entry_id uuid default null,
    p_sequence_no bigint default null,
    p_entry_type text default null,
    p_source_event_at text default null,
    p_source_event_id uuid default null,
    p_target_secret_version_id uuid default null,
    p_error_code text default null,
    p_payload jsonb default '{}'::jsonb,
    p_canonicalization_version integer default null,
    p_previous_entry_hash bytea default null,
    p_entry_hash bytea default null,
    p_hash_algorithm text default null,
    p_signature bytea default null,
    p_signature_algorithm text default null,
    p_signature_key_version integer default null
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
begin
    if p_audit_event_id is null
        or p_request_id is null
        or p_action is null
        or p_result is null
        or p_source_event_id is distinct from p_audit_event_id
        or p_source_event_at is null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_source_event_at is distinct from p_metadata_json ->> 'source_event_at' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if (p_action = 'decrypt' and p_entry_type <> 'secret_decrypted')
        or (p_action = 'restore_test' and p_entry_type <> 'restore_test_completed')
        or (p_action = 'integrity_check' and p_entry_type <> 'integrity_check_completed')
        or (p_action = 'key_rotation_start' and p_entry_type <> 'key_rotation_started')
        or (p_action = 'key_rotation_reencrypt' and p_entry_type <> 'key_rotation_reencrypted')
        or (p_action = 'key_rotation_complete' and p_entry_type <> 'key_rotation_completed')
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    perform public.rpc_append_audit_event(
        p_audit_event_id,
        p_request_id,
        p_actor_user_id,
        p_actor_device_id,
        p_action,
        p_target_secret_id,
        p_result,
        p_key_version,
        p_metadata_json
    );

    return query
    select *
    from public.rpc_append_ledger_entry(
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
end;
$$;

comment on function public.rpc_append_audit_event_with_ledger(
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb,
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) is
    'Appends a non-write-path audit event and its signed Ledger Phase 1 entry in one transaction.';

revoke execute on function public.rpc_append_ledger_entry_from_jsonb(jsonb) from public, anon, authenticated;
revoke execute on function public.rpc_append_ledger_entry_from_jsonb(jsonb) from public;

revoke execute on function public.rpc_append_audit_event_with_ledger(
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb,
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) from public, anon, authenticated;
revoke execute on function public.rpc_append_audit_event_with_ledger(
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb,
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
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

grant execute on function public.rpc_append_audit_event_with_ledger(
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb,
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
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

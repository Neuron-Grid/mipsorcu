-- Section 1420: enforce one monthly_digest ledger entry per target month.
--
-- The prior rpc_check_monthly_digest_exists preflight was not a DB invariant
-- under concurrent generators. This partial unique index makes the invariant
-- durable, and the rpc_append_ledger_entry replacement maps violations to the
-- domain-specific monthly_digest_already_exists marker.

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

    if p_entry_type = 'incident_detected'
        and not (
            p_payload ?& array['incident_type', 'severity', 'detection_source', 'dedupe_key', 'notification_sink', 'notification_result']
        )
    then
        return false;
    end if;

    for v_key, v_value in
        select fields.key, fields.value
        from jsonb_each(p_payload) as fields(key, value)
    loop
        if v_key in ('version', 'key_version', 'old_key_version', 'new_key_version', 'retention_limit', 'start_sequence_no', 'end_sequence_no', 'entry_count', 'target_sequence_no', 'signature_key_version') then
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
        elsif v_key in ('batch_size', 'checked_audit_event_count', 'checked_count', 'checked_secret_count', 'checked_secret_version_count', 'duration_ms', 'entry_count', 'failed_count', 'failure_count', 'processed_count', 'remaining_count', 'resent_count', 'sample_count', 'success_count', 'violation_count') then
            if jsonb_typeof(v_value) <> 'number' or (v_value #>> '{}') !~ '^[0-9]+$' then
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
            if jsonb_typeof(v_value) <> 'string' or (v_value #>> '{}') not in ('background', 'cli', 'startup') then
                return false;
            end if;
        elsif v_key in ('error_code', 'reason_code', 'archive_key', 'job_name', 'detection_source', 'dedupe_key', 'notification_sink') then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;
            v_text := v_value #>> '{}';
            if btrim(v_text) = '' or length(v_text) > 128 then
                return false;
            end if;
        elsif v_key = 'incident_type' then
            if jsonb_typeof(v_value) <> 'string' or not public.incident_type_allowed(v_value #>> '{}') then
                return false;
            end if;
        elsif v_key = 'severity' then
            if jsonb_typeof(v_value) <> 'string' or not public.incident_severity_allowed(v_value #>> '{}') then
                return false;
            end if;
        elsif v_key = 'notification_result' then
            if jsonb_typeof(v_value) <> 'string' or not public.incident_notification_result_allowed(v_value #>> '{}') then
                return false;
            end if;
        elsif v_key in ('digest_hash', 'timestamp_token_hash', 'public_key_fingerprint') then
            if jsonb_typeof(v_value) <> 'string' or (v_value #>> '{}') !~ '^[0-9a-f]{64}$' then
                return false;
            end if;
        elsif v_key = 'sbc_signature' then
            if jsonb_typeof(v_value) <> 'string' or (v_value #>> '{}') !~ '^[0-9a-f]{128}$' then
                return false;
            end if;
        elsif v_key = 'target_year_month' then
            if jsonb_typeof(v_value) <> 'string' or (v_value #>> '{}') !~ '^\d{4}-(0[1-9]|1[0-2])$' then
                return false;
            end if;
        elsif v_key in ('created_at', 'activated_at', 'retired_at') then
            if jsonb_typeof(v_value) <> 'string'
                or not public.audit_metadata_source_event_at_is_valid(jsonb_build_object('source_event_at', v_value #>> '{}')) then
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
is 'Validates ledger payload field types, allowed values, and numeric ranges for all supported entry types, including monthly_digest sbc_signature.';

create unique index ledger_entries_monthly_digest_target_year_month_unique
    on public.ledger_entries ((payload->>'target_year_month'))
    where entry_type = 'monthly_digest';

comment on index public.ledger_entries_monthly_digest_target_year_month_unique
is 'Ensures at most one monthly_digest ledger entry exists for each target_year_month.';

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
        or p_hash_algorithm <> 'sha3-256'
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

    if p_entry_type = 'monthly_digest'
        and exists (
            select 1
            from public.ledger_entries le
            where le.entry_type = 'monthly_digest'
              and le.payload->>'target_year_month' = p_payload->>'target_year_month'
        )
    then
        raise exception 'monthly_digest_already_exists'
            using errcode = '23505';
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

            if v_constraint_name = 'ledger_entries_monthly_digest_target_year_month_unique' then
                raise exception 'monthly_digest_already_exists'
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

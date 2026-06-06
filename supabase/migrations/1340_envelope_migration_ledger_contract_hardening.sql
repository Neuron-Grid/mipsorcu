-- Harden Task 07 envelope migration ledger contract.
-- The signed ledger payload must describe the exact SQL outcome of the batch.

create or replace function public.rpc_apply_envelope_migration_batch(
    p_request_id uuid,
    p_rows jsonb default '[]'::jsonb,
    p_failure_rows jsonb default '[]'::jsonb,
    p_audit_event_id uuid default gen_random_uuid(),
    p_source_event_at text default null,
    p_ledger_entry jsonb default null
)
returns table (
    success_count bigint,
    failure_count bigint,
    remaining_legacy_rows bigint,
    retry_secret_version_ids uuid[]
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_row jsonb;
    v_id uuid;
    v_secret_id uuid;
    v_version integer;
    v_key_version integer;
    v_ciphertext bytea;
    v_nonce_or_iv bytea;
    v_wrapped_dek bytea;
    v_kek_version integer;
    v_error_code text;
    v_failure_metadata jsonb;
    v_batch_metadata jsonb;
    v_expected_payload jsonb;
    v_batch_size bigint;
    v_ledger_source_event_id uuid;
    v_payload jsonb;
begin
    retry_secret_version_ids := array[]::uuid[];

    if p_request_id is null
        or p_audit_event_id is null
        or p_source_event_at is null
        or not public.audit_metadata_source_event_at_is_valid(jsonb_build_object('source_event_at', p_source_event_at))
        or p_rows is null
        or p_failure_rows is null
        or jsonb_typeof(p_rows) <> 'array'
        or jsonb_typeof(p_failure_rows) <> 'array'
        or jsonb_array_length(p_rows) + jsonb_array_length(p_failure_rows) = 0
        or jsonb_array_length(p_rows) + jsonb_array_length(p_failure_rows) > 1000
        or p_ledger_entry is null
        or jsonb_typeof(p_ledger_entry) <> 'object'
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if public.ledger_payload_has_forbidden_key(p_ledger_entry)
        or exists (
            select 1
            from jsonb_object_keys(p_ledger_entry) as keys(key)
            where keys.key <> all(array[
                'p_ledger_entry_id',
                'p_sequence_no',
                'p_entry_type',
                'p_source_event_at',
                'p_request_id',
                'p_source_event_id',
                'p_target_secret_id',
                'p_target_secret_version_id',
                'p_actor_user_id',
                'p_actor_device_id',
                'p_result',
                'p_error_code',
                'p_payload',
                'p_canonicalization_version',
                'p_previous_entry_hash',
                'p_entry_hash',
                'p_hash_algorithm',
                'p_signature',
                'p_signature_algorithm',
                'p_signature_key_version'
            ])
        )
        or p_ledger_entry ->> 'p_entry_type' is distinct from 'envelope_migration_batch_completed'
        or p_ledger_entry ->> 'p_source_event_at' is distinct from p_source_event_at
        or p_ledger_entry ->> 'p_request_id' is distinct from p_request_id::text
        or p_ledger_entry ->> 'p_result' is distinct from 'success'
        or nullif(p_ledger_entry ->> 'p_error_code', '') is not null
    then
        raise exception 'invalid_ledger_entry' using errcode = '22023';
    end if;

    begin
        v_ledger_source_event_id := nullif(p_ledger_entry ->> 'p_source_event_id', '')::uuid;
    exception
        when invalid_text_representation then
            raise exception 'invalid_ledger_entry' using errcode = '22023';
    end;

    if v_ledger_source_event_id is distinct from p_audit_event_id then
        raise exception 'invalid_ledger_entry' using errcode = '22023';
    end if;

    if exists (
        select 1
        from (
            select item.value ->> 'id' as row_id
            from jsonb_array_elements(p_rows) as item(value)
            union all
            select item.value ->> 'id' as row_id
            from jsonb_array_elements(p_failure_rows) as item(value)
        ) ids
        group by row_id
        having count(*) > 1
    ) then
        raise exception 'duplicate_input_row' using errcode = '23505';
    end if;

    for v_row in select item.value from jsonb_array_elements(p_rows) as item(value)
    loop
        if jsonb_typeof(v_row) <> 'object'
            or not (v_row ?& array['id', 'secret_id', 'version', 'key_version', 'ciphertext', 'nonce_or_iv', 'wrapped_dek', 'dek_wrap_algorithm', 'kek_version'])
            or exists (
                select 1
                from jsonb_object_keys(v_row) as keys(key)
                where keys.key <> all(array['id', 'secret_id', 'version', 'key_version', 'ciphertext', 'nonce_or_iv', 'wrapped_dek', 'dek_wrap_algorithm', 'kek_version'])
            )
            or jsonb_typeof(v_row -> 'id') <> 'string'
            or jsonb_typeof(v_row -> 'secret_id') <> 'string'
            or jsonb_typeof(v_row -> 'version') <> 'number'
            or jsonb_typeof(v_row -> 'key_version') <> 'number'
            or jsonb_typeof(v_row -> 'ciphertext') <> 'string'
            or jsonb_typeof(v_row -> 'nonce_or_iv') <> 'string'
            or jsonb_typeof(v_row -> 'wrapped_dek') <> 'string'
            or jsonb_typeof(v_row -> 'dek_wrap_algorithm') <> 'string'
            or jsonb_typeof(v_row -> 'kek_version') <> 'number'
        then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;

        if (v_row ->> 'ciphertext') !~ '^\\x([0-9A-Fa-f]{2})+$'
            or (v_row ->> 'nonce_or_iv') !~ '^\\x([0-9A-Fa-f]{2}){24}$'
            or (v_row ->> 'wrapped_dek') !~ '^\\x([0-9A-Fa-f]{2}){25,}$'
        then
            raise exception 'invalid_bytea_encoding' using errcode = '22023';
        end if;

        v_id := (v_row ->> 'id')::uuid;
        v_secret_id := (v_row ->> 'secret_id')::uuid;
        v_version := (v_row ->> 'version')::integer;
        v_key_version := (v_row ->> 'key_version')::integer;
        v_kek_version := (v_row ->> 'kek_version')::integer;
        v_ciphertext := decode(substr(v_row ->> 'ciphertext', 3), 'hex');
        v_nonce_or_iv := decode(substr(v_row ->> 'nonce_or_iv', 3), 'hex');
        v_wrapped_dek := decode(substr(v_row ->> 'wrapped_dek', 3), 'hex');

        if v_secret_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
            raise exception 'invalid_secret_id' using errcode = '22023';
        end if;
        if v_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
            raise exception 'invalid_secret_version_id' using errcode = '22023';
        end if;
        if v_version <= 0 or v_key_version <= 0 or v_kek_version <= 0 then
            raise exception 'invalid_version' using errcode = '22023';
        end if;
        if v_row ->> 'dek_wrap_algorithm' <> 'envvar-xchacha-v2' then
            raise exception 'invalid_dek_wrap_algorithm' using errcode = '22023';
        end if;
        if left(v_row ->> 'ciphertext', 2) <> '\x'
            or left(v_row ->> 'nonce_or_iv', 2) <> '\x'
            or left(v_row ->> 'wrapped_dek', 2) <> '\x'
        then
            raise exception 'invalid_bytea_prefix' using errcode = '22023';
        end if;
        if octet_length(v_ciphertext) = 0
            or octet_length(v_nonce_or_iv) <> 24
            or octet_length(v_wrapped_dek) <= 24
        then
            raise exception 'invalid_bytea_length' using errcode = '22023';
        end if;

        begin
            perform 1
            from public.secret_versions sv
            where sv.id = v_id
                and sv.secret_id = v_secret_id
                and sv.version = v_version
                and sv.key_version = v_key_version
                and (sv.dek_wrap_algorithm is null or sv.dek_wrap_algorithm = 'legacy-master-key-v1')
            for update nowait;

            if not found then
                raise exception 'envelope_migration_row_conflict' using errcode = '40001';
            end if;

            update public.secret_versions
            set
                ciphertext = v_ciphertext,
                nonce_or_iv = v_nonce_or_iv,
                encrypted_data_key = null,
                wrapped_dek = v_wrapped_dek,
                dek_wrap_algorithm = 'envvar-xchacha-v2',
                kek_version = v_kek_version,
                key_version = v_kek_version
            where id = v_id;

            delete from public.envelope_migration_failures
            where secret_version_id = v_id;

            success_count := coalesce(success_count, 0) + 1;
        exception
            when unique_violation then
                raise exception 'envelope_migration_nonce_reuse' using errcode = '40001';
            when lock_not_available then
                raise exception 'envelope_migration_row_locked' using errcode = '40001';
        end;
    end loop;

    for v_row in select item.value from jsonb_array_elements(p_failure_rows) as item(value)
    loop
        if jsonb_typeof(v_row) <> 'object'
            or not (v_row ?& array['id', 'secret_id', 'version', 'key_version', 'error_code'])
            or exists (
                select 1
                from jsonb_object_keys(v_row) as keys(key)
                where keys.key <> all(array['id', 'secret_id', 'version', 'key_version', 'error_code'])
            )
            or jsonb_typeof(v_row -> 'id') <> 'string'
            or jsonb_typeof(v_row -> 'secret_id') <> 'string'
            or jsonb_typeof(v_row -> 'version') <> 'number'
            or jsonb_typeof(v_row -> 'key_version') <> 'number'
            or jsonb_typeof(v_row -> 'error_code') <> 'string'
        then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;

        v_id := (v_row ->> 'id')::uuid;
        v_secret_id := (v_row ->> 'secret_id')::uuid;
        v_version := (v_row ->> 'version')::integer;
        v_key_version := (v_row ->> 'key_version')::integer;
        v_error_code := v_row ->> 'error_code';

        if v_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
            raise exception 'invalid_secret_version_id' using errcode = '22023';
        end if;
        if v_secret_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
            raise exception 'invalid_secret_id' using errcode = '22023';
        end if;
        if v_version <= 0 or v_key_version <= 0 then
            raise exception 'invalid_version' using errcode = '22023';
        end if;
        if v_error_code !~ '^[a-z0-9_]{1,64}$' then
            raise exception 'invalid_error_code' using errcode = '22023';
        end if;

        begin
            perform 1
            from public.secret_versions sv
            where sv.id = v_id
                and sv.secret_id = v_secret_id
                and sv.version = v_version
                and sv.key_version = v_key_version
                and (sv.dek_wrap_algorithm is null or sv.dek_wrap_algorithm = 'legacy-master-key-v1')
            for update nowait;

            if not found then
                raise exception 'envelope_migration_failure_row_conflict' using errcode = '40001';
            end if;

            insert into public.envelope_migration_failures (
                secret_version_id,
                secret_id,
                version,
                key_version,
                error_code
            )
            values (
                v_id,
                v_secret_id,
                v_version,
                v_key_version,
                v_error_code
            )
            on conflict (secret_version_id) do update
            set
                secret_id = excluded.secret_id,
                version = excluded.version,
                key_version = excluded.key_version,
                error_code = excluded.error_code,
                failure_count = case
                    when public.envelope_migration_failures.failure_count < 2147483647
                        then public.envelope_migration_failures.failure_count + 1
                    else public.envelope_migration_failures.failure_count
                end,
                last_failed_at = now();
        exception
            when lock_not_available then
                raise exception 'envelope_migration_failure_row_locked' using errcode = '40001';
        end;

        v_failure_metadata := jsonb_build_object(
            'secret_version_id', v_id::text,
            'version', v_version,
            'error_code', v_error_code,
            'source_event_at', p_source_event_at
        );
        if public.audit_metadata_has_forbidden_key(v_failure_metadata)
            or public.audit_metadata_has_schema_violation_for_action('key_rotation_envelope_failed', 'failure', v_failure_metadata, true)
        then
            raise exception 'invalid_audit_metadata' using errcode = '22023';
        end if;

        insert into public.audit_events (
            id,
            request_id,
            action,
            target_secret_id,
            result,
            key_version,
            metadata_json
        )
        values (
            gen_random_uuid(),
            p_request_id,
            'key_rotation_envelope_failed',
            v_secret_id,
            'failure',
            v_key_version,
            v_failure_metadata
        );
        failure_count := coalesce(failure_count, 0) + 1;
    end loop;

    success_count := coalesce(success_count, 0);
    failure_count := coalesce(failure_count, 0);
    v_batch_size := success_count + failure_count;
    v_expected_payload := jsonb_build_object(
        'batch_size', v_batch_size,
        'success_count', success_count,
        'failure_count', failure_count
    );
    v_batch_metadata := v_expected_payload || jsonb_build_object('source_event_at', p_source_event_at);
    if public.audit_metadata_has_forbidden_key(v_batch_metadata)
        or public.audit_metadata_has_schema_violation_for_action('key_rotation_envelope_migrated', 'success', v_batch_metadata, true)
    then
        raise exception 'invalid_audit_metadata' using errcode = '22023';
    end if;

    v_payload := p_ledger_entry -> 'p_payload';
    if not public.ledger_payload_is_valid('envelope_migration_batch_completed', v_payload)
        or v_payload is distinct from v_expected_payload
    then
        raise exception 'invalid_ledger_entry' using errcode = '22023';
    end if;

    insert into public.audit_events (
        id,
        request_id,
        action,
        result,
        metadata_json
    )
    values (
        p_audit_event_id,
        p_request_id,
        'key_rotation_envelope_migrated',
        'success',
        v_batch_metadata
    );

    perform public.rpc_append_ledger_entry_from_jsonb(p_ledger_entry);

    select count(*)
    into remaining_legacy_rows
    from public.secret_versions sv
    where sv.dek_wrap_algorithm is null or sv.dek_wrap_algorithm = 'legacy-master-key-v1';

    return next;
exception
    when invalid_text_representation
        or numeric_value_out_of_range
        or null_value_not_allowed
        or string_data_right_truncation
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
end;
$$;

comment on function public.rpc_apply_envelope_migration_batch(uuid, jsonb, jsonb, uuid, text, jsonb)
is 'Applies one Task 07 envelope lazy migration batch. Signed ledger payload must match the exact SQL success/failure counts; plaintext and DEK plaintext never enter SQL.';

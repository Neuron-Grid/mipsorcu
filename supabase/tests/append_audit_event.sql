begin;

create extension if not exists pgtap with schema extensions;
set search_path = public, extensions, pg_temp;

select no_plan();

insert into auth.users (
    id,
    aud,
    role,
    email,
    email_confirmed_at,
    created_at,
    updated_at
)
values
    (
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'authenticated',
        'authenticated',
        'owner@example.test',
        now(),
        now(),
        now()
    ),
    (
        'f47ac10b-58cc-4372-a567-0e02b2c3d480',
        'authenticated',
        'authenticated',
        'other@example.test',
        now(),
        now(),
        now()
    )
on conflict (id) do nothing;

create schema test_helpers;

create function test_helpers.aad_context(
    p_secret_id uuid,
    p_version integer,
    p_owner_user_id uuid,
    p_classification text,
    p_created_at text
)
returns jsonb
language sql
immutable
as $$
    select jsonb_build_object(
        'aad_version',
        1,
        'secret_id',
        p_secret_id::text,
        'version',
        p_version,
        'owner_user_id',
        p_owner_user_id::text,
        'classification',
        p_classification,
        'created_at',
        p_created_at
    );
$$;

create function test_helpers.try_write_secret_version(
    p_request_id uuid,
    p_action text,
    p_secret_id uuid,
    p_owner_user_id uuid,
    p_classification text,
    p_created_by_device_id text,
    p_created_at timestamptz,
    p_version integer,
    p_ciphertext bytea,
    p_encrypted_data_key bytea,
    p_key_version integer,
    p_algorithm text,
    p_nonce_or_iv bytea,
    p_aad_context jsonb
)
returns text
language plpgsql
as $$
begin
    perform *
    from public.rpc_write_secret_version(
        p_request_id,
        p_action,
        p_secret_id,
        p_owner_user_id,
        p_classification,
        p_created_by_device_id,
        p_created_at,
        p_version,
        p_ciphertext,
        p_encrypted_data_key,
        p_key_version,
        p_algorithm,
        p_nonce_or_iv,
        p_aad_context
    );

    return 'ok';
exception
    when others then
        return sqlerrm;
end;
$$;

create function test_helpers.try_append_audit_event(
    p_audit_event_id uuid,
    p_request_id uuid,
    p_actor_user_id uuid,
    p_actor_device_id text,
    p_action text,
    p_target_secret_id uuid,
    p_result text,
    p_key_version integer,
    p_metadata_json jsonb
)
returns text
language plpgsql
as $$
begin
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

    return 'ok';
exception
    when others then
        return sqlerrm;
end;
$$;

create function test_helpers.try_update_secret_classification(
    p_secret_id uuid,
    p_classification text
)
returns text
language plpgsql
as $$
begin
    update public.secrets
    set classification = p_classification
    where id = p_secret_id;

    return 'ok';
exception
    when others then
        return sqlerrm;
end;
$$;

create function test_helpers.try_create_future_public_function()
returns text
language plpgsql
as $$
begin
    execute $create_function$
        create function public.test_future_public_execute()
        returns integer
        language sql
        stable
        as $function$
            select 1;
        $function$;
    $create_function$;

    return 'ok';
exception
    when others then
        return sqlerrm;
end;
$$;
create temp table first_write_result as
select *
from public.rpc_write_secret_version(
    '00000000-0000-4000-8000-000000000001',
    'encrypt_create',
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'confidential',
    'sbc-device-1',
    '2026-04-08T12:00:00Z',
    1,
    decode(repeat('aa', 32), 'hex'),
    decode(repeat('bb', 73), 'hex'),
    1,
    'xchacha20-poly1305',
    decode(repeat('01', 24), 'hex'),
    test_helpers.aad_context(
        '550e8400-e29b-41d4-a716-446655440000',
        1,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        '2026-04-08T12:00:00Z'
    )
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000015',
        '00000000-0000-4000-8000-000000000015',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"source":"sql-test"}'::jsonb
    ),
    'ok',
    'append audit RPC accepts valid audit event'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000015',
        '00000000-0000-4000-8000-000000000015',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"source":"sql-test"}'::jsonb
    ),
    'ok',
    'append audit RPC treats identical audit_event_id replay as idempotent'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.id = '10000000-0000-4000-8000-000000000015'
    ),
    1,
    'append audit RPC stores one row for idempotent replays'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000015',
        '00000000-0000-4000-8000-000000000015',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"source":"changed"}'::jsonb
    ),
    'audit_event_id_conflict',
    'append audit RPC rejects same audit_event_id with different content'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000016',
        '00000000-0000-4000-8000-000000000016',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'unknown_action',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects unknown action'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000017',
        '00000000-0000-4000-8000-000000000017',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'skipped',
        1,
        '{}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects invalid result'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000018',
        '00000000-0000-4000-8000-000000000018',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '[]'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects non-object metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000021',
        '00000000-0000-4000-8000-000000000021',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'encrypt_create',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects encrypt_create success outside write RPC'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000022',
        '00000000-0000-4000-8000-000000000022',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'encrypt_rotate',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects encrypt_rotate success outside write RPC'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000023',
        '00000000-0000-4000-8000-000000000023',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'version_purge',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects version_purge success outside write RPC'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000024',
        '00000000-0000-4000-8000-000000000024',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'encrypt_create',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"error_code":"input_invalid"}'::jsonb
    ),
    'ok',
    'append audit RPC accepts encrypt_create failure audit event'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.id = '10000000-0000-4000-8000-000000000024'
            and ae.action = 'encrypt_create'
            and ae.result = 'failure'
    ),
    1,
    'append audit RPC stores allowed write failure audit event'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000025',
        '00000000-0000-4000-8000-000000000025',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"nested":[{"plaintext":"leak"}]}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects forbidden metadata keys recursively'
);

select * from finish();

rollback;

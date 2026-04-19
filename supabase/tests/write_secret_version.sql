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
    (select count(*)::integer from first_write_result),
    1,
    'new secret write returns one row'
);

select is(
    (
        select s.current_version_id
        from public.secrets s
        where s.id = '550e8400-e29b-41d4-a716-446655440000'
    ),
    (
        select secret_version_id
        from first_write_result
    ),
    'new secret current_version_id points to inserted version'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.action = 'encrypt_create'
            and ae.result = 'success'
            and ae.target_secret_id = '550e8400-e29b-41d4-a716-446655440000'
    ),
    1,
    'new secret write records encrypt_create audit event'
);

select is(
    (
        select sv.created_at
        from public.secret_versions sv
        where sv.secret_id = '550e8400-e29b-41d4-a716-446655440000'
            and sv.version = 1
    ),
    '2026-04-08T12:00:00Z'::timestamptz,
    'secret_versions.created_at stores SBC supplied timestamp'
);

select is(
    (
        select c.column_default
        from information_schema.columns c
        where c.table_schema = 'public'
            and c.table_name = 'secret_versions'
            and c.column_name = 'created_at'
    ),
    null::text,
    'secret_versions.created_at has no database default'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000002',
        'encrypt_rotate',
        '550e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d480',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:01:00Z',
        2,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('02', 24), 'hex'),
        test_helpers.aad_context(
            '550e8400-e29b-41d4-a716-446655440000',
            2,
            'f47ac10b-58cc-4372-a567-0e02b2c3d480',
            'confidential',
            '2026-04-08T12:01:00Z'
        )
    ),
    'owner_mismatch',
    'existing secret write rejects non-owner'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000003',
        'encrypt_rotate',
        '550e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'restricted',
        'sbc-device-1',
        '2026-04-08T12:01:00Z',
        2,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('02', 24), 'hex'),
        test_helpers.aad_context(
            '550e8400-e29b-41d4-a716-446655440000',
            2,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'restricted',
            '2026-04-08T12:01:00Z'
        )
    ),
    'classification_immutable',
    'existing secret write rejects classification changes'
);

select is(
    test_helpers.try_update_secret_classification(
        '550e8400-e29b-41d4-a716-446655440000',
        'restricted'
    ),
    'classification_immutable',
    'direct secrets update rejects classification changes'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000004',
        'encrypt_rotate',
        '550e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:02:00Z',
        3,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('03', 24), 'hex'),
        test_helpers.aad_context(
            '550e8400-e29b-41d4-a716-446655440000',
            3,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:02:00Z'
        )
    ),
    'not_next_version',
    'existing secret write rejects version gaps'
);

select is(
    (
        select count(*)::integer
        from public.secret_versions sv
        where sv.secret_id = '550e8400-e29b-41d4-a716-446655440000'
    ),
    1,
    'rejected writes leave no partial secret version rows'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000005',
        'encrypt_create',
        '650e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('01', 23), 'hex'),
        test_helpers.aad_context(
            '650e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'new secret write rejects invalid nonce length'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000006',
        'encrypt_create',
        '650e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'chacha20-poly1305',
        decode(repeat('01', 24), 'hex'),
        test_helpers.aad_context(
            '650e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'new secret write rejects unsupported algorithm'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000019',
        'encrypt_create',
        '660e8400-e29b-11d4-a716-446655440000',
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
            '660e8400-e29b-11d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'new secret write rejects non-v4 secret_id'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000020',
        'encrypt_create',
        '670e8400-e29b-41d4-a716-446655440000',
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
            '670e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00+00:00'
        )
    ),
    'aad_context_mismatch',
    'new secret write rejects non-canonical aad created_at offset'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000007',
        'encrypt_create',
        '650e8400-e29b-41d4-a716-446655440000',
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
            '750e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'aad_context_mismatch',
    'new secret write rejects aad_context secret_id mismatch'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000026',
        'encrypt_create',
        '680e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('06', 24), 'hex'),
        test_helpers.aad_context(
            '680e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        ) - 'created_at'
    ),
    'aad_context_mismatch',
    'new secret write rejects aad_context missing required key'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000027',
        'encrypt_create',
        '690e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('07', 24), 'hex'),
        test_helpers.aad_context(
            '690e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d480',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'aad_context_mismatch',
    'new secret write rejects aad_context owner_user_id mismatch'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000028',
        'encrypt_create',
        '6a0e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('08', 24), 'hex'),
        test_helpers.aad_context(
            '6a0e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'restricted',
            '2026-04-08T12:00:00Z'
        )
    ),
    'aad_context_mismatch',
    'new secret write rejects aad_context classification mismatch'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000029',
        'encrypt_create',
        '6b0e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('09', 24), 'hex'),
        test_helpers.aad_context(
            '6b0e8400-e29b-41d4-a716-446655440000',
            2,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'aad_context_mismatch',
    'new secret write rejects aad_context version mismatch'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000008',
        'encrypt_create',
        '650e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        ''::bytea,
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('01', 24), 'hex'),
        test_helpers.aad_context(
            '650e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'new secret write rejects empty ciphertext'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000009',
        'encrypt_create',
        '650e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        '   ',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('01', 24), 'hex'),
        test_helpers.aad_context(
            '650e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'new secret write rejects blank device id'
);

create temp table second_write_result as
select *
from public.rpc_write_secret_version(
    '00000000-0000-4000-8000-000000000010',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'confidential',
    'sbc-device-1',
    '2026-04-08T12:01:00Z',
    2,
    decode(repeat('a2', 32), 'hex'),
    decode(repeat('bb', 73), 'hex'),
    1,
    'xchacha20-poly1305',
    decode(repeat('02', 24), 'hex'),
    test_helpers.aad_context(
        '550e8400-e29b-41d4-a716-446655440000',
        2,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        '2026-04-08T12:01:00Z'
    )
);

create temp table third_write_result as
select *
from public.rpc_write_secret_version(
    '00000000-0000-4000-8000-000000000011',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'confidential',
    'sbc-device-1',
    '2026-04-08T12:02:00Z',
    3,
    decode(repeat('a3', 32), 'hex'),
    decode(repeat('bb', 73), 'hex'),
    1,
    'xchacha20-poly1305',
    decode(repeat('03', 24), 'hex'),
    test_helpers.aad_context(
        '550e8400-e29b-41d4-a716-446655440000',
        3,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        '2026-04-08T12:02:00Z'
    )
);

create temp table fourth_write_result as
select *
from public.rpc_write_secret_version(
    '00000000-0000-4000-8000-000000000012',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'confidential',
    'sbc-device-1',
    '2026-04-08T12:03:00Z',
    4,
    decode(repeat('a4', 32), 'hex'),
    decode(repeat('bb', 73), 'hex'),
    1,
    'xchacha20-poly1305',
    decode(repeat('04', 24), 'hex'),
    test_helpers.aad_context(
        '550e8400-e29b-41d4-a716-446655440000',
        4,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        '2026-04-08T12:03:00Z'
    )
);

create temp table fifth_write_result as
select *
from public.rpc_write_secret_version(
    '00000000-0000-4000-8000-000000000013',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'confidential',
    'sbc-device-1',
    '2026-04-08T12:04:00Z',
    5,
    decode(repeat('a5', 32), 'hex'),
    decode(repeat('bb', 73), 'hex'),
    1,
    'xchacha20-poly1305',
    decode(repeat('05', 24), 'hex'),
    test_helpers.aad_context(
        '550e8400-e29b-41d4-a716-446655440000',
        5,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        '2026-04-08T12:04:00Z'
    )
);

select is(
    (
        select count(*)::integer
        from public.secret_versions sv
        where sv.secret_id = '550e8400-e29b-41d4-a716-446655440000'
    ),
    4,
    'fifth write keeps only four secret versions'
);

select is(
    (
        select min(sv.version)
        from public.secret_versions sv
        where sv.secret_id = '550e8400-e29b-41d4-a716-446655440000'
    ),
    2,
    'fifth write physically purges oldest version'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.target_secret_id = '550e8400-e29b-41d4-a716-446655440000'
            and ae.action = 'version_purge'
            and ae.metadata_json ->> 'version' = '1'
    ),
    1,
    'fifth write records version_purge audit event'
);

select is(
    (
        select cardinality(purged_version_ids)
        from fifth_write_result
    ),
    1,
    'fifth write returns one purged version id'
);

select like(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000030',
        'encrypt_rotate',
        '550e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:05:00Z',
        6,
        decode(repeat('a6', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('05', 24), 'hex'),
        test_helpers.aad_context(
            '550e8400-e29b-41d4-a716-446655440000',
            6,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:05:00Z'
        )
    ),
    '%secret_versions_secret_nonce_unique%',
    'existing secret write rejects nonce reuse for retained versions'
);

select is(
    (
        select count(*)::integer
        from public.secret_versions sv
        where sv.secret_id = '550e8400-e29b-41d4-a716-446655440000'
    ),
    4,
    'rejected nonce reuse leaves no partial secret version rows'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.target_secret_id = '550e8400-e29b-41d4-a716-446655440000'
            and ae.action = 'encrypt_rotate'
            and ae.metadata_json ->> 'version' = '6'
    ),
    0,
    'rejected nonce reuse records no success audit event'
);

create temp table other_owner_write_result as
select *
from public.rpc_write_secret_version(
    '00000000-0000-4000-8000-000000000014',
    'encrypt_create',
    '650e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d480',
    'confidential',
    'sbc-device-2',
    '2026-04-08T12:00:00Z',
    1,
    decode(repeat('cc', 32), 'hex'),
    decode(repeat('dd', 73), 'hex'),
    1,
    'xchacha20-poly1305',
    decode(repeat('11', 24), 'hex'),
    test_helpers.aad_context(
        '650e8400-e29b-41d4-a716-446655440000',
        1,
        'f47ac10b-58cc-4372-a567-0e02b2c3d480',
        'confidential',
        '2026-04-08T12:00:00Z'
    )
);

select ok(
    not has_table_privilege('anon', 'public.secrets', 'select'),
    'anon cannot select secrets'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('public.secrets', 'select'),
                ('public.secrets', 'insert'),
                ('public.secrets', 'update'),
                ('public.secrets', 'delete'),
                ('public.secret_versions', 'select'),
                ('public.secret_versions', 'insert'),
                ('public.secret_versions', 'update'),
                ('public.secret_versions', 'delete'),
                ('public.audit_events', 'select'),
                ('public.audit_events', 'insert'),
                ('public.audit_events', 'update'),
                ('public.audit_events', 'delete')
            ) as table_privileges(table_name, privilege_name)
            where has_table_privilege(
                'anon',
                table_privileges.table_name,
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'anon has no direct table privileges on secret store tables'
);

select ok(
    has_table_privilege('authenticated', 'public.secrets', 'select'),
    'authenticated can select secrets through RLS'
);

select ok(
    has_table_privilege('authenticated', 'public.secret_versions', 'select'),
    'authenticated can select secret_versions through RLS'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('public.secrets', 'insert'),
                ('public.secrets', 'update'),
                ('public.secrets', 'delete'),
                ('public.secret_versions', 'insert'),
                ('public.secret_versions', 'update'),
                ('public.secret_versions', 'delete')
            ) as table_privileges(table_name, privilege_name)
            where has_table_privilege(
                'authenticated',
                table_privileges.table_name,
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'authenticated cannot write secret store tables directly'
);

select ok(
    not has_table_privilege('authenticated', 'public.audit_events', 'select'),
    'authenticated cannot select audit_events'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('select'),
                ('insert'),
                ('update'),
                ('delete')
            ) as table_privileges(privilege_name)
            where has_table_privilege(
                'authenticated',
                'public.audit_events',
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'authenticated has no direct table privileges on audit_events'
);

select is(
    (
        select bool_and(c.relrowsecurity and c.relforcerowsecurity)
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public'
            and c.relname in ('secrets', 'secret_versions', 'audit_events')
    ),
    true,
    'secret store tables enable and force row level security'
);

select is(
    (
        select count(*)::integer
        from pg_policies p
        where p.schemaname = 'public'
            and p.tablename = 'audit_events'
    ),
    0,
    'audit_events has no client RLS policies'
);

select is(
    test_helpers.try_create_future_public_function(),
    'ok',
    'test can create a future public function'
);

select is(
    (
        select exists (
            select 1
            from pg_proc p
            join pg_namespace n on n.oid = p.pronamespace
            cross join lateral aclexplode(
                coalesce(p.proacl, acldefault('f', p.proowner))
            ) as acl_entries
            where n.nspname = 'public'
                and p.proname = 'test_future_public_execute'
                and acl_entries.grantee = 0
                and acl_entries.privilege_type = 'EXECUTE'
        )
    ),
    false,
    'future public functions do not grant execute to PUBLIC by default'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.test_future_public_execute()',
        'execute'
    ),
    'anon cannot execute future public functions by default'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.test_future_public_execute()',
        'execute'
    ),
    'authenticated cannot execute future public functions by default'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.rpc_write_secret_version(uuid,text,uuid,uuid,text,text,timestamptz,integer,bytea,bytea,integer,text,bytea,jsonb)',
        'execute'
    ),
    'anon cannot execute write RPC'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.rpc_write_secret_version(uuid,text,uuid,uuid,text,text,timestamptz,integer,bytea,bytea,integer,text,bytea,jsonb)',
        'execute'
    ),
    'authenticated cannot execute write RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_write_secret_version(uuid,text,uuid,uuid,text,text,timestamptz,integer,bytea,bytea,integer,text,bytea,jsonb)',
        'execute'
    ),
    'service_role can execute write RPC'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.rpc_append_audit_event(uuid,uuid,uuid,text,text,uuid,text,integer,jsonb)',
        'execute'
    ),
    'anon cannot execute append audit RPC'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.rpc_append_audit_event(uuid,uuid,uuid,text,text,uuid,text,integer,jsonb)',
        'execute'
    ),
    'authenticated cannot execute append audit RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_append_audit_event(uuid,uuid,uuid,text,text,uuid,text,integer,jsonb)',
        'execute'
    ),
    'service_role can execute append audit RPC'
);

set local role authenticated;
set local "request.jwt.claim.sub" = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';

select is(
    (select count(*)::integer from public.secrets),
    1,
    'RLS exposes only owned secrets to authenticated owner'
);

select is(
    (select count(*)::integer from public.secret_versions),
    1,
    'RLS exposes only current secret version to authenticated owner'
);

select is(
    (select max(version) from public.secret_versions),
    5,
    'RLS exposes current version rather than historical versions'
);

reset role;

set local role authenticated;
set local "request.jwt.claim.sub" = 'f47ac10b-58cc-4372-a567-0e02b2c3d480';

select is(
    (select count(*)::integer from public.secrets),
    1,
    'RLS exposes only owned secrets to other authenticated owner'
);

select is(
    (
        select count(*)::integer
        from public.secrets
        where id = '550e8400-e29b-41d4-a716-446655440000'
    ),
    0,
    'RLS hides another owner secret'
);

select is(
    (select count(*)::integer from public.secret_versions),
    1,
    'RLS exposes only current secret version to other authenticated owner'
);

select is(
    (select max(version) from public.secret_versions),
    1,
    'RLS exposes other owner current version only'
);

reset role;

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

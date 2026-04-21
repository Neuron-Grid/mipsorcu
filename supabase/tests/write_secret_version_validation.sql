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

create function test_helpers.try_insert_secret_version(
    p_secret_id uuid,
    p_owner_user_id uuid,
    p_created_at timestamptz,
    p_classification text,
    p_aad_context jsonb
)
returns text
language plpgsql
as $$
begin
    insert into public.secrets (
        id,
        owner_user_id,
        classification,
        created_at,
        updated_at
    )
    values (
        p_secret_id,
        p_owner_user_id,
        'confidential',
        p_created_at,
        now()
    );

    insert into public.secret_versions (
        secret_id,
        version,
        ciphertext,
        encrypted_data_key,
        key_version,
        algorithm,
        classification,
        nonce_or_iv,
        aad_context,
        created_by_user_id,
        created_by_device_id,
        created_at
    )
    values (
        p_secret_id,
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        p_classification,
        decode(repeat('0a', 24), 'hex'),
        p_aad_context,
        p_owner_user_id,
        'sbc-device-1',
        p_created_at
    );

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

select * from finish();

rollback;

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
        '00000000-0000-4000-8000-000000000030',
        'encrypt_create',
        '6c0e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('0a', 24), 'hex'),
        test_helpers.aad_context(
            '6c0e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        ) || jsonb_build_object('extra', 'not allowed')
    ),
    'aad_context_mismatch',
    'new secret write rejects aad_context extra key'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000031',
        'encrypt_create',
        '6d0e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('0b', 24), 'hex'),
        test_helpers.aad_context(
            '6d0e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        ) || jsonb_build_object('plaintext', 'leak')
    ),
    'aad_context_mismatch',
    'new secret write rejects aad_context forbidden plaintext key'
);

select ok(
    position(
        'secret_versions_aad_context_allowed_keys' in test_helpers.try_insert_secret_version(
            '6e0e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '2026-04-08T12:00:00Z',
            test_helpers.aad_context(
                '6e0e8400-e29b-41d4-a716-446655440000',
                1,
                'f47ac10b-58cc-4372-a567-0e02b2c3d479',
                'confidential',
                '2026-04-08T12:00:00Z'
            ) || jsonb_build_object('plaintext', 'leak')
        )
    ) > 0,
    'direct secret_versions insert rejects aad_context extra keys'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000032',
        'encrypt_create',
        '6f0e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('0c', 24), 'hex'),
        test_helpers.aad_context(
            '6f0e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'new secret write accepts aad_context exact six-key schema'
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

select * from finish();

rollback;

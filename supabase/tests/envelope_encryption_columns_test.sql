begin;

\ir _support/common.psql

select no_plan();

create function test_helpers.try_insert_secret_version_with_envelope_fields(
    p_secret_id uuid,
    p_owner_user_id uuid,
    p_created_at timestamptz,
    p_nonce_byte text,
    p_wrapped_dek bytea,
    p_dek_wrap_algorithm text,
    p_kek_version integer
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
        created_at,
        wrapped_dek,
        dek_wrap_algorithm,
        kek_version
    )
    values (
        p_secret_id,
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        'confidential',
        decode(repeat(p_nonce_byte, 24), 'hex'),
        test_helpers.aad_context(
            p_secret_id,
            1,
            p_owner_user_id,
            'confidential',
            to_char(p_created_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
        ),
        p_owner_user_id,
        'sbc-device-1',
        p_created_at,
        p_wrapped_dek,
        p_dek_wrap_algorithm,
        p_kek_version
    );

    return 'ok';
exception
    when others then
        return sqlerrm;
end;
$$;

select has_column(
    'public',
    'secret_versions',
    'wrapped_dek',
    'secret_versions.wrapped_dek exists'
);

select has_column(
    'public',
    'secret_versions',
    'dek_wrap_algorithm',
    'secret_versions.dek_wrap_algorithm exists'
);

select has_column(
    'public',
    'secret_versions',
    'kek_version',
    'secret_versions.kek_version exists'
);

select has_column(
    'public',
    'secret_versions',
    'encrypted_data_key',
    'secret_versions.encrypted_data_key remains for v0.1.0 compatibility'
);

select ok(
    exists (
        select 1
        from pg_constraint c
        where c.conrelid = 'public.secret_versions'::regclass
            and c.conname = 'secret_versions_dek_wrap_algorithm_check'
            and c.contype = 'c'
    ),
    'secret_versions_dek_wrap_algorithm_check exists'
);

select ok(
    exists (
        select 1
        from pg_constraint c
        where c.conrelid = 'public.secret_versions'::regclass
            and c.conname = 'secret_versions_envelope_v02_required'
            and c.contype = 'c'
    ),
    'secret_versions_envelope_v02_required exists'
);

select ok(
    exists (
        select 1
        from pg_constraint c
        where c.conrelid = 'public.secret_versions'::regclass
            and c.conname = 'secret_versions_kek_version_positive'
            and c.contype = 'c'
    ),
    'secret_versions_kek_version_positive exists'
);

select ok(
    exists (
        select 1
        from pg_constraint c
        where c.conrelid = 'public.secret_versions'::regclass
            and c.conname = 'secret_versions_wrapped_dek_size'
            and c.contype = 'c'
    ),
    'secret_versions_wrapped_dek_size exists'
);

select ok(
    exists (
        select 1
        from pg_constraint c
        where c.conrelid = 'public.secret_versions'::regclass
            and c.conname = 'secret_versions_legacy_encrypted_data_key_required'
            and c.contype = 'c'
    ),
    'secret_versions_legacy_encrypted_data_key_required exists'
);

select is(
    test_helpers.try_insert_secret_version_with_envelope_fields(
        '900e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        '2026-04-08T12:00:00Z',
        '21',
        null::bytea,
        null::text,
        null::integer
    ),
    'ok',
    'v0.1.0 format row accepts nullable envelope fields'
);

select is(
    test_helpers.try_insert_secret_version_with_envelope_fields(
        '910e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        '2026-04-08T12:00:00Z',
        '22',
        null::bytea,
        'legacy-master-key-v1',
        null::integer
    ),
    'ok',
    'legacy-master-key-v1 discriminator remains compatible with v0.1.0 fields'
);

select is(
    test_helpers.try_insert_secret_version_with_envelope_fields(
        '920e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        '2026-04-08T12:00:00Z',
        '23',
        decode(repeat('cc', 72), 'hex'),
        'envvar-xchacha-v2',
        2
    ),
    'ok',
    'v0.2 envelope format row accepts wrapped_dek, algorithm, and kek_version'
);

select ok(
    position(
        'secret_versions_envelope_v02_required' in test_helpers.try_insert_secret_version_with_envelope_fields(
            '930e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '2026-04-08T12:00:00Z',
            '24',
            null::bytea,
            'envvar-xchacha-v2',
            2
        )
    ) > 0,
    'envvar-xchacha-v2 rejects missing wrapped_dek'
);

select ok(
    position(
        'secret_versions_envelope_v02_required' in test_helpers.try_insert_secret_version_with_envelope_fields(
            '940e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '2026-04-08T12:00:00Z',
            '25',
            decode(repeat('cc', 72), 'hex'),
            'envvar-xchacha-v2',
            null::integer
        )
    ) > 0,
    'envvar-xchacha-v2 rejects missing kek_version'
);

select ok(
    position(
        'secret_versions_dek_wrap_algorithm_check' in test_helpers.try_insert_secret_version_with_envelope_fields(
            '950e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '2026-04-08T12:00:00Z',
            '26',
            decode(repeat('cc', 72), 'hex'),
            'unsupported-wrap',
            2
        )
    ) > 0,
    'dek_wrap_algorithm rejects unsupported vocabulary'
);

select ok(
    position(
        'secret_versions_kek_version_positive' in test_helpers.try_insert_secret_version_with_envelope_fields(
            '960e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '2026-04-08T12:00:00Z',
            '27',
            decode(repeat('cc', 72), 'hex'),
            'legacy-master-key-v1',
            0
        )
    ) > 0,
    'kek_version rejects zero'
);

select ok(
    position(
        'secret_versions_wrapped_dek_size' in test_helpers.try_insert_secret_version_with_envelope_fields(
            '970e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '2026-04-08T12:00:00Z',
            '28',
            decode(repeat('cc', 59), 'hex'),
            'legacy-master-key-v1',
            null::integer
        )
    ) > 0,
    'wrapped_dek rejects values below the allowed size range'
);

select * from finish();

rollback;

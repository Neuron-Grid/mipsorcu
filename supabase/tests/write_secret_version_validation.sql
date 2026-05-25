begin;

\ir _support/common.psql

select no_plan();

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
    test_helpers.try_update_secret_owner(
        '550e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d480'
    ),
    'owner_immutable',
    'direct secrets update rejects owner changes'
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
        '00000000-0000-4000-8000-000000000021',
        'encrypt_create',
        '850e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        ''::bytea,
        1,
        'xchacha20-poly1305',
        decode(repeat('01', 24), 'hex'),
        test_helpers.aad_context(
            '850e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'new secret write rejects empty encrypted_data_key'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000022',
        'encrypt_create',
        '860e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 72), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('01', 24), 'hex'),
        test_helpers.aad_context(
            '860e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'new secret write rejects 72-byte encrypted_data_key'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000023',
        'encrypt_create',
        '870e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 74), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('01', 24), 'hex'),
        test_helpers.aad_context(
            '870e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'new secret write rejects 74-byte encrypted_data_key'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000024',
        'encrypt_create',
        '8a0e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        null::bytea,
        1,
        'xchacha20-poly1305',
        decode(repeat('01', 24), 'hex'),
        test_helpers.aad_context(
            '8a0e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'legacy write rejects null encrypted_data_key'
);

select is(
    test_helpers.try_write_secret_version_with_envelope(
        '00000000-0000-4000-8000-000000000025',
        'encrypt_create',
        '8b0e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        null::bytea,
        2,
        'xchacha20-poly1305',
        decode(repeat('01', 24), 'hex'),
        test_helpers.aad_context(
            '8b0e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        ),
        null::bytea,
        'envvar-xchacha-v2',
        2
    ),
    'invalid_rpc_input',
    'v0.2 write rejects missing wrapped_dek'
);

select is(
    test_helpers.try_write_secret_version_with_envelope(
        '00000000-0000-4000-8000-000000000026',
        'encrypt_create',
        '8c0e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        null::bytea,
        2,
        'xchacha20-poly1305',
        decode(repeat('01', 24), 'hex'),
        test_helpers.aad_context(
            '8c0e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        ),
        decode(repeat('cc', 60), 'hex'),
        'envvar-xchacha-v2',
        null::integer
    ),
    'invalid_rpc_input',
    'v0.2 write rejects missing kek_version'
);

select is(
    test_helpers.try_write_secret_version_with_envelope(
        '00000000-0000-4000-8000-000000000027',
        'encrypt_create',
        '8d0e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        null::bytea,
        1,
        'xchacha20-poly1305',
        decode(repeat('01', 24), 'hex'),
        test_helpers.aad_context(
            '8d0e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        ),
        decode(repeat('cc', 60), 'hex'),
        'envvar-xchacha-v2',
        2
    ),
    'invalid_rpc_input',
    'v0.2 write rejects key_version and kek_version mismatch'
);

select is(
    test_helpers.try_write_secret_version_with_envelope(
        '00000000-0000-4000-8000-000000000028',
        'encrypt_create',
        '8e0e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        null::bytea,
        2,
        'xchacha20-poly1305',
        decode(repeat('01', 24), 'hex'),
        test_helpers.aad_context(
            '8e0e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        ),
        decode(repeat('cc', 60), 'hex'),
        'unsupported-wrap',
        2
    ),
    'invalid_rpc_input',
    'write RPC rejects unsupported dek_wrap_algorithm'
);

select ok(
    position(
        'secret_versions_encrypted_data_key_length' in test_helpers.try_insert_secret_version_with_encrypted_data_key(
            '880e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '2026-04-08T12:00:00Z',
            decode(repeat('bb', 72), 'hex')
        )
    ) > 0,
    'direct secret_versions insert rejects 72-byte encrypted_data_key'
);

select ok(
    position(
        'secret_versions_encrypted_data_key_length' in test_helpers.try_insert_secret_version_with_encrypted_data_key(
            '890e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '2026-04-08T12:00:00Z',
            decode(repeat('bb', 74), 'hex')
        )
    ) > 0,
    'direct secret_versions insert rejects 74-byte encrypted_data_key'
);

select ok(
    position(
        'secret_versions_legacy_encrypted_data_key_required' in test_helpers.try_insert_secret_version_with_encrypted_data_key(
            '8f0e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '2026-04-08T12:00:00Z',
            null::bytea
        )
    ) > 0,
    'direct legacy secret_versions insert rejects null encrypted_data_key'
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

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.request_id = '00000000-0000-4000-8000-000000000001'
            and public.audit_metadata_has_forbidden_key(ae.metadata_json)
    ),
    0,
    'write RPC audit metadata passes forbidden key check'
);

select * from finish();

rollback;

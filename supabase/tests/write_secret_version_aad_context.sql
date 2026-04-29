begin;

\ir _support/common.psql

select no_plan();

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

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000033',
        'encrypt_create',
        '730e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('0d', 24), 'hex'),
        test_helpers.aad_context(
            '730e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        ) || jsonb_build_object('aad_version', '1')
    ),
    'aad_context_mismatch',
    'new secret write rejects aad_context aad_version as JSON string'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000034',
        'encrypt_create',
        '740e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('0e', 24), 'hex'),
        test_helpers.aad_context(
            '740e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        ) || jsonb_build_object('version', '1')
    ),
    'aad_context_mismatch',
    'new secret write rejects aad_context version as JSON string'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000035',
        'encrypt_create',
        '750e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        '123',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('0f', 24), 'hex'),
        test_helpers.aad_context(
            '750e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '123',
            '2026-04-08T12:00:00Z'
        ) || jsonb_build_object('classification', 123)
    ),
    'aad_context_mismatch',
    'new secret write rejects text-equivalent non-string aad_context classification'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000036',
        'encrypt_create',
        '760e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('10', 24), 'hex'),
        test_helpers.aad_context(
            '760e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        ) || jsonb_build_object('created_at', 123)
    ),
    'aad_context_mismatch',
    'new secret write rejects non-string aad_context created_at'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000037',
        'encrypt_create',
        '770e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('11', 24), 'hex'),
        test_helpers.aad_context(
            '770e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        ) || jsonb_build_object('secret_id', 123)
    ),
    'aad_context_mismatch',
    'new secret write rejects non-string aad_context secret_id'
);

select is(
    test_helpers.try_write_secret_version(
        '00000000-0000-4000-8000-000000000038',
        'encrypt_create',
        '780e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        '2026-04-08T12:00:00Z',
        1,
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat('12', 24), 'hex'),
        test_helpers.aad_context(
            '780e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        ) || jsonb_build_object('owner_user_id', true)
    ),
    'aad_context_mismatch',
    'new secret write rejects non-string aad_context owner_user_id'
);

select ok(
    position(
        'secret_versions_aad_context_allowed_keys' in test_helpers.try_insert_secret_version(
            '6e0e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '2026-04-08T12:00:00Z',
            'confidential',
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

select ok(
    position(
        'secret_versions_aad_context_matches_row' in test_helpers.try_insert_secret_version(
            '790e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '2026-04-08T12:00:00Z',
            'confidential',
            test_helpers.aad_context(
                '790e8400-e29b-41d4-a716-446655440000',
                1,
                'f47ac10b-58cc-4372-a567-0e02b2c3d479',
                'confidential',
                '2026-04-08T12:00:00Z'
            ) || jsonb_build_object('aad_version', '1')
        )
    ) > 0,
    'direct secret_versions insert rejects quoted aad_version numeric'
);

select ok(
    position(
        'secret_versions_aad_context_matches_row' in test_helpers.try_insert_secret_version(
            '7a0e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '2026-04-08T12:00:00Z',
            'confidential',
            test_helpers.aad_context(
                '7a0e8400-e29b-41d4-a716-446655440000',
                1,
                'f47ac10b-58cc-4372-a567-0e02b2c3d479',
                'confidential',
                '2026-04-08T12:00:00Z'
            ) || jsonb_build_object('version', '1')
        )
    ) > 0,
    'direct secret_versions insert rejects quoted version numeric'
);

select ok(
    position(
        'secret_versions_aad_context_matches_row' in test_helpers.try_insert_secret_version(
            '7b0e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '2026-04-08T12:00:00Z',
            '123',
            test_helpers.aad_context(
                '7b0e8400-e29b-41d4-a716-446655440000',
                1,
                'f47ac10b-58cc-4372-a567-0e02b2c3d479',
                '123',
                '2026-04-08T12:00:00Z'
            ) || jsonb_build_object('classification', 123)
        )
    ) > 0,
    'direct secret_versions insert rejects text-equivalent non-string classification'
);

select ok(
    (
        with classification_mismatch_result as (
            select test_helpers.try_insert_secret_version(
                '700e8400-e29b-41d4-a716-446655440000',
                'f47ac10b-58cc-4372-a567-0e02b2c3d479',
                '2026-04-08T12:00:00Z',
                'restricted',
                test_helpers.aad_context(
                    '700e8400-e29b-41d4-a716-446655440000',
                    1,
                    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
                    'confidential',
                    '2026-04-08T12:00:00Z'
                )
            ) as result
        )
        select
            position('secret_versions_classification_matches_aad' in result) > 0
            or position('secret_versions_aad_context_matches_row' in result) > 0
        from classification_mismatch_result
    ),
    'direct secret_versions insert rejects classification mismatch against aad_context'
);

with blank_classification_result as (
    select test_helpers.try_insert_secret_version(
        '710e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        '2026-04-08T12:00:00Z',
        '   ',
        test_helpers.aad_context(
            '710e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            '   ',
            '2026-04-08T12:00:00Z'
        )
    ) as result
)
select ok(
    (
        select
            result <> 'ok'
            and (
                position('secret_versions_classification_non_blank' in result) > 0
                or position('secret_versions_aad_context_matches_row' in result) > 0
            )
        from blank_classification_result
    ),
    'direct secret_versions insert rejects blank classification'
);

select is(
    test_helpers.try_insert_secret_version(
        '720e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        '2026-04-08T12:00:00Z',
        'confidential',
        test_helpers.aad_context(
            '720e8400-e29b-41d4-a716-446655440000',
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'direct secret_versions insert accepts matching classification and aad_context'
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

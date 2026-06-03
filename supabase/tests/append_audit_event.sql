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
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000015',
        '00000000-0000-4000-8000-000000000015',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"source":"sql-test","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'ok',
    'append audit RPC accepts valid audit event with canonical source_event_at'
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
        '{"source":"sql-test","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
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
    test_helpers.try_update_audit_event(
        '10000000-0000-4000-8000-000000000015'
    ),
    'audit_events_immutable',
    'direct audit_events update is rejected by immutability trigger'
);

select is(
    test_helpers.try_delete_audit_event(
        '10000000-0000-4000-8000-000000000015'
    ),
    'audit_events_immutable',
    'direct audit_events delete is rejected by immutability trigger'
);

select is(
    test_helpers.try_truncate_audit_events(),
    'audit_events_immutable',
    'direct audit_events truncate is rejected by immutability trigger'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000026',
        '00000000-0000-4000-8000-000000000015',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'integrity_check',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"source":"same-request-follow-up"}'::jsonb
    ),
    'ok',
    'append audit RPC allows distinct audit_event_id with same request_id'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.request_id = '00000000-0000-4000-8000-000000000015'
    ),
    2,
    'request_id correlates multiple audit events instead of deduplicating them'
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
        '10000000-0000-4000-8000-000000000015',
        '00000000-0000-4000-8000-000000000015',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"source":"sql-test","source_event_at":"2026-04-08T12:00:01Z"}'::jsonb
    ),
    'audit_event_id_conflict',
    'append audit RPC rejects same audit_event_id when source_event_at differs'
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
        '10000000-0000-4000-8000-000000000019',
        '00000000-0000-4000-8000-000000000019',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"source_event_at":"2026-04-08T12:00:00+00:00"}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects non-canonical source_event_at offset'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000020',
        '00000000-0000-4000-8000-000000000020',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"source_event_at":"2026-04-08 12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects malformed source_event_at'
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

select ok(
    position(
        'audit_events_metadata_json_no_forbidden_keys' in test_helpers.try_insert_audit_event(
            '10000000-0000-4000-8000-000000000027',
            '00000000-0000-4000-8000-000000000027',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'sbc-device-1',
            'decrypt',
            '550e8400-e29b-41d4-a716-446655440000',
            'failure',
            1,
            '{"nested":[{"plaintext":"leak"}]}'::jsonb
        )
    ) > 0,
    'direct audit_events insert rejects forbidden metadata keys recursively'
);

select ok(
    position(
        'audit_events_metadata_json_source_event_at_valid' in test_helpers.try_insert_audit_event(
            '10000000-0000-4000-8000-000000000027',
            '00000000-0000-4000-8000-000000000030',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'sbc-device-1',
            'decrypt',
            '550e8400-e29b-41d4-a716-446655440000',
            'failure',
            1,
            '{"source_event_at":"2026-04-08T12:00:00+00:00"}'::jsonb
        )
    ) > 0,
    'direct audit_events insert rejects non-canonical source_event_at via table constraint'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000028',
        '00000000-0000-4000-8000-000000000028',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"nested":[{"plain_text":"leak"}]}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects synchronized plain_text key recursively'
);

select ok(
    position(
        'audit_events_metadata_json_no_forbidden_keys' in test_helpers.try_insert_audit_event(
            '10000000-0000-4000-8000-000000000029',
            '00000000-0000-4000-8000-000000000029',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'sbc-device-1',
            'decrypt',
            '550e8400-e29b-41d4-a716-446655440000',
            'failure',
            1,
            '{"nested":[{"plain_text":"leak"}]}'::jsonb
        )
    ) > 0,
    'direct audit_events insert rejects synchronized plain_text key recursively'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000030',
        '00000000-0000-4000-8000-000000000030',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"nested":[{"DeCrYpTeD_dAtA":"leak"}]}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects synchronized decrypted_data key case-insensitively'
);

select ok(
    position(
        'audit_events_metadata_json_no_forbidden_keys' in test_helpers.try_insert_audit_event(
            '10000000-0000-4000-8000-000000000031',
            '00000000-0000-4000-8000-000000000031',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'sbc-device-1',
            'decrypt',
            '550e8400-e29b-41d4-a716-446655440000',
            'failure',
            1,
            '{"nested":[{"DeCrYpTeD_dAtA":"leak"}]}'::jsonb
        )
    ) > 0,
    'direct audit_events insert rejects synchronized decrypted_data key case-insensitively'
);

select is(
    (
        select count(*)::integer
        from (values
            ('authorization'),
            ('ciphertext'),
            ('data_key'),
            ('decrypt_result'),
            ('decrypted'),
            ('decrypted_data'),
            ('encrypted_data_key'),
            ('jwt'),
            ('master_key'),
            ('passphrase'),
            ('password'),
            ('plain_text'),
            ('plaintext'),
            ('secret_key'),
            ('secret_value'),
            ('service_role'),
            ('service_role_key'),
            ('token')
        ) as forbidden_keys(key)
        where public.audit_metadata_has_forbidden_key(
            jsonb_build_object(forbidden_keys.key, 'leak')
        )
    ),
    18,
    'audit metadata guard rejects every synchronized forbidden key'
);

select ok(
    not public.audit_metadata_has_forbidden_key(
        '{"error_code":"denied","token_hint":"safe","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'audit metadata guard allows safe metadata keys'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000035',
        '00000000-0000-4000-8000-000000000035',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"secret_value":"leak","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects added secret_value metadata key'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000036',
        '00000000-0000-4000-8000-000000000036',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"nested":[{"password":"leak"}],"source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects added password metadata key in array object'
);

select ok(
    position(
        'audit_events_metadata_json_no_forbidden_keys' in test_helpers.try_insert_audit_event(
            '10000000-0000-4000-8000-000000000037',
            '00000000-0000-4000-8000-000000000037',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'sbc-device-1',
            'decrypt',
            '550e8400-e29b-41d4-a716-446655440000',
            'failure',
            1,
            '{"nested":{" AuThOrIzAtIoN ":"leak"},"source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
        )
    ) > 0,
    'direct audit_events insert rejects added authorization metadata key case-insensitively with trimming'
);

select ok(
    position(
        'audit_events_metadata_json_no_forbidden_keys' in test_helpers.try_insert_audit_event(
            '10000000-0000-4000-8000-000000000038',
            '00000000-0000-4000-8000-000000000038',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'sbc-device-1',
            'decrypt',
            '550e8400-e29b-41d4-a716-446655440000',
            'failure',
            1,
            '{"safe":[{"token":"leak"}],"source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
        )
    ) > 0,
    'direct audit_events insert rejects added token metadata key in array object'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000039',
        '00000000-0000-4000-8000-000000000039',
        null,
        null,
        'auth_failure',
        null,
        'failure',
        null,
        '{"error_code":"authorization_header_missing","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'ok',
    'append audit RPC accepts auth_failure failure with null actor and target'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.id = '10000000-0000-4000-8000-000000000039'
            and ae.action = 'auth_failure'
            and ae.result = 'failure'
            and ae.actor_user_id is null
            and ae.actor_device_id is null
            and ae.target_secret_id is null
            and ae.key_version is null
    ),
    1,
    'append audit RPC stores auth_failure failure audit event'
);

select is(
    test_helpers.try_insert_audit_event(
        '10000000-0000-4000-8000-000000000040',
        '00000000-0000-4000-8000-000000000040',
        null,
        null,
        'auth_failure',
        null,
        'failure',
        null,
        '{"error_code":"authorization_header_missing","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'ok',
    'direct audit_events insert accepts auth_failure failure with null actor and target'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000041',
        '00000000-0000-4000-8000-000000000041',
        null,
        null,
        'auth_failure',
        null,
        'success',
        null,
        '{"error_code":"unexpected_success","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects auth_failure success'
);

select ok(
    position(
        'audit_events_auth_failure_failure_only' in test_helpers.try_insert_audit_event(
            '10000000-0000-4000-8000-000000000042',
            '00000000-0000-4000-8000-000000000042',
            null,
            null,
            'auth_failure',
            null,
            'success',
            null,
            '{"error_code":"unexpected_success","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
        )
    ) > 0,
    'direct audit_events insert rejects auth_failure success via table constraint'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000043',
        '00000000-0000-4000-8000-000000000043',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        null,
        'auth_failure',
        null,
        'failure',
        null,
        '{"error_code":"authorization_header_missing","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects auth_failure with actor_user_id'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000044',
        '00000000-0000-4000-8000-000000000044',
        null,
        'sbc-device-1',
        'auth_failure',
        null,
        'failure',
        null,
        '{"error_code":"authorization_header_missing","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects auth_failure with actor_device_id'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000045',
        '00000000-0000-4000-8000-000000000045',
        null,
        null,
        'auth_failure',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        null,
        '{"error_code":"authorization_header_missing","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects auth_failure with target_secret_id'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000046',
        '00000000-0000-4000-8000-000000000046',
        null,
        null,
        'auth_failure',
        null,
        'failure',
        1,
        '{"error_code":"authorization_header_missing","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'append audit RPC rejects auth_failure with key_version'
);

select ok(
    position(
        'audit_events_auth_failure_null_fields_check' in test_helpers.try_insert_audit_event(
            '10000000-0000-4000-8000-000000000047',
            '00000000-0000-4000-8000-000000000047',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            null,
            'auth_failure',
            null,
            'failure',
            null,
            '{"error_code":"authorization_header_missing","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
        )
    ) > 0,
    'direct audit_events insert rejects auth_failure with actor_user_id'
);

select ok(
    position(
        'audit_events_auth_failure_null_fields_check' in test_helpers.try_insert_audit_event(
            '10000000-0000-4000-8000-000000000048',
            '00000000-0000-4000-8000-000000000048',
            null,
            'sbc-device-1',
            'auth_failure',
            null,
            'failure',
            null,
            '{"error_code":"authorization_header_missing","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
        )
    ) > 0,
    'direct audit_events insert rejects auth_failure with actor_device_id'
);

select ok(
    position(
        'audit_events_auth_failure_null_fields_check' in test_helpers.try_insert_audit_event(
            '10000000-0000-4000-8000-000000000049',
            '00000000-0000-4000-8000-000000000049',
            null,
            null,
            'auth_failure',
            '550e8400-e29b-41d4-a716-446655440000',
            'failure',
            null,
            '{"error_code":"authorization_header_missing","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
        )
    ) > 0,
    'direct audit_events insert rejects auth_failure with target_secret_id'
);

select ok(
    position(
        'audit_events_auth_failure_null_fields_check' in test_helpers.try_insert_audit_event(
            '10000000-0000-4000-8000-000000000050',
            '00000000-0000-4000-8000-000000000050',
            null,
            null,
            'auth_failure',
            null,
            'failure',
            1,
            '{"error_code":"authorization_header_missing","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
        )
    ) > 0,
    'direct audit_events insert rejects auth_failure with key_version'
);

set local mipsorcu.audit_metadata_allowlist_mode = 'strict';

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000120',
        '00000000-0000-4000-8000-000000000120',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_create',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'alias_fingerprint', repeat('aa', 32),
            'alias_fingerprint_key_version', 1,
            'alias_fingerprint_schema_version', 1,
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'append audit RPC accepts secret_alias_create with valid metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000121',
        '00000000-0000-4000-8000-000000000121',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_update',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'old_alias_fingerprint', repeat('aa', 32),
            'new_alias_fingerprint', repeat('bb', 32),
            'alias_fingerprint_key_version', 1,
            'alias_fingerprint_schema_version', 1,
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'append audit RPC accepts secret_alias_update with valid metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000122',
        '00000000-0000-4000-8000-000000000122',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_delete',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'alias_fingerprint', repeat('aa', 32),
            'alias_fingerprint_key_version', 1,
            'alias_fingerprint_schema_version', 1,
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'append audit RPC accepts secret_alias_delete with valid metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000123',
        '00000000-0000-4000-8000-000000000123',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_list',
        null,
        'success',
        null,
        jsonb_build_object(
            'result_count', 1,
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'append audit RPC accepts secret_alias_list with valid metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-0000000000f0',
        '00000000-0000-4000-8000-0000000000f0',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'audit_ui_read',
        null,
        'success',
        null,
        jsonb_build_object(
            'endpoint', '/audit/events',
            'method', 'GET',
            'resource', 'audit_events',
            'result_count', 1,
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'append audit RPC accepts audit_ui_read with valid metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-0000000000f1',
        '00000000-0000-4000-8000-0000000000f1',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'audit_ui_read',
        null,
        'success',
        null,
        jsonb_build_object(
            'endpoint', '/audit/events',
            'method', 'POST',
            'resource', 'audit_events',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'append audit RPC rejects audit_ui_read with invalid metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-0000000000ff',
        '00000000-0000-4000-8000-0000000000ff',
        null,
        null,
        'scheduler_job',
        null,
        'success',
        null,
        jsonb_build_object(
            'job_name', 'test-job',
            'trigger', 'scheduled',
            'duration_ms', 0,
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'append audit RPC rejects scheduled trigger'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000130',
        '00000000-0000-4000-8000-000000000130',
        null,
        null,
        'scheduler_job_started',
        null,
        'success',
        null,
        jsonb_build_object(
            'job_name', 'monthly_hash_chain_verify',
            'scheduled_at', '2026-04-08T12:00:00Z',
            'started_at', '2026-04-08T12:00:01Z',
            'source_event_at', '2026-04-08T12:00:01Z'
        )
    ),
    'ok',
    'append audit RPC accepts scheduler_job_started with valid metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000131',
        '00000000-0000-4000-8000-000000000131',
        null,
        null,
        'scheduler_job_failed',
        null,
        'success',
        null,
        jsonb_build_object(
            'job_name', 'monthly_hash_chain_verify',
            'started_at', '2026-04-08T12:00:01Z',
            'failed_at', '2026-04-08T12:00:02Z',
            'error_code', 'scheduler_job_timeout',
            'retry_count', 0,
            'source_event_at', '2026-04-08T12:00:02Z'
        )
    ),
    'invalid_rpc_input',
    'append audit RPC rejects scheduler_job_failed success result'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000132',
        '00000000-0000-4000-8000-000000000132',
        null,
        null,
        'siem_event_forwarded',
        null,
        'success',
        null,
        jsonb_build_object(
            'exporter_kind', 'splunk_hec',
            'batch_size', 100,
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'append audit RPC accepts siem_event_forwarded success metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000133',
        '00000000-0000-4000-8000-000000000133',
        null,
        null,
        'siem_event_forwarded',
        null,
        'failure',
        null,
        jsonb_build_object(
            'exporter_kind', 'splunk_hec',
            'batch_size', 1,
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'append audit RPC rejects siem_event_forwarded failure result'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000134',
        '00000000-0000-4000-8000-000000000134',
        null,
        null,
        'siem_event_failed',
        null,
        'failure',
        null,
        jsonb_build_object(
            'exporter_kind', 'splunk_hec',
            'error_code', 'siem_splunk_http_503',
            'buffered', true,
            'batch_size', 3,
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'append audit RPC accepts siem_event_failed failure metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000135',
        '00000000-0000-4000-8000-000000000135',
        null,
        null,
        'siem_event_failed',
        null,
        'success',
        null,
        jsonb_build_object(
            'exporter_kind', 'splunk_hec',
            'error_code', 'siem_splunk_http_503',
            'buffered', true,
            'batch_size', 3,
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'append audit RPC rejects siem_event_failed success result'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000136',
        '00000000-0000-4000-8000-000000000136',
        null,
        null,
        'siem_buffer_flushed',
        null,
        'success',
        null,
        jsonb_build_object(
            'flushed_count', 3,
            'buffer_remaining_bytes', 1048576,
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'append audit RPC accepts siem_buffer_flushed success metadata'
);

select ok(
    position(
        'audit_events_siem_event_failed_failure_only' in test_helpers.try_insert_audit_event(
            '10000000-0000-4000-8000-000000000137',
            '00000000-0000-4000-8000-000000000137',
            null,
            null,
            'siem_event_failed',
            null,
            'success',
            null,
            jsonb_build_object(
                'exporter_kind', 'splunk_hec',
                'error_code', 'siem_splunk_http_503',
                'buffered', true,
                'batch_size', 3,
                'source_event_at', '2026-04-08T12:00:00Z'
            )
        )
    ) > 0,
    'direct audit_events insert rejects siem_event_failed success via table constraint'
);

select * from finish();

rollback;

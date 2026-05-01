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
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000032',
        '00000000-0000-4000-8000-000000000032',
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
        where ae.id = '10000000-0000-4000-8000-000000000032'
            and ae.action = 'auth_failure'
            and ae.result = 'failure'
            and ae.actor_user_id is null
            and ae.target_secret_id is null
    ),
    1,
    'append audit RPC stores auth_failure failure audit event'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000033',
        '00000000-0000-4000-8000-000000000033',
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
            '10000000-0000-4000-8000-000000000034',
            '00000000-0000-4000-8000-000000000034',
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

select * from finish();

rollback;

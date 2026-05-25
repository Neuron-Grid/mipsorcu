begin;

\ir _support/common.psql

select no_plan();

create function test_helpers.write_with_ledger(
    p_request_id uuid,
    p_action text,
    p_secret_id uuid,
    p_secret_version_id uuid,
    p_version integer,
    p_ciphertext_byte text,
    p_nonce_byte text,
    p_ledger_entries jsonb
)
returns table (
    secret_id uuid,
    secret_version_id uuid,
    version integer,
    purged_version_ids uuid[]
)
language sql
as $$
    select *
    from public.rpc_write_secret_version(
        p_request_id,
        p_action,
        p_secret_id,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        'sbc-device-1',
        ('2026-04-08T12:00:00Z'::timestamptz + make_interval(secs => p_version)),
        p_version,
        decode(repeat(p_ciphertext_byte, 32), 'hex'),
        decode(repeat('bb', 73), 'hex'),
        1,
        'xchacha20-poly1305',
        decode(repeat(p_nonce_byte, 24), 'hex'),
        test_helpers.aad_context(
            p_secret_id,
            p_version,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            to_char(
                '2026-04-08T12:00:00Z'::timestamptz + make_interval(secs => p_version),
                'YYYY-MM-DD"T"HH24:MI:SS"Z"'
            )
        ),
        p_secret_version_id,
        p_ledger_entries
    );
$$;

create temp table create_result as
select *
from test_helpers.write_with_ledger(
    '00000000-0000-4000-8000-000000000101',
    'encrypt_create',
    '550e8400-e29b-41d4-a716-446655440000',
    '66000000-0000-4000-8000-000000000001',
    1,
    'a1',
    '01',
    jsonb_build_array(test_helpers.ledger_entry_json(
        '20000000-0000-4000-8000-000000000101',
        1,
        'secret_created',
        '2026-04-08T12:00:01Z',
        '00000000-0000-4000-8000-000000000101',
        '22000000-0000-4000-8000-000000000101',
        '550e8400-e29b-41d4-a716-446655440000',
        '66000000-0000-4000-8000-000000000001',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'success',
        null,
        '{"algorithm":"xchacha20-poly1305","classification":"confidential","key_version":1,"version":1}'::jsonb,
        repeat('00', 32),
        repeat('11', 32)
    ))
);

select is(
    (select count(*)::integer from public.audit_events where action = 'encrypt_create'),
    1,
    'secret create appends authoritative audit event'
);

select is(
    (select count(*)::integer from public.ledger_entries where entry_type = 'secret_created'),
    1,
    'secret create appends secret_created ledger entry'
);

select *
from test_helpers.write_with_ledger(
    '00000000-0000-4000-8000-000000000102',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655440000',
    '66000000-0000-4000-8000-000000000002',
    2,
    'a2',
    '02',
    jsonb_build_array(test_helpers.ledger_entry_json(
        '20000000-0000-4000-8000-000000000102',
        2,
        'secret_version_created',
        '2026-04-08T12:00:02Z',
        '00000000-0000-4000-8000-000000000102',
        '22000000-0000-4000-8000-000000000102',
        '550e8400-e29b-41d4-a716-446655440000',
        '66000000-0000-4000-8000-000000000002',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'success',
        null,
        '{"algorithm":"xchacha20-poly1305","classification":"confidential","key_version":1,"version":2}'::jsonb,
        repeat('11', 32),
        repeat('22', 32)
    ))
);

select is(
    (select count(*)::integer from public.ledger_entries where entry_type = 'secret_version_created'),
    1,
    'secret rotation appends secret_version_created ledger entry'
);

select *
from test_helpers.write_with_ledger(
    '00000000-0000-4000-8000-000000000103',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655440000',
    '66000000-0000-4000-8000-000000000003',
    3,
    'a3',
    '03',
    jsonb_build_array(test_helpers.ledger_entry_json(
        '20000000-0000-4000-8000-000000000103',
        3,
        'secret_version_created',
        '2026-04-08T12:00:03Z',
        '00000000-0000-4000-8000-000000000103',
        '22000000-0000-4000-8000-000000000103',
        '550e8400-e29b-41d4-a716-446655440000',
        '66000000-0000-4000-8000-000000000003',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'success',
        null,
        '{"algorithm":"xchacha20-poly1305","classification":"confidential","key_version":1,"version":3}'::jsonb,
        repeat('22', 32),
        repeat('33', 32)
    ))
);

select *
from test_helpers.write_with_ledger(
    '00000000-0000-4000-8000-000000000104',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655440000',
    '66000000-0000-4000-8000-000000000004',
    4,
    'a4',
    '04',
    jsonb_build_array(test_helpers.ledger_entry_json(
        '20000000-0000-4000-8000-000000000104',
        4,
        'secret_version_created',
        '2026-04-08T12:00:04Z',
        '00000000-0000-4000-8000-000000000104',
        '22000000-0000-4000-8000-000000000104',
        '550e8400-e29b-41d4-a716-446655440000',
        '66000000-0000-4000-8000-000000000004',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'success',
        null,
        '{"algorithm":"xchacha20-poly1305","classification":"confidential","key_version":1,"version":4}'::jsonb,
        repeat('33', 32),
        repeat('44', 32)
    ))
);

create temp table fifth_result as
select *
from test_helpers.write_with_ledger(
    '00000000-0000-4000-8000-000000000105',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655440000',
    '66000000-0000-4000-8000-000000000005',
    5,
    'a5',
    '05',
    jsonb_build_array(
        test_helpers.ledger_entry_json(
            '20000000-0000-4000-8000-000000000105',
            5,
            'secret_version_created',
            '2026-04-08T12:00:05Z',
            '00000000-0000-4000-8000-000000000105',
            '22000000-0000-4000-8000-000000000105',
            '550e8400-e29b-41d4-a716-446655440000',
            '66000000-0000-4000-8000-000000000005',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'sbc-device-1',
            'success',
            null,
            '{"algorithm":"xchacha20-poly1305","classification":"confidential","key_version":1,"version":5}'::jsonb,
            repeat('44', 32),
            repeat('55', 32)
        ),
        test_helpers.ledger_entry_json(
            '20000000-0000-4000-8000-000000000106',
            6,
            'secret_version_purged',
            '2026-04-08T12:00:06Z',
            '00000000-0000-4000-8000-000000000105',
            '22000000-0000-4000-8000-000000000106',
            '550e8400-e29b-41d4-a716-446655440000',
            '66000000-0000-4000-8000-000000000001',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'sbc-device-1',
            'success',
            null,
            '{"key_version":1,"retention_limit":4,"version":1}'::jsonb,
            repeat('55', 32),
            repeat('66', 32)
        )
    )
);

select is(
    (select array_length(purged_version_ids, 1) from fifth_result),
    1,
    'fifth version purges one old version'
);

select is(
    (select count(*)::integer from public.ledger_entries where entry_type = 'secret_version_purged'),
    1,
    'purge appends secret_version_purged ledger entry'
);

select is(
    (select last_sequence_no from public.ledger_chain_state where chain_id = 'global'),
    6::bigint,
    'write path ledger entries advance the global hash chain'
);

select *
from public.rpc_append_audit_event_with_ledger(
    '22000000-0000-4000-8000-000000000201',
    '00000000-0000-4000-8000-000000000201',
    null,
    null,
    'restore_test',
    null,
    'success',
    null,
    '{"sample_count":3,"success_count":3,"failure_count":0,"duration_ms":12,"trigger":"cli","source_event_at":"2026-04-08T12:00:07Z"}'::jsonb,
    '20000000-0000-4000-8000-000000000201',
    7,
    'restore_test_completed',
    '2026-04-08T12:00:07Z',
    '22000000-0000-4000-8000-000000000201',
    null,
    null,
    '{"sample_count":3,"success_count":3,"failure_count":0,"duration_ms":12,"trigger":"cli"}'::jsonb,
    1,
    decode(repeat('66', 32), 'hex'),
    decode(repeat('77', 32), 'hex'),
    'sha3-256',
    decode(repeat('aa', 64), 'hex'),
    'ed25519',
    1
);

select is(
    (select count(*)::integer from public.ledger_entries where entry_type = 'restore_test_completed'),
    1,
    'restore test completion appends restore_test_completed ledger entry'
);

select *
from public.rpc_append_audit_event_with_ledger(
    '22000000-0000-4000-8000-000000000202',
    '00000000-0000-4000-8000-000000000202',
    null,
    null,
    'integrity_check',
    null,
    'success',
    null,
    '{"checked_secret_count":1,"checked_secret_version_count":4,"checked_audit_event_count":7,"violation_count":0,"duration_ms":9,"source_event_at":"2026-04-08T12:00:08Z"}'::jsonb,
    '20000000-0000-4000-8000-000000000202',
    8,
    'integrity_check_completed',
    '2026-04-08T12:00:08Z',
    '22000000-0000-4000-8000-000000000202',
    null,
    null,
    '{"checked_secret_count":1,"checked_secret_version_count":4,"checked_audit_event_count":7,"violation_count":0,"duration_ms":9}'::jsonb,
    1,
    decode(repeat('77', 32), 'hex'),
    decode(repeat('88', 32), 'hex'),
    'sha3-256',
    decode(repeat('aa', 64), 'hex'),
    'ed25519',
    1
);

select is(
    (select count(*)::integer from public.ledger_entries where entry_type = 'integrity_check_completed'),
    1,
    'integrity check completion appends integrity_check_completed ledger entry'
);

select is(
    (
        select count(*)::integer
        from public.ledger_entries
        where public.ledger_payload_has_forbidden_key(payload)
    ),
    0,
    'use-case ledger payloads do not contain forbidden keys'
);

select is(
    to_regclass('public.secret_nonce_ledger'),
    null,
    'nonce complete-history table is not introduced'
);

select * from finish();

rollback;

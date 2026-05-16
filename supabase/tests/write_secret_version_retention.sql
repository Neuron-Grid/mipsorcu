begin;

\ir _support/common.psql

select no_plan();

create temp table first_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000000001',
    'encrypt_create',
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:00:00Z',
    1,
    'aa',
    '01'
);

create temp table second_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000000010',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:01:00Z',
    2,
    'a2',
    '02'
);

create temp table third_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000000011',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:02:00Z',
    3,
    'a3',
    '03'
);

create temp table fourth_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000000012',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:03:00Z',
    4,
    'a4',
    '04'
);

create temp table fifth_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000000013',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:04:00Z',
    5,
    'a5',
    '05'
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

select is(
    test_helpers.try_write_secret_version_diagnostics(
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
    '23505:nonce_reuse_detected',
    'existing secret write rejects retained nonce reuse with stable SQLSTATE'
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

select * from finish();

rollback;

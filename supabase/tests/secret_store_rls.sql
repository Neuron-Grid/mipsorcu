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

select * from finish();

rollback;

begin;

\ir _support/common.psql

select no_plan();

create temp table owner_write_result as
select *
from public.rpc_write_secret_version(
    '00000000-0000-4000-8000-000000000101',
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

create temp table other_owner_write_result as
select *
from public.rpc_write_secret_version(
    '00000000-0000-4000-8000-000000000102',
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
    decode(repeat('02', 24), 'hex'),
    test_helpers.aad_context(
        '650e8400-e29b-41d4-a716-446655440000',
        1,
        'f47ac10b-58cc-4372-a567-0e02b2c3d480',
        'confidential',
        '2026-04-08T12:00:00Z'
    )
);

create function test_helpers.try_create_secret_alias(
    p_secret_id uuid,
    p_owner_user_id uuid,
    p_alias text,
    p_alias_normalized text
)
returns text
language plpgsql
as $$
begin
    perform *
    from public.rpc_create_secret_alias(
        p_secret_id,
        p_owner_user_id,
        p_alias,
        p_alias_normalized
    );

    return 'ok';
exception
    when others then
        return sqlstate || ':' || sqlerrm;
end;
$$;

select ok(
    not has_table_privilege('anon', 'public.secret_aliases', 'select'),
    'anon cannot select secret_aliases'
);

select ok(
    has_table_privilege('authenticated', 'public.secret_aliases', 'select'),
    'authenticated can select own secret_aliases through RLS'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('insert'),
                ('update'),
                ('delete'),
                ('truncate')
            ) as table_privileges(privilege_name)
            where has_table_privilege(
                'authenticated',
                'public.secret_aliases',
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'authenticated cannot write secret_aliases directly'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('insert'),
                ('update'),
                ('delete'),
                ('truncate')
            ) as table_privileges(privilege_name)
            where has_table_privilege(
                'service_role',
                'public.secret_aliases',
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'service_role has no direct DML privilege on secret_aliases'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_create_secret_alias(uuid, uuid, text, text)',
        'execute'
    ),
    'service_role can execute rpc_create_secret_alias'
);

select is(
    test_helpers.try_create_secret_alias(
        '550e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'Prod.API_1',
        'prod.api_1'
    ),
    'ok',
    'rpc_create_secret_alias creates an owner-scoped alias'
);

select is(
    (
        select count(*)::integer
        from public.secret_aliases
        where secret_id = '550e8400-e29b-41d4-a716-446655440000'
            and owner_user_id = 'f47ac10b-58cc-4372-a567-0e02b2c3d479'
            and alias = 'Prod.API_1'
            and alias_normalized = 'prod.api_1'
    ),
    1,
    'created alias stores canonical secret_id, owner, alias, and normalized alias'
);

select matches(
    test_helpers.try_create_secret_alias(
        '550e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'prod.api_1',
        'prod.api_1'
    ),
    'secret_alias_duplicate',
    'duplicate normalized alias is rejected per owner'
);

select matches(
    test_helpers.try_create_secret_alias(
        '550e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d480',
        'other-owner',
        'other-owner'
    ),
    'secret_alias_owner_mismatch',
    'owner mismatch is rejected'
);

select matches(
    test_helpers.try_create_secret_alias(
        '550e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        '   ',
        ''
    ),
    'secret_alias_invalid',
    'blank alias is rejected'
);

select matches(
    test_helpers.try_create_secret_alias(
        '550e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        repeat('a', 129),
        repeat('a', 129)
    ),
    'secret_alias_invalid',
    'overlong alias is rejected'
);

select matches(
    test_helpers.try_create_secret_alias(
        '550e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        '750e8400-e29b-41d4-a716-446655440000',
        '750e8400-e29b-41d4-a716-446655440000'
    ),
    'secret_alias_invalid',
    'UUID v4-looking alias is rejected'
);

set local role authenticated;
set local "request.jwt.claim.sub" = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';

select is(
    (select count(*)::integer from public.secret_aliases),
    1,
    'RLS exposes only owned aliases to the owner'
);

reset role;

set local role authenticated;
set local "request.jwt.claim.sub" = 'f47ac10b-58cc-4372-a567-0e02b2c3d480';

select is(
    (select count(*)::integer from public.secret_aliases),
    0,
    'RLS hides another owner aliases'
);

reset role;

select * from finish();

rollback;

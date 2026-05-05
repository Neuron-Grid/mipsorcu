begin;

\ir _support/common.psql

select no_plan();

create temp table integrity_write_result as
select *
from public.rpc_write_secret_version(
    '00000000-0000-4000-8000-000000000031',
    'encrypt_create',
    '850e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'confidential',
    'sbc-device-1',
    '2026-04-08T12:00:00Z',
    1,
    decode(repeat('aa', 32), 'hex'),
    decode(repeat('bb', 73), 'hex'),
    1,
    'xchacha20-poly1305',
    decode(repeat('31', 24), 'hex'),
    test_helpers.aad_context(
        '850e8400-e29b-41d4-a716-446655440000',
        1,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        '2026-04-08T12:00:00Z'
    )
);

select *
into temp table integrity_result
from public.rpc_integrity_check();

select is(
    (select checked_secret_count from integrity_result),
    1,
    'integrity check counts secrets'
);

select is(
    (select checked_secret_version_count from integrity_result),
    1,
    'integrity check counts secret versions'
);

select is(
    (select violation_count from integrity_result),
    0,
    'integrity check returns zero violations for valid fixture'
);

select is(
    (
        select count(*)::integer
        from jsonb_object_keys((select violation_summary from integrity_result)) as keys(key)
    ),
    16,
    'integrity check summary exposes only fixed aggregate categories'
);

select is(
    (
        select count(*)::integer
        from jsonb_each((select violation_summary from integrity_result)) as entries(key, value)
        where jsonb_typeof(entries.value) <> 'number'
    ),
    0,
    'integrity check summary values are numeric counts'
);

select ok(
    not ((select violation_summary::text from integrity_result) like '%850e8400-e29b-41d4-a716-446655440000%'),
    'integrity check summary does not expose secret ids'
);

select ok(
    not ((select violation_summary::text from integrity_result) like '%aad_version%'),
    'integrity check summary does not expose aad_context payload'
);

select ok(
    not ((select violation_summary::text from integrity_result) like '%aaaaaaaa%'),
    'integrity check summary does not expose ciphertext bytes'
);

select ok(
    not ((select violation_summary::text from integrity_result) like '%bbbbbbbb%'),
    'integrity check summary does not expose encrypted data key bytes'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.rpc_integrity_check()',
        'execute'
    ),
    'anon cannot execute integrity check RPC'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.rpc_integrity_check()',
        'execute'
    ),
    'authenticated cannot execute integrity check RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_integrity_check()',
        'execute'
    ),
    'service_role can execute integrity check RPC'
);

select ok(
    (
        select p.prosecdef
        from pg_proc p
        join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public'
            and p.proname = 'rpc_integrity_check'
    ),
    'integrity check RPC is SECURITY DEFINER'
);

select ok(
    (
        select exists (
            select 1
            from pg_proc p
            join pg_namespace n on n.oid = p.pronamespace
            where n.nspname = 'public'
                and p.proname = 'rpc_integrity_check'
                and 'search_path=public, pg_temp' = any (p.proconfig)
        )
    ),
    'integrity check RPC has explicit search_path'
);

select is(
    (
        select count(*)::integer
        from pg_proc p
        join pg_namespace n on n.oid = p.pronamespace
        cross join (
            select c.relowner
            from pg_class c
            where c.oid = 'public.secrets'::regclass
        ) table_owner
        where n.nspname = 'public'
            and p.proname = 'rpc_integrity_check'
            and p.proowner = table_owner.relowner
            and pg_get_userbyid(p.proowner) not in (
                'anon',
                'authenticated',
                'service_role'
            )
    ),
    1,
    'integrity check RPC is owned by the schema/table owner, not runtime roles'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('select'),
                ('insert'),
                ('update'),
                ('delete'),
                ('truncate')
            ) as table_privileges(privilege_name)
            where has_table_privilege(
                'service_role',
                'public.audit_events',
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'service_role still has no direct table privileges on audit_events'
);

set local role service_role;

select is(
    (
        select violation_count
        from public.rpc_integrity_check()
    ),
    0,
    'service_role can execute integrity check RPC'
);

reset role;

select * from finish();

rollback;

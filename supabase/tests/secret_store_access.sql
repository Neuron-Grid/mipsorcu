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

create temp table restore_test_sample_result as
select *
from public.rpc_sample_restore_test(2);

create temp table restore_test_sample_result_limited as
select *
from public.rpc_sample_restore_test(1);

select ok(
    not has_table_privilege('anon', 'public.secrets', 'select'),
    'anon cannot select secrets'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('public.secrets', 'select'),
                ('public.secrets', 'insert'),
                ('public.secrets', 'update'),
                ('public.secrets', 'delete'),
                ('public.secret_versions', 'select'),
                ('public.secret_versions', 'insert'),
                ('public.secret_versions', 'update'),
                ('public.secret_versions', 'delete'),
                ('public.audit_events', 'select'),
                ('public.audit_events', 'insert'),
                ('public.audit_events', 'update'),
                ('public.audit_events', 'delete'),
                ('public.audit_events', 'truncate')
            ) as table_privileges(table_name, privilege_name)
            where has_table_privilege(
                'anon',
                table_privileges.table_name,
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'anon has no direct table privileges on secret store tables'
);

select ok(
    has_table_privilege('authenticated', 'public.secrets', 'select'),
    'authenticated can select secrets through RLS'
);

select ok(
    has_table_privilege('authenticated', 'public.secret_versions', 'select'),
    'authenticated can select secret_versions through RLS'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('public.secrets', 'insert'),
                ('public.secrets', 'update'),
                ('public.secrets', 'delete'),
                ('public.secret_versions', 'insert'),
                ('public.secret_versions', 'update'),
                ('public.secret_versions', 'delete')
            ) as table_privileges(table_name, privilege_name)
            where has_table_privilege(
                'authenticated',
                table_privileges.table_name,
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'authenticated cannot write secret store tables directly'
);

select ok(
    not has_table_privilege('authenticated', 'public.audit_events', 'select'),
    'authenticated cannot select audit_events'
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
                'authenticated',
                'public.audit_events',
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'authenticated has no direct table privileges on audit_events'
);

select is(
    (
        select bool_and(c.relrowsecurity and c.relforcerowsecurity)
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public'
            and c.relname in (
                'secrets',
                'secret_versions',
                'audit_events'
            )
    ),
    true,
    'secret store tables enable and force row level security'
);

select ok(
    (
        select exists (
            select 1
            from pg_policies p
            where p.schemaname = 'public'
                and p.tablename = 'audit_events'
                and p.policyname = 'audit_events_deny_all'
                and p.permissive = 'RESTRICTIVE'
                and p.cmd = 'ALL'
                and position('false' in coalesce(p.qual, '')) > 0
                and position('false' in coalesce(p.with_check, '')) > 0
        )
    ),
    'audit_events has deny-all restrictive RLS policy'
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
    'service_role has no direct table privileges on audit_events'
);

select ok(
    has_table_privilege('service_role', 'public.secrets', 'select'),
    'service_role keeps direct select on secrets for current read paths'
);

select ok(
    has_table_privilege('service_role', 'public.secret_versions', 'select'),
    'service_role keeps direct select on secret_versions for current read paths'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('public.secrets', 'insert'),
                ('public.secrets', 'update'),
                ('public.secrets', 'delete'),
                ('public.secrets', 'truncate'),
                ('public.secret_versions', 'insert'),
                ('public.secret_versions', 'update'),
                ('public.secret_versions', 'delete'),
                ('public.secret_versions', 'truncate')
            ) as table_privileges(table_name, privilege_name)
            where has_table_privilege(
                'service_role',
                table_privileges.table_name,
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'service_role cannot write secrets or secret_versions directly'
);

select is(
    (
        with expected_rpc(proname) as (
            values
                ('rpc_write_secret_version'),
                ('rpc_append_audit_event'),
                ('rpc_sample_restore_test'),
                ('rpc_key_rotation_status'),
                ('rpc_list_key_rotation_batch'),
                ('rpc_apply_key_rotation_batch'),
                ('rpc_complete_key_rotation')
        ),
        table_owner as (
            select c.relowner
            from pg_class c
            where c.oid = 'public.secrets'::regclass
        )
        select count(*)::integer
        from expected_rpc e
        join pg_proc p on p.proname = e.proname
        join pg_namespace n on n.oid = p.pronamespace
        cross join table_owner t
        where n.nspname = 'public'
            and p.prosecdef
            and p.proowner = t.relowner
            and pg_get_userbyid(p.proowner) not in (
                'anon',
                'authenticated',
                'service_role'
            )
    ),
    7,
    'service-role RPCs are SECURITY DEFINER and owned by the schema/table owner, not runtime roles'
);

set local role service_role;

select is(
    (
        select count(*)::integer
        from public.rpc_write_secret_version(
            '00000000-0000-4000-8000-000000000020',
            'encrypt_create',
            '750e8400-e29b-41d4-a716-446655440000',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'confidential',
            'sbc-device-1',
            '2026-04-08T12:00:00Z',
            1,
            decode(repeat('ac', 32), 'hex'),
            decode(repeat('bd', 73), 'hex'),
            1,
            'xchacha20-poly1305',
            decode(repeat('21', 24), 'hex'),
            jsonb_build_object(
                'aad_version',
                1,
                'secret_id',
                '750e8400-e29b-41d4-a716-446655440000',
                'version',
                1,
                'owner_user_id',
                'f47ac10b-58cc-4372-a567-0e02b2c3d479',
                'classification',
                'confidential',
                'created_at',
                '2026-04-08T12:00:00Z'
            )
        )
    ),
    1,
    'service_role can execute write RPC without direct table DML privileges'
);

reset role;

select is(
    test_helpers.try_create_future_public_function(),
    'ok',
    'test can create a future public function'
);

select is(
    (
        select exists (
            select 1
            from pg_proc p
            join pg_namespace n on n.oid = p.pronamespace
            cross join lateral aclexplode(
                coalesce(p.proacl, acldefault('f', p.proowner))
            ) as acl_entries
            where n.nspname = 'public'
                and p.proname = 'test_future_public_execute'
                and acl_entries.grantee = 0
                and acl_entries.privilege_type = 'EXECUTE'
        )
    ),
    false,
    'future public functions do not grant execute to PUBLIC by default'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.test_future_public_execute()',
        'execute'
    ),
    'anon cannot execute future public functions by default'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.test_future_public_execute()',
        'execute'
    ),
    'authenticated cannot execute future public functions by default'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.rpc_write_secret_version(uuid,text,uuid,uuid,text,text,timestamptz,integer,bytea,bytea,integer,text,bytea,jsonb)',
        'execute'
    ),
    'anon cannot execute write RPC'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.rpc_write_secret_version(uuid,text,uuid,uuid,text,text,timestamptz,integer,bytea,bytea,integer,text,bytea,jsonb)',
        'execute'
    ),
    'authenticated cannot execute write RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_write_secret_version(uuid,text,uuid,uuid,text,text,timestamptz,integer,bytea,bytea,integer,text,bytea,jsonb)',
        'execute'
    ),
    'service_role can execute write RPC'
);

select is(
    (
        select count(*)::integer
        from restore_test_sample_result
    ),
    2,
    'restore test sample RPC returns all current versions up to the requested limit'
);

select is(
    (
        select count(*)::integer
        from restore_test_sample_result_limited
    ),
    1,
    'restore test sample RPC respects the requested limit'
);

select is(
    test_helpers.try_sample_restore_test(0),
    'invalid_rpc_input',
    'restore test sample RPC rejects zero limit'
);

select is(
    test_helpers.try_sample_restore_test(1001),
    'invalid_rpc_input',
    'restore test sample RPC rejects excessive limit'
);

select is(
    test_helpers.try_sample_restore_test(1000),
    'ok',
    'restore test sample RPC accepts the maximum limit'
);

select is(
    (
        select count(distinct secret_id)::integer
        from restore_test_sample_result
    ),
    2,
    'restore test sample RPC returns at most one current version per secret'
);

select ok(
    (
        select bool_and(
            id is not null
            and secret_id is not null
            and version is not null
            and ciphertext is not null
            and encrypted_data_key is not null
            and key_version is not null
            and nonce_or_iv is not null
            and aad_context is not null
            and classification is not null
            and created_at is not null
        )
        from restore_test_sample_result
    ),
    'restore test sample RPC returns the fields required by RestoreTestSampleRow'
);

select is(
    (
        select count(*)::integer
        from restore_test_sample_result
        where secret_id = '550e8400-e29b-41d4-a716-446655440000'
            and version <> 5
    ),
    0,
    'restore test sample RPC excludes non-current versions for retained secrets'
);

select is(
    (
        select count(*)::integer
        from restore_test_sample_result
        where secret_id = '650e8400-e29b-41d4-a716-446655440000'
            and version <> 1
    ),
    0,
    'restore test sample RPC returns the current version for single-version secrets'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.rpc_sample_restore_test(integer)',
        'execute'
    ),
    'anon cannot execute restore test sample RPC'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.rpc_sample_restore_test(integer)',
        'execute'
    ),
    'authenticated cannot execute restore test sample RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_sample_restore_test(integer)',
        'execute'
    ),
    'service_role can execute restore test sample RPC'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.rpc_append_audit_event(uuid,uuid,uuid,text,text,uuid,text,integer,jsonb)',
        'execute'
    ),
    'anon cannot execute append audit RPC'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.rpc_append_audit_event(uuid,uuid,uuid,text,text,uuid,text,integer,jsonb)',
        'execute'
    ),
    'authenticated cannot execute append audit RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_append_audit_event(uuid,uuid,uuid,text,text,uuid,text,integer,jsonb)',
        'execute'
    ),
    'service_role can execute append audit RPC'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.rpc_key_rotation_status(integer)',
        'execute'
    ),
    'anon cannot execute key rotation status RPC'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.rpc_key_rotation_status(integer)',
        'execute'
    ),
    'authenticated cannot execute key rotation status RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_key_rotation_status(integer)',
        'execute'
    ),
    'service_role can execute key rotation status RPC'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.rpc_list_key_rotation_batch(integer,integer)',
        'execute'
    ),
    'anon cannot execute list key rotation batch RPC'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.rpc_list_key_rotation_batch(integer,integer)',
        'execute'
    ),
    'authenticated cannot execute list key rotation batch RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_list_key_rotation_batch(integer,integer)',
        'execute'
    ),
    'service_role can execute list key rotation batch RPC'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.rpc_apply_key_rotation_batch(uuid,integer,integer,jsonb)',
        'execute'
    ),
    'anon cannot execute apply key rotation batch RPC'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.rpc_apply_key_rotation_batch(uuid,integer,integer,jsonb)',
        'execute'
    ),
    'authenticated cannot execute apply key rotation batch RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_apply_key_rotation_batch(uuid,integer,integer,jsonb)',
        'execute'
    ),
    'service_role can execute apply key rotation batch RPC'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.rpc_complete_key_rotation(uuid,integer,integer)',
        'execute'
    ),
    'anon cannot execute complete key rotation RPC'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.rpc_complete_key_rotation(uuid,integer,integer)',
        'execute'
    ),
    'authenticated cannot execute complete key rotation RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_complete_key_rotation(uuid,integer,integer)',
        'execute'
    ),
    'service_role can execute complete key rotation RPC'
);

select * from finish();

rollback;

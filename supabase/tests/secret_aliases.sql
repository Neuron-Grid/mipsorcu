begin;

\ir _support/common.psql

select no_plan();

create temp table owner_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000000101',
    'encrypt_create',
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:00:00Z',
    1,
    'aa',
    '01'
);

insert into public.secrets (
    id,
    owner_user_id,
    classification,
    created_at,
    updated_at
)
values (
    '750e8400-e29b-41d4-a716-446655440001',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'confidential',
    '2026-04-08T12:05:00Z',
    '2026-04-08T12:05:00Z'
);

insert into public.secret_aliases (
    id,
    secret_id,
    owner_user_id,
    alias_ciphertext,
    alias_nonce,
    alias_key_version,
    alias_fingerprint,
    alias_fingerprint_key_version,
    alias_fingerprint_schema_version,
    aad_context,
    created_at
)
values (
    '850e8400-e29b-41d4-a716-446655440000',
    '750e8400-e29b-41d4-a716-446655440001',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    decode(repeat('ab', 32), 'hex'),
    decode(repeat('cd', 24), 'hex'),
    1,
    decode(repeat('ef', 32), 'hex'),
    1,
    1,
    jsonb_build_object(
        'aad_version',
        1,
        'alias_key_version',
        1,
        'owner_user_id',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'secret_alias_id',
        '850e8400-e29b-41d4-a716-446655440000',
        'secret_id',
        '750e8400-e29b-41d4-a716-446655440001'
    ),
    '2026-04-08T12:05:00Z'
);

select is(
    (
        select count(*)::integer
        from information_schema.columns
        where table_schema = 'public'
            and table_name = 'secret_aliases'
            and column_name in (
                'alias_ciphertext',
                'alias_nonce',
                'alias_key_version',
                'alias_fingerprint',
                'alias_fingerprint_key_version',
                'alias_fingerprint_schema_version',
                'aad_context',
                'updated_at'
            )
    ),
    8,
    'secret_aliases exposes encrypted alias columns'
);

select is(
    (
        select count(*)::integer
        from information_schema.columns
        where table_schema = 'public'
            and table_name = 'secret_aliases'
            and column_name in ('alias', 'alias_normalized')
    ),
    0,
    'secret_aliases no longer stores plaintext alias columns'
);

select is(
    (
        select column_default
        from information_schema.columns
        where table_schema = 'public'
            and table_name = 'secret_aliases'
            and column_name = 'created_at'
    ),
    null,
    'secret_aliases.created_at has no DB default'
);

select is(
    (
        select count(*)::integer
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public'
            and c.relname = 'secret_aliases'
            and c.relrowsecurity
            and c.relforcerowsecurity
    ),
    1,
    'secret_aliases enables and forces row level security'
);

select ok(
    (
        select exists (
            select 1
            from pg_policies p
            where p.schemaname = 'public'
                and p.tablename = 'secret_aliases'
                and p.policyname = 'secret_aliases_deny_all'
                and p.permissive = 'RESTRICTIVE'
                and p.cmd = 'ALL'
        )
    ),
    'secret_aliases has deny-all restrictive policy'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('anon', 'select'),
                ('anon', 'insert'),
                ('anon', 'update'),
                ('anon', 'delete'),
                ('authenticated', 'select'),
                ('authenticated', 'insert'),
                ('authenticated', 'update'),
                ('authenticated', 'delete'),
                ('service_role', 'select'),
                ('service_role', 'insert'),
                ('service_role', 'update'),
                ('service_role', 'delete')
            ) as table_privileges(role_name, privilege_name)
            where has_table_privilege(
                table_privileges.role_name,
                'public.secret_aliases',
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'runtime roles have no direct privileges on secret_aliases'
);

select ok(
    to_regprocedure('public.rpc_create_secret_alias(uuid, uuid, text, text)') is null,
    'legacy plaintext create RPC is removed'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_create_secret_alias(uuid, uuid, uuid, uuid, bytea, bytea, integer, bytea, integer, integer, jsonb, timestamptz)',
        'execute'
    ),
    'service_role can execute encrypted create RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_update_secret_alias(uuid, uuid, uuid, bytea, bytea, integer, bytea, integer, integer, jsonb)',
        'execute'
    ),
    'service_role can execute encrypted update RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_delete_secret_alias(uuid, uuid, uuid)',
        'execute'
    ),
    'service_role can execute encrypted delete RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_list_secret_aliases(uuid, uuid, integer, integer)',
        'execute'
    ),
    'service_role can execute encrypted list RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_resolve_secret_alias(uuid, bytea)',
        'execute'
    ),
    'service_role can execute encrypted resolve RPC'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('authenticated', 'public.rpc_create_secret_alias(uuid, uuid, uuid, uuid, bytea, bytea, integer, bytea, integer, integer, jsonb, timestamptz)'),
                ('authenticated', 'public.rpc_update_secret_alias(uuid, uuid, uuid, bytea, bytea, integer, bytea, integer, integer, jsonb)'),
                ('authenticated', 'public.rpc_delete_secret_alias(uuid, uuid, uuid)'),
                ('authenticated', 'public.rpc_list_secret_aliases(uuid, uuid, integer, integer)'),
                ('authenticated', 'public.rpc_resolve_secret_alias(uuid, bytea)'),
                ('anon', 'public.rpc_create_secret_alias(uuid, uuid, uuid, uuid, bytea, bytea, integer, bytea, integer, integer, jsonb, timestamptz)'),
                ('anon', 'public.rpc_update_secret_alias(uuid, uuid, uuid, bytea, bytea, integer, bytea, integer, integer, jsonb)'),
                ('anon', 'public.rpc_delete_secret_alias(uuid, uuid, uuid)'),
                ('anon', 'public.rpc_list_secret_aliases(uuid, uuid, integer, integer)'),
                ('anon', 'public.rpc_resolve_secret_alias(uuid, bytea)')
            ) as function_privileges(role_name, signature)
            where has_function_privilege(
                function_privileges.role_name,
                function_privileges.signature,
                'execute'
            )
        )
    ),
    false,
    'anon and authenticated cannot execute secret alias RPCs'
);

set local role authenticated;
select throws_ok(
    $$select count(*) from public.secret_aliases$$,
    null,
    null,
    'authenticated cannot select secret_aliases directly'
);
reset role;

set local role service_role;
select throws_ok(
    $$select count(*) from public.secret_aliases$$,
    null,
    null,
    'service_role cannot select secret_aliases directly'
);
reset role;

select throws_ok(
    $$
        delete from public.secrets
        where id = '750e8400-e29b-41d4-a716-446655440001'
    $$,
    null,
    null,
    'secret deletion is restricted while aliases exist'
);

select * from finish();

rollback;

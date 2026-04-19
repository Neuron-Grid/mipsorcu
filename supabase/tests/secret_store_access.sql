begin;

create extension if not exists pgtap with schema extensions;
set search_path = public, extensions, pg_temp;

select no_plan();

insert into auth.users (
    id,
    aud,
    role,
    email,
    email_confirmed_at,
    created_at,
    updated_at
)
values
    (
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'authenticated',
        'authenticated',
        'owner@example.test',
        now(),
        now(),
        now()
    ),
    (
        'f47ac10b-58cc-4372-a567-0e02b2c3d480',
        'authenticated',
        'authenticated',
        'other@example.test',
        now(),
        now(),
        now()
    )
on conflict (id) do nothing;

create schema test_helpers;

create function test_helpers.aad_context(
    p_secret_id uuid,
    p_version integer,
    p_owner_user_id uuid,
    p_classification text,
    p_created_at text
)
returns jsonb
language sql
immutable
as $$
    select jsonb_build_object(
        'aad_version',
        1,
        'secret_id',
        p_secret_id::text,
        'version',
        p_version,
        'owner_user_id',
        p_owner_user_id::text,
        'classification',
        p_classification,
        'created_at',
        p_created_at
    );
$$;

create function test_helpers.try_write_secret_version(
    p_request_id uuid,
    p_action text,
    p_secret_id uuid,
    p_owner_user_id uuid,
    p_classification text,
    p_created_by_device_id text,
    p_created_at timestamptz,
    p_version integer,
    p_ciphertext bytea,
    p_encrypted_data_key bytea,
    p_key_version integer,
    p_algorithm text,
    p_nonce_or_iv bytea,
    p_aad_context jsonb
)
returns text
language plpgsql
as $$
begin
    perform *
    from public.rpc_write_secret_version(
        p_request_id,
        p_action,
        p_secret_id,
        p_owner_user_id,
        p_classification,
        p_created_by_device_id,
        p_created_at,
        p_version,
        p_ciphertext,
        p_encrypted_data_key,
        p_key_version,
        p_algorithm,
        p_nonce_or_iv,
        p_aad_context
    );

    return 'ok';
exception
    when others then
        return sqlerrm;
end;
$$;

create function test_helpers.try_append_audit_event(
    p_audit_event_id uuid,
    p_request_id uuid,
    p_actor_user_id uuid,
    p_actor_device_id text,
    p_action text,
    p_target_secret_id uuid,
    p_result text,
    p_key_version integer,
    p_metadata_json jsonb
)
returns text
language plpgsql
as $$
begin
    perform public.rpc_append_audit_event(
        p_audit_event_id,
        p_request_id,
        p_actor_user_id,
        p_actor_device_id,
        p_action,
        p_target_secret_id,
        p_result,
        p_key_version,
        p_metadata_json
    );

    return 'ok';
exception
    when others then
        return sqlerrm;
end;
$$;

create function test_helpers.try_update_secret_classification(
    p_secret_id uuid,
    p_classification text
)
returns text
language plpgsql
as $$
begin
    update public.secrets
    set classification = p_classification
    where id = p_secret_id;

    return 'ok';
exception
    when others then
        return sqlerrm;
end;
$$;

create function test_helpers.try_create_future_public_function()
returns text
language plpgsql
as $$
begin
    execute $create_function$
        create function public.test_future_public_execute()
        returns integer
        language sql
        stable
        as $function$
            select 1;
        $function$;
    $create_function$;

    return 'ok';
exception
    when others then
        return sqlerrm;
end;
$$;
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
                ('public.audit_events', 'delete')
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
                ('delete')
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
            and c.relname in ('secrets', 'secret_versions', 'audit_events')
    ),
    true,
    'secret store tables enable and force row level security'
);

select is(
    (
        select count(*)::integer
        from pg_policies p
        where p.schemaname = 'public'
            and p.tablename = 'audit_events'
    ),
    0,
    'audit_events has no client RLS policies'
);

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

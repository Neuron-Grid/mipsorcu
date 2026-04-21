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

select is(
    (select count(*)::integer from first_write_result),
    1,
    'new secret write returns one row'
);

select is(
    (
        select s.current_version_id
        from public.secrets s
        where s.id = '550e8400-e29b-41d4-a716-446655440000'
    ),
    (
        select secret_version_id
        from first_write_result
    ),
    'new secret current_version_id points to inserted version'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.action = 'encrypt_create'
            and ae.result = 'success'
            and ae.target_secret_id = '550e8400-e29b-41d4-a716-446655440000'
    ),
    1,
    'new secret write records encrypt_create audit event'
);

select is(
    (
        select sv.created_at
        from public.secret_versions sv
        where sv.secret_id = '550e8400-e29b-41d4-a716-446655440000'
            and sv.version = 1
    ),
    '2026-04-08T12:00:00Z'::timestamptz,
    'secret_versions.created_at stores SBC supplied timestamp'
);

select is(
    (
        select sv.classification
        from public.secret_versions sv
        where sv.secret_id = '550e8400-e29b-41d4-a716-446655440000'
            and sv.version = 1
    ),
    'confidential',
    'secret_versions.classification stores RPC classification'
);

select is(
    (
        select c.column_default::text
        from information_schema.columns c
        where c.table_schema = 'public'
            and c.table_name = 'secret_versions'
            and c.column_name = 'created_at'
    ),
    null::text,
    'secret_versions.created_at has no database default'
);

select * from finish();

rollback;

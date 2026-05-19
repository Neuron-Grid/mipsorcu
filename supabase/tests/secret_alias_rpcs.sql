begin;

\ir _support/common.psql

select no_plan();

create function test_helpers.alias_aad_context(
    p_secret_alias_id uuid,
    p_secret_id uuid,
    p_owner_user_id uuid,
    p_alias_key_version integer
)
returns jsonb
language sql
immutable
as $$
    select jsonb_build_object(
        'aad_version',
        1,
        'alias_key_version',
        p_alias_key_version,
        'owner_user_id',
        p_owner_user_id::text,
        'secret_alias_id',
        p_secret_alias_id::text,
        'secret_id',
        p_secret_id::text
    );
$$;

create function test_helpers.try_create_secret_alias(
    p_request_id uuid,
    p_secret_alias_id uuid,
    p_secret_id uuid,
    p_owner_user_id uuid,
    p_alias_ciphertext bytea,
    p_alias_nonce bytea,
    p_alias_key_version integer,
    p_alias_fingerprint bytea,
    p_alias_fingerprint_key_version integer,
    p_alias_fingerprint_schema_version integer,
    p_aad_context jsonb,
    p_created_at timestamptz,
    p_source_event_at text
)
returns text
language plpgsql
as $$
begin
    perform *
    from public.rpc_create_secret_alias(
        p_request_id,
        p_secret_alias_id,
        p_secret_id,
        p_owner_user_id,
        p_alias_ciphertext,
        p_alias_nonce,
        p_alias_key_version,
        p_alias_fingerprint,
        p_alias_fingerprint_key_version,
        p_alias_fingerprint_schema_version,
        p_aad_context,
        p_created_at,
        p_source_event_at
    );

    return 'ok';
exception
    when others then
        return sqlerrm;
end;
$$;

create function test_helpers.try_update_secret_alias(
    p_request_id uuid,
    p_secret_alias_id uuid,
    p_owner_user_id uuid,
    p_alias_ciphertext bytea,
    p_alias_nonce bytea,
    p_alias_key_version integer,
    p_new_alias_fingerprint bytea,
    p_alias_fingerprint_key_version integer,
    p_alias_fingerprint_schema_version integer,
    p_aad_context jsonb,
    p_source_event_at text
)
returns text
language plpgsql
as $$
begin
    perform *
    from public.rpc_update_secret_alias(
        p_request_id,
        p_secret_alias_id,
        p_owner_user_id,
        p_alias_ciphertext,
        p_alias_nonce,
        p_alias_key_version,
        p_new_alias_fingerprint,
        p_alias_fingerprint_key_version,
        p_alias_fingerprint_schema_version,
        p_aad_context,
        p_source_event_at
    );

    return 'ok';
exception
    when others then
        return sqlerrm;
end;
$$;

create function test_helpers.try_delete_secret_alias(
    p_request_id uuid,
    p_secret_alias_id uuid,
    p_owner_user_id uuid,
    p_source_event_at text
)
returns text
language plpgsql
as $$
begin
    perform *
    from public.rpc_delete_secret_alias(
        p_request_id,
        p_secret_alias_id,
        p_owner_user_id,
        p_source_event_at
    );

    return 'ok';
exception
    when others then
        return sqlerrm;
end;
$$;

create temp table secret_alias_rpc_fixtures (
    owner_user_id uuid not null,
    other_user_id uuid not null,
    secret_id uuid not null,
    second_secret_id uuid not null,
    other_owner_secret_id uuid not null,
    alias_id uuid not null
);

insert into secret_alias_rpc_fixtures values (
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'f47ac10b-58cc-4372-a567-0e02b2c3d480',
    '650e8400-e29b-41d4-a716-446655440000',
    '650e8400-e29b-41d4-a716-446655440001',
    '650e8400-e29b-41d4-a716-446655440002',
    '850e8400-e29b-41d4-a716-446655440100'
);

select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000000201',
    'encrypt_create',
    (select secret_id from secret_alias_rpc_fixtures),
    (select owner_user_id from secret_alias_rpc_fixtures),
    '2026-04-08T12:00:00Z',
    1,
    'aa',
    '11'
);

select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000000202',
    'encrypt_create',
    (select second_secret_id from secret_alias_rpc_fixtures),
    (select owner_user_id from secret_alias_rpc_fixtures),
    '2026-04-08T12:01:00Z',
    1,
    'ab',
    '12'
);

select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000000203',
    'encrypt_create',
    (select other_owner_secret_id from secret_alias_rpc_fixtures),
    (select other_user_id from secret_alias_rpc_fixtures),
    '2026-04-08T12:02:00Z',
    1,
    'ac',
    '13'
);

select is(
    test_helpers.try_create_secret_alias(
        '00000000-0000-4000-8000-000000000301',
        (select alias_id from secret_alias_rpc_fixtures),
        (select secret_id from secret_alias_rpc_fixtures),
        (select owner_user_id from secret_alias_rpc_fixtures),
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 24), 'hex'),
        1,
        decode(repeat('11', 32), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            (select alias_id from secret_alias_rpc_fixtures),
            (select secret_id from secret_alias_rpc_fixtures),
            (select owner_user_id from secret_alias_rpc_fixtures),
            1
        ),
        '2026-04-08T12:03:00Z',
        '2026-04-08T12:03:00Z'
    ),
    'ok',
    'create alias succeeds with encrypted material and matching AAD'
);

select is(
    (
        select count(*)::integer
        from public.secret_aliases
        where id = (select alias_id from secret_alias_rpc_fixtures)
    ),
    1,
    'create alias inserts one secret_aliases row'
);

select is(
    (
        select count(*)::integer
        from public.audit_events
        where action = 'secret_alias_create'
            and result = 'success'
            and target_secret_id = (select secret_id from secret_alias_rpc_fixtures)
    ),
    1,
    'create alias records success audit in the same transaction'
);

select ok(
    (
        select metadata_json ? 'alias_fingerprint'
            and metadata_json ? 'source_event_at'
            and not (metadata_json ?| array['alias', 'alias_normalized', 'plain_text', 'plaintext'])
        from public.audit_events
        where action = 'secret_alias_create'
            and result = 'success'
            and target_secret_id = (select secret_id from secret_alias_rpc_fixtures)
        limit 1
    ),
    'create alias audit records fingerprint and source_event_at but no plaintext alias metadata'
);

select is(
    test_helpers.try_create_secret_alias(
        '00000000-0000-4000-8000-000000000302',
        '850e8400-e29b-41d4-a716-446655440101',
        (select second_secret_id from secret_alias_rpc_fixtures),
        (select owner_user_id from secret_alias_rpc_fixtures),
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 24), 'hex'),
        1,
        decode(repeat('11', 32), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            '850e8400-e29b-41d4-a716-446655440101',
            (select second_secret_id from secret_alias_rpc_fixtures),
            (select owner_user_id from secret_alias_rpc_fixtures),
            1
        ),
        '2026-04-08T12:04:00Z',
        '2026-04-08T12:04:00Z'
    ),
    'alias_conflict',
    'duplicate owner-scoped alias fingerprint is rejected as alias_conflict'
);

select is(
    test_helpers.try_create_secret_alias(
        '00000000-0000-4000-8000-000000000303',
        '850e8400-e29b-41d4-a716-446655440102',
        (select secret_id from secret_alias_rpc_fixtures),
        (select owner_user_id from secret_alias_rpc_fixtures),
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 24), 'hex'),
        1,
        decode(repeat('12', 32), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            '850e8400-e29b-41d4-a716-446655440102',
            (select secret_id from secret_alias_rpc_fixtures),
            (select owner_user_id from secret_alias_rpc_fixtures),
            1
        ),
        '2026-04-08T12:05:00Z',
        '2026-04-08T12:05:00Z'
    ),
    'alias_conflict',
    'duplicate owner-scoped secret alias is rejected as alias_conflict'
);

select is(
    test_helpers.try_create_secret_alias(
        '00000000-0000-4000-8000-000000000304',
        '850e8400-e29b-41d4-a716-446655440103',
        (select secret_id from secret_alias_rpc_fixtures),
        (select other_user_id from secret_alias_rpc_fixtures),
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 24), 'hex'),
        1,
        decode(repeat('13', 32), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            '850e8400-e29b-41d4-a716-446655440103',
            (select secret_id from secret_alias_rpc_fixtures),
            (select other_user_id from secret_alias_rpc_fixtures),
            1
        ),
        '2026-04-08T12:06:00Z',
        '2026-04-08T12:06:00Z'
    ),
    'owner_mismatch',
    'create alias rejects owner mismatch'
);

select is(
    test_helpers.try_create_secret_alias(
        '00000000-0000-4000-8000-000000000305',
        '850e8400-e29b-41d4-a716-446655440104',
        '650e8400-e29b-41d4-a716-446655449999',
        (select owner_user_id from secret_alias_rpc_fixtures),
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 24), 'hex'),
        1,
        decode(repeat('14', 32), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            '850e8400-e29b-41d4-a716-446655440104',
            '650e8400-e29b-41d4-a716-446655449999',
            (select owner_user_id from secret_alias_rpc_fixtures),
            1
        ),
        '2026-04-08T12:07:00Z',
        '2026-04-08T12:07:00Z'
    ),
    'secret_not_found',
    'create alias rejects missing secret'
);

select is(
    test_helpers.try_create_secret_alias(
        '00000000-0000-4000-8000-000000000306',
        '850e8400-e29b-41d4-a716-446655440105',
        (select second_secret_id from secret_alias_rpc_fixtures),
        (select owner_user_id from secret_alias_rpc_fixtures),
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 23), 'hex'),
        1,
        decode(repeat('15', 32), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            '850e8400-e29b-41d4-a716-446655440105',
            (select second_secret_id from secret_alias_rpc_fixtures),
            (select owner_user_id from secret_alias_rpc_fixtures),
            1
        ),
        '2026-04-08T12:08:00Z',
        '2026-04-08T12:08:00Z'
    ),
    'invalid_rpc_input',
    'create alias rejects invalid nonce length'
);

select is(
    test_helpers.try_create_secret_alias(
        '00000000-0000-4000-8000-000000000307',
        '850e8400-e29b-41d4-a716-446655440106',
        (select second_secret_id from secret_alias_rpc_fixtures),
        (select owner_user_id from secret_alias_rpc_fixtures),
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 24), 'hex'),
        1,
        decode(repeat('16', 31), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            '850e8400-e29b-41d4-a716-446655440106',
            (select second_secret_id from secret_alias_rpc_fixtures),
            (select owner_user_id from secret_alias_rpc_fixtures),
            1
        ),
        '2026-04-08T12:09:00Z',
        '2026-04-08T12:09:00Z'
    ),
    'invalid_rpc_input',
    'create alias rejects invalid fingerprint length'
);

select is(
    test_helpers.try_create_secret_alias(
        '00000000-0000-4000-8000-000000000308',
        '850e8400-e29b-41d4-a716-446655440107',
        (select second_secret_id from secret_alias_rpc_fixtures),
        (select owner_user_id from secret_alias_rpc_fixtures),
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 24), 'hex'),
        1,
        decode(repeat('17', 32), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            '850e8400-e29b-41d4-a716-446655440107',
            (select second_secret_id from secret_alias_rpc_fixtures),
            (select owner_user_id from secret_alias_rpc_fixtures),
            1
        ) || jsonb_build_object('extra', 'bad'),
        '2026-04-08T12:10:00Z',
        '2026-04-08T12:10:00Z'
    ),
    'invalid_rpc_input',
    'create alias rejects extra AAD keys'
);

select is(
    test_helpers.try_create_secret_alias(
        '00000000-0000-4000-8000-000000000309',
        '850e8400-e29b-41d4-a716-446655440108',
        (select second_secret_id from secret_alias_rpc_fixtures),
        (select owner_user_id from secret_alias_rpc_fixtures),
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 24), 'hex'),
        1,
        decode(repeat('18', 32), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            '850e8400-e29b-41d4-a716-446655440109',
            (select second_secret_id from secret_alias_rpc_fixtures),
            (select owner_user_id from secret_alias_rpc_fixtures),
            1
        ),
        '2026-04-08T12:11:00Z',
        '2026-04-08T12:11:00Z'
    ),
    'invalid_rpc_input',
    'create alias rejects AAD row mismatch'
);

select is(
    test_helpers.try_create_secret_alias(
        '00000000-0000-4000-8000-000000000310',
        '850e8400-e29b-41d4-a716-446655440110',
        (select second_secret_id from secret_alias_rpc_fixtures),
        (select owner_user_id from secret_alias_rpc_fixtures),
        decode(repeat('aa', 32), 'hex'),
        decode(repeat('bb', 24), 'hex'),
        1,
        decode(repeat('19', 32), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            '850e8400-e29b-41d4-a716-446655440110',
            (select second_secret_id from secret_alias_rpc_fixtures),
            (select owner_user_id from secret_alias_rpc_fixtures),
            1
        ),
        '2026-04-08T12:12:00Z',
        '2026-04-08T12:12:00+00:00'
    ),
    'invalid_rpc_input',
    'create alias rejects non-canonical source_event_at'
);

select is(
    (
        select count(*)::integer
        from public.rpc_resolve_secret_alias(
            (select owner_user_id from secret_alias_rpc_fixtures),
            decode(repeat('11', 32), 'hex')
        )
    ),
    1,
    'resolve alias returns one owner-scoped encrypted alias row'
);

select is(
    (
        select count(*)::integer
        from public.rpc_list_secret_aliases(
            '00000000-0000-4000-8000-000000000401',
            (select owner_user_id from secret_alias_rpc_fixtures),
            100,
            0
        )
    ),
    1,
    'list aliases returns encrypted alias rows for owner'
);

select is(
    test_helpers.try_update_secret_alias(
        '00000000-0000-4000-8000-000000000501',
        (select alias_id from secret_alias_rpc_fixtures),
        (select owner_user_id from secret_alias_rpc_fixtures),
        decode(repeat('cc', 32), 'hex'),
        decode(repeat('dd', 24), 'hex'),
        2,
        decode(repeat('22', 32), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            (select alias_id from secret_alias_rpc_fixtures),
            (select secret_id from secret_alias_rpc_fixtures),
            (select owner_user_id from secret_alias_rpc_fixtures),
            2
        ),
        '2026-04-08T12:12:00Z'
    ),
    'ok',
    'update alias succeeds without changing canonical secret_id'
);

select is(
    (
        select count(*)::integer
        from public.audit_events
        where action = 'secret_alias_update'
            and result = 'success'
            and target_secret_id = (select secret_id from secret_alias_rpc_fixtures)
    ),
    1,
    'update alias records success audit'
);

select ok(
    (
        select metadata_json ? 'old_alias_fingerprint'
            and metadata_json ? 'new_alias_fingerprint'
            and metadata_json ? 'source_event_at'
            and not (metadata_json ?| array['alias', 'alias_normalized', 'plain_text', 'plaintext'])
        from public.audit_events
        where action = 'secret_alias_update'
            and result = 'success'
            and target_secret_id = (select secret_id from secret_alias_rpc_fixtures)
        limit 1
    ),
    'update alias audit records fingerprints and source_event_at but no plaintext alias metadata'
);

select is(
    (
        select encode(alias_fingerprint, 'hex')
        from public.secret_aliases
        where id = (select alias_id from secret_alias_rpc_fixtures)
    ),
    repeat('22', 32),
    'update alias replaces alias fingerprint'
);

select is(
    test_helpers.try_update_secret_alias(
        '00000000-0000-4000-8000-000000000504',
        (select alias_id from secret_alias_rpc_fixtures),
        (select owner_user_id from secret_alias_rpc_fixtures),
        decode(repeat('cc', 32), 'hex'),
        decode(repeat('dd', 24), 'hex'),
        2,
        decode(repeat('25', 32), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            (select alias_id from secret_alias_rpc_fixtures),
            (select secret_id from secret_alias_rpc_fixtures),
            (select owner_user_id from secret_alias_rpc_fixtures),
            2
        ),
        '2026-04-08T12:14:00+00:00'
    ),
    'invalid_rpc_input',
    'update alias rejects non-canonical source_event_at'
);

select is(
    test_helpers.try_update_secret_alias(
        '00000000-0000-4000-8000-000000000502',
        (select alias_id from secret_alias_rpc_fixtures),
        (select other_user_id from secret_alias_rpc_fixtures),
        decode(repeat('cc', 32), 'hex'),
        decode(repeat('dd', 24), 'hex'),
        2,
        decode(repeat('23', 32), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            (select alias_id from secret_alias_rpc_fixtures),
            (select secret_id from secret_alias_rpc_fixtures),
            (select other_user_id from secret_alias_rpc_fixtures),
            2
        ),
        '2026-04-08T12:13:00Z'
    ),
    'owner_mismatch',
    'update alias rejects owner mismatch'
);

select is(
    test_helpers.try_update_secret_alias(
        '00000000-0000-4000-8000-000000000503',
        '850e8400-e29b-41d4-a716-446655449999',
        (select owner_user_id from secret_alias_rpc_fixtures),
        decode(repeat('cc', 32), 'hex'),
        decode(repeat('dd', 24), 'hex'),
        2,
        decode(repeat('24', 32), 'hex'),
        1,
        1,
        test_helpers.alias_aad_context(
            '850e8400-e29b-41d4-a716-446655449999',
            (select secret_id from secret_alias_rpc_fixtures),
            (select owner_user_id from secret_alias_rpc_fixtures),
            2
        ),
        '2026-04-08T12:14:00Z'
    ),
    'alias_not_found',
    'update alias rejects missing alias'
);

select is(
    test_helpers.try_delete_secret_alias(
        '00000000-0000-4000-8000-000000000600',
        (select alias_id from secret_alias_rpc_fixtures),
        (select owner_user_id from secret_alias_rpc_fixtures),
        '2026-04-08T12:15:00+00:00'
    ),
    'invalid_rpc_input',
    'delete alias rejects non-canonical source_event_at'
);

select is(
    test_helpers.try_delete_secret_alias(
        '00000000-0000-4000-8000-000000000601',
        (select alias_id from secret_alias_rpc_fixtures),
        (select other_user_id from secret_alias_rpc_fixtures),
        '2026-04-08T12:15:00Z'
    ),
    'owner_mismatch',
    'delete alias rejects owner mismatch'
);

select is(
    test_helpers.try_delete_secret_alias(
        '00000000-0000-4000-8000-000000000602',
        (select alias_id from secret_alias_rpc_fixtures),
        (select owner_user_id from secret_alias_rpc_fixtures),
        '2026-04-08T12:16:00Z'
    ),
    'ok',
    'delete alias succeeds for owner'
);

select is(
    (
        select count(*)::integer
        from public.audit_events
        where action = 'secret_alias_delete'
            and result = 'success'
            and target_secret_id = (select secret_id from secret_alias_rpc_fixtures)
    ),
    1,
    'delete alias records success audit'
);

select ok(
    (
        select metadata_json ? 'alias_fingerprint'
            and metadata_json ? 'source_event_at'
            and not (metadata_json ?| array['alias', 'alias_normalized', 'plain_text', 'plaintext'])
        from public.audit_events
        where action = 'secret_alias_delete'
            and result = 'success'
            and target_secret_id = (select secret_id from secret_alias_rpc_fixtures)
        limit 1
    ),
    'delete alias audit records fingerprint and source_event_at but no plaintext alias metadata'
);

select is(
    (
        select count(*)::integer
        from public.secret_aliases
        where id = (select alias_id from secret_alias_rpc_fixtures)
    ),
    0,
    'delete alias removes the row'
);

select is(
    test_helpers.try_delete_secret_alias(
        '00000000-0000-4000-8000-000000000603',
        (select alias_id from secret_alias_rpc_fixtures),
        (select owner_user_id from secret_alias_rpc_fixtures),
        '2026-04-08T12:17:00Z'
    ),
    'alias_not_found',
    'delete alias rejects missing alias'
);

select * from finish();

rollback;

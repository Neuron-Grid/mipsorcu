begin;

\ir _support/common.psql

select no_plan();

select lives_ok(
    $$select public.rpc_register_ledger_signing_public_key(
        1,
        decode(repeat('11', 32), 'hex')
    )$$,
    'legacy active signing key version 1 exists for signing lifecycle ledger entries'
);

select lives_ok(
    $$select * from public.rpc_create_ledger_signing_public_key_with_ledger(
        2,
        decode(repeat('22', 32), 'hex'),
        '10000000-0000-4000-8000-000000000001'::uuid,
        '20000000-0000-4000-8000-000000000001'::uuid,
        null,
        null,
        'signature_key_created',
        null,
        'success',
        null,
        jsonb_build_object(
            'signature_key_version', 2,
            'public_key_fingerprint', public.ledger_signing_public_key_fingerprint(decode(repeat('22', 32), 'hex')),
            'created_at', '2026-05-13T00:00:00Z',
            'source_event_at', '2026-05-13T00:00:00Z'
        ),
        '30000000-0000-4000-8000-000000000001'::uuid,
        1,
        'signature_key_created',
        '2026-05-13T00:00:00Z',
        '10000000-0000-4000-8000-000000000001'::uuid,
        null,
        null,
        jsonb_build_object(
            'signature_key_version', 2,
            'public_key_fingerprint', public.ledger_signing_public_key_fingerprint(decode(repeat('22', 32), 'hex')),
            'created_at', '2026-05-13T00:00:00Z'
        ),
        1,
        decode(repeat('00', 32), 'hex'),
        decode(repeat('01', 32), 'hex'),
        'sha-256',
        decode(repeat('aa', 64), 'hex'),
        'ed25519',
        1
    )$$,
    'create signature key version 2 with audit and ledger in one RPC'
);

select is(
    (select status from public.ledger_signing_public_keys where key_version = 2),
    'created',
    'new signature key starts as created'
);

select is(
    (select activated_at from public.ledger_signing_public_keys where key_version = 2),
    null,
    'created signature key has no activated_at'
);

select lives_ok(
    $$select * from public.rpc_activate_ledger_signing_public_key_with_ledger(
        null,
        '10000000-0000-4000-8000-000000000002'::uuid,
        '20000000-0000-4000-8000-000000000002'::uuid,
        null,
        null,
        'signature_key_activated',
        null,
        'success',
        null,
        jsonb_build_object(
            'signature_key_version', 2,
            'public_key_fingerprint', public.ledger_signing_public_key_fingerprint(decode(repeat('22', 32), 'hex')),
            'activated_at', '2026-05-13T00:01:00Z',
            'source_event_at', '2026-05-13T00:01:00Z'
        ),
        '30000000-0000-4000-8000-000000000002'::uuid,
        2,
        'signature_key_activated',
        '2026-05-13T00:01:00Z',
        '10000000-0000-4000-8000-000000000002'::uuid,
        null,
        null,
        jsonb_build_object(
            'signature_key_version', 2,
            'public_key_fingerprint', public.ledger_signing_public_key_fingerprint(decode(repeat('22', 32), 'hex')),
            'activated_at', '2026-05-13T00:01:00Z'
        ),
        1,
        decode(repeat('01', 32), 'hex'),
        decode(repeat('02', 32), 'hex'),
        'sha-256',
        decode(repeat('bb', 64), 'hex'),
        'ed25519',
        1
    )$$,
    'activate signature key version 2 with audit and ledger in one RPC'
);

select is(
    (
        select count(*)::integer
        from public.ledger_signing_public_keys
        where status = 'active'
    ),
    2,
    'overlapping validity permits multiple active signature keys'
);

select is(
    test_helpers.try_append_ledger_entry(
        '30000000-0000-4000-8000-000000000003'::uuid,
        3::bigint,
        'integrity_check_completed',
        '2026-05-13T00:02:00Z',
        '20000000-0000-4000-8000-000000000003'::uuid,
        '10000000-0000-4000-8000-000000000003'::uuid,
        null,
        null,
        null,
        null,
        'success',
        null,
        '{"checked_audit_event_count":0,"checked_secret_count":0,"checked_secret_version_count":0,"duration_ms":0,"violation_count":0}'::jsonb,
        1,
        decode(repeat('02', 32), 'hex'),
        decode(repeat('03', 32), 'hex'),
        'sha-256',
        decode(repeat('cc', 64), 'hex'),
        'ed25519',
        2
    ),
    'ok',
    'append entry signed by key version 2 while overlapping active'
);

select lives_ok(
    $$select * from public.rpc_retire_ledger_signing_public_key_with_ledger(
        null,
        '10000000-0000-4000-8000-000000000004'::uuid,
        '20000000-0000-4000-8000-000000000004'::uuid,
        null,
        null,
        'signature_key_retired',
        null,
        'success',
        null,
        jsonb_build_object(
            'signature_key_version', 2,
            'public_key_fingerprint', public.ledger_signing_public_key_fingerprint(decode(repeat('22', 32), 'hex')),
            'retired_at', '2026-05-13T00:03:00Z',
            'source_event_at', '2026-05-13T00:03:00Z'
        ),
        '30000000-0000-4000-8000-000000000004'::uuid,
        4,
        'signature_key_retired',
        '2026-05-13T00:03:00Z',
        '10000000-0000-4000-8000-000000000004'::uuid,
        null,
        null,
        jsonb_build_object(
            'signature_key_version', 2,
            'public_key_fingerprint', public.ledger_signing_public_key_fingerprint(decode(repeat('22', 32), 'hex')),
            'retired_at', '2026-05-13T00:03:00Z'
        ),
        1,
        decode(repeat('03', 32), 'hex'),
        decode(repeat('04', 32), 'hex'),
        'sha-256',
        decode(repeat('dd', 64), 'hex'),
        'ed25519',
        1
    )$$,
    'retire signature key version 2 with audit and ledger in one RPC'
);

select is(
    (select status from public.ledger_signing_public_keys where key_version = 2),
    'retired',
    'retired key status is retained'
);

select is(
    (
        select pk_status
        from public.rpc_export_ledger_verification_materials(3, 3)
    ),
    'retired',
    'retired key remains exported for past signature verification'
);

select lives_ok(
    $$select * from public.rpc_create_ledger_signing_public_key_with_ledger(
        3,
        decode(repeat('33', 32), 'hex'),
        '10000000-0000-4000-8000-000000000005'::uuid,
        '20000000-0000-4000-8000-000000000005'::uuid,
        null,
        null,
        'signature_key_created',
        null,
        'success',
        null,
        jsonb_build_object(
            'signature_key_version', 3,
            'public_key_fingerprint', public.ledger_signing_public_key_fingerprint(decode(repeat('33', 32), 'hex')),
            'created_at', '2026-05-13T00:04:00Z',
            'source_event_at', '2026-05-13T00:04:00Z'
        ),
        '30000000-0000-4000-8000-000000000005'::uuid,
        5,
        'signature_key_created',
        '2026-05-13T00:04:00Z',
        '10000000-0000-4000-8000-000000000005'::uuid,
        null,
        null,
        jsonb_build_object(
            'signature_key_version', 3,
            'public_key_fingerprint', public.ledger_signing_public_key_fingerprint(decode(repeat('33', 32), 'hex')),
            'created_at', '2026-05-13T00:04:00Z'
        ),
        1,
        decode(repeat('04', 32), 'hex'),
        decode(repeat('05', 32), 'hex'),
        'sha-256',
        decode(repeat('ee', 64), 'hex'),
        'ed25519',
        1
    )$$,
    'create signature key version 3 for rollback test'
);

select throws_like(
    $$select * from public.rpc_activate_ledger_signing_public_key_with_ledger(
        null,
        '10000000-0000-4000-8000-000000000006'::uuid,
        '20000000-0000-4000-8000-000000000006'::uuid,
        null,
        null,
        'signature_key_activated',
        null,
        'success',
        null,
        jsonb_build_object(
            'signature_key_version', 3,
            'public_key_fingerprint', public.ledger_signing_public_key_fingerprint(decode(repeat('33', 32), 'hex')),
            'activated_at', '2026-05-13T00:05:00Z',
            'source_event_at', '2026-05-13T00:05:00Z'
        ),
        '30000000-0000-4000-8000-000000000006'::uuid,
        5,
        'signature_key_activated',
        '2026-05-13T00:05:00Z',
        '10000000-0000-4000-8000-000000000006'::uuid,
        null,
        null,
        jsonb_build_object(
            'signature_key_version', 3,
            'public_key_fingerprint', public.ledger_signing_public_key_fingerprint(decode(repeat('33', 32), 'hex')),
            'activated_at', '2026-05-13T00:05:00Z'
        ),
        1,
        decode(repeat('05', 32), 'hex'),
        decode(repeat('06', 32), 'hex'),
        'sha-256',
        decode(repeat('ff', 64), 'hex'),
        'ed25519',
        1
    )$$,
    '%ledger_sequence_mismatch%',
    'failed ledger append rolls back activation RPC'
);

select is(
    (select status from public.ledger_signing_public_keys where key_version = 3),
    'created',
    'registry mutation rolls back when lifecycle ledger append fails'
);

select throws_like(
    $$update public.ledger_signing_public_keys
      set status = 'retired', retired_at = '2026-05-13T00:06:00Z'::timestamptz
      where key_version = 3$$,
    '%ledger_signing_public_key_lifecycle_invalid_transition%',
    'created -> retired direct transition is rejected'
);

select ok(
    not has_function_privilege(
        'service_role',
        'public.rpc_register_ledger_signing_public_key(integer,bytea)',
        'execute'
    ),
    'service_role cannot execute legacy unledgered public key register RPC'
);

select ok(
    not has_function_privilege(
        'service_role',
        'public.rpc_retire_ledger_signing_public_key(integer)',
        'execute'
    ),
    'service_role cannot execute legacy unledgered public key retire RPC'
);

select * from finish();

rollback;

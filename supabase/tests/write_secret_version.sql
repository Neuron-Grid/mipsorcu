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

select ok(
    coalesce(
        position(
            'Timestamp determined by the SBC when constructing AAD' in test_helpers.column_comment(
                'public.secret_versions'::regclass,
                'created_at'
            )
        ) > 0,
        false
    ),
    'secret_versions.created_at comment documents SBC-owned AAD timestamp'
);

select ok(
    coalesce(
        position(
            'same SBC-determined timestamp as the initial secret_versions.created_at' in test_helpers.column_comment(
                'public.secrets'::regclass,
                'created_at'
            )
        ) > 0,
        false
    ),
    'secrets.created_at comment documents aggregate timestamp ownership'
);

select ok(
    coalesce(
        position(
            'Automatically maintained by the tg_set_updated_at trigger' in test_helpers.column_comment(
                'public.secrets'::regclass,
                'updated_at'
            )
        ) > 0,
        false
    ),
    'secrets.updated_at comment documents trigger-owned timestamp'
);

select ok(
    coalesce(
        position(
            'producer-side event time is stored in metadata_json.source_event_at' in test_helpers.column_comment(
                'public.audit_events'::regclass,
                'occurred_at'
            )
        ) > 0,
        false
    ),
    'audit_events.occurred_at comment documents DB-confirmed time and source_event_at guidance'
);

select * from finish();

rollback;

begin;

\ir _support/common.psql

select no_plan();

create function test_helpers.try_apply_envelope_migration_batch(
    p_request_id uuid,
    p_rows jsonb,
    p_failure_rows jsonb,
    p_audit_event_id uuid,
    p_source_event_at text,
    p_ledger_entry jsonb
)
returns text
language plpgsql
as $$
begin
    perform *
    from public.rpc_apply_envelope_migration_batch(
        p_request_id,
        p_rows,
        p_failure_rows,
        p_audit_event_id,
        p_source_event_at,
        p_ledger_entry
    );

    return 'ok';
exception
    when others then
        return sqlerrm;
end;
$$;

create temp table legacy_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000001701',
    'encrypt_create',
    '550e8400-e29b-41d4-a716-446655441701',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:00:00Z',
    1,
    'a1',
    '11'
);

create temp table migration_status_before as
select *
from public.rpc_envelope_migration_status();

select ok(
    (select total_legacy_rows from migration_status_before) >= 1,
    'envelope migration status counts legacy rows'
);

create temp table migration_batch as
select *
from public.rpc_list_envelope_migration_batch(
    10,
    '550e8400-e29b-41d4-a716-446655441701'
);

select is(
    (select count(*)::integer from migration_batch),
    1,
    'envelope migration list returns legacy rows for the requested secret'
);

select is(
    (select count(*)::integer from migration_batch where encrypted_data_key is not null),
    1,
    'envelope migration list exposes only encrypted legacy DEK material'
);

select ok(
    public.ledger_payload_is_valid(
        'envelope_migration_batch_completed',
        jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 0)
    ),
    'envelope migration ledger payload schema is accepted'
);

select ok(
    not public.audit_metadata_has_schema_violation_for_action(
        'key_rotation_envelope_migrated',
        'success',
        jsonb_build_object(
            'batch_size', 1,
            'success_count', 1,
            'failure_count', 0,
            'source_event_at', '2026-04-08T12:10:00Z'
        ),
        true
    ),
    'envelope migration batch audit metadata schema is accepted'
);

select ok(
    (
        select mb.id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
            and mb.secret_id::text = '550e8400-e29b-41d4-a716-446655441701'
            and mb.version = 1
            and mb.key_version = 1
            and left(
                jsonb_build_object('ciphertext', '\x' || repeat('c1', 32)) ->> 'ciphertext',
                2
            ) = '\x'
            and left(
                jsonb_build_object('nonce_or_iv', '\x' || repeat('22', 24)) ->> 'nonce_or_iv',
                2
            ) = '\x'
            and left(
                jsonb_build_object('wrapped_dek', '\x' || repeat('d1', 72)) ->> 'wrapped_dek',
                2
            ) = '\x'
            and octet_length(decode(repeat('c1', 32), 'hex')) > 0
            and octet_length(decode(repeat('22', 24), 'hex')) = 24
            and octet_length(decode(repeat('d1', 72), 'hex')) > 24
        from migration_batch mb
    ),
    'envelope migration apply row validation inputs are valid'
);

savepoint envelope_ledger_probe;
create temp table envelope_ledger_probe_result as
select *
from public.rpc_append_ledger_entry_from_jsonb(test_helpers.ledger_entry_json(
    '00000000-0000-4000-8000-000000001704',
    1,
    'envelope_migration_batch_completed',
    '2026-04-08T12:10:00Z',
    '00000000-0000-4000-8000-000000001702',
    '00000000-0000-4000-8000-000000001703',
    '',
    '',
    '',
    '',
    'success',
    '',
    jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 0),
    repeat('00', 32),
    repeat('91', 32)
));

select is(
    (select count(*)::integer from envelope_ledger_probe_result),
    1,
    'envelope migration ledger entry can be appended directly'
);
rollback to savepoint envelope_ledger_probe;

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001702',
        jsonb_build_array(
            jsonb_build_object(
                'id', (select id::text from migration_batch),
                'secret_id', '550e8400-e29b-41d4-a716-446655441701',
                'version', 1,
                'key_version', 1,
                'ciphertext', '\x' || repeat('c1', 32),
                'nonce_or_iv', '\x' || repeat('22', 24),
                'wrapped_dek', '\x' || repeat('d1', 72),
                'dek_wrap_algorithm', 'envvar-xchacha-v2',
                'kek_version', 2
            )
        ),
        '[]'::jsonb,
        '00000000-0000-4000-8000-000000001703',
        '2026-04-08T12:10:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001704',
            1,
            'envelope_migration_batch_completed',
            '2026-04-08T12:10:00Z',
            '00000000-0000-4000-8000-000000001702',
            '00000000-0000-4000-8000-000000001703',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 0),
            repeat('00', 32),
            repeat('91', 32)
        )
    ),
    'ok',
    'apply envelope migration batch accepts a valid migrated row and ledger entry'
);

select is(
    (
        select sv.encrypted_data_key
        from public.secret_versions sv
        join migration_batch mb on mb.id = sv.id
    ),
    null::bytea,
    'apply envelope migration clears legacy encrypted_data_key'
);

select is(
    (
        select sv.dek_wrap_algorithm
        from public.secret_versions sv
        join migration_batch mb on mb.id = sv.id
    ),
    'envvar-xchacha-v2',
    'apply envelope migration stores the v0.2 DEK wrap algorithm'
);

select is(
    (
        select sv.key_version
        from public.secret_versions sv
        join migration_batch mb on mb.id = sv.id
    ),
    2,
    'apply envelope migration aligns key_version with kek_version'
);

select is(
    (
        select sv.created_at
        from public.secret_versions sv
        join migration_batch mb on mb.id = sv.id
    ),
    '2026-04-08T12:00:00Z'::timestamptz,
    'apply envelope migration does not change secret_versions.created_at'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.id = '00000000-0000-4000-8000-000000001703'
            and ae.action = 'key_rotation_envelope_migrated'
            and ae.result = 'success'
            and ae.metadata_json = jsonb_build_object(
                'batch_size', 1,
                'success_count', 1,
                'failure_count', 0,
                'source_event_at', '2026-04-08T12:10:00Z'
            )
    ),
    1,
    'apply envelope migration records batch success audit'
);

select is(
    (
        select count(*)::integer
        from public.ledger_entries le
        where le.source_event_id = '00000000-0000-4000-8000-000000001703'
            and le.entry_type = 'envelope_migration_batch_completed'
            and le.payload = jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 0)
    ),
    1,
    'apply envelope migration appends matching ledger entry'
);

create temp table legacy_failure_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000001705',
    'encrypt_create',
    '550e8400-e29b-41d4-a716-446655441705',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:01:00Z',
    1,
    'a2',
    '33'
);

create temp table failure_batch as
select *
from public.rpc_list_envelope_migration_batch(
    10,
    '550e8400-e29b-41d4-a716-446655441705'
);

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001706',
        '[]'::jsonb,
        jsonb_build_array(
            jsonb_build_object(
                'id', (select id::text from failure_batch),
                'secret_id', '550e8400-e29b-41d4-a716-446655441705',
                'version', 1,
                'key_version', 1,
                'error_code', 'aad_context_mismatch'
            )
        ),
        '00000000-0000-4000-8000-000000001707',
        '2026-04-08T12:11:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001708',
            2,
            'envelope_migration_batch_completed',
            '2026-04-08T12:11:00Z',
            '00000000-0000-4000-8000-000000001706',
            '00000000-0000-4000-8000-000000001707',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 1, 'success_count', 0, 'failure_count', 1),
            repeat('91', 32),
            repeat('92', 32)
        )
    ),
    'ok',
    'apply envelope migration records pre-crypto row failures without updating the row'
);

select is(
    (
        select sv.dek_wrap_algorithm
        from public.secret_versions sv
        join failure_batch fb on fb.id = sv.id
    ),
    null::text,
    'pre-crypto failure row remains legacy'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.request_id = '00000000-0000-4000-8000-000000001706'
            and ae.action = 'key_rotation_envelope_failed'
            and ae.result = 'failure'
            and ae.target_secret_id = '550e8400-e29b-41d4-a716-446655441705'
            and ae.metadata_json ->> 'error_code' = 'aad_context_mismatch'
    ),
    1,
    'pre-crypto failure row records failure audit'
);

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001709',
        jsonb_build_array(
            jsonb_build_object(
                'id', (select id::text from failure_batch),
                'secret_id', '550e8400-e29b-41d4-a716-446655441705',
                'version', 1,
                'key_version', 1,
                'ciphertext', '\x' || repeat('c3', 32),
                'nonce_or_iv', '\x' || repeat('44', 24),
                'wrapped_dek', '\x' || repeat('d3', 72),
                'dek_wrap_algorithm', 'envvar-xchacha-v2',
                'kek_version', 2,
                'unexpected', 'rejected'
            )
        ),
        '[]'::jsonb,
        '00000000-0000-4000-8000-000000001710',
        '2026-04-08T12:12:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001711',
            3,
            'envelope_migration_batch_completed',
            '2026-04-08T12:12:00Z',
            '00000000-0000-4000-8000-000000001709',
            '00000000-0000-4000-8000-000000001710',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 0),
            repeat('92', 32),
            repeat('93', 32)
        )
    ),
    'invalid_rpc_input',
    'apply envelope migration rejects unknown row keys'
);

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001712',
        jsonb_build_array(
            jsonb_build_object(
                'id', (select id::text from failure_batch),
                'secret_id', '550e8400-e29b-41d4-a716-446655441705',
                'version', 1,
                'key_version', 1,
                'ciphertext', '\x' || repeat('c4', 32),
                'nonce_or_iv', '\x' || repeat('45', 24),
                'wrapped_dek', '\x' || repeat('d4', 72),
                'dek_wrap_algorithm', 'envvar-xchacha-v2',
                'kek_version', 2
            )
        ),
        jsonb_build_array(
            jsonb_build_object(
                'id', (select id::text from failure_batch),
                'secret_id', '550e8400-e29b-41d4-a716-446655441705',
                'version', 1,
                'key_version', 1,
                'error_code', 'aad_context_mismatch'
            )
        ),
        '00000000-0000-4000-8000-000000001713',
        '2026-04-08T12:13:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001714',
            4,
            'envelope_migration_batch_completed',
            '2026-04-08T12:13:00Z',
            '00000000-0000-4000-8000-000000001712',
            '00000000-0000-4000-8000-000000001713',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 2, 'success_count', 1, 'failure_count', 1),
            repeat('93', 32),
            repeat('94', 32)
        )
    ),
    'duplicate_input_row',
    'apply envelope migration rejects duplicate input row ids'
);

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001715',
        jsonb_build_array(
            jsonb_build_object(
                'id', (select id::text from failure_batch),
                'secret_id', '550e8400-e29b-41d4-a716-446655441705',
                'version', 1,
                'key_version', 1,
                'ciphertext', '\xnothex',
                'nonce_or_iv', '\x' || repeat('46', 24),
                'wrapped_dek', '\x' || repeat('d5', 72),
                'dek_wrap_algorithm', 'envvar-xchacha-v2',
                'kek_version', 2
            )
        ),
        '[]'::jsonb,
        '00000000-0000-4000-8000-000000001716',
        '2026-04-08T12:14:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001717',
            5,
            'envelope_migration_batch_completed',
            '2026-04-08T12:14:00Z',
            '00000000-0000-4000-8000-000000001715',
            '00000000-0000-4000-8000-000000001716',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 0),
            repeat('94', 32),
            repeat('95', 32)
        )
    ),
    'invalid_bytea_encoding',
    'apply envelope migration rejects malformed bytea strings before decode'
);

select *
from finish();

rollback;

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

create function test_helpers.envelope_migration_apply_row_json(
    p_id uuid,
    p_secret_id uuid,
    p_version integer,
    p_key_version integer,
    p_ciphertext_seed text,
    p_nonce_seed text,
    p_wrapped_dek_seed text,
    p_kek_version integer
)
returns jsonb
language sql
immutable
as $$
    select jsonb_build_object(
        'id', p_id::text,
        'secret_id', p_secret_id::text,
        'version', p_version,
        'key_version', p_key_version,
        'ciphertext', '\x' || repeat(p_ciphertext_seed, 32),
        'nonce_or_iv', '\x' || repeat(p_nonce_seed, 24),
        'wrapped_dek', '\x' || repeat(p_wrapped_dek_seed, 72),
        'dek_wrap_algorithm', 'envvar-xchacha-v2',
        'kek_version', p_kek_version
    );
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

create temp table ledger_success_mismatch_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000001720',
    'encrypt_create',
    '550e8400-e29b-41d4-a716-446655441720',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:02:00Z',
    1,
    'a3',
    '55'
);

create temp table ledger_success_mismatch_batch as
select *
from public.rpc_list_envelope_migration_batch(
    10,
    '550e8400-e29b-41d4-a716-446655441720'
);

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001721',
        jsonb_build_array(test_helpers.envelope_migration_apply_row_json(
            (select id from ledger_success_mismatch_batch),
            '550e8400-e29b-41d4-a716-446655441720',
            1,
            1,
            'c6',
            '66',
            'd6',
            2
        )),
        '[]'::jsonb,
        '00000000-0000-4000-8000-000000001722',
        '2026-04-08T12:20:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001723',
            2,
            'envelope_migration_batch_completed',
            '2026-04-08T12:20:00Z',
            '00000000-0000-4000-8000-000000001721',
            '00000000-0000-4000-8000-000000001722',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 1, 'success_count', 0, 'failure_count', 0),
            repeat('91', 32),
            repeat('93', 32)
        )
    ),
    'invalid_ledger_entry',
    'apply envelope migration rejects success_count ledger payload mismatch'
);

select is(
    (
        select sv.dek_wrap_algorithm
        from public.secret_versions sv
        join ledger_success_mismatch_batch mb on mb.id = sv.id
    ),
    null::text,
    'success_count mismatch leaves the row unchanged'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.request_id = '00000000-0000-4000-8000-000000001721'
            or ae.id = '00000000-0000-4000-8000-000000001722'
    ),
    0,
    'success_count mismatch does not record audit events'
);

select is(
    (
        select count(*)::integer
        from public.ledger_entries le
        where le.source_event_id = '00000000-0000-4000-8000-000000001722'
    ),
    0,
    'success_count mismatch does not append ledger entries'
);

create temp table ledger_failure_mismatch_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000001724',
    'encrypt_create',
    '550e8400-e29b-41d4-a716-446655441724',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:03:00Z',
    1,
    'a4',
    '57'
);

create temp table ledger_failure_mismatch_batch as
select *
from public.rpc_list_envelope_migration_batch(
    10,
    '550e8400-e29b-41d4-a716-446655441724'
);

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001725',
        jsonb_build_array(test_helpers.envelope_migration_apply_row_json(
            (select id from ledger_failure_mismatch_batch),
            '550e8400-e29b-41d4-a716-446655441724',
            1,
            1,
            'c7',
            '67',
            'd7',
            2
        )),
        '[]'::jsonb,
        '00000000-0000-4000-8000-000000001726',
        '2026-04-08T12:21:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001727',
            2,
            'envelope_migration_batch_completed',
            '2026-04-08T12:21:00Z',
            '00000000-0000-4000-8000-000000001725',
            '00000000-0000-4000-8000-000000001726',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 1),
            repeat('91', 32),
            repeat('94', 32)
        )
    ),
    'invalid_ledger_entry',
    'apply envelope migration rejects failure_count ledger payload mismatch'
);

select is(
    (
        select sv.dek_wrap_algorithm
        from public.secret_versions sv
        join ledger_failure_mismatch_batch mb on mb.id = sv.id
    ),
    null::text,
    'failure_count mismatch leaves the row unchanged'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.request_id = '00000000-0000-4000-8000-000000001725'
            or ae.id = '00000000-0000-4000-8000-000000001726'
    ),
    0,
    'failure_count mismatch does not record audit events'
);

select is(
    (
        select count(*)::integer
        from public.ledger_entries le
        where le.source_event_id = '00000000-0000-4000-8000-000000001726'
    ),
    0,
    'failure_count mismatch does not append ledger entries'
);

create temp table ledger_batch_mismatch_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000001728',
    'encrypt_create',
    '550e8400-e29b-41d4-a716-446655441728',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:04:00Z',
    1,
    'a5',
    '59'
);

create temp table ledger_batch_mismatch_batch as
select *
from public.rpc_list_envelope_migration_batch(
    10,
    '550e8400-e29b-41d4-a716-446655441728'
);

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001729',
        jsonb_build_array(test_helpers.envelope_migration_apply_row_json(
            (select id from ledger_batch_mismatch_batch),
            '550e8400-e29b-41d4-a716-446655441728',
            1,
            1,
            'c8',
            '68',
            'd8',
            2
        )),
        '[]'::jsonb,
        '00000000-0000-4000-8000-000000001730',
        '2026-04-08T12:22:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001731',
            2,
            'envelope_migration_batch_completed',
            '2026-04-08T12:22:00Z',
            '00000000-0000-4000-8000-000000001729',
            '00000000-0000-4000-8000-000000001730',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 2, 'success_count', 1, 'failure_count', 0),
            repeat('91', 32),
            repeat('95', 32)
        )
    ),
    'invalid_ledger_entry',
    'apply envelope migration rejects batch_size ledger payload mismatch'
);

select is(
    (
        select sv.dek_wrap_algorithm
        from public.secret_versions sv
        join ledger_batch_mismatch_batch mb on mb.id = sv.id
    ),
    null::text,
    'batch_size mismatch leaves the row unchanged'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.request_id = '00000000-0000-4000-8000-000000001729'
            or ae.id = '00000000-0000-4000-8000-000000001730'
    ),
    0,
    'batch_size mismatch does not record audit events'
);

select is(
    (
        select count(*)::integer
        from public.ledger_entries le
        where le.source_event_id = '00000000-0000-4000-8000-000000001730'
    ),
    0,
    'batch_size mismatch does not append ledger entries'
);

create temp table ledger_top_level_contract_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000001732',
    'encrypt_create',
    '550e8400-e29b-41d4-a716-446655441732',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:05:00Z',
    1,
    'a6',
    '5b'
);

create temp table ledger_top_level_contract_batch as
select *
from public.rpc_list_envelope_migration_batch(
    10,
    '550e8400-e29b-41d4-a716-446655441732'
);

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001733',
        jsonb_build_array(test_helpers.envelope_migration_apply_row_json(
            (select id from ledger_top_level_contract_batch),
            '550e8400-e29b-41d4-a716-446655441732',
            1,
            1,
            'c9',
            '69',
            'd9',
            2
        )),
        '[]'::jsonb,
        '00000000-0000-4000-8000-000000001734',
        '2026-04-08T12:23:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001735',
            2,
            'envelope_migration_batch_completed',
            '2026-04-08T12:23:00Z',
            '00000000-0000-4000-8000-000000001733',
            '00000000-0000-4000-8000-000000001799',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 0),
            repeat('91', 32),
            repeat('96', 32)
        )
    ),
    'invalid_ledger_entry',
    'apply envelope migration rejects source_event_id ledger mismatch'
);

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001733',
        jsonb_build_array(test_helpers.envelope_migration_apply_row_json(
            (select id from ledger_top_level_contract_batch),
            '550e8400-e29b-41d4-a716-446655441732',
            1,
            1,
            'ca',
            '6a',
            'da',
            2
        )),
        '[]'::jsonb,
        '00000000-0000-4000-8000-000000001734',
        '2026-04-08T12:23:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001736',
            2,
            'envelope_migration_batch_completed',
            '2026-04-08T12:23:00Z',
            '00000000-0000-4000-8000-000000001798',
            '00000000-0000-4000-8000-000000001734',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 0),
            repeat('91', 32),
            repeat('97', 32)
        )
    ),
    'invalid_ledger_entry',
    'apply envelope migration rejects request_id ledger mismatch'
);

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001733',
        jsonb_build_array(test_helpers.envelope_migration_apply_row_json(
            (select id from ledger_top_level_contract_batch),
            '550e8400-e29b-41d4-a716-446655441732',
            1,
            1,
            'cb',
            '6b',
            'db',
            2
        )),
        '[]'::jsonb,
        '00000000-0000-4000-8000-000000001734',
        '2026-04-08T12:23:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001737',
            2,
            'envelope_migration_batch_completed',
            '2026-04-08T12:24:00Z',
            '00000000-0000-4000-8000-000000001733',
            '00000000-0000-4000-8000-000000001734',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 0),
            repeat('91', 32),
            repeat('98', 32)
        )
    ),
    'invalid_ledger_entry',
    'apply envelope migration rejects source_event_at ledger mismatch'
);

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001733',
        jsonb_build_array(test_helpers.envelope_migration_apply_row_json(
            (select id from ledger_top_level_contract_batch),
            '550e8400-e29b-41d4-a716-446655441732',
            1,
            1,
            'cc',
            '6c',
            'dc',
            2
        )),
        '[]'::jsonb,
        '00000000-0000-4000-8000-000000001734',
        '2026-04-08T12:23:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001738',
            2,
            'key_rotation_reencrypted',
            '2026-04-08T12:23:00Z',
            '00000000-0000-4000-8000-000000001733',
            '00000000-0000-4000-8000-000000001734',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 0),
            repeat('91', 32),
            repeat('99', 32)
        )
    ),
    'invalid_ledger_entry',
    'apply envelope migration rejects entry_type ledger mismatch'
);

select is(
    (
        select sv.dek_wrap_algorithm
        from public.secret_versions sv
        join ledger_top_level_contract_batch mb on mb.id = sv.id
    ),
    null::text,
    'top-level ledger mismatches leave the row unchanged'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.request_id = '00000000-0000-4000-8000-000000001733'
            or ae.id = '00000000-0000-4000-8000-000000001734'
    ),
    0,
    'top-level ledger mismatches do not record audit events'
);

select is(
    (
        select count(*)::integer
        from public.ledger_entries le
        where le.source_event_id = '00000000-0000-4000-8000-000000001734'
    ),
    0,
    'top-level ledger mismatches do not append ledger entries'
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
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.id = '00000000-0000-4000-8000-000000001707'
            and ae.action = 'key_rotation_envelope_migrated'
            and ae.result = 'success'
            and ae.metadata_json = jsonb_build_object(
                'batch_size', 1,
                'success_count', 0,
                'failure_count', 1,
                'source_event_at', '2026-04-08T12:11:00Z'
            )
    ),
    1,
    'pre-crypto failure row records matching batch audit'
);

select is(
    (
        select count(*)::integer
        from public.ledger_entries le
        where le.source_event_id = '00000000-0000-4000-8000-000000001707'
            and le.entry_type = 'envelope_migration_batch_completed'
            and le.payload = jsonb_build_object('batch_size', 1, 'success_count', 0, 'failure_count', 1)
    ),
    1,
    'pre-crypto failure row appends matching batch ledger entry'
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

create temp table task08_v1_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000001800',
    'encrypt_create',
    '550e8400-e29b-41d4-a716-446655441800',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:20:00Z',
    1,
    'a8',
    '81'
);

create temp table task08_v2_write_result as
select *
from test_helpers.write_secret_version_fixture(
    '00000000-0000-4000-8000-000000001801',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655441800',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    '2026-04-08T12:21:00Z',
    2,
    'a9',
    '82'
);

create temp table task08_limited_batch as
select *
from public.rpc_list_envelope_migration_batch(
    1,
    '550e8400-e29b-41d4-a716-446655441800'
);

select is(
    (select count(*)::integer from task08_limited_batch),
    1,
    'task08 migration list honors p_limit'
);

select is(
    (select version from task08_limited_batch),
    1,
    'task08 migration list selects only the oldest legacy version when limited'
);

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001802',
        jsonb_build_array(test_helpers.envelope_migration_apply_row_json(
            (select id from task08_limited_batch),
            '550e8400-e29b-41d4-a716-446655441800',
            1,
            1,
            'c8',
            '83',
            'd8',
            2
        )),
        '[]'::jsonb,
        '00000000-0000-4000-8000-000000001803',
        '2026-04-08T12:22:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001804',
            3,
            'envelope_migration_batch_completed',
            '2026-04-08T12:22:00Z',
            '00000000-0000-4000-8000-000000001802',
            '00000000-0000-4000-8000-000000001803',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 0),
            repeat('92', 32),
            repeat('96', 32)
        )
    ),
    'ok',
    'task08 applies one limited migration row'
);

select ok(
    (
        select sv.encrypted_data_key is null
            and sv.wrapped_dek is not null
            and sv.dek_wrap_algorithm = 'envvar-xchacha-v2'
            and sv.kek_version = 2
            and sv.key_version = sv.kek_version
        from public.secret_versions sv
        join task08_limited_batch mb on mb.id = sv.id
    ),
    'task08 migrated row has v0.2 envelope key material only'
);

select is(
    (
        select sv.created_at
        from public.secret_versions sv
        join task08_limited_batch mb on mb.id = sv.id
    ),
    '2026-04-08T12:20:00Z'::timestamptz,
    'task08 migration keeps migrated row created_at unchanged'
);

select is(
    (
        select sv.aad_context
        from public.secret_versions sv
        join task08_limited_batch mb on mb.id = sv.id
    ),
    test_helpers.aad_context(
        '550e8400-e29b-41d4-a716-446655441800',
        1,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'confidential',
        '2026-04-08T12:20:00Z'
    ),
    'task08 migration keeps migrated row aad_context unchanged'
);

select ok(
    (
        select sv.dek_wrap_algorithm is null
            and sv.encrypted_data_key is not null
            and sv.wrapped_dek is null
            and sv.created_at = '2026-04-08T12:21:00Z'::timestamptz
        from public.secret_versions sv
        where sv.secret_id = '550e8400-e29b-41d4-a716-446655441800'
            and sv.version = 2
    ),
    'task08 limited migration leaves other versions unchanged'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.id = '00000000-0000-4000-8000-000000001803'
            and ae.action = 'key_rotation_envelope_migrated'
            and ae.result = 'success'
            and ae.metadata_json = jsonb_build_object(
                'batch_size', 1,
                'success_count', 1,
                'failure_count', 0,
                'source_event_at', '2026-04-08T12:22:00Z'
            )
    ),
    1,
    'task08 migration writes success audit'
);

select is(
    (
        select count(*)::integer
        from public.ledger_entries le
        where le.source_event_id = '00000000-0000-4000-8000-000000001803'
            and le.entry_type = 'envelope_migration_batch_completed'
            and le.payload = jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 0)
    ),
    1,
    'task08 migration writes matching ledger entry'
);

create temp table task08_remaining_batch as
select *
from public.rpc_list_envelope_migration_batch(
    10,
    '550e8400-e29b-41d4-a716-446655441800'
);

select is(
    (select count(*)::integer from task08_remaining_batch),
    1,
    'task08 only one legacy row remains after limited migration'
);

select is(
    (select version from task08_remaining_batch),
    2,
    'task08 remaining legacy row is the untouched version'
);

select is(
    test_helpers.try_apply_envelope_migration_batch(
        '00000000-0000-4000-8000-000000001805',
        jsonb_build_array(test_helpers.envelope_migration_apply_row_json(
            (select id from task08_remaining_batch),
            '550e8400-e29b-41d4-a716-446655441800',
            2,
            1,
            'c9',
            '83',
            'd9',
            2
        )),
        '[]'::jsonb,
        '00000000-0000-4000-8000-000000001806',
        '2026-04-08T12:23:00Z',
        test_helpers.ledger_entry_json(
            '00000000-0000-4000-8000-000000001807',
            4,
            'envelope_migration_batch_completed',
            '2026-04-08T12:23:00Z',
            '00000000-0000-4000-8000-000000001805',
            '00000000-0000-4000-8000-000000001806',
            '',
            '',
            '',
            '',
            'success',
            '',
            jsonb_build_object('batch_size', 1, 'success_count', 1, 'failure_count', 0),
            repeat('96', 32),
            repeat('97', 32)
        )
    ),
    'envelope_migration_nonce_reuse',
    'task08 migration fails closed on duplicate nonce for same secret'
);

select ok(
    (
        select sv.dek_wrap_algorithm is null
            and sv.encrypted_data_key is not null
            and sv.wrapped_dek is null
        from public.secret_versions sv
        where sv.secret_id = '550e8400-e29b-41d4-a716-446655441800'
            and sv.version = 2
    ),
    'task08 nonce conflict rollback leaves remaining version legacy'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.id = '00000000-0000-4000-8000-000000001806'
    ),
    0,
    'task08 nonce conflict does not write success audit'
);

select is(
    (
        select count(*)::integer
        from (
            select sv.secret_id, sv.nonce_or_iv
            from public.secret_versions sv
            where sv.secret_id = '550e8400-e29b-41d4-a716-446655441800'
            group by sv.secret_id, sv.nonce_or_iv
            having count(*) > 1
        ) duplicate_nonces
    ),
    0,
    'task08 migration keeps secret_id nonce uniqueness invariant'
);

select *
from finish();

rollback;

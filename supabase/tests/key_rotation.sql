begin;

\ir _support/common.psql

select no_plan();

create temp table first_write_result as
select *
from public.rpc_write_secret_version(
    '00000000-0000-4000-8000-000000000101',
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
    '00000000-0000-4000-8000-000000000102',
    'encrypt_rotate',
    '550e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'confidential',
    'sbc-device-1',
    '2026-04-08T12:01:00Z',
    2,
    decode(repeat('ab', 32), 'hex'),
    decode(repeat('bc', 73), 'hex'),
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

create temp table old_key_status as
select *
from public.rpc_key_rotation_status(1);

select is(
    (
        select remaining_count::integer
        from old_key_status
    ),
    2,
    'key rotation status counts rows for the old key version'
);

create temp table first_rotation_batch as
select *
from public.rpc_list_key_rotation_batch(1, 1);

select is(
    (
        select count(*)::integer
        from first_rotation_batch
    ),
    1,
    'key rotation batch respects the requested limit'
);

create temp table first_apply_result as
select *
from public.rpc_apply_key_rotation_batch(
    '00000000-0000-4000-8000-000000000103',
    1,
    2,
    (
        select jsonb_agg(
            jsonb_build_object(
                'id',
                rb.id,
                'encrypted_data_key',
                '\x' || repeat('ee', 73)
            )
        )
        from first_rotation_batch rb
    )
);

select is(
    (
        select processed_count::integer
        from first_apply_result
    ),
    1,
    'apply key rotation batch updates the claimed old-key row'
);

select is(
    (
        select remaining_count::integer
        from first_apply_result
    ),
    1,
    'apply key rotation batch reports remaining old-key rows'
);

select is(
    (
        select sv.key_version
        from public.secret_versions sv
        join first_rotation_batch rb on rb.id = sv.id
    ),
    2,
    'apply key rotation batch stores the new key_version'
);

select is(
    (
        select sv.encrypted_data_key
        from public.secret_versions sv
        join first_rotation_batch rb on rb.id = sv.id
    ),
    decode(repeat('ee', 73), 'hex'),
    'apply key rotation batch stores the SBC-rewrapped encrypted_data_key'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.request_id = '00000000-0000-4000-8000-000000000103'
            and ae.action = 'key_rotation_reencrypt'
            and ae.result = 'success'
            and ae.key_version = 2
            and ae.metadata_json = jsonb_build_object(
                'old_key_version',
                1,
                'new_key_version',
                2,
                'batch_size',
                1,
                'processed_count',
                1,
                'remaining_count',
                1
            )
    ),
    1,
    'apply key rotation batch records reencrypt audit in the same RPC'
);

select is(
    test_helpers.try_apply_key_rotation_batch(
        '00000000-0000-4000-8000-000000000104',
        1,
        2,
        (
            select jsonb_agg(
                jsonb_build_object(
                    'id',
                    rb.id,
                    'encrypted_data_key',
                    '\x' || repeat('ef', 73)
                )
            )
            from first_rotation_batch rb
        )
    ),
    'key_rotation_conflict',
    'apply key rotation batch rejects rows no longer on old_key_version'
);

select is(
    test_helpers.try_complete_key_rotation(
        '00000000-0000-4000-8000-000000000105',
        1,
        2
    ),
    'key_rotation_incomplete',
    'complete key rotation rejects while old key rows remain'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.request_id = '00000000-0000-4000-8000-000000000105'
            and ae.action = 'key_rotation_complete'
    ),
    0,
    'complete key rotation does not record audit when old key rows remain'
);

create temp table remaining_rotation_batch as
select *
from public.rpc_list_key_rotation_batch(1, 10);

create temp table remaining_apply_result as
select *
from public.rpc_apply_key_rotation_batch(
    '00000000-0000-4000-8000-000000000106',
    1,
    2,
    (
        select jsonb_agg(
            jsonb_build_object(
                'id',
                rb.id,
                'encrypted_data_key',
                '\x' || repeat('f0', 73)
            )
        )
        from remaining_rotation_batch rb
    )
);

select is(
    (
        select remaining_count::integer
        from remaining_apply_result
    ),
    0,
    'final apply key rotation batch clears old-key rows'
);

create temp table complete_rotation_result as
select *
from public.rpc_complete_key_rotation(
    '00000000-0000-4000-8000-000000000107',
    1,
    2
);

select is(
    (
        select remaining_count::integer
        from complete_rotation_result
    ),
    0,
    'complete key rotation succeeds after old-key rows are gone'
);

select is(
    (
        select count(*)::integer
        from public.audit_events ae
        where ae.request_id = '00000000-0000-4000-8000-000000000107'
            and ae.action = 'key_rotation_complete'
            and ae.result = 'success'
            and ae.key_version = 2
            and ae.metadata_json = jsonb_build_object(
                'old_key_version',
                1,
                'new_key_version',
                2,
                'remaining_count',
                0
            )
    ),
    1,
    'complete key rotation records completion audit'
);

select is(
    public.audit_metadata_has_forbidden_key(
        (
            select ae.metadata_json
            from public.audit_events ae
            where ae.request_id = '00000000-0000-4000-8000-000000000106'
                and ae.action = 'key_rotation_reencrypt'
            limit 1
        )
    ),
    false,
    'rotation audit metadata does not contain key material fields'
);

select is(
    test_helpers.try_apply_key_rotation_batch(
        '00000000-0000-4000-8000-000000000108',
        1,
        2,
        jsonb_build_array(
            jsonb_build_object(
                'id',
                'not-a-uuid',
                'encrypted_data_key',
                '\x' || repeat('f1', 73)
            )
        )
    ),
    'invalid_rpc_input',
    'apply key rotation batch rejects invalid input rows'
);

select is(
    test_helpers.try_apply_key_rotation_batch(
        '00000000-0000-4000-8000-000000000109',
        1,
        2,
        jsonb_build_array(
            jsonb_build_object(
                'id',
                '00000000-0000-4000-8000-000000000201',
                'encrypted_data_key',
                '\x' || repeat('f2', 73)
            ),
            jsonb_build_object(
                'id',
                '00000000-0000-4000-8000-000000000201',
                'encrypted_data_key',
                '\x' || repeat('f3', 73)
            )
        )
    ),
    'invalid_rpc_input',
    'apply key rotation batch rejects duplicate input row ids'
);

select is(
    test_helpers.try_apply_key_rotation_batch(
        '00000000-0000-4000-8000-000000000110',
        1,
        2,
        jsonb_build_array(
            jsonb_build_object(
                'id',
                '00000000-0000-4000-8000-000000000202',
                'encrypted_data_key',
                '\xabc'
            )
        )
    ),
    'invalid_rpc_input',
    'apply key rotation batch rejects malformed encrypted_data_key hex'
);

select * from finish();

rollback;

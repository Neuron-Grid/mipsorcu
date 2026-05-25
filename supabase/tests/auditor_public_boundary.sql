begin;

\ir _support/common.psql

select plan(76);

-- Register two signing public keys (one active, one to retire later)
select lives_ok(
    $$select public.rpc_register_ledger_signing_public_key(
        1,
        decode(repeat('11', 32), 'hex')
    )$$,
    'register public key version 1'
);

select lives_ok(
    $$select public.rpc_register_ledger_signing_public_key(
        2,
        decode(repeat('22', 32), 'hex')
    )$$,
    'register public key version 2'
);

-- Retire key version 2
select lives_ok(
    $$select public.rpc_retire_ledger_signing_public_key(2)$$,
    'retire public key version 2'
);

-- Verify key 2 is retired
select is(
    (select status from public.ledger_signing_public_keys where key_version = 2),
    'retired',
    'key version 2 has status retired'
);

-- Create a secret to satisfy audit_events / ledger_entries FK references.
select is(
    test_helpers.try_insert_secret_version(
        'a0000000-0000-4000-a000-000000000301'::uuid,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid,
        '2026-05-09T00:00:00Z'::timestamptz,
        'confidential',
        test_helpers.aad_context(
            'a0000000-0000-4000-a000-000000000301'::uuid,
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid,
            'confidential',
            '2026-05-09T00:00:00Z'
        )
    ),
    'ok',
    'create secret for audit FK reference'
);

-- Insert ledger entries with proper hash chain via RPC.
-- Genesis hash is 32 zero bytes.

select is(
    test_helpers.try_append_ledger_entry(
        'a0000000-0000-4000-a000-000000000001'::uuid,
        1::bigint,
        'secret_created',
        '2026-05-09T00:00:00Z',
        'a0000000-0000-4000-a000-000000000101'::uuid,
        'a0000000-0000-4000-a000-000000000201'::uuid,
        'a0000000-0000-4000-a000-000000000301'::uuid,
        'a0000000-0000-4000-a000-000000000401'::uuid,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid,
        'sbc-device-1',
        'success',
        null,
        '{"algorithm":"xchacha20-poly1305","classification":"confidential","key_version":1,"version":1}'::jsonb,
        1,
        decode(repeat('00', 32), 'hex'),
        decode(repeat('0a', 32), 'hex'),
        'sha3-256',
        decode(repeat('1a', 64), 'hex'),
        'ed25519',
        1
    ),
    'ok',
    'insert ledger entry 1 (secret_created)'
);

select is(
    test_helpers.try_append_ledger_entry(
        'a0000000-0000-4000-a000-000000000002'::uuid,
        2::bigint,
        'secret_decrypted',
        '2026-05-09T00:01:00Z',
        'a0000000-0000-4000-a000-000000000102'::uuid,
        'a0000000-0000-4000-a000-000000000202'::uuid,
        'a0000000-0000-4000-a000-000000000301'::uuid,
        'a0000000-0000-4000-a000-000000000401'::uuid,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid,
        'sbc-device-1',
        'success',
        null,
        '{"algorithm":"xchacha20-poly1305","key_version":1,"version":1}'::jsonb,
        1,
        decode(repeat('0a', 32), 'hex'),
        decode(repeat('0b', 32), 'hex'),
        'sha3-256',
        decode(repeat('1b', 64), 'hex'),
        'ed25519',
        1
    ),
    'ok',
    'insert ledger entry 2 (secret_decrypted)'
);

select is(
    test_helpers.try_append_ledger_entry(
        'a0000000-0000-4000-a000-000000000003'::uuid,
        3::bigint,
        'integrity_check_completed',
        '2026-05-09T00:02:00Z',
        'a0000000-0000-4000-a000-000000000103'::uuid,
        'a0000000-0000-4000-a000-000000000203'::uuid,
        null,
        null,
        null,
        null,
        'success',
        null,
        '{"checked_audit_event_count":10,"checked_secret_count":3,"checked_secret_version_count":3,"duration_ms":150,"violation_count":0}'::jsonb,
        1,
        decode(repeat('0b', 32), 'hex'),
        decode(repeat('0c', 32), 'hex'),
        'sha3-256',
        decode(repeat('1c', 64), 'hex'),
        'ed25519',
        2
    ),
    'ok',
    'insert ledger entry 3 with signature_key_version 2'
);

-- Insert one ledger entry whose signature_key_version has no matching public key.
-- This is required to verify that export uses LEFT JOIN and returns pk_* as NULL.
select is(
    test_helpers.try_append_ledger_entry(
        'a0000000-0000-4000-a000-000000000004'::uuid,
        4::bigint,
        'integrity_check_completed',
        '2026-05-09T00:03:00Z',
        'a0000000-0000-4000-a000-000000000104'::uuid,
        'a0000000-0000-4000-a000-000000000204'::uuid,
        null,
        null,
        null,
        null,
        'success',
        null,
        '{"checked_audit_event_count":11,"checked_secret_count":3,"checked_secret_version_count":3,"duration_ms":160,"violation_count":0}'::jsonb,
        1,
        decode(repeat('0c', 32), 'hex'),
        decode(repeat('0d', 32), 'hex'),
        'sha3-256',
        decode(repeat('1d', 64), 'hex'),
        'ed25519',
        999
    ),
    'ok',
    'insert ledger entry 4 with missing signature_key_version 999'
);

-- Insert an audit event for test data.
select is(
    test_helpers.try_append_audit_event(
        'a0000000-0000-4000-a000-000000000501'::uuid,
        'a0000000-0000-4000-a000-000000000601'::uuid,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid,
        'sbc-device-1',
        'integrity_check',
        'a0000000-0000-4000-a000-000000000301'::uuid,
        'success',
        1,
        '{"duration_ms":150,"checked_count":10}'::jsonb
    ),
    'ok',
    'insert audit event for test data'
);

-- 1. Auditor can SELECT from all 4 views and see real data.
set local role mipsorcu_auditor;
set local search_path = public, extensions, pg_temp;

select is(
    (select count(*)::integer from public.auditor_secret_inventory_view),
    1,
    'auditor can select from auditor_secret_inventory_view and see 1 secret'
);

select is(
    (select count(*)::integer from public.auditor_audit_events_view),
    1,
    'auditor can select from auditor_audit_events_view and see 1 audit event'
);

select is(
    (select count(*)::integer from public.auditor_ledger_entries_view),
    4,
    'auditor can select from auditor_ledger_entries_view and see 4 ledger entries'
);

select is(
    (select count(*)::integer from public.auditor_integrity_status_view),
    1,
    'auditor can select from auditor_integrity_status_view and see 1 chain state'
);

select is(
    (select count(*)::integer from public.ledger_signing_public_keys),
    2,
    'auditor can select ledger_signing_public_keys and see 2 public keys'
);

reset role;

-- 1.1 Auditor views are created with security_barrier = true.
select is(
    (
        select c.reloptions @> array['security_barrier=true']
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public'
          and c.relname = 'auditor_secret_inventory_view'
    ),
    true,
    'auditor_secret_inventory_view has security_barrier=true'
);

select is(
    (
        select c.reloptions @> array['security_barrier=true']
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public'
          and c.relname = 'auditor_audit_events_view'
    ),
    true,
    'auditor_audit_events_view has security_barrier=true'
);

select is(
    (
        select c.reloptions @> array['security_barrier=true']
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public'
          and c.relname = 'auditor_ledger_entries_view'
    ),
    true,
    'auditor_ledger_entries_view has security_barrier=true'
);

select is(
    (
        select c.reloptions @> array['security_barrier=true']
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public'
          and c.relname = 'auditor_integrity_status_view'
    ),
    true,
    'auditor_integrity_status_view has security_barrier=true'
);

-- 2. Auditor cannot directly SELECT from base tables.
set local role mipsorcu_auditor;
set local search_path = public, extensions, pg_temp;

select throws_like(
    $$select count(*) from public.secrets$$,
    '%permission denied%',
    'auditor cannot select from secrets directly'
);

select throws_like(
    $$select count(*) from public.secret_versions$$,
    '%permission denied%',
    'auditor cannot select from secret_versions directly'
);

select throws_like(
    $$select count(*) from public.audit_events$$,
    '%permission denied%',
    'auditor cannot select from audit_events directly'
);

select throws_like(
    $$select count(*) from public.ledger_entries$$,
    '%permission denied%',
    'auditor cannot select from ledger_entries directly'
);

select throws_like(
    $$select count(*) from public.ledger_chain_state$$,
    '%permission denied%',
    'auditor cannot select from ledger_chain_state directly'
);

-- 3. Auditor cannot INSERT / UPDATE / DELETE on views.

select throws_like(
    $$insert into public.auditor_secret_inventory_view (secret_id, owner_user_id, classification)
      values ('a0000000-0000-4000-a000-000000000399'::uuid, 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid, 'test')$$,
    '%permission denied%',
    'auditor cannot insert into auditor_secret_inventory_view'
);

select throws_like(
    $$update public.auditor_ledger_entries_view set result = 'failure'$$,
    '%permission denied%',
    'auditor cannot update auditor_ledger_entries_view'
);

select throws_like(
    $$delete from public.auditor_audit_events_view$$,
    '%permission denied%',
    'auditor cannot delete from auditor_audit_events_view'
);

select throws_like(
    $$insert into public.auditor_integrity_status_view (chain_id, last_sequence_no, last_entry_hash)
      values ('test', 1, decode(repeat('00', 32), 'hex'))$$,
    '%permission denied%',
    'auditor cannot insert into auditor_integrity_status_view'
);

-- 4. Auditor can EXECUTE the 3 verification / export RPCs.
select lives_ok(
    $$select * from public.rpc_verify_ledger_hash_chain()$$,
    'auditor can execute rpc_verify_ledger_hash_chain'
);

select is(
    (select chain_valid from public.rpc_verify_ledger_hash_chain()),
    true,
    'rpc_verify_ledger_hash_chain: full chain is valid'
);

select lives_ok(
    $$select * from public.rpc_verify_ledger_range(1, 4)$$,
    'auditor can execute rpc_verify_ledger_range'
);

select is(
    (select range_valid from public.rpc_verify_ledger_range(1, 4)),
    true,
    'rpc_verify_ledger_range(1,4): range is complete'
);

select lives_ok(
    $$select * from public.rpc_export_ledger_verification_materials()$$,
    'auditor can execute rpc_export_ledger_verification_materials'
);

select is(
    (select count(*)::integer from public.rpc_export_ledger_verification_materials()),
    4,
    'rpc_export_ledger_verification_materials returns 4 entries'
);

reset role;

-- 4.1 Deprecated signature verification RPC must not exist.
select is(
    (
        select count(*)::integer
        from pg_proc p
        join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public'
          and p.proname = 'rpc_verify_ledger_signatures'
    ),
    0,
    'rpc_verify_ledger_signatures is not present'
);

-- 5. anon / authenticated cannot EXECUTE the verification RPCs.
set local role anon;
set local search_path = public, extensions, pg_temp;

-- 5a. anon cannot EXECUTE verification RPCs.
-- PostgreSQL 17.6 segfaults when calling security definer functions
-- with inadequate table privileges, so we verify via has_function_privilege.
select is(
    pg_catalog.has_function_privilege(
        'public.rpc_verify_ledger_hash_chain(bigint, bigint)',
        'execute'
    ),
    false,
    'anon cannot execute rpc_verify_ledger_hash_chain'
);

select is(
    pg_catalog.has_function_privilege(
        'public.rpc_verify_ledger_range(bigint, bigint)',
        'execute'
    ),
    false,
    'anon cannot execute rpc_verify_ledger_range'
);

select is(
    pg_catalog.has_function_privilege(
        'public.rpc_export_ledger_verification_materials(bigint, bigint)',
        'execute'
    ),
    false,
    'anon cannot execute rpc_export_ledger_verification_materials'
);

reset role;

set local role authenticated;
set local search_path = public, extensions, pg_temp;

select is(
    pg_catalog.has_function_privilege(
        'public.rpc_verify_ledger_hash_chain(bigint, bigint)',
        'execute'
    ),
    false,
    'authenticated cannot execute rpc_verify_ledger_hash_chain'
);

select is(
    pg_catalog.has_function_privilege(
        'public.rpc_verify_ledger_range(bigint, bigint)',
        'execute'
    ),
    false,
    'authenticated cannot execute rpc_verify_ledger_range'
);

select is(
    pg_catalog.has_function_privilege(
        'public.rpc_export_ledger_verification_materials(bigint, bigint)',
        'execute'
    ),
    false,
    'authenticated cannot execute rpc_export_ledger_verification_materials'
);

reset role;

-- 6. rpc_verify_ledger_hash_chain: valid chain checks.
set local role mipsorcu_auditor;
set local search_path = public, extensions, pg_temp;

select is(
    (select chain_valid from public.rpc_verify_ledger_hash_chain()),
    true,
    'full hash chain valid=true'
);

select is(
    (select entries_checked from public.rpc_verify_ledger_hash_chain()),
    4::bigint,
    'full hash chain checked 4 entries'
);

select is(
    (select chain_valid from public.rpc_verify_ledger_hash_chain(1, 2)),
    true,
    'range 1-2 hash chain valid=true'
);

reset role;

alter table public.ledger_entries disable trigger ledger_entries_no_update_delete;
update public.ledger_entries
set sequence_no = 5
where id = 'a0000000-0000-4000-a000-000000000003'::uuid;
alter table public.ledger_entries enable trigger ledger_entries_no_update_delete;

set local role mipsorcu_auditor;
set local search_path = public, extensions, pg_temp;

select is(
    (select chain_valid from public.rpc_verify_ledger_hash_chain()),
    false,
    'rpc_verify_ledger_hash_chain detects sequence gap'
);

select is(
    (select first_gap_sequence_no from public.rpc_verify_ledger_hash_chain()),
    3::bigint,
    'rpc_verify_ledger_hash_chain reports first missing sequence_no for sequence gap'
);

reset role;

alter table public.ledger_entries disable trigger ledger_entries_no_update_delete;
update public.ledger_entries
set sequence_no = 3
where id = 'a0000000-0000-4000-a000-000000000003'::uuid;
alter table public.ledger_entries enable trigger ledger_entries_no_update_delete;

update public.ledger_chain_state
set last_sequence_no = 999
where chain_id = 'global';

set local role mipsorcu_auditor;
set local search_path = public, extensions, pg_temp;

select is(
    (select chain_valid from public.rpc_verify_ledger_hash_chain()),
    false,
    'rpc_verify_ledger_hash_chain detects ledger_chain_state last_sequence_no mismatch'
);

reset role;

update public.ledger_chain_state
set last_sequence_no = 4
where chain_id = 'global';

update public.ledger_chain_state
set last_entry_hash = decode(repeat('ee', 32), 'hex')
where chain_id = 'global';

set local role mipsorcu_auditor;
set local search_path = public, extensions, pg_temp;

select is(
    (select chain_valid from public.rpc_verify_ledger_hash_chain()),
    false,
    'rpc_verify_ledger_hash_chain detects ledger_chain_state last_entry_hash mismatch'
);

reset role;

update public.ledger_chain_state
set last_sequence_no = 4,
    last_entry_hash = decode(repeat('0d', 32), 'hex')
where chain_id = 'global';

set local role mipsorcu_auditor;
set local search_path = public, extensions, pg_temp;

-- 7. rpc_verify_ledger_range: gap / empty range detection.
select is(
    (select range_valid from public.rpc_verify_ledger_range(1, 4)),
    true,
    'rpc_verify_ledger_range(1,4) valid'
);

select is(
    (select range_valid from public.rpc_verify_ledger_range(1, 5)),
    false,
    'rpc_verify_ledger_range(1,5) detects missing tail sequence'
);

select is(
    (select range_valid from public.rpc_verify_ledger_range(5, 10)),
    false,
    'rpc_verify_ledger_range(5,10) detects empty range'
);

reset role;

-- 8. ledger_signing_public_keys immutability: UPDATE rejection.
select throws_like(
    $$update public.ledger_signing_public_keys
       set public_key = decode(repeat('ff', 32), 'hex')
       where key_version = 1$$,
    '%ledger_signing_public_keys%',
    'cannot update public_key on ledger_signing_public_keys'
);

select throws_like(
    $$update public.ledger_signing_public_keys
       set key_version = 99
       where key_version = 1$$,
    '%ledger_signing_public_keys%',
    'cannot update key_version on ledger_signing_public_keys'
);

select throws_like(
    $$update public.ledger_signing_public_keys
       set algorithm = 'ecdsa'
       where key_version = 1$$,
    '%ledger_signing_public_keys%',
    'cannot update algorithm on ledger_signing_public_keys'
);

select throws_like(
    $$update public.ledger_signing_public_keys
       set created_at = now()
       where key_version = 1$$,
    '%ledger_signing_public_keys%',
    'cannot update created_at on ledger_signing_public_keys'
);

select throws_like(
    $$update public.ledger_signing_public_keys
       set status = 'active',
           retired_at = null
       where key_version = 2$$,
    '%ledger_signing_public_keys%',
    'cannot change retired key back to active'
);

-- 9. ledger_signing_public_keys immutability: DELETE / TRUNCATE rejection.
select throws_like(
    $$delete from public.ledger_signing_public_keys where key_version = 1$$,
    '%ledger_signing_public_keys%',
    'cannot delete from ledger_signing_public_keys'
);

select throws_like(
    $$truncate table public.ledger_signing_public_keys$$,
    '%ledger_signing_public_keys%',
    'cannot truncate ledger_signing_public_keys'
);

-- 10. rpc_register_ledger_signing_public_key: idempotent replay.
select lives_ok(
    $$select public.rpc_register_ledger_signing_public_key(
        1,
        decode(repeat('11', 32), 'hex')
    )$$,
    'idempotent re-register same key version 1 + same public key'
);

select is(
    (
        select replayed
        from public.rpc_register_ledger_signing_public_key(
            1,
            decode(repeat('11', 32), 'hex')
        )
        where out_key_version = 1
    ),
    true,
    're-register same key reports replayed=true'
);

-- 11. Same key_version + different public_key = conflict.
select throws_like(
    $$select public.rpc_register_ledger_signing_public_key(
        1,
        decode(repeat('ff', 32), 'hex')
    )$$,
    'ledger_signing_public_key_conflict%',
    'same key_version different public_key raises conflict'
);

-- 12. active -> retired -> re-retire is idempotent.
select lives_ok(
    $$select public.rpc_retire_ledger_signing_public_key(1)$$,
    'retire active key version 1'
);

select is(
    (select status from public.ledger_signing_public_keys where key_version = 1),
    'retired',
    'key version 1 is now retired'
);

select lives_ok(
    $$select public.rpc_retire_ledger_signing_public_key(1)$$,
    'idempotent re-retire key version 1'
);

select is(
    (
        select already_retired
        from public.rpc_retire_ledger_signing_public_key(1)
        where out_key_version = 1
    ),
    true,
    're-retire reports already_retired=true'
);

-- 13. Register to retired key_version should be rejected.
select throws_like(
    $$select public.rpc_register_ledger_signing_public_key(
        1,
        decode(repeat('33', 32), 'hex')
    )$$,
    'ledger_signing_public_key_retired%',
    'cannot register to retired key_version'
);

-- 14. Forbidden metadata key in audit_events INSERT is rejected.
select isnt(
    test_helpers.try_append_audit_event(
        'b0000000-0000-4000-a000-000000000001'::uuid,
        'b0000000-0000-4000-a000-000000000101'::uuid,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid,
        'sbc-device-1',
        'integrity_check',
        'a0000000-0000-4000-a000-000000000301'::uuid,
        'success',
        1,
        '{"plaintext":"secret data","duration_ms":100}'::jsonb
    ),
    'ok',
    'audit event with forbidden metadata key "plaintext" is rejected'
);

select isnt(
    test_helpers.try_append_audit_event(
        'b0000000-0000-4000-a000-000000000002'::uuid,
        'b0000000-0000-4000-a000-000000000102'::uuid,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid,
        'sbc-device-1',
        'integrity_check',
        'a0000000-0000-4000-a000-000000000301'::uuid,
        'success',
        1,
        '{"ciphertext":"AAEC","duration_ms":100}'::jsonb
    ),
    'ok',
    'audit event with forbidden metadata key "ciphertext" is rejected'
);

-- 15. Export RPC returns retired public key.
set local role mipsorcu_auditor;
set local search_path = public, extensions, pg_temp;

select is(
    (
        select pk_status
        from public.rpc_export_ledger_verification_materials()
        where signature_key_version = 2
        limit 1
    ),
    'retired',
    'export RPC returns retired public key status'
);

select isnt(
    (
        select pk_public_key
        from public.rpc_export_ledger_verification_materials()
        where signature_key_version = 2
        limit 1
    ),
    null,
    'export RPC returns non-null public key for retired key'
);

-- 16. Export RPC returns pk_* IS NULL for missing public key.
select is(
    (
        select pk_key_version
        from public.rpc_export_ledger_verification_materials()
        where signature_key_version = 999
        limit 1
    ),
    null,
    'export RPC returns null pk_key_version for missing public key'
);

select is(
    (
        select pk_public_key
        from public.rpc_export_ledger_verification_materials()
        where signature_key_version = 999
        limit 1
    ),
    null,
    'export RPC returns null pk_public_key for missing public key'
);

select is(
    (
        select pk_algorithm
        from public.rpc_export_ledger_verification_materials()
        where signature_key_version = 999
        limit 1
    ),
    null,
    'export RPC returns null pk_algorithm for missing public key'
);

select is(
    (
        select pk_status
        from public.rpc_export_ledger_verification_materials()
        where signature_key_version = 999
        limit 1
    ),
    null,
    'export RPC returns null pk_status for missing public key'
);

select is(
    (
        select pk_created_at
        from public.rpc_export_ledger_verification_materials()
        where signature_key_version = 999
        limit 1
    ),
    null,
    'export RPC returns null pk_created_at for missing public key'
);

select is(
    (
        select pk_retired_at
        from public.rpc_export_ledger_verification_materials()
        where signature_key_version = 999
        limit 1
    ),
    null,
    'export RPC returns null pk_retired_at for missing public key'
);

reset role;

select * from finish();

rollback;
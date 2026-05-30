-- pgTAP: Section 1370 監査UI読み取り RPC (rpc_audit_ui_*) の検証。
-- Rust 側 (src/server/supabase/audit_ui_rpc.rs) が呼ぶ 5 本の RPC が存在し、
-- auditor_*_view をラップして期待どおりにページネーション・フィルタ・権限境界を満たすことを確認する。

begin;

\ir _support/common.psql

select no_plan();

-- セットアップ: 署名鍵 / 秘密 / ledger チェーン (success x2 + failure x1) / 監査イベント (success)
select lives_ok(
    $$select public.rpc_register_ledger_signing_public_key(
        1,
        decode(repeat('11', 32), 'hex')
    )$$,
    'register signing public key version 1'
);

select is(
    test_helpers.try_insert_secret_version(
        'c0000000-0000-4000-a000-000000000301'::uuid,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid,
        '2026-05-09T00:00:00Z'::timestamptz,
        'confidential',
        test_helpers.aad_context(
            'c0000000-0000-4000-a000-000000000301'::uuid,
            1,
            'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid,
            'confidential',
            '2026-05-09T00:00:00Z'
        )
    ),
    'ok',
    'create secret for audit FK reference'
);

-- ledger seq 1: secret_created (success)
select is(
    test_helpers.try_append_ledger_entry(
        'c0000000-0000-4000-a000-000000000001'::uuid,
        1::bigint,
        'secret_created',
        '2026-05-09T00:00:00Z',
        'c0000000-0000-4000-a000-000000000101'::uuid,
        'c0000000-0000-4000-a000-000000000201'::uuid,
        'c0000000-0000-4000-a000-000000000301'::uuid,
        'c0000000-0000-4000-a000-000000000401'::uuid,
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
    'append ledger entry 1 (secret_created, success)'
);

-- ledger seq 2: secret_decrypted (success)
select is(
    test_helpers.try_append_ledger_entry(
        'c0000000-0000-4000-a000-000000000002'::uuid,
        2::bigint,
        'secret_decrypted',
        '2026-05-09T00:01:00Z',
        'c0000000-0000-4000-a000-000000000102'::uuid,
        'c0000000-0000-4000-a000-000000000202'::uuid,
        'c0000000-0000-4000-a000-000000000301'::uuid,
        'c0000000-0000-4000-a000-000000000401'::uuid,
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
    'append ledger entry 2 (secret_decrypted, success)'
);

-- ledger seq 3: ledger_verification_failed (failure) — verification_failures の検証対象
select is(
    test_helpers.try_append_ledger_entry(
        'c0000000-0000-4000-a000-000000000003'::uuid,
        3::bigint,
        'ledger_verification_failed',
        '2026-05-09T00:02:00Z',
        'c0000000-0000-4000-a000-000000000103'::uuid,
        'c0000000-0000-4000-a000-000000000203'::uuid,
        null,
        null,
        null,
        null,
        'failure',
        'hash_mismatch',
        '{"end_sequence_no":2,"error_code":"hash_mismatch","failed_count":1,"start_sequence_no":1}'::jsonb,
        1,
        decode(repeat('0b', 32), 'hex'),
        decode(repeat('0c', 32), 'hex'),
        'sha3-256',
        decode(repeat('1c', 64), 'hex'),
        'ed25519',
        1
    ),
    'ok',
    'append ledger entry 3 (ledger_verification_failed, failure)'
);

-- audit event: integrity_check (success)
select is(
    test_helpers.try_append_audit_event(
        'c0000000-0000-4000-a000-000000000501'::uuid,
        'c0000000-0000-4000-a000-000000000601'::uuid,
        'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid,
        'sbc-device-1',
        'integrity_check',
        'c0000000-0000-4000-a000-000000000301'::uuid,
        'success',
        1,
        '{"duration_ms":150,"checked_count":10}'::jsonb
    ),
    'ok',
    'append audit event (integrity_check, success)'
);

-- 1. rpc_audit_ui_secret_inventory
select is(
    (select count(*)::integer from public.rpc_audit_ui_secret_inventory(100, 0)),
    1,
    'rpc_audit_ui_secret_inventory returns the 1 secret'
);

select is(
    (select count(*)::integer from public.rpc_audit_ui_secret_inventory(100, 1)),
    0,
    'rpc_audit_ui_secret_inventory honors offset'
);

select throws_like(
    $$select * from public.rpc_audit_ui_secret_inventory(0, 0)$$,
    '%invalid_rpc_input%',
    'rpc_audit_ui_secret_inventory rejects p_limit = 0'
);

-- 2. rpc_audit_ui_audit_events
select is(
    (select count(*)::integer
     from public.rpc_audit_ui_audit_events(100, 0)
     where action = 'integrity_check' and result = 'success'),
    1,
    'rpc_audit_ui_audit_events returns the integrity_check success event'
);

select is(
    (select count(*)::integer
     from public.rpc_audit_ui_audit_events(100, 0, null, null, 'integrity_check', 'failure')),
    0,
    'rpc_audit_ui_audit_events result filter excludes non-matching result'
);

select is(
    (select count(*)::integer
     from public.rpc_audit_ui_audit_events(100, 0, null, null, 'decrypt', null)),
    0,
    'rpc_audit_ui_audit_events action filter excludes non-matching action'
);

-- 広い period (2000-2100) で now() の監査イベントを含むことを確認 (日付依存を避ける)
select is(
    (select count(*)::integer
     from public.rpc_audit_ui_audit_events(
        100, 0, '2000-01-01T00:00:00Z', '2100-01-01T00:00:00Z', 'integrity_check', 'success')),
    1,
    'rpc_audit_ui_audit_events period filter includes the event within a wide range'
);

select throws_like(
    $$select * from public.rpc_audit_ui_audit_events(100, 0, null, null, null, 'bogus')$$,
    '%invalid_rpc_input%',
    'rpc_audit_ui_audit_events rejects invalid p_result'
);

-- 3. rpc_audit_ui_ledger_entries
select is(
    (select count(*)::integer from public.rpc_audit_ui_ledger_entries(100, 0)),
    3,
    'rpc_audit_ui_ledger_entries returns all 3 entries'
);

select is(
    (select count(*)::integer from public.rpc_audit_ui_ledger_entries(100, 0, null, null, null, 'failure')),
    1,
    'rpc_audit_ui_ledger_entries result filter returns the 1 failure'
);

select is(
    (select count(*)::integer from public.rpc_audit_ui_ledger_entries(100, 0, 2, null, null, null)),
    2,
    'rpc_audit_ui_ledger_entries start_sequence_no filter returns seq >= 2'
);

select is(
    (select count(*)::integer from public.rpc_audit_ui_ledger_entries(100, 0, null, null, 'secret_created', null)),
    1,
    'rpc_audit_ui_ledger_entries entry_type filter returns matching type'
);

-- ページネーション + 降順 (sequence_no desc): 先頭ページは seq 3,2
select is(
    (select array_agg(sequence_no order by sequence_no desc)
     from public.rpc_audit_ui_ledger_entries(2, 0)),
    array[3, 2]::bigint[],
    'rpc_audit_ui_ledger_entries page 1 (limit 2) returns newest two by sequence_no'
);

select is(
    (select array_agg(sequence_no)
     from public.rpc_audit_ui_ledger_entries(2, 2)),
    array[1]::bigint[],
    'rpc_audit_ui_ledger_entries page 2 (offset 2) returns the remaining entry'
);

-- 4. rpc_audit_ui_integrity_status
select is(
    (select count(*)::integer from public.rpc_audit_ui_integrity_status()),
    1,
    'rpc_audit_ui_integrity_status returns the global chain head row'
);

select is(
    (select last_sequence_no from public.rpc_audit_ui_integrity_status()),
    3::bigint,
    'rpc_audit_ui_integrity_status reports last_sequence_no = 3'
);

-- 5. rpc_audit_ui_verification_failures
select is(
    (select count(*)::integer
     from public.rpc_audit_ui_verification_failures(
        100, 0, '2026-05-01T00:00:00Z', '2026-06-01T00:00:00Z')),
    1,
    'rpc_audit_ui_verification_failures returns the 1 ledger failure in period'
);

select is(
    (select code
     from public.rpc_audit_ui_verification_failures(
        100, 0, '2026-05-01T00:00:00Z', '2026-06-01T00:00:00Z')
     limit 1),
    'hash_mismatch',
    'rpc_audit_ui_verification_failures reports the ledger error_code'
);

select is(
    (select source
     from public.rpc_audit_ui_verification_failures(
        100, 0, '2026-05-01T00:00:00Z', '2026-06-01T00:00:00Z')
     limit 1),
    'ledger',
    'rpc_audit_ui_verification_failures reports source = ledger'
);

select is(
    (select sequence_no
     from public.rpc_audit_ui_verification_failures(
        100, 0, '2026-05-01T00:00:00Z', '2026-06-01T00:00:00Z')
     limit 1),
    3::bigint,
    'rpc_audit_ui_verification_failures reports the failing sequence_no'
);

select is(
    (select count(*)::integer
     from public.rpc_audit_ui_verification_failures(
        100, 0, '2026-06-01T00:00:00Z', '2026-07-01T00:00:00Z')),
    0,
    'rpc_audit_ui_verification_failures returns 0 outside the failure period'
);

select throws_like(
    $$select * from public.rpc_audit_ui_verification_failures(100, 0, 'not-a-timestamp', '2026-06-01T00:00:00Z')$$,
    '%invalid_rpc_input%',
    'rpc_audit_ui_verification_failures rejects invalid period string'
);

select throws_like(
    $$select * from public.rpc_audit_ui_verification_failures(100, 0, '2026-06-01T00:00:00Z', '2026-05-01T00:00:00Z')$$,
    '%invalid_rpc_input%',
    'rpc_audit_ui_verification_failures rejects start >= end'
);

-- 6. 権限境界: service_role は EXECUTE 可、anon / authenticated は不可。
--    PostgreSQL は権限不足の SECURITY DEFINER 呼び出しで segfault するため has_function_privilege で検証する。
select is(
    pg_catalog.has_function_privilege(
        'service_role', 'public.rpc_audit_ui_secret_inventory(integer, integer)', 'execute'),
    true,
    'service_role can execute rpc_audit_ui_secret_inventory'
);

select is(
    pg_catalog.has_function_privilege(
        'service_role', 'public.rpc_audit_ui_audit_events(integer, integer, text, text, text, text)', 'execute'),
    true,
    'service_role can execute rpc_audit_ui_audit_events'
);

select is(
    pg_catalog.has_function_privilege(
        'service_role', 'public.rpc_audit_ui_ledger_entries(integer, integer, bigint, bigint, text, text)', 'execute'),
    true,
    'service_role can execute rpc_audit_ui_ledger_entries'
);

select is(
    pg_catalog.has_function_privilege(
        'service_role', 'public.rpc_audit_ui_integrity_status()', 'execute'),
    true,
    'service_role can execute rpc_audit_ui_integrity_status'
);

select is(
    pg_catalog.has_function_privilege(
        'service_role', 'public.rpc_audit_ui_verification_failures(integer, integer, text, text)', 'execute'),
    true,
    'service_role can execute rpc_audit_ui_verification_failures'
);

select is(
    pg_catalog.has_function_privilege(
        'anon', 'public.rpc_audit_ui_secret_inventory(integer, integer)', 'execute'),
    false,
    'anon cannot execute rpc_audit_ui_secret_inventory'
);

select is(
    pg_catalog.has_function_privilege(
        'authenticated', 'public.rpc_audit_ui_secret_inventory(integer, integer)', 'execute'),
    false,
    'authenticated cannot execute rpc_audit_ui_secret_inventory'
);

select is(
    pg_catalog.has_function_privilege(
        'anon', 'public.rpc_audit_ui_verification_failures(integer, integer, text, text)', 'execute'),
    false,
    'anon cannot execute rpc_audit_ui_verification_failures'
);

select is(
    pg_catalog.has_function_privilege(
        'authenticated', 'public.rpc_audit_ui_verification_failures(integer, integer, text, text)', 'execute'),
    false,
    'authenticated cannot execute rpc_audit_ui_verification_failures'
);

select * from finish();

rollback;

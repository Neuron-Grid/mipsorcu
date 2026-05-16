begin;

\ir _support/common.psql

select no_plan();

select ok(
    to_regclass('public.ledger_entries') is not null,
    'ledger_entries table exists'
);

select ok(
    to_regclass('public.ledger_chain_state') is not null,
    'ledger_chain_state table exists'
);

select is(
    (
        select count(*)::integer
        from pg_attribute a
        where a.attrelid = 'public.ledger_entries'::regclass
            and a.attname in (
                'id',
                'sequence_no',
                'entry_type',
                'source_event_at',
                'request_id',
                'source_event_id',
                'target_secret_id',
                'target_secret_version_id',
                'actor_user_id',
                'actor_device_id',
                'result',
                'error_code',
                'payload',
                'canonicalization_version',
                'previous_entry_hash',
                'entry_hash',
                'hash_algorithm',
                'signature',
                'signature_algorithm',
                'signature_key_version',
                'created_at'
            )
            and not a.attisdropped
    ),
    21,
    'ledger_entries exposes the planned Phase 1 columns'
);

select is(
    (
        select count(*)::integer
        from pg_constraint c
        where c.conrelid = 'public.ledger_entries'::regclass
            and c.conname in (
                'ledger_entries_sequence_no_unique',
                'ledger_entries_entry_hash_unique',
                'ledger_entries_payload_valid',
                'ledger_entries_previous_entry_hash_len',
                'ledger_entries_entry_hash_len',
                'ledger_entries_signature_len',
                'ledger_entries_hash_algorithm_sha256',
                'ledger_entries_signature_algorithm_ed25519',
                'ledger_entries_canonicalization_version_v1'
            )
    ),
    9,
    'ledger_entries has the critical uniqueness, algorithm, length, and payload constraints'
);

select is(
    (
        select count(*)::integer
        from pg_constraint c
        where c.conrelid = 'public.ledger_entries'::regclass
            and c.contype = 'f'
    ),
    0,
    'ledger_entries uses UUID snapshots instead of FKs to audit_events, secrets, or secret_versions'
);

select is(
    (
        select count(*)::integer
        from public.ledger_chain_state
        where chain_id = 'global'
            and last_sequence_no = 0
            and octet_length(last_entry_hash) = 32
            and last_entry_hash = decode(repeat('00', 32), 'hex')
    ),
    1,
    'ledger_chain_state starts with one global genesis row'
);

select is(
    (
        select bool_and(c.relrowsecurity and c.relforcerowsecurity)
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public'
            and c.relname in ('ledger_entries', 'ledger_chain_state')
    ),
    true,
    'ledger tables enable and force row level security'
);

select ok(
    (
        select exists (
            select 1
            from pg_policies p
            where p.schemaname = 'public'
                and p.tablename = 'ledger_entries'
                and p.policyname = 'ledger_entries_deny_all'
                and p.permissive = 'RESTRICTIVE'
                and p.cmd = 'ALL'
                and position('false' in coalesce(p.qual, '')) > 0
                and position('false' in coalesce(p.with_check, '')) > 0
        )
    ),
    'ledger_entries has deny-all restrictive RLS policy'
);

select ok(
    (
        select exists (
            select 1
            from pg_policies p
            where p.schemaname = 'public'
                and p.tablename = 'ledger_chain_state'
                and p.policyname = 'ledger_chain_state_deny_all'
                and p.permissive = 'RESTRICTIVE'
                and p.cmd = 'ALL'
                and position('false' in coalesce(p.qual, '')) > 0
                and position('false' in coalesce(p.with_check, '')) > 0
        )
    ),
    'ledger_chain_state has deny-all restrictive RLS policy'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('public.ledger_entries', 'select'),
                ('public.ledger_entries', 'insert'),
                ('public.ledger_entries', 'update'),
                ('public.ledger_entries', 'delete'),
                ('public.ledger_entries', 'truncate'),
                ('public.ledger_chain_state', 'select'),
                ('public.ledger_chain_state', 'insert'),
                ('public.ledger_chain_state', 'update'),
                ('public.ledger_chain_state', 'delete'),
                ('public.ledger_chain_state', 'truncate')
            ) as table_privileges(table_name, privilege_name)
            where has_table_privilege(
                'anon',
                table_privileges.table_name,
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'anon has no direct ledger table privileges'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('public.ledger_entries', 'select'),
                ('public.ledger_entries', 'insert'),
                ('public.ledger_entries', 'update'),
                ('public.ledger_entries', 'delete'),
                ('public.ledger_entries', 'truncate'),
                ('public.ledger_chain_state', 'select'),
                ('public.ledger_chain_state', 'insert'),
                ('public.ledger_chain_state', 'update'),
                ('public.ledger_chain_state', 'delete'),
                ('public.ledger_chain_state', 'truncate')
            ) as table_privileges(table_name, privilege_name)
            where has_table_privilege(
                'authenticated',
                table_privileges.table_name,
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'authenticated has no direct ledger table privileges'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('select'),
                ('insert'),
                ('update'),
                ('delete'),
                ('truncate')
            ) as table_privileges(privilege_name)
            where has_table_privilege(
                'service_role',
                'public.ledger_entries',
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'service_role has no direct privileges on ledger_entries'
);

select ok(
    has_table_privilege('service_role', 'public.ledger_chain_state', 'select'),
    'service_role can select ledger_chain_state for current chain head reads'
);

select is(
    (
        select exists (
            select 1
            from (values
                ('insert'),
                ('update'),
                ('delete'),
                ('truncate')
            ) as table_privileges(privilege_name)
            where has_table_privilege(
                'service_role',
                'public.ledger_chain_state',
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'service_role cannot directly write ledger_chain_state'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.rpc_append_ledger_entry(uuid,bigint,text,text,uuid,uuid,uuid,uuid,uuid,text,text,text,jsonb,integer,bytea,bytea,text,bytea,text,integer)',
        'execute'
    ),
    'anon cannot execute append ledger RPC'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.rpc_append_ledger_entry(uuid,bigint,text,text,uuid,uuid,uuid,uuid,uuid,text,text,text,jsonb,integer,bytea,bytea,text,bytea,text,integer)',
        'execute'
    ),
    'authenticated cannot execute append ledger RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_append_ledger_entry(uuid,bigint,text,text,uuid,uuid,uuid,uuid,uuid,text,text,text,jsonb,integer,bytea,bytea,text,bytea,text,integer)',
        'execute'
    ),
    'service_role can execute append ledger RPC'
);

select ok(
    (
        select p.prosecdef
        from pg_proc p
        join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public'
            and p.proname = 'rpc_append_ledger_entry'
    ),
    'append ledger RPC is SECURITY DEFINER'
);

select ok(
    (
        select exists (
            select 1
            from pg_proc p
            join pg_namespace n on n.oid = p.pronamespace
            where n.nspname = 'public'
                and p.proname = 'rpc_append_ledger_entry'
                and 'search_path=public, pg_temp' = any (p.proconfig)
        )
    ),
    'append ledger RPC has explicit search_path'
);

select is(
    (
        select count(*)::integer
        from pg_proc p
        join pg_namespace n on n.oid = p.pronamespace
        cross join (
            select c.relowner
            from pg_class c
            where c.oid = 'public.ledger_entries'::regclass
        ) table_owner
        where n.nspname = 'public'
            and p.proname = 'rpc_append_ledger_entry'
            and p.proowner = table_owner.relowner
            and pg_get_userbyid(p.proowner) not in (
                'anon',
                'authenticated',
                'service_role'
            )
    ),
    1,
    'append ledger RPC is owned by the schema/table owner, not runtime roles'
);

select ok(
    public.ledger_payload_has_forbidden_key(
        '{"nested":{"Token":"redacted"}}'::jsonb
    ),
    'ledger payload forbidden key guard is recursive and case-insensitive'
);

select ok(
    public.ledger_payload_has_forbidden_key(
        '{"array":[{" request_body ":"redacted"}]}'::jsonb
    ),
    'ledger payload forbidden key guard trims object keys inside arrays'
);

select ok(
    not public.ledger_payload_has_forbidden_key(
        '{"classification":"confidential","version":1}'::jsonb
    ),
    'ledger payload forbidden key guard accepts safe keys'
);

select is(
    (
        select count(*)::integer
        from (values
            ('authorization'),
            ('ciphertext'),
            ('data_key'),
            ('decrypt_result'),
            ('decrypted'),
            ('decrypted_data'),
            ('encrypted_data_key'),
            ('jwt'),
            ('master_key'),
            ('passphrase'),
            ('password'),
            ('plain_text'),
            ('plaintext'),
            ('request_body'),
            ('response_body'),
            ('secret_key'),
            ('secret_value'),
            ('service_role'),
            ('service_role_key'),
            ('token')
        ) as forbidden_keys(key_name)
        where public.ledger_payload_has_forbidden_key(
            jsonb_build_object(forbidden_keys.key_name, 'redacted')
        )
    ),
    20,
    'ledger payload forbidden key guard covers the full Phase 1 denied key list'
);

select ok(
    public.ledger_payload_is_valid(
        'secret_created',
        '{"classification":"confidential","version":1,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb
    ),
    'ledger payload guard accepts valid secret_created payload'
);

select ok(
    not public.ledger_payload_is_valid(
        'secret_created',
        '{"classification":"confidential","version":1,"key_version":1,"algorithm":"xchacha20-poly1305","unexpected":true}'::jsonb
    ),
    'ledger payload guard rejects unknown keys'
);

select ok(
    not public.ledger_payload_is_valid(
        'secret_created',
        '{"classification":"confidential","version":0,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb
    ),
    'ledger payload guard rejects invalid numeric ranges'
);

select ok(
    not public.ledger_payload_is_valid(
        'restore_test_completed',
        '{"trigger":"manual"}'::jsonb
    ),
    'ledger payload guard rejects invalid fixed vocabulary values'
);

select ok(
    public.ledger_payload_is_valid(
        'scheduler_job_completed',
        '{"duration_ms":12,"job_name":"monthly_digest_generate","target_year_month":"2026-05","trigger":"background"}'::jsonb
    ),
    'ledger payload guard accepts valid scheduler_job_completed payload'
);

select ok(
    not public.ledger_payload_is_valid(
        'scheduler_job_completed',
        '{"duration_ms":12,"job_name":" ","trigger":"background"}'::jsonb
    ),
    'ledger payload guard rejects blank scheduler job_name'
);

select ok(
    not public.ledger_payload_is_valid(
        'scheduler_job_completed',
        '{"duration_ms":12,"job_name":"monthly_digest_generate","target_year_month":"2026-13","trigger":"background"}'::jsonb
    ),
    'ledger payload guard rejects invalid scheduler target_year_month'
);

select ok(
    not public.ledger_payload_is_valid(
        'scheduler_job_completed',
        '{"duration_ms":12,"job_name":"monthly_digest_generate","trigger":"manual"}'::jsonb
    ),
    'ledger payload guard rejects invalid scheduler trigger'
);

select ok(
    not public.ledger_payload_is_valid(
        'scheduler_job_completed',
        '{"duration_ms":12,"job_name":"monthly_digest_generate","trigger":"scheduled"}'::jsonb
    ),
    'ledger payload guard rejects scheduled trigger removed in T00'
);

select ok(
    public.ledger_payload_is_valid(
        'incident_detected',
        jsonb_build_object(
            'incident_type', 'hash_chain_mismatch',
            'severity', 'critical',
            'detection_source', 'ledger_hash_chain_full_verify',
            'dedupe_key', 'global-chain',
            'notification_sink', 'dummy',
            'notification_result', 'sent',
            'target_sequence_no', 42,
            'target_year_month', '2026-05'
        )
    ),
    'ledger payload guard accepts valid incident_detected payload'
);

select ok(
    not public.ledger_payload_is_valid(
        'incident_detected',
        jsonb_build_object(
            'severity', 'critical',
            'detection_source', 'ledger_hash_chain_full_verify',
            'dedupe_key', 'global-chain',
            'notification_sink', 'dummy',
            'notification_result', 'sent'
        )
    ),
    'ledger payload guard rejects incident_detected missing incident_type'
);

select ok(
    not public.ledger_payload_is_valid(
        'incident_detected',
        jsonb_build_object(
            'incident_type', 'unexpected_incident',
            'severity', 'critical',
            'detection_source', 'ledger_hash_chain_full_verify',
            'dedupe_key', 'global-chain',
            'notification_sink', 'dummy',
            'notification_result', 'sent'
        )
    ),
    'ledger payload guard rejects invalid incident_type'
);

select ok(
    not public.ledger_payload_is_valid(
        'incident_detected',
        jsonb_build_object(
            'incident_type', 'hash_chain_mismatch',
            'severity', 'urgent',
            'detection_source', 'ledger_hash_chain_full_verify',
            'dedupe_key', 'global-chain',
            'notification_sink', 'dummy',
            'notification_result', 'sent'
        )
    ),
    'ledger payload guard rejects invalid incident severity'
);

select ok(
    not public.ledger_payload_is_valid(
        'incident_detected',
        jsonb_build_object(
            'incident_type', 'hash_chain_mismatch',
            'severity', 'critical',
            'detection_source', 'ledger_hash_chain_full_verify',
            'dedupe_key', 'global-chain',
            'notification_sink', 'dummy',
            'notification_result', 'queued'
        )
    ),
    'ledger payload guard rejects invalid incident notification_result'
);

select ok(
    not public.ledger_payload_is_valid(
        'incident_detected',
        jsonb_build_object(
            'incident_type', 'hash_chain_mismatch',
            'severity', 'critical',
            'detection_source', 'ledger_hash_chain_full_verify',
            'dedupe_key', ' ',
            'notification_sink', 'dummy',
            'notification_result', 'sent'
        )
    ),
    'ledger payload guard rejects blank incident dedupe_key'
);

select ok(
    not public.ledger_payload_is_valid(
        'incident_detected',
        jsonb_build_object(
            'incident_type', 'hash_chain_mismatch',
            'severity', 'critical',
            'detection_source', 'ledger_hash_chain_full_verify',
            'dedupe_key', 'global-chain',
            'notification_sink', 'dummy',
            'notification_result', 'sent',
            'target_sequence_no', 0
        )
    ),
    'ledger payload guard rejects invalid incident target_sequence_no'
);

select ok(
    not public.ledger_payload_is_valid(
        'incident_detected',
        jsonb_build_object(
            'incident_type', 'monthly_digest_mismatch',
            'severity', 'high',
            'detection_source', 'monthly_digest_verify',
            'dedupe_key', 'digest-2026-13',
            'notification_sink', 'dummy',
            'notification_result', 'not_configured',
            'target_year_month', '2026-13'
        )
    ),
    'ledger payload guard rejects invalid incident target_year_month'
);

select ok(
    not public.ledger_payload_is_valid(
        'secret_created',
        '{"classification":"confidential","nested":{"version":1}}'::jsonb
    ),
    'ledger payload guard rejects nested payload objects in Phase 1'
);

select ok(
    public.ledger_source_event_at_is_valid('2026-04-08T12:00:00Z'),
    'ledger source_event_at guard accepts canonical UTC RFC3339'
);

select ok(
    not public.ledger_source_event_at_is_valid('2026-04-08T12:00:00+00:00'),
    'ledger source_event_at guard rejects offset timestamps'
);

create temp table first_ledger_append_result as
select *
from public.rpc_append_ledger_entry(
    '20000000-0000-4000-8000-000000000001',
    1,
    'secret_created',
    '2026-04-08T12:00:00Z',
    '21000000-0000-4000-8000-000000000001',
    '22000000-0000-4000-8000-000000000001',
    '550e8400-e29b-41d4-a716-446655440000',
    '560e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'sbc-device-1',
    'success',
    null,
    '{"classification":"confidential","version":1,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
    1,
    decode(repeat('00', 32), 'hex'),
    decode(repeat('11', 32), 'hex'),
    'sha-256',
    decode(repeat('aa', 64), 'hex'),
    'ed25519',
    1
);

select is(
    (select count(*)::integer from first_ledger_append_result),
    1,
    'append ledger RPC stores the genesis entry'
);

select is(
    (select replayed from first_ledger_append_result),
    false,
    'append ledger RPC marks a new entry as not replayed'
);

select is(
    (
        select last_sequence_no
        from public.ledger_chain_state
        where chain_id = 'global'
    ),
    1::bigint,
    'append ledger RPC advances chain sequence for a new entry'
);

select is(
    (
        select encode(last_entry_hash, 'hex')
        from public.ledger_chain_state
        where chain_id = 'global'
    ),
    repeat('11', 32),
    'append ledger RPC advances chain hash for a new entry'
);

set local role service_role;

select is(
    (
        select count(*)::integer
        from public.rpc_append_ledger_entry(
            '20000000-0000-4000-8000-000000000002',
            2,
            'secret_version_created',
            '2026-04-08T12:01:00Z',
            '21000000-0000-4000-8000-000000000002',
            '22000000-0000-4000-8000-000000000002',
            '550e8400-e29b-41d4-a716-446655440000',
            '560e8400-e29b-41d4-a716-446655440001',
            'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            'sbc-device-1',
            'success',
            null,
            '{"classification":"confidential","version":2,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
            1,
            decode(repeat('11', 32), 'hex'),
            decode(repeat('22', 32), 'hex'),
            'sha-256',
            decode(repeat('bb', 64), 'hex'),
            'ed25519',
            1
        )
    ),
    1,
    'service_role can execute append ledger RPC without direct table DML privileges'
);

reset role;

select is(
    (
        select last_sequence_no
        from public.ledger_chain_state
        where chain_id = 'global'
    ),
    2::bigint,
    'second append advances the global chain to sequence 2'
);

create temp table stale_first_replay_result as
select *
from public.rpc_append_ledger_entry(
    '20000000-0000-4000-8000-000000000001',
    1,
    'secret_created',
    '2026-04-08T12:00:00Z',
    '21000000-0000-4000-8000-000000000001',
    '22000000-0000-4000-8000-000000000001',
    '550e8400-e29b-41d4-a716-446655440000',
    '560e8400-e29b-41d4-a716-446655440000',
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'sbc-device-1',
    'success',
    null,
    '{"classification":"confidential","version":1,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
    1,
    decode(repeat('00', 32), 'hex'),
    decode(repeat('11', 32), 'hex'),
    'sha-256',
    decode(repeat('aa', 64), 'hex'),
    'ed25519',
    1
);

select is(
    (select replayed from stale_first_replay_result),
    true,
    'append ledger RPC treats stale-chain retry of an existing entry as replay success'
);

select is(
    (select chain_last_sequence_no from stale_first_replay_result),
    2::bigint,
    'replay success returns current chain state without validating stale sequence first'
);

select is(
    (
        select count(*)::integer
        from public.ledger_entries
        where id = '20000000-0000-4000-8000-000000000001'
    ),
    1,
    'idempotent replay keeps a single ledger row'
);

select is(
    test_helpers.try_append_ledger_entry(
        '20000000-0000-4000-8000-000000000001',
        1,
        'secret_created',
        '2026-04-08T12:00:00Z',
        '21000000-0000-4000-8000-000000000001',
        '22000000-0000-4000-8000-000000000001',
        '550e8400-e29b-41d4-a716-446655440000',
        '560e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'success',
        null,
        '{"classification":"public","version":1,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
        1,
        decode(repeat('00', 32), 'hex'),
        decode(repeat('11', 32), 'hex'),
        'sha-256',
        decode(repeat('aa', 64), 'hex'),
        'ed25519',
        1
    ),
    'ledger_entry_id_conflict',
    'append ledger RPC rejects same ledger_entry_id with different content'
);

select is(
    test_helpers.try_append_ledger_entry_diagnostics(
        '20000000-0000-4000-8000-000000000001',
        1,
        'secret_created',
        '2026-04-08T12:00:00Z',
        '21000000-0000-4000-8000-000000000001',
        '22000000-0000-4000-8000-000000000001',
        '550e8400-e29b-41d4-a716-446655440000',
        '560e8400-e29b-41d4-a716-446655440000',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'success',
        null,
        '{"classification":"public","version":1,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
        1,
        decode(repeat('00', 32), 'hex'),
        decode(repeat('11', 32), 'hex'),
        'sha-256',
        decode(repeat('aa', 64), 'hex'),
        'ed25519',
        1
    ),
    '23505:ledger_entry_id_conflict',
    'ledger_entry_id conflict uses SQLSTATE 23505'
);

select is(
    test_helpers.try_append_ledger_entry(
        '20000000-0000-4000-8000-000000000003',
        3,
        'secret_version_created',
        '2026-04-08T12:02:00Z',
        '21000000-0000-4000-8000-000000000003',
        null,
        '550e8400-e29b-41d4-a716-446655440000',
        '560e8400-e29b-41d4-a716-446655440002',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'success',
        null,
        '{"classification":"confidential","version":3,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
        1,
        decode(repeat('11', 32), 'hex'),
        decode(repeat('33', 32), 'hex'),
        'sha-256',
        decode(repeat('cc', 64), 'hex'),
        'ed25519',
        1
    ),
    'ledger_previous_hash_mismatch',
    'append ledger RPC rejects new entries with stale previous hash'
);

select is(
    test_helpers.try_append_ledger_entry(
        '20000000-0000-4000-8000-000000000004',
        4,
        'secret_version_created',
        '2026-04-08T12:02:00Z',
        '21000000-0000-4000-8000-000000000004',
        null,
        '550e8400-e29b-41d4-a716-446655440000',
        '560e8400-e29b-41d4-a716-446655440003',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'success',
        null,
        '{"classification":"confidential","version":3,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
        1,
        decode(repeat('22', 32), 'hex'),
        decode(repeat('44', 32), 'hex'),
        'sha-256',
        decode(repeat('dd', 64), 'hex'),
        'ed25519',
        1
    ),
    'ledger_sequence_mismatch',
    'append ledger RPC rejects new entries with stale or skipped sequence'
);

select is(
    test_helpers.try_append_ledger_entry(
        '20000000-0000-4000-8000-000000000005',
        3,
        'secret_version_created',
        '2026-04-08T12:02:00Z',
        '21000000-0000-4000-8000-000000000005',
        null,
        '550e8400-e29b-41d4-a716-446655440000',
        '560e8400-e29b-41d4-a716-446655440004',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'success',
        null,
        '{"classification":"confidential","version":3,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
        1,
        decode(repeat('22', 32), 'hex'),
        decode(repeat('22', 32), 'hex'),
        'sha-256',
        decode(repeat('ee', 64), 'hex'),
        'ed25519',
        1
    ),
    'ledger_entry_hash_conflict',
    'append ledger RPC normalizes duplicate entry_hash conflicts'
);

select is(
    test_helpers.try_append_ledger_entry(
        '20000000-0000-4000-8000-000000000006',
        3,
        'unknown_entry',
        '2026-04-08T12:02:00Z',
        '21000000-0000-4000-8000-000000000006',
        null,
        null,
        null,
        null,
        null,
        'success',
        null,
        '{}'::jsonb,
        1,
        decode(repeat('22', 32), 'hex'),
        decode(repeat('66', 32), 'hex'),
        'sha-256',
        decode(repeat('12', 64), 'hex'),
        'ed25519',
        1
    ),
    'invalid_rpc_input',
    'append ledger RPC rejects unknown entry_type'
);

select is(
    test_helpers.try_append_ledger_entry(
        '20000000-0000-4000-8000-000000000007',
        3,
        'secret_version_created',
        '2026-04-08T12:02:00+00:00',
        '21000000-0000-4000-8000-000000000007',
        null,
        null,
        null,
        null,
        null,
        'success',
        null,
        '{"classification":"confidential","version":3,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
        1,
        decode(repeat('22', 32), 'hex'),
        decode(repeat('67', 32), 'hex'),
        'sha-256',
        decode(repeat('13', 64), 'hex'),
        'ed25519',
        1
    ),
    'invalid_rpc_input',
    'append ledger RPC rejects non-canonical source_event_at'
);

select is(
    test_helpers.try_append_ledger_entry(
        '20000000-0000-4000-8000-000000000008',
        3,
        'secret_version_created',
        '2026-04-08T12:02:00Z',
        '21000000-0000-4000-8000-000000000008',
        null,
        null,
        null,
        null,
        null,
        'success',
        null,
        '{"classification":"confidential","version":3,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
        2,
        decode(repeat('22', 32), 'hex'),
        decode(repeat('68', 32), 'hex'),
        'sha-256',
        decode(repeat('14', 64), 'hex'),
        'ed25519',
        1
    ),
    'invalid_rpc_input',
    'append ledger RPC rejects invalid canonicalization version'
);

select is(
    test_helpers.try_append_ledger_entry(
        '20000000-0000-4000-8000-000000000009',
        3,
        'secret_version_created',
        '2026-04-08T12:02:00Z',
        '21000000-0000-4000-8000-000000000009',
        null,
        null,
        null,
        null,
        null,
        'success',
        null,
        '{"classification":"confidential","version":3,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
        1,
        decode(repeat('22', 32), 'hex'),
        decode(repeat('69', 32), 'hex'),
        'sha512',
        decode(repeat('15', 64), 'hex'),
        'ed25519',
        1
    ),
    'invalid_rpc_input',
    'append ledger RPC rejects invalid hash algorithm'
);

select is(
    test_helpers.try_append_ledger_entry(
        '20000000-0000-4000-8000-000000000010',
        3,
        'secret_version_created',
        '2026-04-08T12:02:00Z',
        '21000000-0000-4000-8000-000000000010',
        null,
        null,
        null,
        null,
        null,
        'success',
        null,
        '{"classification":"confidential","version":3,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
        1,
        decode(repeat('22', 32), 'hex'),
        decode(repeat('6a', 32), 'hex'),
        'sha-256',
        decode(repeat('16', 64), 'hex'),
        'ecdsa',
        1
    ),
    'invalid_rpc_input',
    'append ledger RPC rejects invalid signature algorithm'
);

select is(
    test_helpers.try_append_ledger_entry(
        '20000000-0000-4000-8000-000000000011',
        3,
        'secret_version_created',
        '2026-04-08T12:02:00Z',
        '21000000-0000-4000-8000-000000000011',
        null,
        null,
        null,
        null,
        null,
        'success',
        null,
        '{"classification":"confidential","version":3,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
        1,
        decode(repeat('22', 32), 'hex'),
        decode(repeat('6b', 31), 'hex'),
        'sha-256',
        decode(repeat('17', 64), 'hex'),
        'ed25519',
        1
    ),
    'invalid_rpc_input',
    'append ledger RPC rejects invalid entry_hash length'
);

select is(
    test_helpers.try_append_ledger_entry(
        '20000000-0000-4000-8000-000000000012',
        3,
        'secret_version_created',
        '2026-04-08T12:02:00Z',
        '21000000-0000-4000-8000-000000000012',
        null,
        null,
        null,
        null,
        null,
        'success',
        null,
        '{"classification":"confidential","version":3,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb,
        1,
        decode(repeat('22', 32), 'hex'),
        decode(repeat('6c', 32), 'hex'),
        'sha-256',
        decode(repeat('18', 63), 'hex'),
        'ed25519',
        1
    ),
    'invalid_rpc_input',
    'append ledger RPC rejects invalid signature length'
);

select is(
    test_helpers.try_append_ledger_entry(
        '20000000-0000-4000-8000-000000000013',
        3,
        'secret_version_created',
        '2026-04-08T12:02:00Z',
        '21000000-0000-4000-8000-000000000013',
        null,
        null,
        null,
        null,
        null,
        'success',
        null,
        '{"classification":"confidential","version":3,"key_version":1,"algorithm":"xchacha20-poly1305","token":"redacted"}'::jsonb,
        1,
        decode(repeat('22', 32), 'hex'),
        decode(repeat('6d', 32), 'hex'),
        'sha-256',
        decode(repeat('19', 64), 'hex'),
        'ed25519',
        1
    ),
    'invalid_rpc_input',
    'append ledger RPC rejects forbidden payload keys'
);

select is(
    test_helpers.try_update_ledger_entry(
        '20000000-0000-4000-8000-000000000001'
    ),
    'ledger_entries_immutable',
    'direct ledger_entries update is rejected by immutability trigger'
);

select is(
    test_helpers.try_delete_ledger_entry(
        '20000000-0000-4000-8000-000000000001'
    ),
    'ledger_entries_immutable',
    'direct ledger_entries delete is rejected by immutability trigger'
);

select is(
    test_helpers.try_truncate_ledger_entries(),
    'ledger_entries_immutable',
    'direct ledger_entries truncate is rejected by immutability trigger'
);

select is(
    test_helpers.try_delete_ledger_chain_state(),
    'ledger_chain_state_mutation_restricted',
    'direct ledger_chain_state delete is rejected by trigger'
);

select is(
    test_helpers.try_truncate_ledger_chain_state(),
    'ledger_chain_state_mutation_restricted',
    'direct ledger_chain_state truncate is rejected by trigger'
);

select is(
    (
        select count(*)::integer
        from public.audit_events
    ),
    0,
    'ledger tests do not mutate audit_events'
);

select is(
    to_regclass('public.secret_nonce_ledger'),
    null,
    'Ledger Phase 1 SQL implementation does not add secret_nonce_ledger'
);

select * from finish();

rollback;

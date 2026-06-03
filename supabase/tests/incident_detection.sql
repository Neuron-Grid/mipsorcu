begin;

\ir _support/common.psql

select no_plan();

create function test_helpers.incident_payload(
    p_incident_type text,
    p_severity text,
    p_detection_source text,
    p_dedupe_key text,
    p_notification_sink text,
    p_notification_result text,
    p_target_sequence_no bigint default null,
    p_target_year_month text default null
)
returns jsonb
language plpgsql
immutable
as $$
declare
    v_payload jsonb;
begin
    v_payload := jsonb_build_object(
        'incident_type', p_incident_type,
        'severity', p_severity,
        'detection_source', p_detection_source,
        'dedupe_key', p_dedupe_key,
        'notification_sink', p_notification_sink,
        'notification_result', p_notification_result
    );

    if p_target_sequence_no is not null then
        v_payload := v_payload || jsonb_build_object('target_sequence_no', p_target_sequence_no);
    end if;

    if p_target_year_month is not null then
        v_payload := v_payload || jsonb_build_object('target_year_month', p_target_year_month);
    end if;

    return v_payload;
end;
$$;

create function test_helpers.incident_ledger_entry_json(
    p_ledger_entry_id uuid,
    p_sequence_no bigint,
    p_source_event_at text,
    p_request_id uuid,
    p_source_event_id uuid,
    p_error_code text,
    p_payload jsonb,
    p_previous_hash text,
    p_entry_hash text
)
returns jsonb
language sql
immutable
as $$
    select test_helpers.ledger_entry_json(
        p_ledger_entry_id,
        p_sequence_no,
        'incident_detected',
        p_source_event_at,
        p_request_id::text,
        p_source_event_id::text,
        '',
        '',
        '',
        '',
        'failure',
        p_error_code,
        p_payload,
        p_previous_hash,
        p_entry_hash
    );
$$;

create function test_helpers.try_record_incident(
    p_audit_event_id uuid,
    p_request_id uuid,
    p_incident_type text,
    p_severity text,
    p_detection_source text,
    p_dedupe_key text,
    p_notification_sink text,
    p_notification_result text,
    p_error_code text,
    p_source_event_at text,
    p_ledger_entry jsonb,
    p_incident_source_event_id uuid default null,
    p_target_sequence_no bigint default null,
    p_target_year_month text default null,
    p_dedupe_window_seconds integer default 3600
)
returns text
language plpgsql
as $$
begin
    perform *
    from public.rpc_record_incident(
        p_audit_event_id,
        p_request_id,
        p_incident_type,
        p_severity,
        p_detection_source,
        p_dedupe_key,
        p_notification_sink,
        p_notification_result,
        p_error_code,
        p_source_event_at,
        p_ledger_entry,
        p_incident_source_event_id,
        p_target_sequence_no,
        p_target_year_month,
        p_dedupe_window_seconds
    );

    return 'ok';
exception
    when others then
    return sqlerrm;
end;
$$;

select is(
    public.incident_type_allowed('scheduler_failure'),
    true,
    'scheduler_failure is an allowed incident type'
);

select is(
    public.rpc_incident_recently_seen(
        'hash_chain_mismatch',
        'global-chain',
        '2026-06-01T02:59:00Z',
        3600
    ),
    false,
    'incident debounce precheck is false before the first matching incident'
);

create temp table incident_result as
select *
from public.rpc_record_incident(
    '12000000-0000-4000-8000-000000000001',
    '00000000-0000-4000-8000-000000001001',
    'hash_chain_mismatch',
    'critical',
    'ledger_hash_chain_full_verify',
    'global-chain',
    'dummy',
    'sent',
    'ledger_entry_hash_mismatch',
    '2026-06-01T03:00:00Z',
    test_helpers.incident_ledger_entry_json(
        '22000000-0000-4000-8000-000000000001',
        1,
        '2026-06-01T03:00:00Z',
        '00000000-0000-4000-8000-000000001001',
        '12000000-0000-4000-8000-000000000001',
        'ledger_entry_hash_mismatch',
        test_helpers.incident_payload(
            'hash_chain_mismatch',
            'critical',
            'ledger_hash_chain_full_verify',
            'global-chain',
            'dummy',
            'sent',
            42,
            '2026-05'
        ),
        repeat('00', 32),
        repeat('11', 32)
    ),
    null,
    42,
    '2026-05',
    3600
);

select is(
    (select audit_event_id::text from incident_result),
    '12000000-0000-4000-8000-000000000001',
    'rpc_record_incident returns the audit event id'
);

select is(
    (select ledger_entry_id::text from incident_result),
    '22000000-0000-4000-8000-000000000001',
    'rpc_record_incident returns the ledger entry id'
);

select is(
    (select suppressed from incident_result),
    false,
    'first incident is not suppressed'
);

select is(
    (select count(*)::integer from public.audit_events where action = 'incident_detected'),
    1,
    'valid incident appends one authoritative audit event'
);

select is(
    (select count(*)::integer from public.ledger_entries where entry_type = 'incident_detected'),
    1,
    'valid incident appends one incident ledger entry'
);

select is(
    (
        select metadata_json ->> 'incident_type'
        from public.audit_events
        where id = '12000000-0000-4000-8000-000000000001'
    ),
    'hash_chain_mismatch',
    'audit metadata records the incident type'
);

select is(
    (
        select payload ->> 'notification_result'
        from public.ledger_entries
        where id = '22000000-0000-4000-8000-000000000001'
    ),
    'sent',
    'ledger payload records the non-secret notification result'
);

select is(
    public.rpc_incident_recently_seen(
        'hash_chain_mismatch',
        'global-chain',
        '2026-06-01T03:30:00Z',
        3600
    ),
    true,
    'incident debounce precheck is true inside the matching window'
);

select is(
    public.rpc_incident_recently_seen(
        'hash_chain_mismatch',
        'global-chain',
        '2026-06-01T05:01:00Z',
        3600
    ),
    false,
    'incident debounce precheck is false outside the matching window'
);

select ok(
    not (
        (
            select metadata_json::text
            from public.audit_events
            where id = '12000000-0000-4000-8000-000000000001'
        ) like '%plaintext%'
    ),
    'audit metadata does not contain forbidden secret keys'
);

create temp table replay_result as
select *
from public.rpc_record_incident(
    '12000000-0000-4000-8000-000000000001',
    '00000000-0000-4000-8000-000000001001',
    'hash_chain_mismatch',
    'critical',
    'ledger_hash_chain_full_verify',
    'global-chain',
    'dummy',
    'sent',
    'ledger_entry_hash_mismatch',
    '2026-06-01T03:00:00Z',
    test_helpers.incident_ledger_entry_json(
        '22000000-0000-4000-8000-000000000001',
        1,
        '2026-06-01T03:00:00Z',
        '00000000-0000-4000-8000-000000001001',
        '12000000-0000-4000-8000-000000000001',
        'ledger_entry_hash_mismatch',
        test_helpers.incident_payload(
            'hash_chain_mismatch',
            'critical',
            'ledger_hash_chain_full_verify',
            'global-chain',
            'dummy',
            'sent',
            42,
            '2026-05'
        ),
        repeat('00', 32),
        repeat('11', 32)
    ),
    null,
    42,
    '2026-05',
    3600
);

select is(
    (select suppressed from replay_result),
    false,
    'same audit and ledger ids replay idempotently instead of being debounced'
);

select is(
    (select count(*)::integer from public.audit_events where action = 'incident_detected'),
    1,
    'idempotent replay does not add another audit event'
);

select is(
    (select count(*)::integer from public.ledger_entries where entry_type = 'incident_detected'),
    1,
    'idempotent replay does not add another ledger entry'
);

create temp table suppressed_result as
select *
from public.rpc_record_incident(
    '12000000-0000-4000-8000-000000000002',
    '00000000-0000-4000-8000-000000001002',
    'hash_chain_mismatch',
    'critical',
    'ledger_hash_chain_full_verify',
    'global-chain',
    'dummy',
    'sent',
    'ledger_entry_hash_mismatch',
    '2026-06-01T03:15:00Z',
    test_helpers.incident_ledger_entry_json(
        '22000000-0000-4000-8000-000000000002',
        2,
        '2026-06-01T03:15:00Z',
        '00000000-0000-4000-8000-000000001002',
        '12000000-0000-4000-8000-000000000002',
        'ledger_entry_hash_mismatch',
        test_helpers.incident_payload(
            'hash_chain_mismatch',
            'critical',
            'ledger_hash_chain_full_verify',
            'global-chain',
            'dummy',
            'sent',
            43,
            '2026-05'
        ),
        repeat('11', 32),
        repeat('22', 32)
    ),
    null,
    43,
    '2026-05',
    3600
);

select is(
    (select suppressed from suppressed_result),
    true,
    'same incident_type and dedupe_key inside the window is suppressed'
);

select is(
    (select ledger_entry_id from suppressed_result),
    null::uuid,
    'suppressed duplicate does not append a ledger entry'
);

select is(
    (select count(*)::integer from public.audit_events where action = 'incident_detected'),
    1,
    'suppressed duplicate does not add another audit event'
);

select is(
    (select count(*)::integer from public.ledger_entries where entry_type = 'incident_detected'),
    1,
    'suppressed duplicate does not add another ledger entry'
);

select is(
    test_helpers.try_record_incident(
        '12000000-0000-4000-8000-000000000003',
        '00000000-0000-4000-8000-000000001003',
        'unknown_incident',
        'critical',
        'ledger_hash_chain_full_verify',
        'unknown-incident',
        'dummy',
        'sent',
        'ledger_entry_hash_mismatch',
        '2026-06-01T04:00:00Z',
        test_helpers.incident_ledger_entry_json(
            '22000000-0000-4000-8000-000000000003',
            2,
            '2026-06-01T04:00:00Z',
            '00000000-0000-4000-8000-000000001003',
            '12000000-0000-4000-8000-000000000003',
            'ledger_entry_hash_mismatch',
            test_helpers.incident_payload(
                'unknown_incident',
                'critical',
                'ledger_hash_chain_full_verify',
                'unknown-incident',
                'dummy',
                'sent',
                null,
                null
            ),
            repeat('11', 32),
            repeat('22', 32)
        )
    ),
    'invalid_rpc_input',
    'rpc_record_incident rejects unknown incident_type'
);

select is(
    test_helpers.try_record_incident(
        '12000000-0000-4000-8000-000000000004',
        '00000000-0000-4000-8000-000000001004',
        'signature_mismatch',
        'urgent',
        'ledger_signature_full_verify',
        'signature-urgent',
        'dummy',
        'sent',
        'ledger_signature_invalid',
        '2026-06-01T04:01:00Z',
        test_helpers.incident_ledger_entry_json(
            '22000000-0000-4000-8000-000000000004',
            2,
            '2026-06-01T04:01:00Z',
            '00000000-0000-4000-8000-000000001004',
            '12000000-0000-4000-8000-000000000004',
            'ledger_signature_invalid',
            test_helpers.incident_payload(
                'signature_mismatch',
                'urgent',
                'ledger_signature_full_verify',
                'signature-urgent',
                'dummy',
                'sent',
                null,
                null
            ),
            repeat('11', 32),
            repeat('22', 32)
        )
    ),
    'invalid_rpc_input',
    'rpc_record_incident rejects invalid severity'
);

select is(
    test_helpers.try_record_incident(
        '12000000-0000-4000-8000-000000000005',
        '00000000-0000-4000-8000-000000001005',
        'signature_mismatch',
        'high',
        'ledger_signature_full_verify',
        'signature-notification',
        'dummy',
        'queued',
        'ledger_signature_invalid',
        '2026-06-01T04:02:00Z',
        test_helpers.incident_ledger_entry_json(
            '22000000-0000-4000-8000-000000000005',
            2,
            '2026-06-01T04:02:00Z',
            '00000000-0000-4000-8000-000000001005',
            '12000000-0000-4000-8000-000000000005',
            'ledger_signature_invalid',
            test_helpers.incident_payload(
                'signature_mismatch',
                'high',
                'ledger_signature_full_verify',
                'signature-notification',
                'dummy',
                'queued',
                null,
                null
            ),
            repeat('11', 32),
            repeat('22', 32)
        )
    ),
    'invalid_rpc_input',
    'rpc_record_incident rejects invalid notification_result'
);

select is(
    test_helpers.try_record_incident(
        '12000000-0000-4000-8000-000000000006',
        '00000000-0000-4000-8000-000000001006',
        'sequence_gap',
        'high',
        'ledger_hash_chain_full_verify',
        ' ',
        'dummy',
        'failed',
        'ledger_sequence_gap',
        '2026-06-01T04:03:00Z',
        test_helpers.incident_ledger_entry_json(
            '22000000-0000-4000-8000-000000000006',
            2,
            '2026-06-01T04:03:00Z',
            '00000000-0000-4000-8000-000000001006',
            '12000000-0000-4000-8000-000000000006',
            'ledger_sequence_gap',
            test_helpers.incident_payload(
                'sequence_gap',
                'high',
                'ledger_hash_chain_full_verify',
                ' ',
                'dummy',
                'failed',
                44,
                null
            ),
            repeat('11', 32),
            repeat('22', 32)
        ),
        null,
        44,
        null
    ),
    'invalid_rpc_input',
    'rpc_record_incident rejects blank dedupe_key'
);

select is(
    test_helpers.try_record_incident(
        '12000000-0000-4000-8000-000000000007',
        '00000000-0000-4000-8000-000000001007',
        'monthly_digest_mismatch',
        'high',
        'monthly_digest_verify',
        'digest-2026-13',
        'dummy',
        'not_configured',
        'monthly_digest_hash_mismatch',
        '2026-06-01T04:04:00Z',
        test_helpers.incident_ledger_entry_json(
            '22000000-0000-4000-8000-000000000007',
            2,
            '2026-06-01T04:04:00Z',
            '00000000-0000-4000-8000-000000001007',
            '12000000-0000-4000-8000-000000000007',
            'monthly_digest_hash_mismatch',
            test_helpers.incident_payload(
                'monthly_digest_mismatch',
                'high',
                'monthly_digest_verify',
                'digest-2026-13',
                'dummy',
                'not_configured',
                null,
                '2026-13'
            ),
            repeat('11', 32),
            repeat('22', 32)
        ),
        null,
        null,
        '2026-13'
    ),
    'invalid_rpc_input',
    'rpc_record_incident rejects invalid target_year_month'
);

select is(
    test_helpers.try_record_incident(
        '12000000-0000-4000-8000-000000000008',
        '00000000-0000-4000-8000-000000001008',
        'archive_export_mismatch',
        'medium',
        'archive_export_verify',
        'archive-2026-05',
        'dummy',
        'sent',
        'archive_export_digest_mismatch',
        '2026-06-01T04:05:00Z',
        test_helpers.incident_ledger_entry_json(
            '22000000-0000-4000-8000-000000000008',
            2,
            '2026-06-01T04:05:00Z',
            '00000000-0000-4000-8000-000000001008',
            '12000000-0000-4000-8000-000000000008',
            'archive_export_digest_mismatch',
            test_helpers.incident_payload(
                'monthly_digest_mismatch',
                'medium',
                'archive_export_verify',
                'archive-2026-05',
                'dummy',
                'sent',
                null,
                '2026-05'
            ),
            repeat('11', 32),
            repeat('22', 32)
        ),
        null,
        null,
        '2026-05'
    ),
    'invalid_rpc_input',
    'rpc_record_incident rejects ledger payload mismatch'
);

select is(
    test_helpers.try_record_incident(
        '12000000-0000-4000-8000-000000000009',
        '00000000-0000-4000-8000-000000001009',
        'ledger_secret_leak_suspected',
        'critical',
        'ledger_payload_scan',
        'ledger-leak',
        'dummy',
        'sent',
        'ledger_payload_forbidden_key',
        '2026-06-01T04:06:00Z',
        test_helpers.incident_ledger_entry_json(
            '22000000-0000-4000-8000-000000000009',
            2,
            '2026-06-01T04:06:00Z',
            '00000000-0000-4000-8000-000000001009',
            '12000000-0000-4000-8000-000000000009',
            'ledger_payload_forbidden_key',
            test_helpers.incident_payload(
                'ledger_secret_leak_suspected',
                'critical',
                'ledger_payload_scan',
                'ledger-leak',
                'dummy',
                'sent',
                null,
                null
            ) || '{"plaintext":"redacted"}'::jsonb,
            repeat('11', 32),
            repeat('22', 32)
        )
    ),
    'invalid_rpc_input',
    'rpc_record_incident rejects forbidden ledger payload keys'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.rpc_record_incident(uuid, uuid, text, text, text, text, text, text, text, text, jsonb, uuid, bigint, text, integer)',
        'execute'
    ),
    'anon cannot execute incident RPC'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.rpc_record_incident(uuid, uuid, text, text, text, text, text, text, text, text, jsonb, uuid, bigint, text, integer)',
        'execute'
    ),
    'authenticated cannot execute incident RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_record_incident(uuid, uuid, text, text, text, text, text, text, text, text, jsonb, uuid, bigint, text, integer)',
        'execute'
    ),
    'service_role can execute incident RPC'
);

select ok(
    not has_function_privilege(
        'anon',
        'public.rpc_incident_recently_seen(text, text, text, integer)',
        'execute'
    ),
    'anon cannot execute incident debounce precheck RPC'
);

select ok(
    not has_function_privilege(
        'authenticated',
        'public.rpc_incident_recently_seen(text, text, text, integer)',
        'execute'
    ),
    'authenticated cannot execute incident debounce precheck RPC'
);

select ok(
    has_function_privilege(
        'service_role',
        'public.rpc_incident_recently_seen(text, text, text, integer)',
        'execute'
    ),
    'service_role can execute incident debounce precheck RPC'
);

select ok(
    (
        select p.prosecdef
        from pg_proc p
        join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'public'
            and p.proname = 'rpc_record_incident'
    ),
    'incident RPC is SECURITY DEFINER'
);

select ok(
    (
        select exists (
            select 1
            from pg_proc p
            join pg_namespace n on n.oid = p.pronamespace
            where n.nspname = 'public'
                and p.proname = 'rpc_record_incident'
                and 'search_path=public, pg_temp' = any (p.proconfig)
        )
    ),
    'incident RPC has explicit search_path'
);

select is(
    (
        select count(*)::integer
        from pg_proc p
        join pg_namespace n on n.oid = p.pronamespace
        cross join (
            select c.relowner
            from pg_class c
            where c.oid = 'public.audit_events'::regclass
        ) table_owner
        where n.nspname = 'public'
            and p.proname = 'rpc_record_incident'
            and p.proowner = table_owner.relowner
            and pg_get_userbyid(p.proowner) not in (
                'anon',
                'authenticated',
                'service_role'
            )
    ),
    1,
    'incident RPC is owned by the schema/table owner, not runtime roles'
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
                'public.audit_events',
                table_privileges.privilege_name
            )
        )
    ),
    false,
    'service_role still has no direct table privileges on audit_events'
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
    'service_role still has no direct table privileges on ledger_entries'
);

set local role service_role;

select is(
    (
        select suppressed
        from public.rpc_record_incident(
            '12000000-0000-4000-8000-000000000010',
            '00000000-0000-4000-8000-000000001010',
            'siem_long_failure',
            'medium',
            'siem_resend_loop',
            'siem-long-failure',
            'dummy',
            'failed',
            'siem_long_outage',
            '2026-06-01T05:00:00Z',
            jsonb_build_object(
                'p_ledger_entry_id', '22000000-0000-4000-8000-000000000010',
                'p_sequence_no', 2,
                'p_entry_type', 'incident_detected',
                'p_source_event_at', '2026-06-01T05:00:00Z',
                'p_request_id', '00000000-0000-4000-8000-000000001010',
                'p_source_event_id', '12000000-0000-4000-8000-000000000010',
                'p_target_secret_id', '',
                'p_target_secret_version_id', '',
                'p_actor_user_id', '',
                'p_actor_device_id', '',
                'p_result', 'failure',
                'p_error_code', 'siem_long_outage',
                'p_payload', jsonb_build_object(
                    'incident_type', 'siem_long_failure',
                    'severity', 'medium',
                    'detection_source', 'siem_resend_loop',
                    'dedupe_key', 'siem-long-failure',
                    'notification_sink', 'dummy',
                    'notification_result', 'failed'
                ),
                'p_canonicalization_version', 1,
                'p_previous_entry_hash', '\x' || repeat('11', 32),
                'p_entry_hash', '\x' || repeat('22', 32),
                'p_hash_algorithm', 'sha3-256',
                'p_signature', '\x' || repeat('aa', 64),
                'p_signature_algorithm', 'ed25519',
                'p_signature_key_version', 1
            )
        )
    ),
    false,
    'service_role can execute incident RPC'
);

reset role;

select * from finish();

rollback;

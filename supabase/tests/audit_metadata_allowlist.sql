begin;

\ir _support/common.psql

select no_plan();

-- Feature flag default value (Phase 1: warning mode)
-- Must check BEFORE overriding with set local.
select is(
    public.audit_metadata_allowlist_mode(),
    'warning',
    'default allowlist mode is warning (Phase 1)'
);

-- This test validates strict allowlist enforcement.
-- Phase 1 default is 'warning'; we set 'strict' for these tests.
set local mipsorcu.audit_metadata_allowlist_mode = 'strict';

select is(
    public.audit_metadata_allowlist_mode(),
    'strict',
    'allowlist mode is strict after GUC override'
);


-- Setup: create a secret via write RPC to provide audit target

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


-- 1. decrypt success: source_event_at only (unknown key rejected)

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000100',
        '00000000-0000-4000-8000-000000000100',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'ok',
    'decrypt success with source_event_at only is allowed'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000101',
        '00000000-0000-4000-8000-000000000101',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"source_event_at":"2026-04-08T12:00:00Z","unknown":"bad"}'::jsonb
    ),
    'invalid_rpc_input',
    'decrypt success rejects unknown key'
);


-- 2. decrypt failure: attempted_secret_id + source_event_at (unknown rejected)

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000102',
        '00000000-0000-4000-8000-000000000102',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"attempted_secret_id":"550e8400-e29b-41d4-a716-446655440000","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'ok',
    'decrypt failure with attempted_secret_id is allowed'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000103',
        '00000000-0000-4000-8000-000000000103',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'decrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"attempted_secret_id":"550e8400-e29b-41d4-a716-446655440000","source_event_at":"2026-04-08T12:00:00Z","extra":"bad"}'::jsonb
    ),
    'invalid_rpc_input',
    'decrypt failure rejects unknown key'
);


-- 3. encrypt_create failure: version, secret_version_id, source_event_at

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000104',
        '00000000-0000-4000-8000-000000000104',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'encrypt_create',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"version":1,"secret_version_id":"550e8400-e29b-41d4-a716-446655440000","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'ok',
    'encrypt_create failure with allowlist keys is allowed'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-00000000104b',
        '00000000-0000-4000-8000-00000000104b',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'encrypt_create',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"version":1,"secret_version_id":"550e8400-e29b-41d4-a716-446655440000","attempted_secret_id":"550e8400-e29b-41d4-a716-446655440000","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'encrypt_create failure rejects attempted_secret_id reserved for decrypt failure'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000105',
        '00000000-0000-4000-8000-000000000105',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'encrypt_create',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"version":1,"source_event_at":"2026-04-08T12:00:00Z","extra":"bad"}'::jsonb
    ),
    'invalid_rpc_input',
    'encrypt_create failure rejects unknown key'
);


-- 4. encrypt_rotate failure: same allowlist as encrypt_create

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000106',
        '00000000-0000-4000-8000-000000000106',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'encrypt_rotate',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"version":2,"secret_version_id":"550e8400-e29b-41d4-a716-446655440001","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'ok',
    'encrypt_rotate failure with allowlist keys is allowed'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000107',
        '00000000-0000-4000-8000-000000000107',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'encrypt_rotate',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"version":2,"secret_version_id":"550e8400-e29b-41d4-a716-446655440001","source_event_at":"2026-04-08T12:00:00Z","extra":"bad"}'::jsonb
    ),
    'invalid_rpc_input',
    'encrypt_rotate failure rejects unknown key'
);


-- 5. version_purge failure: version, secret_version_id, source_event_at

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000108',
        '00000000-0000-4000-8000-000000000108',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'version_purge',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"version":1,"secret_version_id":"550e8400-e29b-41d4-a716-446655440000","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'ok',
    'version_purge failure with allowlist keys is allowed'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-00000000108b',
        '00000000-0000-4000-8000-00000000108b',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'version_purge',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"version":1,"secret_version_id":"550e8400-e29b-41d4-a716-446655440000","attempted_secret_id":"550e8400-e29b-41d4-a716-446655440000","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'version_purge failure rejects attempted_secret_id reserved for decrypt failure'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000109',
        '00000000-0000-4000-8000-000000000109',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'version_purge',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"version":1,"source_event_at":"2026-04-08T12:00:00Z","extra":"bad"}'::jsonb
    ),
    'invalid_rpc_input',
    'version_purge failure rejects unknown key'
);


-- 6. integrity_check success: full allowlist + violation_summary

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000110',
        '00000000-0000-4000-8000-000000000110',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'integrity_check',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'check_name', 'mvp_integrity_check',
            'checked_secret_count', 0,
            'checked_secret_version_count', 0,
            'checked_audit_event_count', 0,
            'duration_ms', 0,
            'violation_count', 0,
            'violation_summary', jsonb_build_object(
                'current_version_invalid', 0,
                'version_invalid', 0,
                'retention_exceeded', 0,
                'ciphertext_empty', 0,
                'encrypted_data_key_empty', 0,
                'nonce_length_invalid', 0,
                'algorithm_invalid', 0,
                'nonce_duplicate', 0,
                'aad_keys_invalid', 0,
                'aad_row_mismatch', 0,
                'created_at_mismatch', 0,
                'audit_action_invalid', 0,
                'audit_result_invalid', 0,
                'audit_metadata_not_object', 0,
                'audit_metadata_forbidden_key', 0,
                'audit_source_event_at_invalid', 0
            ),
            'trigger', 'startup',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'integrity_check success with full allowlist is allowed'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000111',
        '00000000-0000-4000-8000-000000000111',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'integrity_check',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'check_name', 'mvp_integrity_check',
            'checked_secret_count', 0,
            'checked_secret_version_count', 0,
            'checked_audit_event_count', 0,
            'duration_ms', 0,
            'violation_count', 0,
            'violation_summary', jsonb_build_object(
                'current_version_invalid', 0,
                'unknown_violation', 1
            ),
            'trigger', 'startup',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'integrity_check success rejects unknown violation_summary key'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000112',
        '00000000-0000-4000-8000-000000000112',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'integrity_check',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'check_name', 'mvp_integrity_check',
            'checked_secret_count', 0,
            'duration_ms', 0,
            'violation_count', 0,
            'trigger', 'startup',
            'source_event_at', '2026-04-08T12:00:00Z',
            'extra', 'bad'
        )
    ),
    'invalid_rpc_input',
    'integrity_check success rejects unknown top-level key'
);


-- 7. integrity_check failure: error_code addition

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000113',
        '00000000-0000-4000-8000-000000000113',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'integrity_check',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        jsonb_build_object(
            'check_name', 'mvp_integrity_check',
            'checked_secret_count', 0,
            'checked_secret_version_count', 0,
            'checked_audit_event_count', 0,
            'duration_ms', 0,
            'violation_count', 1,
            'violation_summary', jsonb_build_object(
                'current_version_invalid', 1,
                'version_invalid', 0,
                'retention_exceeded', 0,
                'ciphertext_empty', 0,
                'encrypted_data_key_empty', 0,
                'nonce_length_invalid', 0,
                'algorithm_invalid', 0,
                'nonce_duplicate', 0,
                'aad_keys_invalid', 0,
                'aad_row_mismatch', 0,
                'created_at_mismatch', 0,
                'audit_action_invalid', 0,
                'audit_result_invalid', 0,
                'audit_metadata_not_object', 0,
                'audit_metadata_forbidden_key', 0,
                'audit_source_event_at_invalid', 0
            ),
            'trigger', 'background',
            'error_code', 'rpc_failed',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'integrity_check failure with error_code is allowed'
);


-- 8. restore_test: full allowlist

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000114',
        '00000000-0000-4000-8000-000000000114',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'restore_test',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'phase', 'verify',
            'sample_count', 5,
            'trigger', 'background',
            'duration_ms', 100,
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'restore_test success with allowlist keys is allowed'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000115',
        '00000000-0000-4000-8000-000000000115',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'restore_test',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        jsonb_build_object(
            'phase', 'verify',
            'sample_count', 0,
            'trigger', 'cli',
            'duration_ms', 0,
            'error_code', 'sample_fetch_failed',
            'failed_version', null,
            'reason', 'no_current_secret_versions',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'restore_test failure with all optional keys is allowed'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000116',
        '00000000-0000-4000-8000-000000000116',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'restore_test',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'phase', 'verify',
            'sample_count', 5,
            'trigger', 'startup',
            'duration_ms', 0,
            'source_event_at', '2026-04-08T12:00:00Z',
            'extra', 'bad'
        )
    ),
    'invalid_rpc_input',
    'restore_test rejects unknown key'
);


-- 9. auth_failure: error_code + source_event_at

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000117',
        '00000000-0000-4000-8000-000000000117',
        null,
        null,
        'auth_failure',
        null,
        'failure',
        null,
        '{"error_code":"authorization_header_missing","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'ok',
    'auth_failure with allowlist keys is allowed'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000118',
        '00000000-0000-4000-8000-000000000118',
        null,
        null,
        'auth_failure',
        null,
        'failure',
        null,
        '{"error_code":"bad","source_event_at":"2026-04-08T12:00:00Z","extra":"bad"}'::jsonb
    ),
    'invalid_rpc_input',
    'auth_failure rejects unknown key'
);


-- 10. key_rotation_start

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000119',
        '00000000-0000-4000-8000-000000000119',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'key_rotation_start',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"old_key_version":1,"new_key_version":2,"source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'ok',
    'key_rotation_start with allowlist keys is allowed'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000120',
        '00000000-0000-4000-8000-000000000120',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'key_rotation_start',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"old_key_version":1,"new_key_version":2,"source_event_at":"2026-04-08T12:00:00Z","extra":"bad"}'::jsonb
    ),
    'invalid_rpc_input',
    'key_rotation_start rejects unknown key'
);


-- 11. key_rotation_reencrypt

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000121',
        '00000000-0000-4000-8000-000000000121',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'key_rotation_reencrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"old_key_version":1,"new_key_version":2,"batch_size":100,"processed_count":50,"remaining_count":50,"source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'ok',
    'key_rotation_reencrypt with allowlist keys is allowed'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000122',
        '00000000-0000-4000-8000-000000000122',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'key_rotation_reencrypt',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"old_key_version":1,"new_key_version":2,"batch_size":100,"processed_count":50,"remaining_count":50,"source_event_at":"2026-04-08T12:00:00Z","extra":"bad"}'::jsonb
    ),
    'invalid_rpc_input',
    'key_rotation_reencrypt rejects unknown key'
);


-- 12. key_rotation_complete

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000123',
        '00000000-0000-4000-8000-000000000123',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'key_rotation_complete',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"old_key_version":1,"new_key_version":2,"remaining_count":0,"source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'ok',
    'key_rotation_complete with allowlist keys is allowed'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000124',
        '00000000-0000-4000-8000-000000000124',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'key_rotation_complete',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"old_key_version":1,"new_key_version":2,"remaining_count":0,"source_event_at":"2026-04-08T12:00:00Z","extra":"bad"}'::jsonb
    ),
    'invalid_rpc_input',
    'key_rotation_complete rejects unknown key'
);


-- 13. denylist still coexists (forbidden key in allowlisted action rejected)

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000125',
        '00000000-0000-4000-8000-000000000125',
        null,
        null,
        'auth_failure',
        null,
        'failure',
        null,
        '{"error_code":"bad","source_event_at":"2026-04-08T12:00:00Z","plaintext":"leak"}'::jsonb
    ),
    'invalid_rpc_input',
    'denylist still rejects forbidden key even when action allowlist matches'
);


-- 14. write_secret_version internal audit metadata passes allowlist

select ok(
    exists (
        select 1
        from public.audit_events ae
        where ae.action = 'encrypt_create'
            and ae.result = 'success'
            and ae.metadata_json ? 'version'
            and ae.metadata_json ? 'secret_version_id'
    ),
    'write RPC internal audit metadata conforms to allowlist'
);

select ok(
    not exists (
        select 1
        from public.audit_events ae
        where ae.action = 'encrypt_create'
            and ae.metadata_json ? 'extra_unknown_key'
    ),
    'write RPC internal audit metadata does not contain unknown keys'
);


-- 15. unknown action still fail-closed via allowlist

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000126',
        '00000000-0000-4000-8000-000000000126',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'unknown_future_action',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{}'::jsonb
    ),
    'invalid_rpc_input',
    'unknown action is rejected before allowlist check'
);


select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000127',
        '00000000-0000-4000-8000-000000000127',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'integrity_check',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'check_name', 'mvp_integrity_check',
            'checked_secret_count', -1,
            'checked_secret_version_count', 0,
            'checked_audit_event_count', 0,
            'duration_ms', 0,
            'violation_count', 0,
            'violation_summary', jsonb_build_object('current_version_invalid', 0),
            'trigger', 'startup',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'integrity_check rejects negative checked_secret_count'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000128',
        '00000000-0000-4000-8000-000000000128',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'restore_test',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'phase', 'verify',
            'sample_count', 1,
            'trigger', 'cli',
            'duration_ms', -1,
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'restore_test rejects negative duration_ms'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000129',
        '00000000-0000-4000-8000-000000000129',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'encrypt_create',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"version":0,"secret_version_id":"550e8400-e29b-41d4-a716-446655440000","source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'encrypt_create rejects non-positive version metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000130',
        '00000000-0000-4000-8000-000000000130',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'key_rotation_start',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        '{"old_key_version":0,"new_key_version":2,"source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'key_rotation_start rejects non-positive old_key_version'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000131',
        '00000000-0000-4000-8000-000000000131',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'restore_test',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        jsonb_build_object(
            'phase', 'verify',
            'sample_count', 0,
            'trigger', 'not_valid',
            'duration_ms', 0,
            'error_code', 'sample_fetch_failed',
            'failed_version', null,
            'reason', 'no_current_secret_versions',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'restore_test rejects invalid trigger'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-0000000001ff',
        '00000000-0000-4000-8000-0000000001ff',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'restore_test',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        jsonb_build_object(
            'phase', 'verify',
            'sample_count', 0,
            'trigger', 'scheduled',
            'duration_ms', 0,
            'error_code', 'sample_fetch_failed',
            'failed_version', null,
            'reason', 'no_current_secret_versions',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'restore_test rejects scheduled trigger removed in T00'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000132',
        '00000000-0000-4000-8000-000000000132',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'integrity_check',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'check_name', 'mvp_integrity_check',
            'checked_secret_count', 0,
            'checked_secret_version_count', 0,
            'checked_audit_event_count', 0,
            'duration_ms', 0,
            'violation_count', 0,
            'violation_summary', 'not_an_object',
            'trigger', 'startup',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'integrity_check rejects non-object violation_summary'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000133',
        '00000000-0000-4000-8000-000000000133',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'integrity_check',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'check_name', 'mvp_integrity_check',
            'checked_secret_count', 0,
            'checked_secret_version_count', 0,
            'checked_audit_event_count', 0,
            'duration_ms', 0,
            'violation_count', 0,
            'violation_summary', jsonb_build_object('current_version_invalid', 'bad'),
            'trigger', 'startup',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'integrity_check rejects non-number violation_summary value'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000134',
        '00000000-0000-4000-8000-000000000134',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'integrity_check',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'check_name', 'mvp_integrity_check',
            'checked_secret_count', 0,
            'checked_secret_version_count', 0,
            'checked_audit_event_count', 0,
            'duration_ms', 0,
            'violation_count', 0,
            'violation_summary', jsonb_build_object('current_version_invalid', -1),
            'trigger', 'startup',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'integrity_check rejects negative violation_summary value'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000135',
        '00000000-0000-4000-8000-000000000135',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'restore_test',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        jsonb_build_object(
            'phase', 'verify',
            'sample_count', 0,
            'trigger', 'cli',
            'duration_ms', 0,
            'error_code', 'sample_fetch_failed',
            'failed_version', null,
            'reason', 'no_current_secret_versions',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'ok',
    'restore_test allows null failed_version'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000136',
        '00000000-0000-4000-8000-000000000136',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'encrypt_create',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        1,
        '{"version":1,"source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'encrypt_create rejects missing required secret_version_id'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000137',
        '00000000-0000-4000-8000-000000000137',
        null,
        null,
        'auth_failure',
        null,
        'failure',
        null,
        '{"source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'invalid_rpc_input',
    'auth_failure rejects missing required error_code'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000138',
        '00000000-0000-4000-8000-000000000138',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'restore_test',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'phase', 'verify',
            'sample_count', 1,
            'trigger', 'cli',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'restore_test rejects missing required duration_ms'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000139',
        '00000000-0000-4000-8000-000000000139',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'integrity_check',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'check_name', 'mvp_integrity_check',
            'checked_secret_count', 0,
            'checked_secret_version_count', 0,
            'checked_audit_event_count', 0,
            'duration_ms', 0,
            'violation_count', 0,
            'violation_summary', jsonb_build_object(
                'current_version_invalid', 0,
                'version_invalid', 0
            ),
            'trigger', 'startup',
            'source_event_at', '2026-04-08T12:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'integrity_check rejects missing required violation_summary keys'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000140',
        '00000000-0000-4000-8000-000000000140',
        null,
        null,
        'scheduler_job',
        null,
        'success',
        null,
        jsonb_build_object(
            'job_name', 'monthly_digest_generate',
            'trigger', 'background',
            'duration_ms', 12,
            'target_year_month', '2026-05',
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'ok',
    'scheduler_job success accepts valid metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000141',
        '00000000-0000-4000-8000-000000000141',
        null,
        null,
        'scheduler_job',
        null,
        'failure',
        null,
        jsonb_build_object(
            'job_name', 'archive_export',
            'trigger', 'background',
            'duration_ms', 12,
            'error_code', 'archive_export_failed',
            'target_year_month', '2026-05',
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'ok',
    'scheduler_job failure accepts valid error_code metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000142',
        '00000000-0000-4000-8000-000000000142',
        null,
        null,
        'scheduler_job',
        null,
        'success',
        null,
        jsonb_build_object(
            'trigger', 'background',
            'duration_ms', 12,
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'scheduler_job rejects missing required job_name'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000143',
        '00000000-0000-4000-8000-000000000143',
        null,
        null,
        'scheduler_job',
        null,
        'success',
        null,
        jsonb_build_object(
            'job_name', 'monthly_digest_generate',
            'trigger', 'background',
            'duration_ms', 12,
            'unexpected', 'bad',
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'scheduler_job rejects unknown metadata key'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000144',
        '00000000-0000-4000-8000-000000000144',
        null,
        null,
        'scheduler_job',
        null,
        'success',
        null,
        jsonb_build_object(
            'job_name', ' ',
            'trigger', 'background',
            'duration_ms', 12,
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'scheduler_job rejects blank job_name'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000145',
        '00000000-0000-4000-8000-000000000145',
        null,
        null,
        'scheduler_job',
        null,
        'success',
        null,
        jsonb_build_object(
            'job_name', 'monthly_digest_generate',
            'trigger', 'background',
            'duration_ms', 12,
            'error_code', 'should_be_failure_only',
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'scheduler_job success rejects error_code'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000146',
        '00000000-0000-4000-8000-000000000146',
        null,
        null,
        'scheduler_job',
        null,
        'success',
        null,
        jsonb_build_object(
            'job_name', 'monthly_digest_generate',
            'trigger', 'background',
            'duration_ms', 12,
            'target_year_month', '2026-13',
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'scheduler_job rejects invalid target_year_month'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000147',
        '00000000-0000-4000-8000-000000000147',
        null,
        null,
        'incident_detected',
        null,
        'failure',
        null,
        jsonb_build_object(
            'incident_type', 'hash_chain_mismatch',
            'severity', 'critical',
            'detection_source', 'ledger_hash_chain_full_verify',
            'dedupe_key', 'global-chain',
            'notification_sink', 'dummy',
            'notification_result', 'sent',
            'error_code', 'ledger_entry_hash_mismatch',
            'source_event_at', '2026-06-01T03:00:00Z',
            'source_event_id', '12000000-0000-4000-8000-000000000147',
            'target_sequence_no', 42,
            'target_year_month', '2026-05'
        )
    ),
    'ok',
    'incident_detected failure accepts valid metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000148',
        '00000000-0000-4000-8000-000000000148',
        null,
        null,
        'incident_detected',
        null,
        'failure',
        null,
        jsonb_build_object(
            'severity', 'critical',
            'detection_source', 'ledger_hash_chain_full_verify',
            'dedupe_key', 'global-chain-missing',
            'notification_sink', 'dummy',
            'notification_result', 'sent',
            'error_code', 'ledger_entry_hash_mismatch',
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'incident_detected rejects missing required incident_type'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000149',
        '00000000-0000-4000-8000-000000000149',
        null,
        null,
        'incident_detected',
        null,
        'failure',
        null,
        jsonb_build_object(
            'incident_type', 'hash_chain_mismatch',
            'severity', 'critical',
            'detection_source', 'ledger_hash_chain_full_verify',
            'dedupe_key', 'global-chain-extra',
            'notification_sink', 'dummy',
            'notification_result', 'sent',
            'error_code', 'ledger_entry_hash_mismatch',
            'source_event_at', '2026-06-01T03:00:00Z',
            'unexpected', 'bad'
        )
    ),
    'invalid_rpc_input',
    'incident_detected rejects unknown metadata key'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000150',
        '00000000-0000-4000-8000-000000000150',
        null,
        null,
        'incident_detected',
        null,
        'failure',
        null,
        jsonb_build_object(
            'incident_type', 'hash_chain_mismatch',
            'severity', 'urgent',
            'detection_source', 'ledger_hash_chain_full_verify',
            'dedupe_key', 'global-chain-severity',
            'notification_sink', 'dummy',
            'notification_result', 'sent',
            'error_code', 'ledger_entry_hash_mismatch',
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'incident_detected rejects invalid severity'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000151',
        '00000000-0000-4000-8000-000000000151',
        null,
        null,
        'incident_detected',
        null,
        'failure',
        null,
        jsonb_build_object(
            'incident_type', 'hash_chain_mismatch',
            'severity', 'critical',
            'detection_source', 'ledger_hash_chain_full_verify',
            'dedupe_key', 'global-chain-notification',
            'notification_sink', 'dummy',
            'notification_result', 'queued',
            'error_code', 'ledger_entry_hash_mismatch',
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'incident_detected rejects invalid notification_result'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000152',
        '00000000-0000-4000-8000-000000000152',
        null,
        null,
        'incident_detected',
        null,
        'success',
        null,
        jsonb_build_object(
            'incident_type', 'hash_chain_mismatch',
            'severity', 'critical',
            'detection_source', 'ledger_hash_chain_full_verify',
            'dedupe_key', 'global-chain-success',
            'notification_sink', 'dummy',
            'notification_result', 'sent',
            'error_code', 'ledger_entry_hash_mismatch',
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'incident_detected rejects success result'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000000153',
        '00000000-0000-4000-8000-000000000153',
        null,
        null,
        'incident_detected',
        null,
        'failure',
        null,
        jsonb_build_object(
            'incident_type', 'monthly_digest_mismatch',
            'severity', 'high',
            'detection_source', 'monthly_digest_verify',
            'dedupe_key', 'digest-2026-13',
            'notification_sink', 'dummy',
            'notification_result', 'not_configured',
            'error_code', 'monthly_digest_hash_mismatch',
            'source_event_at', '2026-06-01T03:00:00Z',
            'target_year_month', '2026-13'
        )
    ),
    'invalid_rpc_input',
    'incident_detected rejects invalid target_year_month'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000001200',
        '00000000-0000-4000-8000-000000001200',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_create',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'alias_fingerprint', repeat('aa', 32),
            'alias_fingerprint_key_version', 1,
            'alias_fingerprint_schema_version', 1,
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'ok',
    'secret_alias_create success accepts valid metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000001201',
        '00000000-0000-4000-8000-000000001201',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_update',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'old_alias_fingerprint', repeat('aa', 32),
            'new_alias_fingerprint', repeat('bb', 32),
            'alias_fingerprint_key_version', 1,
            'alias_fingerprint_schema_version', 1,
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'ok',
    'secret_alias_update success accepts valid metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000001202',
        '00000000-0000-4000-8000-000000001202',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_delete',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'alias_fingerprint', repeat('aa', 32),
            'alias_fingerprint_key_version', 1,
            'alias_fingerprint_schema_version', 1,
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'ok',
    'secret_alias_delete success accepts valid metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000001203',
        '00000000-0000-4000-8000-000000001203',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_list',
        null,
        'success',
        null,
        jsonb_build_object(
            'result_count', 3,
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'ok',
    'secret_alias_list success accepts valid metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000001208',
        '00000000-0000-4000-8000-000000001208',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_create',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        null,
        jsonb_build_object(
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'ok',
    'secret_alias_create failure accepts source_event_at-only metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000001209',
        '00000000-0000-4000-8000-000000001209',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_update',
        '550e8400-e29b-41d4-a716-446655440000',
        'failure',
        null,
        jsonb_build_object(
            'error_code', 'upstream_dependency_failed',
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'ok',
    'secret_alias_update failure accepts safe error_code metadata'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000001210',
        '00000000-0000-4000-8000-000000001210',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_create',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'alias_fingerprint', repeat('aa', 32),
            'alias_fingerprint_key_version', 1,
            'alias_fingerprint_schema_version', 1,
            'error_code', 'should_only_appear_on_failure',
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'secret_alias_create success rejects error_code'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000001204',
        '00000000-0000-4000-8000-000000001204',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_create',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'alias_fingerprint', repeat('aa', 32),
            'alias_fingerprint_key_version', 1,
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'secret_alias_create rejects missing schema version'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000001205',
        '00000000-0000-4000-8000-000000001205',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_update',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'old_alias_fingerprint', repeat('aa', 32),
            'new_alias_fingerprint', repeat('bb', 32),
            'alias_fingerprint_key_version', 1,
            'alias_fingerprint_schema_version', 1,
            'source_event_at', '2026-06-01T03:00:00Z',
            'extra', 'bad'
        )
    ),
    'invalid_rpc_input',
    'secret_alias_update rejects unknown metadata key'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000001206',
        '00000000-0000-4000-8000-000000001206',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_delete',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'alias_fingerprint', repeat('aa', 31),
            'alias_fingerprint_key_version', 1,
            'alias_fingerprint_schema_version', 1,
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'secret_alias_delete rejects invalid fingerprint length'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000001211',
        '00000000-0000-4000-8000-000000001211',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_delete',
        '550e8400-e29b-41d4-a716-446655440000',
        'success',
        1,
        jsonb_build_object(
            'alias_fingerprint', repeat('AA', 32),
            'alias_fingerprint_key_version', 1,
            'alias_fingerprint_schema_version', 1,
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'secret_alias_delete rejects uppercase fingerprint hex'
);

select is(
    test_helpers.try_append_audit_event(
        '10000000-0000-4000-8000-000000001207',
        '00000000-0000-4000-8000-000000001207',
        'f47ac10b-58cc-4372-a567-0e02b2c3d479',
        'sbc-device-1',
        'secret_alias_list',
        null,
        'success',
        null,
        jsonb_build_object(
            'result_count', -1,
            'source_event_at', '2026-06-01T03:00:00Z'
        )
    ),
    'invalid_rpc_input',
    'secret_alias_list rejects negative result_count'
);

select is(
    has_function_privilege(
        'anon',
        'public.audit_metadata_has_invalid_value_for_action(text, text, jsonb)',
        'EXECUTE'
    ),
    false,
    'anon cannot execute audit metadata invalid value helper'
);

select is(
    has_function_privilege(
        'authenticated',
        'public.audit_metadata_has_invalid_value_for_action(text, text, jsonb)',
        'EXECUTE'
    ),
    false,
    'authenticated cannot execute audit metadata invalid value helper'
);

select is(
    has_function_privilege(
        'anon',
        'public.audit_metadata_has_schema_violation_for_action(text, text, jsonb, boolean)',
        'EXECUTE'
    ),
    false,
    'anon cannot execute audit metadata schema violation helper'
);


select * from finish();

rollback;

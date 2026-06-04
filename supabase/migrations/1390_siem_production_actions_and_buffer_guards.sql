-- Section 1390: SIEM production forwarding actions and buffer guard parity.
--
-- Trust boundary: SIEM operational audit metadata contains only exporter
-- vocabulary, batch counters, buffer byte counts, stable error codes, and
-- canonical timestamps. It must never contain tokens, URLs with credentials,
-- request/response bodies, plaintext, ciphertext, keys, nonces, or HEC payloads.

create or replace function public.audit_metadata_has_forbidden_key(p_metadata_json jsonb)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    with recursive nodes(value) as (
        values (p_metadata_json)

        union all

        select child_values.value
        from nodes
        cross join lateral (
            select object_values.value
            from jsonb_each(
                case
                    when jsonb_typeof(nodes.value) = 'object' then nodes.value
                    else '{}'::jsonb
                end
            ) as object_values(key, value)

            union all

            select array_values.value
            from jsonb_array_elements(
                case
                    when jsonb_typeof(nodes.value) = 'array' then nodes.value
                    else '[]'::jsonb
                end
            ) as array_values(value)
        ) as child_values(value)
    )
    select exists (
        select 1
        from nodes
        cross join lateral jsonb_object_keys(
            case
                when jsonb_typeof(nodes.value) = 'object' then nodes.value
                else '{}'::jsonb
            end
        ) as metadata_keys(key)
        where jsonb_typeof(nodes.value) = 'object'
            and lower(btrim(metadata_keys.key)) in (
                -- FORBIDDEN_AUDIT_METADATA_KEYS_START
                'alias_decryption_key',
                'alias_encryption_key',
                'alias_fingerprint_key',
                'alias_nonce',
                'authorization',
                'authorization_header',
                'bearer_token',
                'canonical_alias_plaintext',
                'ciphertext',
                'data_key',
                'decrypt_result',
                'decrypted',
                'decrypted_data',
                'ed25519_private_key',
                'encrypted_data_key',
                'jwt',
                'jwt_full',
                'kek_value',
                'ledger_signing_key',
                'master_key',
                'nonce',
                'nonce_or_iv',
                'passphrase',
                'password',
                'plain_text',
                'plaintext',
                'raw_jwt',
                'request_body',
                'request_body_full',
                'response_body',
                'response_body_full',
                'secret_body',
                'secret_key',
                'secret_value',
                'service_role',
                'service_role_key',
                'signature_private_key',
                'token',
                'wrapped_dek'
                -- FORBIDDEN_AUDIT_METADATA_KEYS_END
            )
    );
$$;

comment on function public.audit_metadata_has_forbidden_key(jsonb) is
    'Recursively rejects audit metadata keys that could carry secrets, credentials, request/response bodies, ciphertext, nonce material, wrapped DEKs, or private key material. Section 1390 adds SIEM production leakage vocabulary.';

create or replace function public.ledger_payload_has_forbidden_key(p_payload jsonb)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    with recursive nodes(value) as (
        values (p_payload)

        union all

        select child_values.value
        from nodes
        cross join lateral (
            select object_values.value
            from jsonb_each(
                case
                    when jsonb_typeof(nodes.value) = 'object' then nodes.value
                    else '{}'::jsonb
                end
            ) as object_values(key, value)

            union all

            select array_values.value
            from jsonb_array_elements(
                case
                    when jsonb_typeof(nodes.value) = 'array' then nodes.value
                    else '[]'::jsonb
                end
            ) as array_values(value)
        ) as child_values(value)
    )
    select exists (
        select 1
        from nodes
        cross join lateral jsonb_object_keys(
            case
                when jsonb_typeof(nodes.value) = 'object' then nodes.value
                else '{}'::jsonb
            end
        ) as payload_keys(key)
        where jsonb_typeof(nodes.value) = 'object'
            and lower(btrim(payload_keys.key)) in (
                -- FORBIDDEN_LEDGER_PAYLOAD_KEYS_START
                'alias_decryption_key',
                'alias_encryption_key',
                'alias_fingerprint_key',
                'alias_nonce',
                'authorization',
                'authorization_header',
                'bearer_token',
                'canonical_alias_plaintext',
                'ciphertext',
                'data_key',
                'decrypt_result',
                'decrypted',
                'decrypted_data',
                'ed25519_private_key',
                'encrypted_data_key',
                'jwt',
                'jwt_full',
                'kek_value',
                'ledger_signing_key',
                'master_key',
                'nonce',
                'nonce_or_iv',
                'passphrase',
                'password',
                'plain_text',
                'plaintext',
                'raw_jwt',
                'request_body',
                'request_body_full',
                'response_body',
                'response_body_full',
                'secret_body',
                'secret_key',
                'secret_value',
                'service_role',
                'service_role_key',
                'signature_private_key',
                'token',
                'wrapped_dek'
                -- FORBIDDEN_LEDGER_PAYLOAD_KEYS_END
            )
    );
$$;

comment on function public.ledger_payload_has_forbidden_key(jsonb) is
    'Recursively rejects ledger payload keys that could carry secrets, credentials, request/response bodies, ciphertext, nonce material, wrapped DEKs, or private key material. Section 1390 keeps audit/ledger forbidden key parity.';

alter table public.audit_events
    drop constraint if exists audit_events_action_allowed,
    add constraint audit_events_action_allowed check (
        action in (
            'encrypt_create',
            'encrypt_rotate',
            'decrypt',
            'version_purge',
            'integrity_check',
            'restore_test',
            'auth_failure',
            'key_rotation_start',
            'key_rotation_reencrypt',
            'key_rotation_complete',
            'key_rotation_envelope_migrated',
            'key_rotation_envelope_failed',
            'signature_key_created',
            'signature_key_activated',
            'signature_key_retired',
            'monthly_digest_generate',
            'monthly_digest_verify',
            'archive_export',
            'digest_timestamping',
            'siem_forward_failure',
            'siem_event_forwarded',
            'siem_event_failed',
            'siem_buffer_flushed',
            'audit_report_generate',
            'audit_ui_read',
            'scheduler_job',
            'scheduler_job_started',
            'scheduler_job_completed',
            'scheduler_job_failed',
            'scheduler_job_skipped',
            'incident_detected',
            'incident_notification_sent',
            'incident_notification_failed',
            'incident_notification_suppressed',
            'secret_alias_create',
            'secret_alias_update',
            'secret_alias_delete',
            'secret_alias_list'
        )
    ),
    drop constraint if exists audit_events_siem_event_forwarded_success_only,
    add constraint audit_events_siem_event_forwarded_success_only check (
        action <> 'siem_event_forwarded' or result = 'success'
    ),
    drop constraint if exists audit_events_siem_event_failed_failure_only,
    add constraint audit_events_siem_event_failed_failure_only check (
        action <> 'siem_event_failed' or result = 'failure'
    ),
    drop constraint if exists audit_events_siem_buffer_flushed_success_only,
    add constraint audit_events_siem_buffer_flushed_success_only check (
        action <> 'siem_buffer_flushed' or result = 'success'
    ),
    drop constraint if exists audit_events_incident_notification_sent_success_only,
    add constraint audit_events_incident_notification_sent_success_only check (
        action <> 'incident_notification_sent' or result = 'success'
    ),
    drop constraint if exists audit_events_incident_notification_failed_failure_only,
    add constraint audit_events_incident_notification_failed_failure_only check (
        action <> 'incident_notification_failed' or result = 'failure'
    ),
    drop constraint if exists audit_events_incident_notification_suppressed_success_only,
    add constraint audit_events_incident_notification_suppressed_success_only check (
        action <> 'incident_notification_suppressed' or result = 'success'
    );

comment on constraint audit_events_siem_event_forwarded_success_only on public.audit_events is
    'siem_event_forwarded records successful SIEM batch delivery only.';
comment on constraint audit_events_siem_event_failed_failure_only on public.audit_events is
    'siem_event_failed records final SIEM batch delivery failures only.';
comment on constraint audit_events_siem_buffer_flushed_success_only on public.audit_events is
    'siem_buffer_flushed records successful pending-buffer flush progress only.';
comment on constraint audit_events_incident_notification_sent_success_only on public.audit_events is
    'incident_notification_sent records successful incident notification delivery only.';
comment on constraint audit_events_incident_notification_failed_failure_only on public.audit_events is
    'incident_notification_failed records final incident notification delivery failures only.';
comment on constraint audit_events_incident_notification_suppressed_success_only on public.audit_events is
    'incident_notification_suppressed records rate-limit suppression decisions only.';

create or replace function public.audit_metadata_has_unknown_key_for_action(
    p_action text,
    p_result text,
    p_metadata_json jsonb
)
returns boolean
language plpgsql
stable
set search_path = public, pg_temp
as $$
declare
    v_key text;
    v_allowed_keys text[];
    v_violation_summary_keys text[];
begin
    if jsonb_typeof(p_metadata_json) <> 'object' then
        return true;
    end if;

    -- ACTION_ALLOWLIST_START
    case p_action
        when 'encrypt_create', 'encrypt_rotate', 'version_purge' then
            v_allowed_keys := array['version', 'secret_version_id', 'source_event_at'];
        when 'decrypt' then
            if p_result = 'failure' then
                v_allowed_keys := array['attempted_secret_id', 'source_event_at'];
            else
                v_allowed_keys := array['source_event_at'];
            end if;
        when 'integrity_check' then
            v_allowed_keys := array['check_name', 'checked_secret_count', 'checked_secret_version_count', 'checked_audit_event_count', 'duration_ms', 'violation_count', 'violation_summary', 'trigger', 'error_code', 'source_event_at'];
            v_violation_summary_keys := array['current_version_invalid', 'version_invalid', 'retention_exceeded', 'ciphertext_empty', 'encrypted_data_key_empty', 'nonce_length_invalid', 'algorithm_invalid', 'nonce_duplicate', 'aad_keys_invalid', 'aad_row_mismatch', 'created_at_mismatch', 'audit_action_invalid', 'audit_result_invalid', 'audit_metadata_not_object', 'audit_metadata_forbidden_key', 'audit_source_event_at_invalid'];
        when 'restore_test' then
            v_allowed_keys := array['phase', 'sample_count', 'trigger', 'duration_ms', 'error_code', 'failed_version', 'reason', 'source_event_at'];
        when 'auth_failure' then
            v_allowed_keys := array['error_code', 'source_event_at'];
        when 'key_rotation_start' then
            v_allowed_keys := array['old_key_version', 'new_key_version', 'source_event_at'];
        when 'key_rotation_reencrypt' then
            v_allowed_keys := array['old_key_version', 'new_key_version', 'batch_size', 'processed_count', 'remaining_count', 'source_event_at'];
        when 'key_rotation_complete' then
            v_allowed_keys := array['old_key_version', 'new_key_version', 'remaining_count', 'source_event_at'];
        when 'key_rotation_envelope_migrated' then
            v_allowed_keys := array['batch_size', 'success_count', 'failure_count', 'source_event_at'];
        when 'key_rotation_envelope_failed' then
            v_allowed_keys := array['secret_version_id', 'version', 'error_code', 'source_event_at'];
        when 'signature_key_created' then
            v_allowed_keys := array['created_at', 'public_key_fingerprint', 'signature_key_version', 'source_event_at'];
        when 'signature_key_activated' then
            v_allowed_keys := array['activated_at', 'public_key_fingerprint', 'signature_key_version', 'source_event_at'];
        when 'signature_key_retired' then
            v_allowed_keys := array['public_key_fingerprint', 'retired_at', 'signature_key_version', 'source_event_at'];
        when 'monthly_digest_generate' then
            v_allowed_keys := array['error_code', 'target_year_month', 'source_event_at', 'start_sequence_no', 'end_sequence_no', 'entry_count', 'signature_key_version', 'digest_hash'];
        when 'monthly_digest_verify' then
            v_allowed_keys := array['error_code', 'target_year_month', 'verify_result', 'source_event_at'];
        when 'archive_export' then
            v_allowed_keys := array['archive_key', 'digest_hash', 'target_year_month', 'error_code', 'source_event_at'];
        when 'digest_timestamping' then
            v_allowed_keys := array['digest_hash', 'timestamp_token_hash', 'target_year_month', 'error_code', 'source_event_at'];
        when 'siem_forward_failure' then
            v_allowed_keys := array['error_code', 'event_type', 'event_count', 'source_event_at'];
        when 'siem_event_forwarded' then
            v_allowed_keys := array['exporter_kind', 'batch_size', 'source_event_at'];
        when 'siem_event_failed' then
            v_allowed_keys := array['exporter_kind', 'error_code', 'buffered', 'batch_size', 'source_event_at'];
        when 'siem_buffer_flushed' then
            v_allowed_keys := array['flushed_count', 'buffer_remaining_bytes', 'source_event_at'];
        when 'audit_report_generate' then
            v_allowed_keys := array['error_code', 'format', 'period_end', 'period_start', 'source_event_at'];
        when 'audit_ui_read' then
            v_allowed_keys := array['endpoint', 'method', 'resource', 'result_count', 'period_start', 'period_end', 'start_sequence_no', 'end_sequence_no', 'target_year_month', 'error_code', 'source_event_at'];
        when 'scheduler_job' then
            v_allowed_keys := array['duration_ms', 'error_code', 'job_name', 'target_year_month', 'trigger', 'source_event_at'];
        when 'scheduler_job_started' then
            v_allowed_keys := array['job_name', 'scheduled_at', 'started_at', 'source_event_at'];
        when 'scheduler_job_completed' then
            v_allowed_keys := array['completed_at', 'duration_ms', 'job_name', 'result_summary', 'started_at', 'source_event_at'];
        when 'scheduler_job_failed' then
            v_allowed_keys := array['error_code', 'failed_at', 'job_name', 'retry_count', 'started_at', 'source_event_at'];
        when 'scheduler_job_skipped' then
            v_allowed_keys := array['job_name', 'reason', 'skipped_at', 'source_event_at'];
        when 'incident_detected' then
            v_allowed_keys := array['incident_type', 'severity', 'detection_source', 'dedupe_key', 'notification_sink', 'notification_result', 'error_code', 'source_event_at', 'source_event_id', 'target_sequence_no', 'target_year_month'];
        when 'incident_notification_sent' then
            v_allowed_keys := array['incident_id', 'category', 'notifier_kind', 'duration_ms', 'source_event_at'];
        when 'incident_notification_failed' then
            v_allowed_keys := array['incident_id', 'category', 'notifier_kind', 'error_code', 'retry_count', 'source_event_at'];
        when 'incident_notification_suppressed' then
            v_allowed_keys := array['incident_id', 'category', 'reason', 'suppressed_count', 'window_remaining_sec', 'source_event_at'];
        when 'secret_alias_create' then
            v_allowed_keys := array['alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version', 'error_code', 'source_event_at'];
        when 'secret_alias_update' then
            v_allowed_keys := array['old_alias_fingerprint', 'new_alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version', 'error_code', 'source_event_at'];
        when 'secret_alias_delete' then
            v_allowed_keys := array['alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version', 'error_code', 'source_event_at'];
        when 'secret_alias_list' then
            v_allowed_keys := array['result_count', 'error_code', 'source_event_at'];
        else
            return true;
    end case;
    -- ACTION_ALLOWLIST_END

    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        if not (v_key = any(v_allowed_keys)) then
            return true;
        end if;
    end loop;

    if p_action = 'integrity_check'
        and p_metadata_json ? 'violation_summary'
        and jsonb_typeof(p_metadata_json -> 'violation_summary') = 'object'
    then
        for v_key in select jsonb_object_keys(p_metadata_json -> 'violation_summary')
        loop
            if not (v_key = any(v_violation_summary_keys)) then
                return true;
            end if;
        end loop;
    end if;

    return false;
end;
$$;

comment on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb)
is 'Returns true when audit metadata contains a key outside the per-action allowlist. Section 1390 adds SIEM operational action metadata keys.';

drop function if exists public.audit_metadata_has_missing_required_key_for_action_before_1390(text, text, jsonb, boolean);
alter function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean)
    rename to audit_metadata_has_missing_required_key_for_action_before_1390;

create function public.audit_metadata_has_missing_required_key_for_action(
    p_action text,
    p_result text,
    p_metadata_json jsonb,
    p_require_source_event_at boolean default true
)
returns boolean
language plpgsql
stable
set search_path = public, pg_temp
as $$
declare
    v_required_keys text[];
begin
    if jsonb_typeof(p_metadata_json) <> 'object' then
        return true;
    end if;

    case p_action
        when 'siem_event_forwarded' then
            v_required_keys := array['exporter_kind', 'batch_size'];
        when 'siem_event_failed' then
            v_required_keys := array['exporter_kind', 'error_code', 'buffered', 'batch_size'];
        when 'siem_buffer_flushed' then
            v_required_keys := array['flushed_count', 'buffer_remaining_bytes'];
        when 'incident_notification_sent' then
            v_required_keys := array['incident_id', 'category', 'notifier_kind', 'duration_ms'];
        when 'incident_notification_failed' then
            v_required_keys := array['incident_id', 'category', 'notifier_kind', 'error_code', 'retry_count'];
        when 'incident_notification_suppressed' then
            v_required_keys := array['incident_id', 'category', 'reason', 'suppressed_count', 'window_remaining_sec'];
        else
            return public.audit_metadata_has_missing_required_key_for_action_before_1390(
                p_action,
                p_result,
                p_metadata_json,
                p_require_source_event_at
            );
    end case;

    if p_require_source_event_at then
        v_required_keys := v_required_keys || array['source_event_at'];
    end if;

    return not (p_metadata_json ?& v_required_keys);
end;
$$;

comment on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean)
is 'Returns true when audit metadata is missing a required key for the given action/result. Section 1390 adds SIEM operational required keys.';

drop function if exists public.audit_metadata_has_invalid_value_for_action_before_1390(text, text, jsonb);
alter function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb)
    rename to audit_metadata_has_invalid_value_for_action_before_1390;

create function public.audit_metadata_has_invalid_value_for_action(
    p_action text,
    p_result text,
    p_metadata_json jsonb
)
returns boolean
language plpgsql
stable
set search_path = public, pg_temp
as $$
declare
    v_key text;
    v_value jsonb;
begin
    if jsonb_typeof(p_metadata_json) <> 'object' then
        return true;
    end if;

    if p_action not in (
        'siem_event_forwarded',
        'siem_event_failed',
        'siem_buffer_flushed',
        'incident_notification_sent',
        'incident_notification_failed',
        'incident_notification_suppressed'
    ) then
        return public.audit_metadata_has_invalid_value_for_action_before_1390(
            p_action,
            p_result,
            p_metadata_json
        );
    end if;

    if p_action in ('siem_event_forwarded', 'siem_buffer_flushed') and p_result <> 'success' then
        return true;
    end if;

    if p_action = 'siem_event_failed' and p_result <> 'failure' then
        return true;
    end if;

    if p_action in ('incident_notification_sent', 'incident_notification_suppressed') and p_result <> 'success' then
        return true;
    end if;

    if p_action = 'incident_notification_failed' and p_result <> 'failure' then
        return true;
    end if;

    v_value := p_metadata_json -> 'source_event_at';
    if jsonb_typeof(v_value) <> 'string'
        or not public.audit_metadata_source_event_at_is_valid(
            jsonb_build_object('source_event_at', v_value #>> '{}')
        )
    then
        return true;
    end if;

    if p_action in ('siem_event_forwarded', 'siem_event_failed') then
        v_value := p_metadata_json -> 'exporter_kind';
        if jsonb_typeof(v_value) <> 'string'
            or (v_value #>> '{}') not in ('in_memory', 'otlp', 'splunk_hec')
        then
            return true;
        end if;

        v_value := p_metadata_json -> 'batch_size';
        if jsonb_typeof(v_value) <> 'number'
            or (v_value #>> '{}') !~ '^[0-9]+$'
            or (v_value #>> '{}')::bigint <= 0
        then
            return true;
        end if;
    end if;

    if p_action = 'siem_event_failed' then
        v_value := p_metadata_json -> 'error_code';
        if jsonb_typeof(v_value) <> 'string'
            or btrim(v_value #>> '{}') = ''
            or length(v_value #>> '{}') > 64
        then
            return true;
        end if;

        v_value := p_metadata_json -> 'buffered';
        if jsonb_typeof(v_value) <> 'boolean' then
            return true;
        end if;
    end if;

    if p_action = 'siem_buffer_flushed' then
        foreach v_key in array array['flushed_count', 'buffer_remaining_bytes']
        loop
            v_value := p_metadata_json -> v_key;
            if jsonb_typeof(v_value) <> 'number'
                or (v_value #>> '{}') !~ '^[0-9]+$'
            then
                return true;
            end if;
        end loop;
    end if;

    if p_action in (
        'incident_notification_sent',
        'incident_notification_failed',
        'incident_notification_suppressed'
    ) then
        v_value := p_metadata_json -> 'incident_id';
        if jsonb_typeof(v_value) <> 'string'
            or (v_value #>> '{}') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        then
            return true;
        end if;

        v_value := p_metadata_json -> 'category';
        if jsonb_typeof(v_value) <> 'string'
            or (v_value #>> '{}') not in (
                'ledger_anomaly',
                'scheduler_failure',
                'archive_failure_persistent',
                'timestamping_failure_persistent',
                'siem_buffer_threshold',
                'envelope_migration_failure_burst',
                'auth_failure_burst',
                'key_rotation_failure'
            )
        then
            return true;
        end if;
    end if;

    if p_action in ('incident_notification_sent', 'incident_notification_failed') then
        v_value := p_metadata_json -> 'notifier_kind';
        if jsonb_typeof(v_value) <> 'string'
            or (v_value #>> '{}') not in ('dummy', 'webhook')
        then
            return true;
        end if;
    end if;

    if p_action = 'incident_notification_sent' then
        v_value := p_metadata_json -> 'duration_ms';
        if jsonb_typeof(v_value) <> 'number'
            or (v_value #>> '{}') !~ '^[0-9]+$'
        then
            return true;
        end if;
    end if;

    if p_action = 'incident_notification_failed' then
        v_value := p_metadata_json -> 'error_code';
        if jsonb_typeof(v_value) <> 'string'
            or btrim(v_value #>> '{}') = ''
            or length(v_value #>> '{}') > 64
        then
            return true;
        end if;

        v_value := p_metadata_json -> 'retry_count';
        if jsonb_typeof(v_value) <> 'number'
            or (v_value #>> '{}') !~ '^[0-9]+$'
        then
            return true;
        end if;
    end if;

    if p_action = 'incident_notification_suppressed' then
        v_value := p_metadata_json -> 'reason';
        if jsonb_typeof(v_value) <> 'string'
            or (v_value #>> '{}') <> 'rate_limited'
        then
            return true;
        end if;

        foreach v_key in array array['suppressed_count', 'window_remaining_sec']
        loop
            v_value := p_metadata_json -> v_key;
            if jsonb_typeof(v_value) <> 'number'
                or (v_value #>> '{}') !~ '^[0-9]+$'
            then
                return true;
            end if;
        end loop;
    end if;

    return false;
exception
    when numeric_value_out_of_range then
        return true;
end;
$$;

comment on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) is
    'Returns true if metadata_json contains invalid values per action schema. Section 1390 validates SIEM operational metadata.';

create or replace function public.rpc_append_audit_event(
    p_audit_event_id uuid,
    p_request_id uuid,
    p_actor_user_id uuid default null,
    p_actor_device_id text default null,
    p_action text default null,
    p_target_secret_id uuid default null,
    p_result text default null,
    p_key_version integer default null,
    p_metadata_json jsonb default '{}'::jsonb
)
returns uuid
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_existing_audit_event record;
    v_allowlist_mode text;
begin
    if p_audit_event_id is null
        or p_request_id is null
        or p_action is null
        or p_result is null
        or p_metadata_json is null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_action not in (
        'encrypt_create',
        'encrypt_rotate',
        'decrypt',
        'version_purge',
        'integrity_check',
        'restore_test',
        'auth_failure',
        'key_rotation_start',
        'key_rotation_reencrypt',
        'key_rotation_complete',
        'key_rotation_envelope_migrated',
        'key_rotation_envelope_failed',
        'signature_key_created',
        'signature_key_activated',
        'signature_key_retired',
        'monthly_digest_generate',
        'monthly_digest_verify',
        'archive_export',
        'digest_timestamping',
        'siem_forward_failure',
        'siem_event_forwarded',
        'siem_event_failed',
        'siem_buffer_flushed',
        'audit_report_generate',
        'audit_ui_read',
        'scheduler_job',
        'scheduler_job_started',
        'scheduler_job_completed',
        'scheduler_job_failed',
        'scheduler_job_skipped',
        'incident_detected',
        'incident_notification_sent',
        'incident_notification_failed',
        'incident_notification_suppressed',
        'secret_alias_create',
        'secret_alias_update',
        'secret_alias_delete',
        'secret_alias_list'
    ) then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_result not in ('success', 'failure') then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_result = 'success'
        and p_action in ('encrypt_create', 'encrypt_rotate', 'version_purge')
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_action in (
        'auth_failure',
        'siem_forward_failure',
        'siem_event_failed',
        'incident_detected',
        'incident_notification_failed',
        'key_rotation_envelope_failed',
        'scheduler_job_failed'
    )
        and p_result <> 'failure'
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_action in (
        'key_rotation_envelope_migrated',
        'scheduler_job_started',
        'scheduler_job_completed',
        'scheduler_job_skipped',
        'siem_event_forwarded',
        'siem_buffer_flushed',
        'incident_notification_sent',
        'incident_notification_suppressed'
    )
        and p_result <> 'success'
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_action = 'auth_failure'
        and (
            p_actor_user_id is not null
            or p_actor_device_id is not null
            or p_target_secret_id is not null
            or p_key_version is not null
        )
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_action in ('signature_key_created', 'signature_key_activated', 'signature_key_retired')
        and (
            p_actor_user_id is not null
            or p_actor_device_id is not null
            or p_target_secret_id is not null
            or p_key_version is not null
        )
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_actor_device_id is not null and btrim(p_actor_device_id) = '' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_key_version is not null and p_key_version <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if jsonb_typeof(p_metadata_json) <> 'object' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if public.audit_metadata_has_forbidden_key(p_metadata_json)
        or not public.audit_metadata_source_event_at_is_valid(p_metadata_json)
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    v_allowlist_mode := public.audit_metadata_allowlist_mode();

    if public.audit_metadata_has_schema_violation_for_action(p_action, p_result, p_metadata_json, true) then
        if v_allowlist_mode = 'strict' then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        else
            raise notice 'audit_metadata_schema_warning: action=%, result=%, schema_violation_present',
                p_action, p_result;
        end if;
    end if;

    insert into public.audit_events (
        id,
        request_id,
        actor_user_id,
        actor_device_id,
        action,
        target_secret_id,
        result,
        key_version,
        metadata_json
    )
    values (
        p_audit_event_id,
        p_request_id,
        p_actor_user_id,
        p_actor_device_id,
        p_action,
        p_target_secret_id,
        p_result,
        p_key_version,
        p_metadata_json
    )
    on conflict (id) do nothing;

    select *
    into v_existing_audit_event
    from public.audit_events ae
    where ae.id = p_audit_event_id;

    if v_existing_audit_event.id is null then
        raise exception 'audit_event_id_conflict' using errcode = '23505';
    end if;

    if v_existing_audit_event.request_id <> p_request_id
        or v_existing_audit_event.actor_user_id is distinct from p_actor_user_id
        or v_existing_audit_event.actor_device_id is distinct from p_actor_device_id
        or v_existing_audit_event.action <> p_action
        or v_existing_audit_event.target_secret_id is distinct from p_target_secret_id
        or v_existing_audit_event.result <> p_result
        or v_existing_audit_event.key_version is distinct from p_key_version
        or v_existing_audit_event.metadata_json <> p_metadata_json
    then
        raise exception 'audit_event_id_conflict' using errcode = '23505';
    end if;

    return p_audit_event_id;
end;
$$;

comment on function public.rpc_append_audit_event(
    uuid, uuid, uuid, text, text, uuid, text, integer, jsonb
) is
    'Audit append RPC for non-write-path audit events and failure events. Section 1390 adds SIEM operational actions and result constraints.';

revoke execute on function public.audit_metadata_has_forbidden_key(jsonb) from public, anon, authenticated;
revoke execute on function public.ledger_payload_has_forbidden_key(jsonb) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_schema_violation_for_action(text, text, jsonb, boolean) from public, anon, authenticated;
grant execute on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb) to service_role;
grant execute on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean) to service_role;
grant execute on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) to service_role;
grant execute on function public.audit_metadata_has_schema_violation_for_action(text, text, jsonb, boolean) to service_role;
revoke execute on function public.rpc_append_audit_event(
    uuid, uuid, uuid, text, text, uuid, text, integer, jsonb
) from public, anon, authenticated;
grant execute on function public.rpc_append_audit_event(
    uuid, uuid, uuid, text, text, uuid, text, integer, jsonb
) to service_role;

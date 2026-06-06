-- Bug #2: distinguish SIEM buffer capacity overflow from generic SIEM failures.
-- This migration extends only non-secret incident vocabulary.

create or replace function public.incident_type_allowed(p_incident_type text)
returns boolean
language sql
immutable
set search_path = public
as $$
    select p_incident_type in (
        'hash_chain_mismatch',
        'signature_mismatch',
        'monthly_digest_mismatch',
        'digest_timestamping_mismatch',
        'archive_export_mismatch',
        'sequence_gap',
        'unknown_signature_key',
        'non_auditor_ledger_read',
        'ledger_secret_leak_suspected',
        'siem_long_failure',
        'audit_ui_forbidden_operation',
        'scheduler_failure',
        'ledger_anomaly',
        'archive_failure_persistent',
        'timestamping_failure_persistent',
        'siem_buffer_threshold',
        'siem_buffer_overflow',
        'envelope_migration_failure_burst',
        'auth_failure_burst',
        'key_rotation_failure'
    );
$$;

comment on function public.incident_type_allowed(text) is
    'Returns true for non-secret incident type vocabulary accepted by incident audit and ledger records. Section 1430 adds siem_buffer_overflow.';

revoke execute on function public.incident_type_allowed(text) from public, anon, authenticated;

create or replace function public.audit_metadata_has_invalid_value_for_action(
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
    if p_action not in (
        'incident_notification_sent',
        'incident_notification_failed',
        'incident_notification_suppressed'
    ) then
        return public.audit_metadata_has_invalid_value_for_action_before_1400(
            p_action,
            p_result,
            p_metadata_json
        );
    end if;

    if jsonb_typeof(p_metadata_json) <> 'object' then
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
            'siem_buffer_overflow',
            'envelope_migration_failure_burst',
            'auth_failure_burst',
            'key_rotation_failure'
        )
    then
        return true;
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

comment on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb)
is 'Returns true when audit metadata contains an invalid value. Section 1430 adds siem_buffer_overflow incident notification category.';

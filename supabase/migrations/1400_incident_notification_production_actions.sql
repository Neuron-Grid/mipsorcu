-- Section 1400: Task 14 incident notification production actions.
--
-- This migration is intentionally forward-compatible with databases that have
-- already applied 1390 before incident_notification_* actions existed. Fresh
-- databases also keep the full allowlist definition in 1390 for Rust/SQL parity
-- tests, while this migration updates an existing local/prod database in place.

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

comment on constraint audit_events_incident_notification_sent_success_only on public.audit_events is
    'incident_notification_sent records successful incident notification delivery only.';
comment on constraint audit_events_incident_notification_failed_failure_only on public.audit_events is
    'incident_notification_failed records final incident notification delivery failures only.';
comment on constraint audit_events_incident_notification_suppressed_success_only on public.audit_events is
    'incident_notification_suppressed records rate-limit suppression decisions only.';

drop function if exists public.audit_metadata_has_unknown_key_for_action_before_1400(text, text, jsonb);
alter function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb)
    rename to audit_metadata_has_unknown_key_for_action_before_1400;

create function public.audit_metadata_has_unknown_key_for_action(
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
begin
    case p_action
        when 'incident_notification_sent' then
            v_allowed_keys := array['incident_id', 'category', 'notifier_kind', 'duration_ms', 'source_event_at'];
        when 'incident_notification_failed' then
            v_allowed_keys := array['incident_id', 'category', 'notifier_kind', 'error_code', 'retry_count', 'source_event_at'];
        when 'incident_notification_suppressed' then
            v_allowed_keys := array['incident_id', 'category', 'reason', 'suppressed_count', 'window_remaining_sec', 'source_event_at'];
        else
            return public.audit_metadata_has_unknown_key_for_action_before_1400(
                p_action,
                p_result,
                p_metadata_json
            );
    end case;

    if jsonb_typeof(p_metadata_json) <> 'object' then
        return true;
    end if;

    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        if not (v_key = any(v_allowed_keys)) then
            return true;
        end if;
    end loop;

    return false;
end;
$$;

drop function if exists public.audit_metadata_has_missing_required_key_for_action_before_1400(text, text, jsonb, boolean);
alter function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean)
    rename to audit_metadata_has_missing_required_key_for_action_before_1400;

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
        when 'incident_notification_sent' then
            v_required_keys := array['incident_id', 'category', 'notifier_kind', 'duration_ms'];
        when 'incident_notification_failed' then
            v_required_keys := array['incident_id', 'category', 'notifier_kind', 'error_code', 'retry_count'];
        when 'incident_notification_suppressed' then
            v_required_keys := array['incident_id', 'category', 'reason', 'suppressed_count', 'window_remaining_sec'];
        else
            return public.audit_metadata_has_missing_required_key_for_action_before_1400(
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

drop function if exists public.audit_metadata_has_invalid_value_for_action_before_1400(text, text, jsonb);
alter function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb)
    rename to audit_metadata_has_invalid_value_for_action_before_1400;

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

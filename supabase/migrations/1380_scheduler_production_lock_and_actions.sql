-- Section 1380: production scheduler locks and lifecycle audit actions.
--
-- Trust boundary: scheduler lock rows and lifecycle metadata contain only job
-- names, timestamps, durations, non-secret status summaries, and error codes.
-- They must never contain plaintext, keys, JWTs, service credentials, request
-- bodies, response bodies, or ciphertext material.

create or replace function public.incident_type_allowed(p_incident_type text)
returns boolean
language sql
stable
set search_path = public, pg_temp
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
        'scheduler_failure'
    );
$$;

comment on function public.incident_type_allowed(text) is
    'Returns true for non-secret incident type vocabulary accepted by incident audit and ledger records. Section 1380 adds scheduler_failure.';

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
            'audit_report_generate',
            'audit_ui_read',
            'scheduler_job',
            'scheduler_job_started',
            'scheduler_job_completed',
            'scheduler_job_failed',
            'scheduler_job_skipped',
            'incident_detected',
            'secret_alias_create',
            'secret_alias_update',
            'secret_alias_delete',
            'secret_alias_list'
        )
    ),
    drop constraint if exists audit_events_scheduler_job_started_success_only,
    add constraint audit_events_scheduler_job_started_success_only check (
        action <> 'scheduler_job_started' or result = 'success'
    ),
    drop constraint if exists audit_events_scheduler_job_completed_success_only,
    add constraint audit_events_scheduler_job_completed_success_only check (
        action <> 'scheduler_job_completed' or result = 'success'
    ),
    drop constraint if exists audit_events_scheduler_job_failed_failure_only,
    add constraint audit_events_scheduler_job_failed_failure_only check (
        action <> 'scheduler_job_failed' or result = 'failure'
    ),
    drop constraint if exists audit_events_scheduler_job_skipped_success_only,
    add constraint audit_events_scheduler_job_skipped_success_only check (
        action <> 'scheduler_job_skipped' or result = 'success'
    );

comment on constraint audit_events_scheduler_job_started_success_only on public.audit_events is
    'scheduler_job_started is a success lifecycle marker.';
comment on constraint audit_events_scheduler_job_completed_success_only on public.audit_events is
    'scheduler_job_completed is a success lifecycle marker and the only scheduler lifecycle action mirrored into ledger_entries.';
comment on constraint audit_events_scheduler_job_failed_failure_only on public.audit_events is
    'scheduler_job_failed is failure-only.';
comment on constraint audit_events_scheduler_job_skipped_success_only on public.audit_events is
    'scheduler_job_skipped records non-error skips such as DB lock contention.';

create table if not exists public.scheduler_locks (
    job_name text primary key,
    acquired_at timestamptz not null,
    expires_at timestamptz not null,
    constraint scheduler_locks_job_name_valid check (
        job_name ~ '^[a-z0-9_]{1,128}$'
    ),
    constraint scheduler_locks_expires_after_acquired check (
        expires_at > acquired_at
    )
);

comment on table public.scheduler_locks is
    'DB-backed TTL leases used by the production scheduler to suppress duplicate job execution across process restarts. This is not HA leader election.';
comment on column public.scheduler_locks.job_name is
    'Non-secret scheduler job name. Must match the Rust scheduler registry.';
comment on column public.scheduler_locks.acquired_at is
    'Database server time when the TTL lease was acquired.';
comment on column public.scheduler_locks.expires_at is
    'Database server time after which another scheduler invocation may replace the lease.';

alter table public.scheduler_locks enable row level security;
alter table public.scheduler_locks force row level security;

drop policy if exists scheduler_locks_deny_all on public.scheduler_locks;
create policy scheduler_locks_deny_all
on public.scheduler_locks
as restrictive
for all
using (false)
with check (false);

revoke all on table public.scheduler_locks from public, anon, authenticated;
revoke all privileges on table public.scheduler_locks from service_role;

create or replace function public.rpc_acquire_scheduler_lock(
    p_job_name text,
    p_ttl_seconds integer default 3600
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_now timestamptz := statement_timestamp();
    v_acquired boolean := false;
begin
    if p_job_name is null
        or p_job_name !~ '^[a-z0-9_]{1,128}$'
        or p_ttl_seconds is null
        or p_ttl_seconds <= 0
        or p_ttl_seconds > 86400
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    insert into public.scheduler_locks (job_name, acquired_at, expires_at)
    values (
        p_job_name,
        v_now,
        v_now + make_interval(secs => p_ttl_seconds)
    )
    on conflict (job_name) do update
        set acquired_at = excluded.acquired_at,
            expires_at = excluded.expires_at
        where public.scheduler_locks.expires_at <= v_now
    returning true into v_acquired;

    return coalesce(v_acquired, false);
end;
$$;

comment on function public.rpc_acquire_scheduler_lock(text, integer) is
    'Acquires or refreshes a scheduler TTL lease when no active lease exists. Returns false when another active lease is present.';

create or replace function public.rpc_release_scheduler_lock(p_job_name text)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_released boolean := false;
begin
    if p_job_name is null or p_job_name !~ '^[a-z0-9_]{1,128}$' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    delete from public.scheduler_locks
    where job_name = p_job_name
    returning true into v_released;

    return coalesce(v_released, false);
end;
$$;

comment on function public.rpc_release_scheduler_lock(text) is
    'Releases a scheduler TTL lease after the job wrapper completes. Returns false if no lease row existed.';

revoke execute on function public.rpc_acquire_scheduler_lock(text, integer) from public, anon, authenticated;
revoke execute on function public.rpc_acquire_scheduler_lock(text, integer) from public;
revoke execute on function public.rpc_release_scheduler_lock(text) from public, anon, authenticated;
revoke execute on function public.rpc_release_scheduler_lock(text) from public;
grant execute on function public.rpc_acquire_scheduler_lock(text, integer) to service_role;
grant execute on function public.rpc_release_scheduler_lock(text) to service_role;

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
        'audit_report_generate',
        'audit_ui_read',
        'scheduler_job',
        'scheduler_job_started',
        'scheduler_job_completed',
        'scheduler_job_failed',
        'scheduler_job_skipped',
        'incident_detected',
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
        'incident_detected',
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
        'scheduler_job_skipped'
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

    if not found then
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
    'Audit append RPC for non-write-path audit events and failure events. Section 1380 adds scheduler lifecycle actions and result constraints.';

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
is 'Returns true when audit metadata contains a key outside the per-action allowlist. Section 1380 adds scheduler lifecycle metadata keys.';

drop function if exists public.audit_metadata_has_missing_required_key_for_action_before_1380(text, text, jsonb, boolean);
alter function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean)
    rename to audit_metadata_has_missing_required_key_for_action_before_1380;

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
        when 'key_rotation_envelope_migrated' then
            v_required_keys := array['batch_size', 'success_count', 'failure_count'];
        when 'key_rotation_envelope_failed' then
            v_required_keys := array['secret_version_id', 'version', 'error_code'];
        when 'scheduler_job_started' then
            v_required_keys := array['job_name', 'scheduled_at', 'started_at'];
        when 'scheduler_job_completed' then
            v_required_keys := array['job_name', 'started_at', 'completed_at', 'duration_ms', 'result_summary'];
        when 'scheduler_job_failed' then
            v_required_keys := array['job_name', 'started_at', 'failed_at', 'error_code', 'retry_count'];
        when 'scheduler_job_skipped' then
            v_required_keys := array['job_name', 'skipped_at', 'reason'];
        else
            return public.audit_metadata_has_missing_required_key_for_action_before_1380(
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
is 'Returns true when audit metadata is missing a required key for the given action/result. Section 1380 adds scheduler lifecycle required keys.';

drop function if exists public.audit_metadata_has_invalid_value_for_action_before_1380(text, text, jsonb);
alter function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb)
    rename to audit_metadata_has_invalid_value_for_action_before_1380;

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
        'key_rotation_envelope_migrated',
        'key_rotation_envelope_failed',
        'scheduler_job_started',
        'scheduler_job_completed',
        'scheduler_job_failed',
        'scheduler_job_skipped'
    ) then
        return public.audit_metadata_has_invalid_value_for_action_before_1380(
            p_action,
            p_result,
            p_metadata_json
        );
    end if;

    if p_action = 'key_rotation_envelope_migrated' then
        if p_result <> 'success' then
            return true;
        end if;

        v_value := p_metadata_json -> 'batch_size';
        if jsonb_typeof(v_value) <> 'number'
            or (v_value #>> '{}') !~ '^[0-9]+$'
            or (v_value #>> '{}')::bigint <= 0
        then
            return true;
        end if;

        foreach v_value in array array[p_metadata_json -> 'success_count', p_metadata_json -> 'failure_count']
        loop
            if jsonb_typeof(v_value) <> 'number' or (v_value #>> '{}') !~ '^[0-9]+$' then
                return true;
            end if;
        end loop;

        v_value := p_metadata_json -> 'source_event_at';
        if jsonb_typeof(v_value) <> 'string'
            or not public.audit_metadata_source_event_at_is_valid(
                jsonb_build_object('source_event_at', v_value #>> '{}')
            )
        then
            return true;
        end if;

        return false;
    end if;

    if p_action = 'key_rotation_envelope_failed' then
        if p_result <> 'failure' then
            return true;
        end if;

        v_value := p_metadata_json -> 'secret_version_id';
        if jsonb_typeof(v_value) <> 'string'
            or (v_value #>> '{}') !~ '^[0-9a-fA-F-]{36}$'
        then
            return true;
        end if;

        v_value := p_metadata_json -> 'version';
        if jsonb_typeof(v_value) <> 'number'
            or (v_value #>> '{}') !~ '^[0-9]+$'
            or (v_value #>> '{}')::bigint <= 0
        then
            return true;
        end if;

        v_value := p_metadata_json -> 'error_code';
        if jsonb_typeof(v_value) <> 'string'
            or btrim(v_value #>> '{}') = ''
            or length(v_value #>> '{}') > 64
        then
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

        return false;
    end if;

    if p_action in ('scheduler_job_started', 'scheduler_job_completed', 'scheduler_job_skipped')
        and p_result <> 'success'
    then
        return true;
    end if;

    if p_action = 'scheduler_job_failed' and p_result <> 'failure' then
        return true;
    end if;

    v_value := p_metadata_json -> 'job_name';
    if jsonb_typeof(v_value) <> 'string'
        or btrim(v_value #>> '{}') = ''
        or length(v_value #>> '{}') > 128
    then
        return true;
    end if;

    foreach v_key in array array['source_event_at', 'scheduled_at', 'started_at', 'completed_at', 'failed_at', 'skipped_at']
    loop
        if p_metadata_json ? v_key then
            v_value := p_metadata_json -> v_key;
            if jsonb_typeof(v_value) <> 'string'
                or not public.audit_metadata_source_event_at_is_valid(
                    jsonb_build_object('source_event_at', v_value #>> '{}')
                )
            then
                return true;
            end if;
        end if;
    end loop;

    if p_metadata_json ? 'duration_ms' then
        v_value := p_metadata_json -> 'duration_ms';
        if jsonb_typeof(v_value) <> 'number' or (v_value #>> '{}') !~ '^[0-9]+$' then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'retry_count' then
        v_value := p_metadata_json -> 'retry_count';
        if jsonb_typeof(v_value) <> 'number'
            or (v_value #>> '{}') !~ '^[0-9]+$'
            or (v_value #>> '{}')::bigint <> 0
        then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'error_code' then
        v_value := p_metadata_json -> 'error_code';
        if p_result <> 'failure'
            or jsonb_typeof(v_value) <> 'string'
            or btrim(v_value #>> '{}') = ''
            or length(v_value #>> '{}') > 64
        then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'reason' then
        v_value := p_metadata_json -> 'reason';
        if p_action <> 'scheduler_job_skipped'
            or jsonb_typeof(v_value) <> 'string'
            or (v_value #>> '{}') <> 'lock_not_acquired'
        then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'result_summary'
        and jsonb_typeof(p_metadata_json -> 'result_summary') <> 'object'
    then
        return true;
    end if;

    return false;
exception
    when numeric_value_out_of_range then
        return true;
end;
$$;

comment on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) is
    'Returns true if metadata_json contains invalid values per action schema. Section 1380 validates scheduler lifecycle metadata.';

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

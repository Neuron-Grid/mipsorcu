-- T15: ledger signature key lifecycle registry and ledger-bound rotation events.
--
-- Trust boundary: only Ed25519 public keys, key versions, timestamps, and
-- fingerprints are stored in Supabase. Signing private keys remain inside SBC.

alter table public.ledger_signing_public_keys
    add column if not exists activated_at timestamptz;

update public.ledger_signing_public_keys
set activated_at = created_at
where status in ('active', 'retired')
    and activated_at is null;

alter table public.ledger_signing_public_keys
    drop constraint if exists ledger_signing_public_keys_status_allowed,
    drop constraint if exists ledger_signing_public_keys_active_retired_at_null,
    drop constraint if exists ledger_signing_public_keys_retired_retired_at_not_null,
    add constraint ledger_signing_public_keys_status_allowed check (
        status in ('created', 'active', 'retired')
    ),
    add constraint ledger_signing_public_keys_created_timestamps check (
        status <> 'created'
        or (activated_at is null and retired_at is null)
    ),
    add constraint ledger_signing_public_keys_active_timestamps check (
        status <> 'active'
        or (activated_at is not null and retired_at is null)
    ),
    add constraint ledger_signing_public_keys_retired_timestamps check (
        status <> 'retired'
        or (activated_at is not null and retired_at is not null)
    );

comment on column public.ledger_signing_public_keys.status
is 'created, active, or retired. created -> active -> retired is the only allowed lifecycle.';
comment on column public.ledger_signing_public_keys.activated_at
is 'SBC source_event_at timestamp when this signing public key became valid for new signatures. Null for created keys.';
comment on column public.ledger_signing_public_keys.retired_at
is 'SBC source_event_at timestamp when this signing public key stopped being valid for new signatures. Retired keys remain verification-only.';

create or replace function public.ledger_signing_public_key_fingerprint(p_public_key bytea)
returns text
language sql
immutable
set search_path = public, extensions, pg_temp
as $$
    select encode(extensions.digest(p_public_key, 'sha256'), 'hex');
$$;

comment on function public.ledger_signing_public_key_fingerprint(bytea)
is 'Returns lowercase SHA-256 hex fingerprint for a non-secret Ed25519 public key.';

create or replace function public.ledger_signing_public_keys_check_mutation()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if tg_op = 'INSERT' then
        return new;
    end if;

    if tg_op = 'UPDATE' then
        if old.key_version <> new.key_version
            or old.public_key <> new.public_key
            or old.algorithm <> new.algorithm
            or old.created_at <> new.created_at
        then
            raise exception 'ledger_signing_public_keys_immutable'
                using errcode = '42501';
        end if;

        if old.status = 'created'
            and new.status = 'active'
            and old.activated_at is null
            and new.activated_at is not null
            and old.retired_at is null
            and new.retired_at is null
        then
            return new;
        end if;

        if old.status = 'active'
            and new.status = 'retired'
            and old.activated_at = new.activated_at
            and old.retired_at is null
            and new.retired_at is not null
        then
            return new;
        end if;

        raise exception 'ledger_signing_public_key_lifecycle_invalid_transition on ledger_signing_public_keys'
            using errcode = '42501';
    end if;

    if tg_op = 'DELETE' then
        raise exception 'ledger_signing_public_keys_no_delete'
            using errcode = '42501';
    end if;

    if tg_op = 'TRUNCATE' then
        raise exception 'ledger_signing_public_keys_no_truncate'
            using errcode = '42501';
    end if;

    return null;
end;
$$;

alter table public.audit_events
    drop constraint audit_events_action_allowed,
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
            'signature_key_created',
            'signature_key_activated',
            'signature_key_retired',
            'monthly_digest_generate',
            'monthly_digest_verify',
            'archive_export',
            'digest_timestamping',
            'siem_forward_failure',
            'audit_report_generate',
            'scheduler_job',
            'incident_detected'
        )
    );

-- FORBIDDEN_AUDIT_METADATA_KEYS_START
-- 'authorization'
-- 'authorization_header'
-- 'bearer_token'
-- 'ciphertext'
-- 'data_key'
-- 'decrypt_result'
-- 'decrypted'
-- 'decrypted_data'
-- 'encrypted_data_key'
-- 'jwt'
-- 'jwt_full'
-- 'master_key'
-- 'passphrase'
-- 'password'
-- 'plain_text'
-- 'plaintext'
-- 'raw_jwt'
-- 'request_body'
-- 'request_body_full'
-- 'response_body'
-- 'response_body_full'
-- 'secret_key'
-- 'secret_value'
-- 'service_role'
-- 'service_role_key'
-- 'token'
-- FORBIDDEN_AUDIT_METADATA_KEYS_END

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
        'signature_key_created',
        'signature_key_activated',
        'signature_key_retired',
        'monthly_digest_generate',
        'monthly_digest_verify',
        'archive_export',
        'digest_timestamping',
        'siem_forward_failure',
        'audit_report_generate',
        'scheduler_job',
        'incident_detected'
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

    if p_action in ('auth_failure', 'siem_forward_failure', 'incident_detected')
        and p_result <> 'failure'
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_action in ('monthly_digest_generate', 'monthly_digest_verify')
        and p_result <> 'failure'
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

create or replace function public.audit_metadata_has_missing_required_key_for_action(
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
    v_summary_required_keys text[];
begin
    if jsonb_typeof(p_metadata_json) <> 'object' then
        return true;
    end if;

    case p_action
        when 'encrypt_create', 'encrypt_rotate', 'version_purge' then
            v_required_keys := array['version', 'secret_version_id'];
        when 'decrypt' then
            v_required_keys := array[]::text[];
        when 'integrity_check' then
            v_required_keys := array['check_name', 'checked_secret_count', 'checked_secret_version_count', 'checked_audit_event_count', 'duration_ms', 'violation_count', 'violation_summary', 'trigger'];
            v_summary_required_keys := array['current_version_invalid', 'version_invalid', 'retention_exceeded', 'ciphertext_empty', 'encrypted_data_key_empty', 'nonce_length_invalid', 'algorithm_invalid', 'nonce_duplicate', 'aad_keys_invalid', 'aad_row_mismatch', 'created_at_mismatch', 'audit_action_invalid', 'audit_result_invalid', 'audit_metadata_not_object', 'audit_metadata_forbidden_key', 'audit_source_event_at_invalid'];
        when 'restore_test' then
            v_required_keys := array['phase', 'sample_count', 'trigger', 'duration_ms'];
        when 'auth_failure' then
            v_required_keys := array['error_code'];
        when 'key_rotation_start' then
            v_required_keys := array['old_key_version', 'new_key_version'];
        when 'key_rotation_reencrypt' then
            v_required_keys := array['old_key_version', 'new_key_version', 'batch_size', 'processed_count', 'remaining_count'];
        when 'key_rotation_complete' then
            v_required_keys := array['old_key_version', 'new_key_version', 'remaining_count'];
        when 'signature_key_created' then
            v_required_keys := array['signature_key_version', 'public_key_fingerprint', 'created_at'];
        when 'signature_key_activated' then
            v_required_keys := array['signature_key_version', 'public_key_fingerprint', 'activated_at'];
        when 'signature_key_retired' then
            v_required_keys := array['signature_key_version', 'public_key_fingerprint', 'retired_at'];
        when 'monthly_digest_generate', 'monthly_digest_verify' then
            v_required_keys := array[]::text[];
        when 'archive_export', 'digest_timestamping' then
            v_required_keys := array['target_year_month'];
        when 'siem_forward_failure' then
            v_required_keys := array['error_code'];
        when 'audit_report_generate' then
            v_required_keys := array['format', 'period_end', 'period_start'];
        when 'scheduler_job' then
            v_required_keys := array['job_name', 'trigger', 'duration_ms'];
        when 'incident_detected' then
            v_required_keys := array['incident_type', 'severity', 'detection_source', 'dedupe_key', 'notification_sink', 'notification_result', 'error_code'];
        else
            return true;
    end case;

    if p_require_source_event_at then
        v_required_keys := v_required_keys || array['source_event_at'];
    end if;

    if not (p_metadata_json ?& v_required_keys) then
        return true;
    end if;

    if p_action = 'integrity_check' then
        if jsonb_typeof(p_metadata_json -> 'violation_summary') <> 'object' then
            return true;
        end if;

        if not ((p_metadata_json -> 'violation_summary') ?& v_summary_required_keys) then
            return true;
        end if;
    end if;

    return false;
end;
$$;

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
        when 'signature_key_created' then
            v_allowed_keys := array['created_at', 'public_key_fingerprint', 'signature_key_version', 'source_event_at'];
        when 'signature_key_activated' then
            v_allowed_keys := array['activated_at', 'public_key_fingerprint', 'signature_key_version', 'source_event_at'];
        when 'signature_key_retired' then
            v_allowed_keys := array['public_key_fingerprint', 'retired_at', 'signature_key_version', 'source_event_at'];
        when 'monthly_digest_generate', 'monthly_digest_verify' then
            v_allowed_keys := array['error_code', 'target_year_month', 'source_event_at'];
        when 'archive_export' then
            v_allowed_keys := array['archive_key', 'digest_hash', 'target_year_month', 'error_code', 'source_event_at'];
        when 'digest_timestamping' then
            v_allowed_keys := array['digest_hash', 'timestamp_token_hash', 'target_year_month', 'error_code', 'source_event_at'];
        when 'siem_forward_failure' then
            v_allowed_keys := array['error_code', 'event_type', 'event_count', 'source_event_at'];
        when 'audit_report_generate' then
            v_allowed_keys := array['error_code', 'format', 'period_end', 'period_start', 'source_event_at'];
        when 'scheduler_job' then
            v_allowed_keys := array['duration_ms', 'error_code', 'job_name', 'target_year_month', 'trigger', 'source_event_at'];
        when 'incident_detected' then
            v_allowed_keys := array['incident_type', 'severity', 'detection_source', 'dedupe_key', 'notification_sink', 'notification_result', 'error_code', 'source_event_at', 'source_event_id', 'target_sequence_no', 'target_year_month'];
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
    v_val jsonb;
    v_text text;
begin
    if jsonb_typeof(p_metadata_json) <> 'object' then
        return true;
    end if;

    for v_key, v_val in
        select fields.key, fields.value
        from jsonb_each(p_metadata_json) as fields(key, value)
    loop
        if v_key in ('version', 'old_key_version', 'new_key_version', 'batch_size', 'target_sequence_no', 'signature_key_version') then
            if jsonb_typeof(v_val) <> 'number' or (v_val #>> '{}') !~ '^[0-9]+$' or (v_val #>> '{}')::bigint <= 0 then
                return true;
            end if;
        elsif v_key in ('checked_secret_count', 'checked_secret_version_count', 'checked_audit_event_count', 'duration_ms', 'violation_count', 'sample_count', 'processed_count', 'remaining_count', 'event_count') then
            if jsonb_typeof(v_val) <> 'number' or (v_val #>> '{}') !~ '^[0-9]+$' then
                return true;
            end if;
        elsif v_key = 'error_code' then
            if p_result <> 'failure' or jsonb_typeof(v_val) <> 'string' or btrim(v_val #>> '{}') = '' or length(v_val #>> '{}') > 64 then
                return true;
            end if;
        elsif v_key in ('source_event_at', 'created_at', 'activated_at', 'retired_at', 'period_start', 'period_end') then
            if jsonb_typeof(v_val) <> 'string' or not public.audit_metadata_source_event_at_is_valid(jsonb_build_object('source_event_at', v_val #>> '{}')) then
                return true;
            end if;
        elsif v_key = 'public_key_fingerprint' then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') !~ '^[0-9a-f]{64}$' then
                return true;
            end if;
        elsif v_key in ('secret_version_id', 'attempted_secret_id') then
            if v_key = 'attempted_secret_id'
                and not (p_action = 'decrypt' and p_result = 'failure') then
                return true;
            end if;
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') !~ '^[0-9a-fA-F-]{36}$' then
                return true;
            end if;
        elsif v_key = 'source_event_id' then
            if p_action <> 'incident_detected' or jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') !~ '^[0-9a-fA-F-]{36}$' then
                return true;
            end if;
        elsif v_key = 'trigger' then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') not in ('background', 'cli', 'scheduled', 'startup') then
                return true;
            end if;
        elsif v_key in ('job_name', 'event_type', 'detection_source', 'dedupe_key', 'notification_sink') then
            if jsonb_typeof(v_val) <> 'string' or btrim(v_val #>> '{}') = '' or length(v_val #>> '{}') > 128 then
                return true;
            end if;
        elsif v_key = 'target_year_month' then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') !~ '^\d{4}-(0[1-9]|1[0-2])$' then
                return true;
            end if;
        elsif v_key in ('digest_hash', 'timestamp_token_hash') then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') !~ '^[0-9a-f]{64}$' then
                return true;
            end if;
        elsif v_key = 'format' then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') not in ('json', 'markdown') then
                return true;
            end if;
        elsif v_key = 'check_name' then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') <> 'mvp_integrity_check' then
                return true;
            end if;
        elsif v_key = 'phase' then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') <> 'verify' then
                return true;
            end if;
        elsif v_key = 'reason' then
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') <> 'no_current_secret_versions' then
                return true;
            end if;
        elsif v_key = 'failed_version' then
            if p_result = 'success' then
                return true;
            end if;
            if v_val <> 'null'::jsonb and (jsonb_typeof(v_val) <> 'number' or (v_val #>> '{}') !~ '^[0-9]+$' or (v_val #>> '{}')::bigint <= 0) then
                return true;
            end if;
        elsif v_key = 'archive_key' then
            if p_result = 'failure' or jsonb_typeof(v_val) <> 'string' or btrim(v_val #>> '{}') = '' or length(v_val #>> '{}') > 256 then
                return true;
            end if;
        elsif v_key = 'incident_type' then
            if jsonb_typeof(v_val) <> 'string' or not public.incident_type_allowed(v_val #>> '{}') then
                return true;
            end if;
        elsif v_key = 'severity' then
            if jsonb_typeof(v_val) <> 'string' or not public.incident_severity_allowed(v_val #>> '{}') then
                return true;
            end if;
        elsif v_key = 'notification_result' then
            if jsonb_typeof(v_val) <> 'string' or not public.incident_notification_result_allowed(v_val #>> '{}') then
                return true;
            end if;
        elsif v_key = 'violation_summary' then
            if jsonb_typeof(v_val) <> 'object' then
                return true;
            end if;
        end if;
    end loop;

    return false;
exception
    when numeric_value_out_of_range then
        return true;
end;
$$;

create or replace function public.ledger_entry_type_allowed(p_entry_type text)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select p_entry_type in (
        'secret_created',
        'secret_version_created',
        'secret_decrypted',
        'secret_version_purged',
        'integrity_check_completed',
        'restore_test_completed',
        'key_rotation_started',
        'key_rotation_reencrypted',
        'key_rotation_completed',
        'key_rotation_aborted',
        'signature_key_created',
        'signature_key_activated',
        'signature_key_retired',
        'ledger_verified',
        'ledger_verification_failed',
        'audit_fallback_resent',
        'monthly_digest',
        'archive_exported',
        'digest_timestamped',
        'scheduler_job_completed',
        'incident_detected'
    );
$$;

create or replace function public.ledger_payload_allowed_keys(p_entry_type text)
returns text[]
language sql
stable
set search_path = public, pg_temp
as $$
    select case p_entry_type
        when 'secret_created' then array['algorithm', 'classification', 'key_version', 'version']::text[]
        when 'secret_version_created' then array['algorithm', 'classification', 'key_version', 'version']::text[]
        when 'secret_decrypted' then array['algorithm', 'key_version', 'version']::text[]
        when 'secret_version_purged' then array['key_version', 'retention_limit', 'version']::text[]
        when 'integrity_check_completed' then array['checked_audit_event_count', 'checked_secret_count', 'checked_secret_version_count', 'duration_ms', 'violation_count']::text[]
        when 'restore_test_completed' then array['duration_ms', 'failure_count', 'sample_count', 'success_count', 'trigger']::text[]
        when 'key_rotation_started' then array['new_key_version', 'old_key_version']::text[]
        when 'key_rotation_reencrypted' then array['batch_size', 'new_key_version', 'old_key_version', 'processed_count', 'remaining_count']::text[]
        when 'key_rotation_completed' then array['new_key_version', 'old_key_version', 'remaining_count']::text[]
        when 'key_rotation_aborted' then array['new_key_version', 'old_key_version', 'reason_code']::text[]
        when 'signature_key_created' then array['created_at', 'public_key_fingerprint', 'signature_key_version']::text[]
        when 'signature_key_activated' then array['activated_at', 'public_key_fingerprint', 'signature_key_version']::text[]
        when 'signature_key_retired' then array['public_key_fingerprint', 'retired_at', 'signature_key_version']::text[]
        when 'ledger_verified' then array['checked_count', 'duration_ms', 'end_sequence_no', 'start_sequence_no']::text[]
        when 'ledger_verification_failed' then array['end_sequence_no', 'error_code', 'failed_count', 'start_sequence_no']::text[]
        when 'audit_fallback_resent' then array['duration_ms', 'failed_count', 'resent_count']::text[]
        when 'monthly_digest' then array['digest_hash', 'end_sequence_no', 'entry_count', 'start_sequence_no', 'target_year_month']::text[]
        when 'archive_exported' then array['archive_key', 'digest_hash', 'target_year_month']::text[]
        when 'digest_timestamped' then array['digest_hash', 'target_year_month', 'timestamp_token_hash']::text[]
        when 'scheduler_job_completed' then array['duration_ms', 'job_name', 'target_year_month', 'trigger']::text[]
        when 'incident_detected' then array['dedupe_key', 'detection_source', 'incident_type', 'notification_result', 'notification_sink', 'severity', 'target_sequence_no', 'target_year_month']::text[]
        else null::text[]
    end;
$$;

create or replace function public.ledger_payload_schema_is_valid(
    p_entry_type text,
    p_payload jsonb
)
returns boolean
language plpgsql
stable
set search_path = public, pg_temp
as $$
declare
    v_key text;
    v_value jsonb;
    v_text text;
    v_integer bigint;
    v_old_key_version bigint;
    v_new_key_version bigint;
begin
    if p_payload is null or jsonb_typeof(p_payload) <> 'object' then
        return false;
    end if;

    if not public.ledger_entry_type_allowed(p_entry_type) then
        return false;
    end if;

    if public.ledger_payload_has_unknown_key(p_entry_type, p_payload) then
        return false;
    end if;

    if exists (
        select 1
        from jsonb_each(p_payload) as fields(key, value)
        where jsonb_typeof(fields.value) in ('object', 'array')
    ) then
        return false;
    end if;

    if p_entry_type = 'incident_detected'
        and not (
            p_payload ?& array['incident_type', 'severity', 'detection_source', 'dedupe_key', 'notification_sink', 'notification_result']
        )
    then
        return false;
    end if;

    for v_key, v_value in
        select fields.key, fields.value
        from jsonb_each(p_payload) as fields(key, value)
    loop
        if v_key in ('version', 'key_version', 'old_key_version', 'new_key_version', 'retention_limit', 'start_sequence_no', 'end_sequence_no', 'entry_count', 'target_sequence_no', 'signature_key_version') then
            if jsonb_typeof(v_value) <> 'number' or (v_value #>> '{}') !~ '^[0-9]+$' then
                return false;
            end if;
            v_integer := (v_value #>> '{}')::bigint;
            if v_integer <= 0 then
                return false;
            end if;
            if v_key = 'retention_limit' and v_integer <> 4 then
                return false;
            end if;
        elsif v_key in ('batch_size', 'checked_audit_event_count', 'checked_count', 'checked_secret_count', 'checked_secret_version_count', 'duration_ms', 'entry_count', 'failed_count', 'failure_count', 'processed_count', 'remaining_count', 'resent_count', 'sample_count', 'success_count', 'violation_count') then
            if jsonb_typeof(v_value) <> 'number' or (v_value #>> '{}') !~ '^[0-9]+$' then
                return false;
            end if;
        elsif v_key = 'algorithm' then
            if jsonb_typeof(v_value) <> 'string' or v_value #>> '{}' <> 'xchacha20-poly1305' then
                return false;
            end if;
        elsif v_key = 'classification' then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;
            v_text := v_value #>> '{}';
            if btrim(v_text) = '' or length(v_text) > 128 then
                return false;
            end if;
        elsif v_key = 'trigger' then
            if jsonb_typeof(v_value) <> 'string' or (v_value #>> '{}') not in ('background', 'cli', 'scheduled', 'startup') then
                return false;
            end if;
        elsif v_key in ('error_code', 'reason_code', 'archive_key', 'job_name', 'detection_source', 'dedupe_key', 'notification_sink') then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;
            v_text := v_value #>> '{}';
            if btrim(v_text) = '' or length(v_text) > 128 then
                return false;
            end if;
        elsif v_key = 'incident_type' then
            if jsonb_typeof(v_value) <> 'string' or not public.incident_type_allowed(v_value #>> '{}') then
                return false;
            end if;
        elsif v_key = 'severity' then
            if jsonb_typeof(v_value) <> 'string' or not public.incident_severity_allowed(v_value #>> '{}') then
                return false;
            end if;
        elsif v_key = 'notification_result' then
            if jsonb_typeof(v_value) <> 'string' or not public.incident_notification_result_allowed(v_value #>> '{}') then
                return false;
            end if;
        elsif v_key in ('digest_hash', 'timestamp_token_hash', 'public_key_fingerprint') then
            if jsonb_typeof(v_value) <> 'string' or (v_value #>> '{}') !~ '^[0-9a-f]{64}$' then
                return false;
            end if;
        elsif v_key = 'target_year_month' then
            if jsonb_typeof(v_value) <> 'string' or (v_value #>> '{}') !~ '^\d{4}-(0[1-9]|1[0-2])$' then
                return false;
            end if;
        elsif v_key in ('created_at', 'activated_at', 'retired_at') then
            if jsonb_typeof(v_value) <> 'string'
                or not public.audit_metadata_source_event_at_is_valid(jsonb_build_object('source_event_at', v_value #>> '{}')) then
                return false;
            end if;
        else
            return false;
        end if;
    end loop;

    if p_payload ? 'old_key_version' and p_payload ? 'new_key_version' then
        v_old_key_version := (p_payload ->> 'old_key_version')::bigint;
        v_new_key_version := (p_payload ->> 'new_key_version')::bigint;
        if v_old_key_version = v_new_key_version then
            return false;
        end if;
    end if;

    return true;
exception
    when numeric_value_out_of_range then
        return false;
end;
$$;

create or replace function public.rpc_get_ledger_signing_public_key_status(
    p_key_version integer
)
returns table (
    key_version integer,
    public_key bytea,
    public_key_fingerprint text,
    algorithm text,
    status text,
    created_at timestamptz,
    activated_at timestamptz,
    retired_at timestamptz
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if p_key_version is null or p_key_version <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return query
    select
        pk.key_version,
        pk.public_key,
        public.ledger_signing_public_key_fingerprint(pk.public_key),
        pk.algorithm,
        pk.status,
        pk.created_at,
        pk.activated_at,
        pk.retired_at
    from public.ledger_signing_public_keys pk
    where pk.key_version = p_key_version;

    if not found then
        raise exception 'ledger_signing_public_key_not_found'
            using errcode = '02000';
    end if;
end;
$$;

-- Legacy unledgered registration remains available only to object owners for
-- test/backfill compatibility. Runtime service_role execute is revoked below.
create or replace function public.rpc_register_ledger_signing_public_key(
    p_key_version integer,
    p_public_key bytea
)
returns table (
    out_key_version integer,
    public_key bytea,
    algorithm text,
    status text,
    created_at timestamptz,
    retired_at timestamptz,
    replayed boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_existing public.ledger_signing_public_keys%rowtype;
begin
    if p_key_version is null or p_key_version <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_public_key is null or octet_length(p_public_key) <> 32 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    select *
    into v_existing
    from public.ledger_signing_public_keys
    where ledger_signing_public_keys.key_version = rpc_register_ledger_signing_public_key.p_key_version;

    if found then
        if v_existing.status = 'retired' then
            raise exception 'ledger_signing_public_key_retired'
                using errcode = '23514';
        end if;

        if v_existing.public_key = p_public_key
            and v_existing.status in ('created', 'active')
        then
            out_key_version := v_existing.key_version;
            public_key := v_existing.public_key;
            algorithm := v_existing.algorithm;
            status := v_existing.status;
            created_at := v_existing.created_at;
            retired_at := v_existing.retired_at;
            replayed := true;
            return next;
            return;
        end if;

        raise exception 'ledger_signing_public_key_conflict'
            using errcode = '23505';
    end if;

    insert into public.ledger_signing_public_keys (
        key_version,
        public_key,
        algorithm,
        status,
        created_at,
        activated_at
    )
    values (
        p_key_version,
        p_public_key,
        'ed25519',
        'active',
        now(),
        now()
    )
    returning *
    into v_existing;

    out_key_version := v_existing.key_version;
    public_key := v_existing.public_key;
    algorithm := v_existing.algorithm;
    status := v_existing.status;
    created_at := v_existing.created_at;
    retired_at := v_existing.retired_at;
    replayed := false;
    return next;
end;
$$;

create or replace function public.signature_key_lifecycle_input_is_valid(
    p_expected_action text,
    p_expected_entry_type text,
    p_expected_timestamp_key text,
    p_key_version integer,
    p_public_key_fingerprint text,
    p_action text,
    p_result text,
    p_key_version_audit integer,
    p_metadata_json jsonb,
    p_entry_type text,
    p_source_event_at text,
    p_source_event_id uuid,
    p_audit_event_id uuid,
    p_payload jsonb
)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select p_action = p_expected_action
        and p_entry_type = p_expected_entry_type
        and p_result = 'success'
        and p_key_version_audit is null
        and p_source_event_id = p_audit_event_id
        and public.audit_metadata_source_event_at_is_valid(jsonb_build_object('source_event_at', p_source_event_at))
        and p_metadata_json ->> 'source_event_at' = p_source_event_at
        and (p_metadata_json ->> 'signature_key_version')::integer = p_key_version
        and p_metadata_json ->> 'public_key_fingerprint' = p_public_key_fingerprint
        and p_metadata_json ->> p_expected_timestamp_key = p_source_event_at
        and public.ledger_payload_schema_is_valid(p_entry_type, p_payload)
        and (p_payload ->> 'signature_key_version')::integer = p_key_version
        and p_payload ->> 'public_key_fingerprint' = p_public_key_fingerprint
        and p_payload ->> p_expected_timestamp_key = p_source_event_at;
$$;

create or replace function public.rpc_create_ledger_signing_public_key_with_ledger(
    p_key_version integer,
    p_public_key bytea,
    p_audit_event_id uuid,
    p_request_id uuid,
    p_actor_user_id uuid default null,
    p_actor_device_id text default null,
    p_action text default null,
    p_target_secret_id uuid default null,
    p_result text default null,
    p_key_version_audit integer default null,
    p_metadata_json jsonb default '{}'::jsonb,
    p_ledger_entry_id uuid default null,
    p_sequence_no bigint default null,
    p_entry_type text default null,
    p_source_event_at text default null,
    p_source_event_id uuid default null,
    p_target_secret_version_id uuid default null,
    p_error_code text default null,
    p_payload jsonb default '{}'::jsonb,
    p_canonicalization_version integer default null,
    p_previous_entry_hash bytea default null,
    p_entry_hash bytea default null,
    p_hash_algorithm text default null,
    p_signature bytea default null,
    p_signature_algorithm text default null,
    p_signature_key_version integer default null
)
returns table (
    ledger_entry_id uuid,
    sequence_no bigint,
    entry_hash bytea,
    chain_last_sequence_no bigint,
    chain_last_entry_hash bytea,
    replayed boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_existing public.ledger_signing_public_keys%rowtype;
    v_fingerprint text;
begin
    if p_key_version is null or p_key_version <= 0
        or p_public_key is null or octet_length(p_public_key) <> 32
        or p_actor_user_id is not null
        or p_actor_device_id is not null
        or p_target_secret_id is not null
        or p_target_secret_version_id is not null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    v_fingerprint := public.ledger_signing_public_key_fingerprint(p_public_key);

    if not public.signature_key_lifecycle_input_is_valid(
        'signature_key_created',
        'signature_key_created',
        'created_at',
        p_key_version,
        v_fingerprint,
        p_action,
        p_result,
        p_key_version_audit,
        p_metadata_json,
        p_entry_type,
        p_source_event_at,
        p_source_event_id,
        p_audit_event_id,
        p_payload
    ) then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    select *
    into v_existing
    from public.ledger_signing_public_keys pk
    where pk.key_version = p_key_version
    for update;

    if found then
        if v_existing.public_key <> p_public_key or v_existing.status <> 'created' then
            raise exception 'ledger_signing_public_key_lifecycle_invalid_transition on ledger_signing_public_keys'
                using errcode = '42501';
        end if;
    else
        insert into public.ledger_signing_public_keys (
            key_version,
            public_key,
            algorithm,
            status,
            created_at
        )
        values (
            p_key_version,
            p_public_key,
            'ed25519',
            'created',
            p_source_event_at::timestamptz
        );
    end if;

    perform public.rpc_append_audit_event(
        p_audit_event_id,
        p_request_id,
        p_actor_user_id,
        p_actor_device_id,
        p_action,
        p_target_secret_id,
        p_result,
        p_key_version_audit,
        p_metadata_json
    );

    return query
    select *
    from public.rpc_append_ledger_entry(
        p_ledger_entry_id,
        p_sequence_no,
        p_entry_type,
        p_source_event_at,
        p_request_id,
        p_source_event_id,
        p_target_secret_id,
        p_target_secret_version_id,
        p_actor_user_id,
        p_actor_device_id,
        p_result,
        p_error_code,
        p_payload,
        p_canonicalization_version,
        p_previous_entry_hash,
        p_entry_hash,
        p_hash_algorithm,
        p_signature,
        p_signature_algorithm,
        p_signature_key_version
    );
end;
$$;

create or replace function public.rpc_activate_ledger_signing_public_key_with_ledger(
    p_key_version integer default null,
    p_audit_event_id uuid default null,
    p_request_id uuid default null,
    p_actor_user_id uuid default null,
    p_actor_device_id text default null,
    p_action text default null,
    p_target_secret_id uuid default null,
    p_result text default null,
    p_key_version_audit integer default null,
    p_metadata_json jsonb default '{}'::jsonb,
    p_ledger_entry_id uuid default null,
    p_sequence_no bigint default null,
    p_entry_type text default null,
    p_source_event_at text default null,
    p_source_event_id uuid default null,
    p_target_secret_version_id uuid default null,
    p_error_code text default null,
    p_payload jsonb default '{}'::jsonb,
    p_canonicalization_version integer default null,
    p_previous_entry_hash bytea default null,
    p_entry_hash bytea default null,
    p_hash_algorithm text default null,
    p_signature bytea default null,
    p_signature_algorithm text default null,
    p_signature_key_version integer default null
)
returns table (
    ledger_entry_id uuid,
    sequence_no bigint,
    entry_hash bytea,
    chain_last_sequence_no bigint,
    chain_last_entry_hash bytea,
    replayed boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_key_version integer;
    v_row public.ledger_signing_public_keys%rowtype;
    v_fingerprint text;
begin
    v_key_version := coalesce(p_key_version, (p_metadata_json ->> 'signature_key_version')::integer);
    if v_key_version is null or v_key_version <= 0
        or p_actor_user_id is not null
        or p_actor_device_id is not null
        or p_target_secret_id is not null
        or p_target_secret_version_id is not null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    select *
    into v_row
    from public.ledger_signing_public_keys pk
    where pk.key_version = v_key_version
    for update;

    if not found then
        raise exception 'ledger_signing_public_key_not_found' using errcode = '02000';
    end if;
    if v_row.status <> 'created' then
        raise exception 'ledger_signing_public_key_lifecycle_invalid_transition on ledger_signing_public_keys'
            using errcode = '42501';
    end if;

    v_fingerprint := public.ledger_signing_public_key_fingerprint(v_row.public_key);
    if not public.signature_key_lifecycle_input_is_valid(
        'signature_key_activated',
        'signature_key_activated',
        'activated_at',
        v_key_version,
        v_fingerprint,
        p_action,
        p_result,
        p_key_version_audit,
        p_metadata_json,
        p_entry_type,
        p_source_event_at,
        p_source_event_id,
        p_audit_event_id,
        p_payload
    ) then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    update public.ledger_signing_public_keys
    set status = 'active',
        activated_at = p_source_event_at::timestamptz
    where key_version = v_key_version;

    perform public.rpc_append_audit_event(
        p_audit_event_id,
        p_request_id,
        p_actor_user_id,
        p_actor_device_id,
        p_action,
        p_target_secret_id,
        p_result,
        p_key_version_audit,
        p_metadata_json
    );

    return query
    select *
    from public.rpc_append_ledger_entry(
        p_ledger_entry_id,
        p_sequence_no,
        p_entry_type,
        p_source_event_at,
        p_request_id,
        p_source_event_id,
        p_target_secret_id,
        p_target_secret_version_id,
        p_actor_user_id,
        p_actor_device_id,
        p_result,
        p_error_code,
        p_payload,
        p_canonicalization_version,
        p_previous_entry_hash,
        p_entry_hash,
        p_hash_algorithm,
        p_signature,
        p_signature_algorithm,
        p_signature_key_version
    );
end;
$$;

create or replace function public.rpc_retire_ledger_signing_public_key_with_ledger(
    p_key_version integer default null,
    p_audit_event_id uuid default null,
    p_request_id uuid default null,
    p_actor_user_id uuid default null,
    p_actor_device_id text default null,
    p_action text default null,
    p_target_secret_id uuid default null,
    p_result text default null,
    p_key_version_audit integer default null,
    p_metadata_json jsonb default '{}'::jsonb,
    p_ledger_entry_id uuid default null,
    p_sequence_no bigint default null,
    p_entry_type text default null,
    p_source_event_at text default null,
    p_source_event_id uuid default null,
    p_target_secret_version_id uuid default null,
    p_error_code text default null,
    p_payload jsonb default '{}'::jsonb,
    p_canonicalization_version integer default null,
    p_previous_entry_hash bytea default null,
    p_entry_hash bytea default null,
    p_hash_algorithm text default null,
    p_signature bytea default null,
    p_signature_algorithm text default null,
    p_signature_key_version integer default null
)
returns table (
    ledger_entry_id uuid,
    sequence_no bigint,
    entry_hash bytea,
    chain_last_sequence_no bigint,
    chain_last_entry_hash bytea,
    replayed boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_key_version integer;
    v_row public.ledger_signing_public_keys%rowtype;
    v_fingerprint text;
begin
    v_key_version := coalesce(p_key_version, (p_metadata_json ->> 'signature_key_version')::integer);
    if v_key_version is null or v_key_version <= 0
        or p_actor_user_id is not null
        or p_actor_device_id is not null
        or p_target_secret_id is not null
        or p_target_secret_version_id is not null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    select *
    into v_row
    from public.ledger_signing_public_keys pk
    where pk.key_version = v_key_version
    for update;

    if not found then
        raise exception 'ledger_signing_public_key_not_found' using errcode = '02000';
    end if;
    if v_row.status <> 'active' then
        raise exception 'ledger_signing_public_key_lifecycle_invalid_transition on ledger_signing_public_keys'
            using errcode = '42501';
    end if;

    v_fingerprint := public.ledger_signing_public_key_fingerprint(v_row.public_key);
    if not public.signature_key_lifecycle_input_is_valid(
        'signature_key_retired',
        'signature_key_retired',
        'retired_at',
        v_key_version,
        v_fingerprint,
        p_action,
        p_result,
        p_key_version_audit,
        p_metadata_json,
        p_entry_type,
        p_source_event_at,
        p_source_event_id,
        p_audit_event_id,
        p_payload
    ) then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    update public.ledger_signing_public_keys
    set status = 'retired',
        retired_at = p_source_event_at::timestamptz
    where key_version = v_key_version;

    perform public.rpc_append_audit_event(
        p_audit_event_id,
        p_request_id,
        p_actor_user_id,
        p_actor_device_id,
        p_action,
        p_target_secret_id,
        p_result,
        p_key_version_audit,
        p_metadata_json
    );

    return query
    select *
    from public.rpc_append_ledger_entry(
        p_ledger_entry_id,
        p_sequence_no,
        p_entry_type,
        p_source_event_at,
        p_request_id,
        p_source_event_id,
        p_target_secret_id,
        p_target_secret_version_id,
        p_actor_user_id,
        p_actor_device_id,
        p_result,
        p_error_code,
        p_payload,
        p_canonicalization_version,
        p_previous_entry_hash,
        p_entry_hash,
        p_hash_algorithm,
        p_signature,
        p_signature_algorithm,
        p_signature_key_version
    );
end;
$$;

create or replace function public.rpc_append_audit_event_with_ledger(
    p_audit_event_id uuid,
    p_request_id uuid,
    p_actor_user_id uuid default null,
    p_actor_device_id text default null,
    p_action text default null,
    p_target_secret_id uuid default null,
    p_result text default null,
    p_key_version integer default null,
    p_metadata_json jsonb default '{}'::jsonb,
    p_ledger_entry_id uuid default null,
    p_sequence_no bigint default null,
    p_entry_type text default null,
    p_source_event_at text default null,
    p_source_event_id uuid default null,
    p_target_secret_version_id uuid default null,
    p_error_code text default null,
    p_payload jsonb default '{}'::jsonb,
    p_canonicalization_version integer default null,
    p_previous_entry_hash bytea default null,
    p_entry_hash bytea default null,
    p_hash_algorithm text default null,
    p_signature bytea default null,
    p_signature_algorithm text default null,
    p_signature_key_version integer default null
)
returns table (
    ledger_entry_id uuid,
    sequence_no bigint,
    entry_hash bytea,
    chain_last_sequence_no bigint,
    chain_last_entry_hash bytea,
    replayed boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if p_audit_event_id is null
        or p_request_id is null
        or p_action is null
        or p_result is null
        or p_source_event_id is distinct from p_audit_event_id
        or p_source_event_at is null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_source_event_at is distinct from p_metadata_json ->> 'source_event_at' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if (p_action = 'decrypt' and p_entry_type <> 'secret_decrypted')
        or (p_action = 'restore_test' and p_entry_type <> 'restore_test_completed')
        or (p_action = 'integrity_check' and p_entry_type <> 'integrity_check_completed')
        or (p_action = 'key_rotation_start' and p_entry_type <> 'key_rotation_started')
        or (p_action = 'key_rotation_reencrypt' and p_entry_type <> 'key_rotation_reencrypted')
        or (p_action = 'key_rotation_complete' and p_entry_type <> 'key_rotation_completed')
        or (p_action = 'signature_key_created' and p_entry_type <> 'signature_key_created')
        or (p_action = 'signature_key_activated' and p_entry_type <> 'signature_key_activated')
        or (p_action = 'signature_key_retired' and p_entry_type <> 'signature_key_retired')
        or (p_action = 'scheduler_job' and p_entry_type <> 'scheduler_job_completed')
        or (p_action = 'incident_detected' and p_entry_type <> 'incident_detected')
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    perform public.rpc_append_audit_event(
        p_audit_event_id,
        p_request_id,
        p_actor_user_id,
        p_actor_device_id,
        p_action,
        p_target_secret_id,
        p_result,
        p_key_version,
        p_metadata_json
    );

    return query
    select *
    from public.rpc_append_ledger_entry(
        p_ledger_entry_id,
        p_sequence_no,
        p_entry_type,
        p_source_event_at,
        p_request_id,
        p_source_event_id,
        p_target_secret_id,
        p_target_secret_version_id,
        p_actor_user_id,
        p_actor_device_id,
        p_result,
        p_error_code,
        p_payload,
        p_canonicalization_version,
        p_previous_entry_hash,
        p_entry_hash,
        p_hash_algorithm,
        p_signature,
        p_signature_algorithm,
        p_signature_key_version
    );
end;
$$;

drop function public.rpc_export_ledger_verification_materials(bigint, bigint);

create function public.rpc_export_ledger_verification_materials(
    p_start_sequence_no bigint default null,
    p_end_sequence_no bigint default null
)
returns table (
    ledger_entry_id uuid,
    sequence_no bigint,
    entry_hash bytea,
    previous_entry_hash bytea,
    signature bytea,
    signature_key_version integer,
    entry_type text,
    source_event_at text,
    request_id uuid,
    source_event_id uuid,
    target_secret_id uuid,
    target_secret_version_id uuid,
    actor_user_id uuid,
    actor_device_id text,
    result text,
    error_code text,
    payload jsonb,
    canonicalization_version integer,
    hash_algorithm text,
    signature_algorithm text,
    pk_key_version integer,
    pk_public_key bytea,
    pk_algorithm text,
    pk_status text,
    pk_created_at timestamptz,
    pk_activated_at timestamptz,
    pk_retired_at timestamptz
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    if p_start_sequence_no is not null and p_start_sequence_no <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_end_sequence_no is not null and p_end_sequence_no <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_start_sequence_no is not null and p_end_sequence_no is not null
        and p_start_sequence_no > p_end_sequence_no then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return query
    select
        le.id as ledger_entry_id,
        le.sequence_no,
        le.entry_hash,
        le.previous_entry_hash,
        le.signature,
        le.signature_key_version,
        le.entry_type,
        le.source_event_at,
        le.request_id,
        le.source_event_id,
        le.target_secret_id,
        le.target_secret_version_id,
        le.actor_user_id,
        le.actor_device_id,
        le.result,
        le.error_code,
        le.payload,
        le.canonicalization_version,
        le.hash_algorithm,
        le.signature_algorithm,
        pk.key_version as pk_key_version,
        pk.public_key as pk_public_key,
        pk.algorithm as pk_algorithm,
        pk.status as pk_status,
        pk.created_at as pk_created_at,
        pk.activated_at as pk_activated_at,
        pk.retired_at as pk_retired_at
    from public.ledger_entries le
    left join public.ledger_signing_public_keys pk
        on le.signature_key_version = pk.key_version
    where (
        p_start_sequence_no is null
        or le.sequence_no >= p_start_sequence_no
    )
    and (
        p_end_sequence_no is null
        or le.sequence_no <= p_end_sequence_no
    )
    order by le.sequence_no;
end;
$$;

grant execute on function public.rpc_get_ledger_signing_public_key_status(integer)
    to service_role;
grant execute on function public.rpc_export_ledger_verification_materials(bigint, bigint)
    to service_role;
grant execute on function public.rpc_export_ledger_verification_materials(bigint, bigint)
    to mipsorcu_auditor;
grant execute on function public.rpc_create_ledger_signing_public_key_with_ledger(
    integer, bytea, uuid, uuid, uuid, text, text, uuid, text, integer, jsonb,
    uuid, bigint, text, text, uuid, uuid, text, jsonb, integer, bytea, bytea, text, bytea, text, integer
) to service_role;
grant execute on function public.rpc_activate_ledger_signing_public_key_with_ledger(
    integer, uuid, uuid, uuid, text, text, uuid, text, integer, jsonb,
    uuid, bigint, text, text, uuid, uuid, text, jsonb, integer, bytea, bytea, text, bytea, text, integer
) to service_role;
grant execute on function public.rpc_retire_ledger_signing_public_key_with_ledger(
    integer, uuid, uuid, uuid, text, text, uuid, text, integer, jsonb,
    uuid, bigint, text, text, uuid, uuid, text, jsonb, integer, bytea, bytea, text, bytea, text, integer
) to service_role;

revoke execute on function public.rpc_register_ledger_signing_public_key(integer, bytea)
    from service_role, anon, authenticated, public;
revoke execute on function public.rpc_retire_ledger_signing_public_key(integer)
    from service_role, anon, authenticated, public;
revoke execute on function public.rpc_get_ledger_signing_public_key_status(integer)
    from anon, authenticated, public;
revoke execute on function public.rpc_export_ledger_verification_materials(bigint, bigint)
    from anon, authenticated, public;
revoke execute on function public.rpc_create_ledger_signing_public_key_with_ledger(
    integer, bytea, uuid, uuid, uuid, text, text, uuid, text, integer, jsonb,
    uuid, bigint, text, text, uuid, uuid, text, jsonb, integer, bytea, bytea, text, bytea, text, integer
) from anon, authenticated, public;
revoke execute on function public.rpc_activate_ledger_signing_public_key_with_ledger(
    integer, uuid, uuid, uuid, text, text, uuid, text, integer, jsonb,
    uuid, bigint, text, text, uuid, uuid, text, jsonb, integer, bytea, bytea, text, bytea, text, integer
) from anon, authenticated, public;
revoke execute on function public.rpc_retire_ledger_signing_public_key_with_ledger(
    integer, uuid, uuid, uuid, text, text, uuid, text, integer, jsonb,
    uuid, bigint, text, text, uuid, uuid, text, jsonb, integer, bytea, bytea, text, bytea, text, integer
) from anon, authenticated, public;

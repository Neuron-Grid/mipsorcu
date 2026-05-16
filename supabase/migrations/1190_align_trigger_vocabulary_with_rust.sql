-- SQL trigger 語彙整合 / Rust 側 AuditTrigger 列挙子と一致させる
-- Rust 側は startup / background / cli のみを生成。SQL 側から scheduled を削除。

-- audit_metadata_has_invalid_value_for_action (1000版) ── trigger enum から scheduled を除去
-- audit_metadata_has_schema_violation_for_action は本関数をラップしているため、同時に修正される。

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
            if jsonb_typeof(v_val) <> 'string' or (v_val #>> '{}') not in ('background', 'cli', 'startup') then
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

-- 修正対象 4/4: ledger_payload_schema_is_valid (1000版) ── trigger enum から scheduled を除去

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
            if jsonb_typeof(v_value) <> 'string' or (v_value #>> '{}') not in ('background', 'cli', 'startup') then
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

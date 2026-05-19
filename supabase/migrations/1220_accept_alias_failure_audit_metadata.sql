-- Section 1220: allow generic failure audit metadata for encrypted secret aliases

-- Keep the forbidden-key marker in the latest audit metadata migration so
-- Rust/SQL parity tests can use this file as the single current SQL source.
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
        when 'secret_alias_create' then
            if p_result = 'success' then
                v_required_keys := array['alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version'];
            else
                v_required_keys := array[]::text[];
            end if;
        when 'secret_alias_update' then
            if p_result = 'success' then
                v_required_keys := array['old_alias_fingerprint', 'new_alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version'];
            else
                v_required_keys := array[]::text[];
            end if;
        when 'secret_alias_delete' then
            if p_result = 'success' then
                v_required_keys := array['alias_fingerprint', 'alias_fingerprint_key_version', 'alias_fingerprint_schema_version'];
            else
                v_required_keys := array[]::text[];
            end if;
        when 'secret_alias_list' then
            if p_result = 'success' then
                v_required_keys := array['result_count'];
            else
                v_required_keys := array[]::text[];
            end if;
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

comment on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean)
is 'Returns true when audit metadata is missing a required key for the given action/result. Alias failure audit requires only source_event_at so generic failure audit can fail closed.';

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
is 'Returns true when audit metadata contains a key outside the allowlist for the given action. Latest allowlist source for Rust/SQL parity tests.';

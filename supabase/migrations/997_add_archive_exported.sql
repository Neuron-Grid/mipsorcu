-- Ledger Phase 2: 外部アーカイブ export サポート（§6）。
--
-- 変更内容:
-- 1. ledger_entry_type_allowed: 'archive_exported' を追加
-- 2. ledger_payload_allowed_keys: 'archive_exported' payload keys を追加
-- 3. ledger_payload_schema_is_valid: 'archive_key' フィールド検証を追加
-- 4. rpc_append_audit_event: 'archive_export' action を allowlist に追加
-- 5. audit_metadata_has_unknown_key_for_action: 'archive_export' case を追加
--
-- 信頼境界: 非秘密メタデータのみを扱う。平文・鍵・JWT を含まない。
-- `ArchiveExportPackage` は `SignedMonthlyDigest` からのみ構築可能（Rust 型安全保証）。

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. ledger_entry_type_allowed: 'archive_exported' を追加
-- ─────────────────────────────────────────────────────────────────────────────

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
        'ledger_verified',
        'ledger_verification_failed',
        'audit_fallback_resent',
        'monthly_digest',
        -- Ledger Phase 2 §6: 外部アーカイブ export 完了
        'archive_exported'
    );
$$;

comment on function public.ledger_entry_type_allowed(text)
is 'Returns true for all allowed ledger entry_type values. Updated in T08 to include archive_exported.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. ledger_payload_allowed_keys: 'archive_exported' payload keys を追加
-- ─────────────────────────────────────────────────────────────────────────────

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
        when 'integrity_check_completed' then array[
            'checked_audit_event_count',
            'checked_secret_count',
            'checked_secret_version_count',
            'duration_ms',
            'violation_count'
        ]::text[]
        when 'restore_test_completed' then array[
            'duration_ms',
            'failure_count',
            'sample_count',
            'success_count',
            'trigger'
        ]::text[]
        when 'key_rotation_started' then array['new_key_version', 'old_key_version']::text[]
        when 'key_rotation_reencrypted' then array[
            'batch_size',
            'new_key_version',
            'old_key_version',
            'processed_count',
            'remaining_count'
        ]::text[]
        when 'key_rotation_completed' then array[
            'new_key_version',
            'old_key_version',
            'remaining_count'
        ]::text[]
        when 'key_rotation_aborted' then array[
            'new_key_version',
            'old_key_version',
            'reason_code'
        ]::text[]
        when 'ledger_verified' then array[
            'checked_count',
            'duration_ms',
            'end_sequence_no',
            'start_sequence_no'
        ]::text[]
        when 'ledger_verification_failed' then array[
            'end_sequence_no',
            'error_code',
            'failed_count',
            'start_sequence_no'
        ]::text[]
        when 'audit_fallback_resent' then array[
            'duration_ms',
            'failed_count',
            'resent_count'
        ]::text[]
        when 'monthly_digest' then array[
            'digest_hash',
            'end_sequence_no',
            'entry_count',
            'start_sequence_no',
            'target_year_month'
        ]::text[]
        -- Ledger Phase 2 §6: archive_exported payload keys（アルファベット順）
        when 'archive_exported' then array[
            'archive_key',
            'digest_hash',
            'target_year_month'
        ]::text[]
        else null::text[]
    end;
$$;

comment on function public.ledger_payload_allowed_keys(text)
is 'Returns top-level ledger payload keys allowed for a given entry_type. Updated in T08 to include archive_exported.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. ledger_payload_schema_is_valid: 'archive_key' フィールド検証を追加
--    Phase 2 T07 の関数を or replace で更新。
--    追加: archive_key（非空・128 文字以内の文字列）
-- ─────────────────────────────────────────────────────────────────────────────

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

    for v_key, v_value in
        select fields.key, fields.value
        from jsonb_each(p_payload) as fields(key, value)
    loop
        if v_key in (
            'version',
            'key_version',
            'old_key_version',
            'new_key_version',
            'retention_limit',
            'start_sequence_no',
            'end_sequence_no'
        ) then
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
        elsif v_key in (
            'batch_size',
            'checked_audit_event_count',
            'checked_count',
            'checked_secret_count',
            'checked_secret_version_count',
            'duration_ms',
            'entry_count',
            'failed_count',
            'failure_count',
            'processed_count',
            'remaining_count',
            'resent_count',
            'sample_count',
            'success_count',
            'violation_count'
        ) then
            if jsonb_typeof(v_value) <> 'number' or (v_value #>> '{}') !~ '^[0-9]+$' then
                return false;
            end if;

            v_integer := (v_value #>> '{}')::bigint;

            if v_integer < 0 then
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
            if jsonb_typeof(v_value) <> 'string' or (v_value #>> '{}') not in (
                'background',
                'cli',
                'scheduled',
                'startup'
            ) then
                return false;
            end if;
        elsif v_key in ('error_code', 'reason_code') then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;

            v_text := v_value #>> '{}';

            if btrim(v_text) = '' or length(v_text) > 128 then
                return false;
            end if;
        -- Ledger Phase 2 T07: monthly_digest フィールド
        elsif v_key = 'digest_hash' then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;

            v_text := v_value #>> '{}';

            if v_text !~ '^[0-9a-f]{64}$' then
                return false;
            end if;
        elsif v_key = 'target_year_month' then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;

            v_text := v_value #>> '{}';

            if v_text !~ '^\d{4}-(0[1-9]|1[0-2])$' then
                return false;
            end if;
        -- Ledger Phase 2 T08: archive_exported フィールド
        elsif v_key = 'archive_key' then
            if jsonb_typeof(v_value) <> 'string' then
                return false;
            end if;

            v_text := v_value #>> '{}';

            if btrim(v_text) = '' or length(v_text) > 128 then
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

comment on function public.ledger_payload_schema_is_valid(text, jsonb)
is 'Validates type, length, vocabulary, and numeric range for ledger payload fields. Updated in T08 to add archive_key field.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. rpc_append_audit_event: 'archive_export' action を allowlist に追加
--    'archive_export' は success と failure の両方を記録する（result 制限なし）。
-- ─────────────────────────────────────────────────────────────────────────────

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
        'monthly_digest_generate',
        'monthly_digest_verify',
        -- Ledger Phase 2 §6: archive export（成功・失敗両方を記録）
        'archive_export'
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

    if p_action = 'auth_failure' and p_result <> 'failure' then
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

    -- allowlist / schema validation (段階的移行対応)
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
    'Audit append RPC for non-write-path audit events and failure events. Updated in T08 to add archive_export action.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 5. audit_metadata_has_unknown_key_for_action: 'archive_export' case を追加
--    ACTION_ALLOWLIST_START / END マーカーを維持したまま追加する。
--    parity test と Rust 側 AuditMetadata::validate_allowlist_for_action が同期対象。
-- ─────────────────────────────────────────────────────────────────────────────

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
            v_allowed_keys := array[
                'version',
                'secret_version_id',
                'source_event_at'
            ];
        when 'decrypt' then
            if p_result = 'failure' then
                v_allowed_keys := array[
                    'attempted_secret_id',
                    'source_event_at'
                ];
            else
                v_allowed_keys := array[
                    'source_event_at'
                ];
            end if;
        when 'integrity_check' then
            v_allowed_keys := array[
                'check_name',
                'checked_secret_count',
                'checked_secret_version_count',
                'checked_audit_event_count',
                'duration_ms',
                'violation_count',
                'violation_summary',
                'trigger',
                'error_code',
                'source_event_at'
            ];
            v_violation_summary_keys := array[
                'current_version_invalid',
                'version_invalid',
                'retention_exceeded',
                'ciphertext_empty',
                'encrypted_data_key_empty',
                'nonce_length_invalid',
                'algorithm_invalid',
                'nonce_duplicate',
                'aad_keys_invalid',
                'aad_row_mismatch',
                'created_at_mismatch',
                'audit_action_invalid',
                'audit_result_invalid',
                'audit_metadata_not_object',
                'audit_metadata_forbidden_key',
                'audit_source_event_at_invalid'
            ];
        when 'restore_test' then
            v_allowed_keys := array[
                'phase',
                'sample_count',
                'trigger',
                'duration_ms',
                'error_code',
                'failed_version',
                'reason',
                'source_event_at'
            ];
        when 'auth_failure' then
            v_allowed_keys := array[
                'error_code',
                'source_event_at'
            ];
        when 'key_rotation_start' then
            v_allowed_keys := array[
                'old_key_version',
                'new_key_version',
                'source_event_at'
            ];
        when 'key_rotation_reencrypt' then
            v_allowed_keys := array[
                'old_key_version',
                'new_key_version',
                'batch_size',
                'processed_count',
                'remaining_count',
                'source_event_at'
            ];
        when 'key_rotation_complete' then
            v_allowed_keys := array[
                'old_key_version',
                'new_key_version',
                'remaining_count',
                'source_event_at'
            ];
        -- Ledger Phase 2 T06: 月次 digest 生成失敗の監査記録
        when 'monthly_digest_generate' then
            v_allowed_keys := array[
                'error_code',
                'target_year_month',
                'source_event_at'
            ];
        -- Ledger Phase 2 T07: 月次 digest 検証失敗の監査記録
        when 'monthly_digest_verify' then
            v_allowed_keys := array[
                'error_code',
                'target_year_month',
                'source_event_at'
            ];
        -- Ledger Phase 2 T08 §6: archive export（成功・失敗両方を記録）
        -- archive_key は success 時のみ有効（RPC 外の Rust 側 validate_metadata_values で検証）
        when 'archive_export' then
            v_allowed_keys := array[
                'archive_key',
                'digest_hash',
                'target_year_month',
                'error_code',
                'source_event_at'
            ];
        else
            -- 未知の action は拒否
            return true;
    end case;
    -- ACTION_ALLOWLIST_END

    -- トップレベルキーの allowlist チェック
    for v_key in
        select jsonb_object_keys(p_metadata_json)
    loop
        if not (v_key = any(v_allowed_keys)) then
            return true;
        end if;
    end loop;

    -- integrity_check の violation_summary サブオブジェクトを検証
    if p_action = 'integrity_check'
        and p_metadata_json ? 'violation_summary'
        and jsonb_typeof(p_metadata_json -> 'violation_summary') = 'object'
    then
        for v_key in
            select jsonb_object_keys(p_metadata_json -> 'violation_summary')
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
is 'Returns true when audit metadata contains a key outside the allowlist for the given action. Updated in T08 to include archive_export action.';

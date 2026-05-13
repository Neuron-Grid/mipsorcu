-- Ledger Phase 2: 月次 digest サポート（ADR 0037）。
--
-- 変更内容:
-- 1. ledger_entry_type_allowed: 'monthly_digest' を追加
-- 2. ledger_payload_allowed_keys: 'monthly_digest' payload keys を追加
-- 3. ledger_payload_schema_is_valid: 'monthly_digest' フィールド検証を追加
-- 4. audit_metadata_has_unknown_key_for_action: 'monthly_digest_generate' action を追加
-- 5. rpc_fetch_ledger_range_for_month: 指定年月の ledger range 取得 RPC
-- 6. rpc_check_monthly_digest_exists: 同一年月 digest 重複確認 RPC
--
-- 信頼境界: 非秘密メタデータのみを扱う。平文・鍵・JWT を含まない。
-- ADR 参照: docs/adr/0037-adr-monthly-digest-canonical-form.md

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. ledger_entry_type_allowed: 'monthly_digest' を追加
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
        'monthly_digest'
    );
$$;

comment on function public.ledger_entry_type_allowed(text)
is 'Returns true for all allowed ledger entry_type values (Phase 1 + monthly_digest from Phase 2 T06).';

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. ledger_payload_allowed_keys: 'monthly_digest' payload keys を追加
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
        -- ADR 0037: monthly_digest payload keys（アルファベット順）
        when 'monthly_digest' then array[
            'digest_hash',
            'end_sequence_no',
            'entry_count',
            'start_sequence_no',
            'target_year_month'
        ]::text[]
        else null::text[]
    end;
$$;

comment on function public.ledger_payload_allowed_keys(text)
is 'Returns top-level ledger payload keys allowed for a given entry_type. Updated in T06 to include monthly_digest.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. ledger_payload_schema_is_valid: monthly_digest フィールド検証を追加
--    Phase 1 の validate_ 関数を完全に置き換え。
-- ─────────────────────────────────────────────────────────────────────────────

create or replace function public.ledger_monthly_digest_target_year_month_is_valid(p_value text)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select p_value ~ '^\d{4}-(0[1-9]|1[0-2])$';
$$;

comment on function public.ledger_monthly_digest_target_year_month_is_valid(text)
is 'Validates that a target_year_month value is a valid YYYY-MM string with a month in 01-12 range.';

create or replace function public.ledger_monthly_digest_hash_is_valid(p_value text)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select p_value ~ '^[0-9a-f]{64}$';
$$;

comment on function public.ledger_monthly_digest_hash_is_valid(text)
is 'Validates that a digest_hash value is a 64-character lowercase hex string (SHA-256).';

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. audit_metadata_has_unknown_key_for_action: monthly_digest_generate を追加
--    ACTION_ALLOWLIST_START と ACTION_ALLOWLIST_END の間に全 action を含む。
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
is 'Returns true when audit metadata contains a key outside the allowlist for the given action. Updated in T06 to include monthly_digest_generate action.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 5. rpc_fetch_ledger_range_for_month: 指定年月の ledger range 取得
-- ─────────────────────────────────────────────────────────────────────────────

create or replace function public.rpc_fetch_ledger_range_for_month(
    p_year_month text
)
returns table(
    start_sequence_no bigint,
    end_sequence_no bigint,
    start_entry_hash text,
    end_entry_hash text,
    entry_count bigint
)
language plpgsql
set search_path = public, pg_temp
as $$
declare
    v_month_start timestamptz;
    v_month_end   timestamptz;
    v_min_seq     bigint;
    v_max_seq     bigint;
    v_count       bigint;
    v_start_hash  text;
    v_end_hash    text;
begin
    -- 入力フォーマット検証: YYYY-MM
    if p_year_month is null or p_year_month !~ '^\d{4}-(0[1-9]|1[0-2])$' then
        raise exception 'invalid_year_month_format: p_year_month must be YYYY-MM';
    end if;

    begin
        v_month_start := date_trunc('month', (p_year_month || '-01')::timestamptz);
    exception when others then
        raise exception 'invalid_rpc_input: p_year_month could not be parsed as a date';
    end;
    v_month_end := v_month_start + interval '1 month';

    -- 対象月の sequence_no 範囲とカウントを取得
    -- source_event_at は TEXT（RFC3339 UTC "Z" suffix）として格納されており、
    -- cast して month 単位でフィルタする。
    select
        min(le.sequence_no),
        max(le.sequence_no),
        count(*)
    into v_min_seq, v_max_seq, v_count
    from ledger_entries le
    where (le.source_event_at)::timestamptz >= v_month_start
      and (le.source_event_at)::timestamptz <  v_month_end;

    -- エントリが存在しない場合は行を返さない
    if v_min_seq is null or v_count = 0 then
        return;
    end if;

    -- 最初と最後の entry_hash を取得
    select encode(entry_hash, 'hex')
    into v_start_hash
    from ledger_entries
    where sequence_no = v_min_seq;

    select encode(entry_hash, 'hex')
    into v_end_hash
    from ledger_entries
    where sequence_no = v_max_seq;

    -- Rust 側の from_bytea_hex は "\\x..." を期待する
    start_sequence_no := v_min_seq;
    end_sequence_no   := v_max_seq;
    start_entry_hash  := '\x' || v_start_hash;
    end_entry_hash    := '\x' || v_end_hash;
    entry_count       := v_count;
    return next;
end;
$$;

comment on function public.rpc_fetch_ledger_range_for_month(text)
is 'Returns the ledger_entries range (start/end sequence, hashes, count) for the given YYYY-MM period. Returns no row if no entries exist for that month. T06.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 6. rpc_check_monthly_digest_exists: 同一年月 digest 重複確認
-- ─────────────────────────────────────────────────────────────────────────────

create or replace function public.rpc_check_monthly_digest_exists(
    p_year_month text
)
returns table("exists" boolean)
language plpgsql
stable
set search_path = public, pg_temp
as $$
begin
    if p_year_month is null or p_year_month !~ '^\d{4}-(0[1-9]|1[0-2])$' then
        raise exception 'invalid_year_month_format: p_year_month must be YYYY-MM';
    end if;

    return query
    select exists (
        select 1
        from ledger_entries
        where entry_type = 'monthly_digest'
          and payload->>'target_year_month' = p_year_month
    );
end;
$$;

comment on function public.rpc_check_monthly_digest_exists(text)
is 'Returns {exists: true} if a monthly_digest ledger entry already exists for the given YYYY-MM period. Used for duplicate prevention (T06).';

-- ─────────────────────────────────────────────────────────────────────────────
-- 7. GRANT: service_role に新 RPC の EXECUTE 権限を付与
-- ─────────────────────────────────────────────────────────────────────────────

grant execute on function public.rpc_fetch_ledger_range_for_month(text)
    to service_role;

grant execute on function public.rpc_check_monthly_digest_exists(text)
    to service_role;

grant execute on function public.ledger_monthly_digest_target_year_month_is_valid(text)
    to service_role;

grant execute on function public.ledger_monthly_digest_hash_is_valid(text)
    to service_role;

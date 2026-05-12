-- T11/T12: SIEM forward failure audit action, audit report generation support,
-- and metadata guards.
--
-- 信頼境界: SIEM 送信失敗および監査レポート生成を audit_events に記録するための
-- 非秘密 metadata のみを追加する。レポート生成 RPC は read-only 集計のみを行い、
-- 台帳を変更しない。平文・鍵・JWT・Authorization header・request/response body は
-- audit_metadata_has_forbidden_key で再帰的に拒否する。

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. 禁止 metadata key を T11 §9.3 に合わせて拡張
-- ─────────────────────────────────────────────────────────────────────────────

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
                'authorization',
                'authorization_header',
                'bearer_token',
                'ciphertext',
                'data_key',
                'decrypt_result',
                'decrypted',
                'decrypted_data',
                'encrypted_data_key',
                'jwt',
                'jwt_full',
                'master_key',
                'passphrase',
                'password',
                'plain_text',
                'plaintext',
                'raw_jwt',
                'request_body',
                'request_body_full',
                'response_body',
                'response_body_full',
                'secret_key',
                'secret_value',
                'service_role',
                'service_role_key',
                'token'
                -- FORBIDDEN_AUDIT_METADATA_KEYS_END
            )
    );
$$;

comment on function public.audit_metadata_has_forbidden_key(jsonb) is
    'Recursive guard used by audit constraints and RPCs to reject metadata keys that could carry plaintext, keys, JWTs, Authorization headers, request/response bodies, or ciphertext material. Updated in T11/T12 for SIEM forwarding and audit report generation.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. audit_events.action CHECK に siem_forward_failure / audit_report_generate を追加
-- ─────────────────────────────────────────────────────────────────────────────

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
            'monthly_digest_generate',
            'monthly_digest_verify',
            'archive_export',
            'digest_timestamping',
            'siem_forward_failure',
            'audit_report_generate'
        )
    );

alter table public.audit_events
    add constraint audit_events_siem_forward_failure_failure_only check (
        action <> 'siem_forward_failure' or result = 'failure'
    );

comment on constraint audit_events_siem_forward_failure_failure_only on public.audit_events is
    'siem_forward_failure audit events are emitted only when SIEM forwarding failed and must never use result=success.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. rpc_append_audit_event に siem_forward_failure / audit_report_generate を追加
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
        'archive_export',
        'digest_timestamping',
        'siem_forward_failure',
        'audit_report_generate'
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

    if p_action in ('auth_failure', 'siem_forward_failure') and p_result <> 'failure' then
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
    'Audit append RPC for non-write-path audit events and failure events. Updated in T11/T12 to add siem_forward_failure and audit_report_generate actions.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. metadata allowlist / required keys に siem_forward_failure / audit_report_generate を追加
-- ─────────────────────────────────────────────────────────────────────────────

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
            v_required_keys := array[
                'check_name',
                'checked_secret_count',
                'checked_secret_version_count',
                'checked_audit_event_count',
                'duration_ms',
                'violation_count',
                'violation_summary',
                'trigger'
            ];
            v_summary_required_keys := array[
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
            v_required_keys := array['phase', 'sample_count', 'trigger', 'duration_ms'];
        when 'auth_failure' then
            v_required_keys := array['error_code'];
        when 'key_rotation_start' then
            v_required_keys := array['old_key_version', 'new_key_version'];
        when 'key_rotation_reencrypt' then
            v_required_keys := array[
                'old_key_version',
                'new_key_version',
                'batch_size',
                'processed_count',
                'remaining_count'
            ];
        when 'key_rotation_complete' then
            v_required_keys := array['old_key_version', 'new_key_version', 'remaining_count'];
        when 'monthly_digest_generate', 'monthly_digest_verify' then
            v_required_keys := array[]::text[];
        when 'archive_export', 'digest_timestamping' then
            v_required_keys := array['target_year_month'];
        when 'siem_forward_failure' then
            v_required_keys := array['error_code'];
        when 'audit_report_generate' then
            v_required_keys := array['format', 'period_end', 'period_start'];
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
            v_allowed_keys := array['error_code', 'source_event_at'];
        when 'key_rotation_start' then
            v_allowed_keys := array['old_key_version', 'new_key_version', 'source_event_at'];
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
        when 'monthly_digest_generate', 'monthly_digest_verify' then
            v_allowed_keys := array['error_code', 'target_year_month', 'source_event_at'];
        when 'archive_export' then
            v_allowed_keys := array[
                'archive_key',
                'digest_hash',
                'target_year_month',
                'error_code',
                'source_event_at'
            ];
        when 'digest_timestamping' then
            v_allowed_keys := array[
                'digest_hash',
                'timestamp_token_hash',
                'target_year_month',
                'error_code',
                'source_event_at'
            ];
        when 'siem_forward_failure' then
            v_allowed_keys := array[
                'error_code',
                'event_type',
                'event_count',
                'source_event_at'
            ];
        when 'audit_report_generate' then
            v_allowed_keys := array[
                'error_code',
                'format',
                'period_end',
                'period_start',
                'source_event_at'
            ];
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
is 'Returns true when audit metadata contains a key outside the allowlist for the given action. Updated in T11/T12 to include siem_forward_failure and audit_report_generate actions.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 5. 期間指定レポート集計 RPC（read-only）
-- ─────────────────────────────────────────────────────────────────────────────

create or replace function public.rpc_audit_report_summary(
    p_period_start text,
    p_period_end text
)
returns table (report_json jsonb)
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
declare
    v_start timestamptz;
    v_end timestamptz;
    v_sequence_start bigint;
    v_sequence_end bigint;
    v_ledger_entry_count bigint;
    v_audit_event_count bigint;
    v_secret_count bigint;
    v_hash_chain jsonb;
    v_restore_tests jsonb;
    v_integrity_checks jsonb;
    v_verification_failures jsonb;
    v_signature_keys jsonb;
    v_monthly_digests jsonb;
begin
    if p_period_start is null
        or p_period_end is null
        or not public.ledger_source_event_at_is_valid(p_period_start)
        or not public.ledger_source_event_at_is_valid(p_period_end)
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    v_start := p_period_start::timestamptz;
    v_end := p_period_end::timestamptz;

    if v_start >= v_end then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    select min(le.sequence_no), max(le.sequence_no), count(*)::bigint
    into v_sequence_start, v_sequence_end, v_ledger_entry_count
    from public.ledger_entries le
    where le.source_event_at::timestamptz >= v_start
        and le.source_event_at::timestamptz < v_end;

    select count(*)::bigint
    into v_audit_event_count
    from public.audit_events ae
    where ae.occurred_at >= v_start
        and ae.occurred_at < v_end;

    select count(distinct s.id)::bigint
    into v_secret_count
    from public.secrets s
    where s.created_at < v_end;

    if v_sequence_start is null then
        v_hash_chain := jsonb_build_object(
            'checked_count', 0,
            'detail', 'no ledger entries in period',
            'valid', true
        );
    else
        select jsonb_build_object(
            'checked_count', vhc.entries_checked,
            'detail', coalesce(vhc.first_gap_detail, vhc.first_hash_mismatch_detail),
            'valid', vhc.chain_valid
        )
        into v_hash_chain
        from public.rpc_verify_ledger_hash_chain(v_sequence_start, v_sequence_end) vhc;
    end if;

    select coalesce(jsonb_agg(item order by item ->> 'occurred_at'), '[]'::jsonb)
    into v_restore_tests
    from (
        select jsonb_build_object(
            'duration_ms', (ae.metadata_json ->> 'duration_ms')::bigint,
            'occurred_at', to_char(ae.occurred_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'result', ae.result,
            'sample_count', (ae.metadata_json ->> 'sample_count')::bigint,
            'trigger', ae.metadata_json ->> 'trigger'
        ) as item
        from public.audit_events ae
        where ae.action = 'restore_test'
            and ae.occurred_at >= v_start
            and ae.occurred_at < v_end
    ) rows;

    select coalesce(jsonb_agg(item order by item ->> 'occurred_at'), '[]'::jsonb)
    into v_integrity_checks
    from (
        select jsonb_build_object(
            'checked_audit_event_count', (ae.metadata_json ->> 'checked_audit_event_count')::bigint,
            'checked_secret_count', (ae.metadata_json ->> 'checked_secret_count')::bigint,
            'checked_secret_version_count', (ae.metadata_json ->> 'checked_secret_version_count')::bigint,
            'duration_ms', (ae.metadata_json ->> 'duration_ms')::bigint,
            'occurred_at', to_char(ae.occurred_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'result', ae.result,
            'trigger', ae.metadata_json ->> 'trigger',
            'violation_count', (ae.metadata_json ->> 'violation_count')::bigint
        ) as item
        from public.audit_events ae
        where ae.action = 'integrity_check'
            and ae.occurred_at >= v_start
            and ae.occurred_at < v_end
    ) rows;

    select coalesce(jsonb_agg(item order by item ->> 'source', item ->> 'occurred_at'), '[]'::jsonb)
    into v_verification_failures
    from (
        select jsonb_build_object(
            'code', coalesce(le.error_code, 'ledger_failure'),
            'occurred_at', le.source_event_at,
            'sequence_no', le.sequence_no,
            'source', 'ledger'
        ) as item
        from public.ledger_entries le
        where le.source_event_at::timestamptz >= v_start
            and le.source_event_at::timestamptz < v_end
            and le.result = 'failure'
            and le.entry_type in ('ledger_verification_failed', 'integrity_check_completed', 'restore_test_completed')
        union all
        select jsonb_build_object(
            'code', coalesce(ae.metadata_json ->> 'error_code', ae.result),
            'occurred_at', to_char(ae.occurred_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
            'sequence_no', null,
            'source', 'audit_events.' || ae.action
        ) as item
        from public.audit_events ae
        where ae.occurred_at >= v_start
            and ae.occurred_at < v_end
            and ae.result = 'failure'
            and ae.action in ('integrity_check', 'restore_test', 'monthly_digest_verify')
    ) rows;

    select coalesce(jsonb_agg(item order by (item ->> 'key_version')::integer), '[]'::jsonb)
    into v_signature_keys
    from (
        select jsonb_build_object(
            'key_version', pk.key_version,
            'status', pk.status
        ) as item
        from public.ledger_signing_public_keys pk
    ) rows;

    select coalesce(jsonb_agg(item order by item ->> 'target_year_month'), '[]'::jsonb)
    into v_monthly_digests
    from (
        select jsonb_build_object(
            'digest_hash', le.payload ->> 'digest_hash',
            'end_sequence_no', (le.payload ->> 'end_sequence_no')::bigint,
            'entry_count', (le.payload ->> 'entry_count')::bigint,
            'sequence_no', le.sequence_no,
            'start_sequence_no', (le.payload ->> 'start_sequence_no')::bigint,
            'target_year_month', le.payload ->> 'target_year_month'
        ) as item
        from public.ledger_entries le
        where le.entry_type = 'monthly_digest'
            and le.source_event_at::timestamptz >= v_start
            and le.source_event_at::timestamptz < v_end
    ) rows;

    report_json := jsonb_build_object(
        'audit_event_count', v_audit_event_count,
        'hash_chain_verification', v_hash_chain,
        'integrity_checks', v_integrity_checks,
        'ledger_entry_count', v_ledger_entry_count,
        'monthly_digests', v_monthly_digests,
        'period_end', p_period_end,
        'period_start', p_period_start,
        'restore_tests', v_restore_tests,
        'secret_count', v_secret_count,
        'sequence_end', v_sequence_end,
        'sequence_start', v_sequence_start,
        'signature_key_versions', v_signature_keys,
        'verification_failures', v_verification_failures
    );
    return next;
end;
$$;

comment on function public.rpc_audit_report_summary(text, text)
is 'Returns a read-only JSONB summary for audit report generation over [period_start, period_end). Does not modify ledger_entries or audit_events.';

revoke execute on function public.rpc_audit_report_summary(text, text) from public, anon, authenticated;
revoke execute on function public.rpc_audit_report_summary(text, text) from public;
grant execute on function public.rpc_audit_report_summary(text, text) to service_role;

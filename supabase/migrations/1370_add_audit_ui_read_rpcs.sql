-- Section 1370: 監査UIバックエンド用の読み取り RPC を SQL に定義し、Rust との境界不整合を解消する。
--
-- 背景: Rust の監査UIバックエンド (src/server/supabase/audit_ui_rpc.rs) は PostgREST 経由で
-- rpc_audit_ui_secret_inventory / rpc_audit_ui_audit_events / rpc_audit_ui_ledger_entries /
-- rpc_audit_ui_integrity_status / rpc_audit_ui_verification_failures を呼び出すが、これらの
-- 関数が migration に存在せず PostgREST が PGRST202 (404 / 関数が見つからない) を返していた。
-- 本マイグレーションは既存の auditor_*_view を再利用してラップする SECURITY DEFINER 関数を
-- 定義し、Rust と SQL の境界定義を一致させる。
--
-- 信頼境界: これらは読み取り専用 RPC であり、非秘密メタデータのみを返す。平文・データキー・
-- マスターキー・JWT・ciphertext は一切含まない。audit_events への書き込みは行わないため
-- audit metadata allowlist の変更は不要。
--
-- 権限: Rust バックエンドは常に service_role キーで呼び出すため EXECUTE は service_role のみに
-- 付与し、anon / authenticated / public からは revoke する (rpc_audit_report_summary と同方針)。
-- 独立監査人向けの検証は既存の rpc_verify_ledger_hash_chain /
-- rpc_export_ledger_verification_materials (mipsorcu_auditor 付与済み) が担う。
--
-- ページネーション契約: HTTP ハンドラ (src/server/handlers/audit_ui.rs) は limit を 1..=500 に
-- 制限し、has_more 判定のため rpc_limit() = limit + 1 (最大 501) を送る。各 RPC は決定的な
-- ORDER BY を持ち、p_limit の上限を 1000 に設定して 501 を許容する。

-- 1. rpc_audit_ui_secret_inventory: auditor_secret_inventory_view のページネーションラッパ。
create or replace function public.rpc_audit_ui_secret_inventory(
    p_limit integer,
    p_offset integer
)
returns setof public.auditor_secret_inventory_view
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
begin
    if p_limit is null or p_limit <= 0 or p_limit > 1000 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_offset is null or p_offset < 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return query
    select v.*
    from public.auditor_secret_inventory_view v
    order by v.secret_created_at desc, v.secret_id
    limit p_limit offset p_offset;
end;
$$;

comment on function public.rpc_audit_ui_secret_inventory(integer, integer) is
    'Audit UI read RPC. Paginated wrapper over auditor_secret_inventory_view. Non-secret metadata only. Section 1370.';

revoke execute on function public.rpc_audit_ui_secret_inventory(integer, integer) from public, anon, authenticated;
grant execute on function public.rpc_audit_ui_secret_inventory(integer, integer) to service_role;

-- 2. rpc_audit_ui_audit_events: auditor_audit_events_view を period / action / result で絞り込む。
create or replace function public.rpc_audit_ui_audit_events(
    p_limit integer,
    p_offset integer,
    p_period_start text default null,
    p_period_end text default null,
    p_action text default null,
    p_result text default null
)
returns setof public.auditor_audit_events_view
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
begin
    if p_limit is null or p_limit <= 0 or p_limit > 1000 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_offset is null or p_offset < 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_result is not null and p_result not in ('success', 'failure') then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return query
    select v.*
    from public.auditor_audit_events_view v
    where (p_period_start is null or v.occurred_at >= p_period_start::timestamptz)
        and (p_period_end is null or v.occurred_at < p_period_end::timestamptz)
        and (p_action is null or v.action = p_action)
        and (p_result is null or v.result = p_result)
    order by v.occurred_at desc, v.audit_event_id
    limit p_limit offset p_offset;
end;
$$;

comment on function public.rpc_audit_ui_audit_events(integer, integer, text, text, text, text) is
    'Audit UI read RPC. Filtered (period/action/result) + paginated wrapper over auditor_audit_events_view. Non-secret metadata only. Section 1370.';

revoke execute on function public.rpc_audit_ui_audit_events(integer, integer, text, text, text, text) from public, anon, authenticated;
grant execute on function public.rpc_audit_ui_audit_events(integer, integer, text, text, text, text) to service_role;

-- 3. rpc_audit_ui_ledger_entries: auditor_ledger_entries_view を sequence 範囲 / entry_type / result で絞り込む。
create or replace function public.rpc_audit_ui_ledger_entries(
    p_limit integer,
    p_offset integer,
    p_start_sequence_no bigint default null,
    p_end_sequence_no bigint default null,
    p_entry_type text default null,
    p_result text default null
)
returns setof public.auditor_ledger_entries_view
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
begin
    if p_limit is null or p_limit <= 0 or p_limit > 1000 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_offset is null or p_offset < 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_result is not null and p_result not in ('success', 'failure') then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return query
    select v.*
    from public.auditor_ledger_entries_view v
    where (p_start_sequence_no is null or v.sequence_no >= p_start_sequence_no)
        and (p_end_sequence_no is null or v.sequence_no <= p_end_sequence_no)
        and (p_entry_type is null or v.entry_type = p_entry_type)
        and (p_result is null or v.result = p_result)
    order by v.sequence_no desc
    limit p_limit offset p_offset;
end;
$$;

comment on function public.rpc_audit_ui_ledger_entries(integer, integer, bigint, bigint, text, text) is
    'Audit UI read RPC. Filtered (sequence range/entry_type/result) + paginated wrapper over auditor_ledger_entries_view. Non-secret fields only. Section 1370.';

revoke execute on function public.rpc_audit_ui_ledger_entries(integer, integer, bigint, bigint, text, text) from public, anon, authenticated;
grant execute on function public.rpc_audit_ui_ledger_entries(integer, integer, bigint, bigint, text, text) to service_role;

-- 4. rpc_audit_ui_integrity_status: auditor_integrity_status_view 全行 (グローバルチェーン先頭状態)。
create or replace function public.rpc_audit_ui_integrity_status()
returns setof public.auditor_integrity_status_view
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
begin
    return query
    select v.*
    from public.auditor_integrity_status_view v
    order by v.chain_id;
end;
$$;

comment on function public.rpc_audit_ui_integrity_status() is
    'Audit UI read RPC. Returns global ledger chain head state from auditor_integrity_status_view. Non-secret metadata only. Section 1370.';

revoke execute on function public.rpc_audit_ui_integrity_status() from public, anon, authenticated;
grant execute on function public.rpc_audit_ui_integrity_status() to service_role;

-- 5. rpc_audit_ui_verification_failures: 期間内の検証失敗を ledger / audit_events から集約する。
--    対応ビューが存在しないため、rpc_audit_report_summary 内の UNION ロジック (0900) を踏襲し、
--    jsonb 集約ではなく行として返す。
create or replace function public.rpc_audit_ui_verification_failures(
    p_limit integer,
    p_offset integer,
    p_period_start text,
    p_period_end text
)
returns table (
    code text,
    occurred_at text,
    sequence_no bigint,
    source text
)
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
declare
    v_start timestamptz;
    v_end timestamptz;
begin
    if p_limit is null or p_limit <= 0 or p_limit > 1000 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_offset is null or p_offset < 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
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

    return query
    select
        f.code,
        f.occurred_at,
        f.sequence_no,
        f.source
    from (
        select
            coalesce(le.error_code, 'ledger_failure') as code,
            le.source_event_at as occurred_at,
            le.sequence_no as sequence_no,
            'ledger'::text as source
        from public.ledger_entries le
        where le.source_event_at::timestamptz >= v_start
            and le.source_event_at::timestamptz < v_end
            and le.result = 'failure'
            and le.entry_type in ('ledger_verification_failed', 'integrity_check_completed', 'restore_test_completed')
        union all
        select
            coalesce(ae.metadata_json ->> 'error_code', ae.result) as code,
            to_char(ae.occurred_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') as occurred_at,
            null::bigint as sequence_no,
            'audit_events.' || ae.action as source
        from public.audit_events ae
        where ae.occurred_at >= v_start
            and ae.occurred_at < v_end
            and ae.result = 'failure'
            and ae.action in ('integrity_check', 'restore_test', 'monthly_digest_verify')
    ) f
    order by f.occurred_at desc, f.source, f.sequence_no nulls last
    limit p_limit offset p_offset;
end;
$$;

comment on function public.rpc_audit_ui_verification_failures(integer, integer, text, text) is
    'Audit UI read RPC. Aggregates ledger and audit_events verification failures over [period_start, period_end), paginated. Mirrors rpc_audit_report_summary failure logic. Non-secret metadata only. Section 1370.';

revoke execute on function public.rpc_audit_ui_verification_failures(integer, integer, text, text) from public, anon, authenticated;
grant execute on function public.rpc_audit_ui_verification_failures(integer, integer, text, text) to service_role;

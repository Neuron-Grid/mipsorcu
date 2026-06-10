-- bug-05 仕上げ（値 enum parity 完結）: severity / notification_result の値集合に
-- parity 抽出用マーカーを付与する。
--
-- `incident_severity_allowed` / `incident_notification_result_allowed` は 1000 で定義以降
-- 再定義されておらず、許可値リストが単一行・マーカー無しだったため、cargo の値 enum parity
-- テスト（audit_metadata_forbidden_keys_parity）が Rust const と突合する正本を持てなかった
-- （incident_type / category / notifier_kind は 1430 でマーカー化済み）。
--
-- 本 migration は両関数を全値**完全再掲**の `create or replace` として再定義し、
-- `-- SEVERITY_ALLOWLIST_START/END` / `-- NOTIFICATION_RESULT_ALLOWLIST_START/END` の
-- 独立行マーカーで囲む。許可値集合は 1000 とバイト等価（critical/high/medium/low,
-- sent/failed/suppressed/not_configured）で**不変**のため ADR 不要（docs/coding-rules.md §14.3）。
-- `create or replace` は適用済み DB に前方互換、privileges も保持される。

-- severity 許可値の正本（Rust 側は INCIDENT_SEVERITY_ALLOWLIST が単一ソース）
create or replace function public.incident_severity_allowed(p_severity text)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select p_severity in (
        -- SEVERITY_ALLOWLIST_START
        'critical',
        'high',
        'medium',
        'low'
        -- SEVERITY_ALLOWLIST_END
    );
$$;

comment on function public.incident_severity_allowed(text) is
    'Returns true for non-secret incident severity vocabulary accepted by incident audit and ledger records. Section 1450 restates the full value set with -- SEVERITY_ALLOWLIST_START/END markers so the Rust/SQL value enum parity test can auto-discover this effective definition.';

revoke execute on function public.incident_severity_allowed(text) from public, anon, authenticated;

-- notification_result 許可値の正本（Rust 側は NOTIFICATION_RESULT_ALLOWLIST が単一ソース）
create or replace function public.incident_notification_result_allowed(p_notification_result text)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select p_notification_result in (
        -- NOTIFICATION_RESULT_ALLOWLIST_START
        'sent',
        'failed',
        'suppressed',
        'not_configured'
        -- NOTIFICATION_RESULT_ALLOWLIST_END
    );
$$;

comment on function public.incident_notification_result_allowed(text) is
    'Returns true for non-secret incident notification_result vocabulary accepted by incident audit and ledger records. Section 1450 restates the full value set with -- NOTIFICATION_RESULT_ALLOWLIST_START/END markers so the Rust/SQL value enum parity test can auto-discover this effective definition.';

revoke execute on function public.incident_notification_result_allowed(text) from public, anon, authenticated;

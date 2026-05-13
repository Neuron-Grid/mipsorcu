create or replace function public.rpc_integrity_check()
returns table (
    checked_secret_count integer,
    checked_secret_version_count integer,
    checked_audit_event_count integer,
    violation_count integer,
    violation_summary jsonb
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_checked_secret_count integer;
    v_checked_secret_version_count integer;
    v_checked_audit_event_count integer;
    v_current_version_invalid integer;
    v_version_invalid integer;
    v_retention_exceeded integer;
    v_ciphertext_empty integer;
    v_encrypted_data_key_empty integer;
    v_nonce_length_invalid integer;
    v_algorithm_invalid integer;
    v_nonce_duplicate integer;
    v_aad_keys_invalid integer;
    v_aad_row_mismatch integer;
    v_created_at_mismatch integer;
    v_audit_action_invalid integer;
    v_audit_result_invalid integer;
    v_audit_metadata_not_object integer;
    v_audit_metadata_forbidden_key integer;
    v_audit_source_event_at_invalid integer;
begin
    select count(*)::integer into v_checked_secret_count from public.secrets;
    select count(*)::integer into v_checked_secret_version_count from public.secret_versions;
    select count(*)::integer into v_checked_audit_event_count from public.audit_events;

    select count(*)::integer
    into v_current_version_invalid
    from public.secrets s
    left join public.secret_versions sv
        on sv.id = s.current_version_id
        and sv.secret_id = s.id
    where s.current_version_id is null
        or sv.id is null;

    select count(*)::integer
    into v_version_invalid
    from public.secret_versions sv
    where sv.version <= 0;

    select count(*)::integer
    into v_retention_exceeded
    from (
        select sv.secret_id
        from public.secret_versions sv
        group by sv.secret_id
        having count(*) > 4
    ) retained;

    select count(*)::integer
    into v_ciphertext_empty
    from public.secret_versions sv
    where octet_length(sv.ciphertext) = 0;

    select count(*)::integer
    into v_encrypted_data_key_empty
    from public.secret_versions sv
    where octet_length(sv.encrypted_data_key) = 0;

    select count(*)::integer
    into v_nonce_length_invalid
    from public.secret_versions sv
    where octet_length(sv.nonce_or_iv) <> 24;

    select count(*)::integer
    into v_algorithm_invalid
    from public.secret_versions sv
    where sv.algorithm <> 'xchacha20-poly1305';

    select count(*)::integer
    into v_nonce_duplicate
    from (
        select sv.secret_id, sv.nonce_or_iv
        from public.secret_versions sv
        group by sv.secret_id, sv.nonce_or_iv
        having count(*) > 1
    ) duplicate_nonces;

    select count(*)::integer
    into v_aad_keys_invalid
    from public.secret_versions sv
    where jsonb_typeof(sv.aad_context) is distinct from 'object'
        or not (
            sv.aad_context ?& array[
                'aad_version',
                'secret_id',
                'version',
                'owner_user_id',
                'classification',
                'created_at'
            ]
        )
        or sv.aad_context - array[
            'aad_version',
            'secret_id',
            'version',
            'owner_user_id',
            'classification',
            'created_at'
        ] <> '{}'::jsonb
        or jsonb_typeof(sv.aad_context -> 'aad_version') is distinct from 'number'
        or jsonb_typeof(sv.aad_context -> 'secret_id') is distinct from 'string'
        or jsonb_typeof(sv.aad_context -> 'version') is distinct from 'number'
        or jsonb_typeof(sv.aad_context -> 'owner_user_id') is distinct from 'string'
        or jsonb_typeof(sv.aad_context -> 'classification') is distinct from 'string'
        or jsonb_typeof(sv.aad_context -> 'created_at') is distinct from 'string'
        or sv.aad_context ->> 'aad_version' <> '1';

    select count(*)::integer
    into v_aad_row_mismatch
    from public.secret_versions sv
    inner join public.secrets s
        on s.id = sv.secret_id
    where jsonb_typeof(sv.aad_context) = 'object'
        and sv.aad_context ?& array[
            'aad_version',
            'secret_id',
            'version',
            'owner_user_id',
            'classification',
            'created_at'
        ]
        and sv.aad_context - array[
            'aad_version',
            'secret_id',
            'version',
            'owner_user_id',
            'classification',
            'created_at'
        ] = '{}'::jsonb
        and (
            sv.aad_context ->> 'secret_id' <> sv.secret_id::text
            or sv.aad_context ->> 'version' <> sv.version::text
            or sv.aad_context ->> 'owner_user_id' <> s.owner_user_id::text
            or sv.aad_context ->> 'owner_user_id' <> sv.created_by_user_id::text
            or sv.aad_context ->> 'classification' <> s.classification
            or sv.aad_context ->> 'classification' <> sv.classification
        );

    select count(*)::integer
    into v_created_at_mismatch
    from public.secret_versions sv
    where jsonb_typeof(sv.aad_context) = 'object'
        and jsonb_typeof(sv.aad_context -> 'created_at') = 'string'
        and not (
            sv.aad_context ->> 'created_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$'
            and case
                when sv.aad_context ->> 'created_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$'
                    then (sv.aad_context ->> 'created_at')::timestamptz = sv.created_at
                else false
            end
        );

    select count(*)::integer
    into v_audit_action_invalid
    from public.audit_events ae
    where ae.action not in (
        'encrypt_create',
        'encrypt_rotate',
        'decrypt',
        'version_purge',
        'integrity_check',
        'restore_test',
        'auth_failure',
        'key_rotation_start',
        'key_rotation_reencrypt',
        'key_rotation_complete'
    );

    select count(*)::integer
    into v_audit_result_invalid
    from public.audit_events ae
    where ae.result not in ('success', 'failure');

    select count(*)::integer
    into v_audit_metadata_not_object
    from public.audit_events ae
    where jsonb_typeof(ae.metadata_json) is distinct from 'object';

    select count(*)::integer
    into v_audit_metadata_forbidden_key
    from public.audit_events ae
    where public.audit_metadata_has_forbidden_key(ae.metadata_json);

    select count(*)::integer
    into v_audit_source_event_at_invalid
    from public.audit_events ae
    where jsonb_typeof(ae.metadata_json) = 'object'
        and not public.audit_metadata_source_event_at_is_valid(ae.metadata_json);

    violation_summary := jsonb_build_object(
        'current_version_invalid', v_current_version_invalid,
        'version_invalid', v_version_invalid,
        'retention_exceeded', v_retention_exceeded,
        'ciphertext_empty', v_ciphertext_empty,
        'encrypted_data_key_empty', v_encrypted_data_key_empty,
        'nonce_length_invalid', v_nonce_length_invalid,
        'algorithm_invalid', v_algorithm_invalid,
        'nonce_duplicate', v_nonce_duplicate,
        'aad_keys_invalid', v_aad_keys_invalid,
        'aad_row_mismatch', v_aad_row_mismatch,
        'created_at_mismatch', v_created_at_mismatch,
        'audit_action_invalid', v_audit_action_invalid,
        'audit_result_invalid', v_audit_result_invalid,
        'audit_metadata_not_object', v_audit_metadata_not_object,
        'audit_metadata_forbidden_key', v_audit_metadata_forbidden_key,
        'audit_source_event_at_invalid', v_audit_source_event_at_invalid
    );

    checked_secret_count := v_checked_secret_count;
    checked_secret_version_count := v_checked_secret_version_count;
    checked_audit_event_count := v_checked_audit_event_count;
    violation_count := v_current_version_invalid
        + v_version_invalid
        + v_retention_exceeded
        + v_ciphertext_empty
        + v_encrypted_data_key_empty
        + v_nonce_length_invalid
        + v_algorithm_invalid
        + v_nonce_duplicate
        + v_aad_keys_invalid
        + v_aad_row_mismatch
        + v_created_at_mismatch
        + v_audit_action_invalid
        + v_audit_result_invalid
        + v_audit_metadata_not_object
        + v_audit_metadata_forbidden_key
        + v_audit_source_event_at_invalid;

    return next;
end;
$$;

comment on function public.rpc_integrity_check() is
    'Runs MVP integrity checks and returns aggregate violation counts only. Supabase の service_role ロールは BYPASSRLS 属性を持つ高権限ロールである。ただし mipsorcu runtime では direct DML に依存せず、rpc_write_secret_version / rpc_append_audit_event / rpc_sample_restore_test / rpc_integrity_check の EXECUTE 権限と、復号用の限定的 SELECT を中心に最小化して運用する。audit_events には service_role を含む runtime role の direct table privileges を付与しない。';

comment on table public.audit_events is
    'Append-only audit source of truth. Supabase の service_role ロールは BYPASSRLS 属性を持つ高権限ロールである。ただし mipsorcu runtime では direct DML に依存せず、rpc_write_secret_version / rpc_append_audit_event / rpc_sample_restore_test / rpc_integrity_check の EXECUTE 権限と、復号用の限定的 SELECT を中心に最小化して運用する。audit_events には service_role を含む runtime role の direct table privileges を付与しない。';

comment on policy audit_events_deny_all on public.audit_events is
    'Restrictive deny-all policy for runtime roles. audit_events direct table privileges must not be granted to service_role or other runtime roles; append and operational reads stay behind dedicated SECURITY DEFINER RPCs.';

comment on function public.rpc_write_secret_version(
    uuid,
    text,
    uuid,
    uuid,
    text,
    text,
    timestamptz,
    integer,
    bytea,
    bytea,
    integer,
    text,
    bytea,
    jsonb,
    uuid,
    jsonb
) is
    'Authoritative production write RPC for encrypt_create and encrypt_rotate. Supabase の service_role ロールは BYPASSRLS 属性を持つ高権限ロールである。ただし mipsorcu runtime では direct DML に依存せず、rpc_write_secret_version / rpc_append_audit_event / rpc_sample_restore_test / rpc_integrity_check の EXECUTE 権限と、復号用の限定的 SELECT を中心に最小化して運用する。audit_events には service_role を含む runtime role の direct table privileges を付与しない。';

comment on function public.rpc_append_audit_event(
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb
) is
    'Audit append RPC for non-write-path audit events and failure events. Supabase の service_role ロールは BYPASSRLS 属性を持つ高権限ロールである。ただし mipsorcu runtime では direct DML に依存せず、rpc_write_secret_version / rpc_append_audit_event / rpc_sample_restore_test / rpc_integrity_check の EXECUTE 権限と、復号用の限定的 SELECT を中心に最小化して運用する。audit_events には service_role を含む runtime role の direct table privileges を付与しない。';

comment on function public.rpc_sample_restore_test(integer) is
    'Returns current encrypted rows for restore verification. Supabase の service_role ロールは BYPASSRLS 属性を持つ高権限ロールである。ただし mipsorcu runtime では direct DML に依存せず、rpc_write_secret_version / rpc_append_audit_event / rpc_sample_restore_test / rpc_integrity_check の EXECUTE 権限と、復号用の限定的 SELECT を中心に最小化して運用する。audit_events には service_role を含む runtime role の direct table privileges を付与しない。';

revoke execute on function public.rpc_integrity_check() from public, anon, authenticated;
revoke execute on function public.rpc_integrity_check() from public;

grant execute on function public.rpc_integrity_check() to service_role;

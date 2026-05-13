-- Local squash note:
-- This migration consolidates the local, unapplied 0900-0999 migration series.
-- The historical section order is intentionally preserved so each later
-- create-or-replace step remains comparable with the original sequence.

-- ============================================================================
-- Section 0900: integrity check RPC and service role comments
-- ============================================================================

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

-- ============================================================================
-- Section 0950: ledger phase1 base schema and append RPC
-- ============================================================================

-- Ledger Phase 1 SQL support.
-- The audit_events table remains the primary audit record. ledger_entries adds
-- append-only hash-chain evidence without backfilling audit_events.

-- Ledger validation helpers

create or replace function public.ledger_source_event_at_is_valid(p_source_event_at text)
returns boolean
language plpgsql
stable
set search_path = public, pg_temp
as $$
declare
    v_parsed timestamptz;
begin
    if p_source_event_at is null then
        return false;
    end if;

    if p_source_event_at !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$' then
        return false;
    end if;

    begin
        v_parsed := p_source_event_at::timestamptz;
    exception
        when others then
            return false;
    end;

    return to_char(v_parsed at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') = p_source_event_at
        or (
            p_source_event_at ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+Z$'
            and (v_parsed at time zone 'UTC')::text is not null
        );
end;
$$;

comment on function public.ledger_source_event_at_is_valid(text)
is 'Validates canonical UTC RFC3339 producer timestamps for ledger_entries.source_event_at.';

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
        'audit_fallback_resent'
    );
$$;

comment on function public.ledger_entry_type_allowed(text)
is 'Returns true for Ledger Phase 1 entry_type vocabulary only.';

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
        else null::text[]
    end;
$$;

comment on function public.ledger_payload_allowed_keys(text)
is 'Returns top-level ledger payload keys allowed for a Ledger Phase 1 entry_type.';

create or replace function public.ledger_payload_has_forbidden_key(p_payload jsonb)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    with recursive nodes(value) as (
        select p_payload
        where p_payload is not null
        union all
        select child.value
        from nodes
        cross join lateral (
            select value
            from jsonb_each(nodes.value)
            where jsonb_typeof(nodes.value) = 'object'
            union all
            select value
            from jsonb_array_elements(nodes.value)
            where jsonb_typeof(nodes.value) = 'array'
        ) as child
    ),
    keys(key_name) as (
        select lower(btrim(obj.key))
        from nodes
        cross join lateral jsonb_each(nodes.value) as obj(key, value)
        where jsonb_typeof(nodes.value) = 'object'
    )
    select exists (
        select 1
        from keys
        where key_name in (
            'authorization',
            'ciphertext',
            'data_key',
            'decrypt_result',
            'decrypted',
            'decrypted_data',
            'encrypted_data_key',
            'jwt',
            'master_key',
            'passphrase',
            'password',
            'plain_text',
            'plaintext',
            'request_body',
            'response_body',
            'secret_key',
            'secret_value',
            'service_role',
            'service_role_key',
            'token'
        )
    );
$$;

comment on function public.ledger_payload_has_forbidden_key(jsonb)
is 'Recursively rejects ledger payload keys that could carry plaintext, decryptable data, credentials, or key material.';

create or replace function public.ledger_payload_has_unknown_key(
    p_entry_type text,
    p_payload jsonb
)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select case
        when p_payload is null then true
        when jsonb_typeof(p_payload) <> 'object' then true
        when public.ledger_payload_allowed_keys(p_entry_type) is null then true
        else exists (
            select 1
            from jsonb_object_keys(p_payload) as payload_keys(key)
            where not (payload_keys.key = any(public.ledger_payload_allowed_keys(p_entry_type)))
        )
    end;
$$;

comment on function public.ledger_payload_has_unknown_key(text, jsonb)
is 'Returns true when a ledger payload includes keys outside the entry_type allowlist.';

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
is 'Validates type, length, vocabulary, and numeric range for Ledger Phase 1 payload fields.';

create or replace function public.ledger_payload_is_valid(
    p_entry_type text,
    p_payload jsonb
)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select p_payload is not null
        and jsonb_typeof(p_payload) = 'object'
        and pg_column_size(p_payload) <= 8192
        and public.ledger_entry_type_allowed(p_entry_type)
        and not public.ledger_payload_has_forbidden_key(p_payload)
        and not public.ledger_payload_has_unknown_key(p_entry_type, p_payload)
        and public.ledger_payload_schema_is_valid(p_entry_type, p_payload);
$$;

comment on function public.ledger_payload_is_valid(text, jsonb)
is 'Composite ledger payload guard used by table constraints and rpc_append_ledger_entry.';

-- Ledger tables, indexes, and chain state

create table public.ledger_entries (
    id uuid primary key,
    sequence_no bigint not null,
    entry_type text not null,
    source_event_at text not null,
    request_id uuid not null,
    source_event_id uuid,
    target_secret_id uuid,
    target_secret_version_id uuid,
    actor_user_id uuid,
    actor_device_id text,
    result text not null,
    error_code text,
    payload jsonb not null,
    canonicalization_version integer not null,
    previous_entry_hash bytea not null,
    entry_hash bytea not null,
    hash_algorithm text not null,
    signature bytea not null,
    signature_algorithm text not null,
    signature_key_version integer not null,
    created_at timestamptz not null default now(),
    constraint ledger_entries_id_uuid_v4 check (
        id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    constraint ledger_entries_sequence_no_positive check (sequence_no > 0),
    constraint ledger_entries_sequence_no_unique unique (sequence_no),
    constraint ledger_entries_entry_type_allowed check (
        length(entry_type) <= 64
        and public.ledger_entry_type_allowed(entry_type)
    ),
    constraint ledger_entries_source_event_at_canonical check (
        public.ledger_source_event_at_is_valid(source_event_at)
    ),
    constraint ledger_entries_actor_device_id_non_blank check (
        actor_device_id is null
        or (btrim(actor_device_id) <> '' and length(actor_device_id) <= 128)
    ),
    constraint ledger_entries_result_allowed check (result in ('success', 'failure')),
    constraint ledger_entries_error_code_non_blank check (
        error_code is null
        or (btrim(error_code) <> '' and length(error_code) <= 128)
    ),
    constraint ledger_entries_success_error_code_null check (
        result <> 'success'
        or error_code is null
    ),
    constraint ledger_entries_payload_valid check (
        public.ledger_payload_is_valid(entry_type, payload)
    ),
    constraint ledger_entries_canonicalization_version_v1 check (
        canonicalization_version = 1
    ),
    constraint ledger_entries_previous_entry_hash_len check (
        octet_length(previous_entry_hash) = 32
    ),
    constraint ledger_entries_entry_hash_len check (
        octet_length(entry_hash) = 32
    ),
    constraint ledger_entries_entry_hash_unique unique (entry_hash),
    constraint ledger_entries_hash_algorithm_sha256 check (
        hash_algorithm = 'sha-256'
    ),
    constraint ledger_entries_signature_len check (
        octet_length(signature) = 64
    ),
    constraint ledger_entries_signature_algorithm_ed25519 check (
        signature_algorithm = 'ed25519'
    ),
    constraint ledger_entries_signature_key_version_positive check (
        signature_key_version > 0
    )
);

comment on table public.ledger_entries
is 'Append-only Ledger Phase 1 entries for global hash-chain verification. Does not replace audit_events.';
comment on column public.ledger_entries.id is 'Caller-supplied UUID v4 idempotency key generated by Rust/SBC.';
comment on column public.ledger_entries.sequence_no is 'Caller-supplied expected global sequence number, verified under ledger_chain_state row lock.';
comment on column public.ledger_entries.source_event_at is 'Producer timestamp in canonical UTC RFC3339 text; part of the signed canonical payload.';
comment on column public.ledger_entries.source_event_id is 'Optional audit_events.id UUID snapshot. No FK so audit_events remains append-only and independent.';
comment on column public.ledger_entries.target_secret_id is 'Optional secret UUID snapshot. No FK to keep ledger verification independent of later lifecycle changes.';
comment on column public.ledger_entries.target_secret_version_id is 'Optional secret version UUID snapshot. No FK so four-generation purge cannot break ledger verification.';
comment on column public.ledger_entries.payload is 'Allowlisted, non-secret, flat JSON object. Canonical JSONB serialization is not used for hashing.';
comment on column public.ledger_entries.entry_hash is 'Rust/SBC-computed SHA-256 entry hash. SQL stores and chains it but does not recompute it.';
comment on column public.ledger_entries.signature is 'Rust/SBC-generated Ed25519 signature. SQL stores it but never holds signing private keys.';
comment on column public.ledger_entries.created_at is 'Database insertion timestamp. Not part of the signed canonical ledger payload.';

create index ledger_entries_request_id_idx on public.ledger_entries (request_id);
create index ledger_entries_source_event_id_idx on public.ledger_entries (source_event_id);
create index ledger_entries_target_secret_id_idx on public.ledger_entries (target_secret_id);
create index ledger_entries_target_secret_version_id_idx on public.ledger_entries (target_secret_version_id);
create index ledger_entries_actor_user_id_idx on public.ledger_entries (actor_user_id);
create index ledger_entries_entry_type_source_event_at_idx on public.ledger_entries (entry_type, source_event_at);
create index ledger_entries_signature_key_version_idx on public.ledger_entries (signature_key_version);

create table public.ledger_chain_state (
    chain_id text primary key,
    last_sequence_no bigint not null,
    last_entry_hash bytea not null,
    updated_at timestamptz not null default now(),
    constraint ledger_chain_state_global_only check (chain_id = 'global'),
    constraint ledger_chain_state_last_sequence_no_non_negative check (last_sequence_no >= 0),
    constraint ledger_chain_state_last_entry_hash_len check (octet_length(last_entry_hash) = 32)
);

comment on table public.ledger_chain_state
is 'Single-row global chain head for Ledger Phase 1. Updated only by rpc_append_ledger_entry for new entries.';
comment on column public.ledger_chain_state.chain_id is 'Fixed to global in Ledger Phase 1.';
comment on column public.ledger_chain_state.last_sequence_no is 'Current global chain head sequence. Initial genesis state is 0.';
comment on column public.ledger_chain_state.last_entry_hash is 'Current global chain head hash. Initial genesis previous hash is 32 zero bytes.';

insert into public.ledger_chain_state (
    chain_id,
    last_sequence_no,
    last_entry_hash,
    updated_at
)
values (
    'global',
    0,
    decode(repeat('00', 32), 'hex'),
    now()
);

create or replace function public.ledger_entries_immutable()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    raise exception 'ledger_entries_immutable'
        using errcode = '42501';
end;
$$;

comment on function public.ledger_entries_immutable()
is 'Rejects UPDATE, DELETE, and TRUNCATE on append-only ledger_entries.';

create trigger ledger_entries_no_update_delete
before update or delete on public.ledger_entries
for each row
execute function public.ledger_entries_immutable();

create trigger ledger_entries_no_truncate
before truncate on public.ledger_entries
for each statement
execute function public.ledger_entries_immutable();

create or replace function public.ledger_chain_state_no_delete_truncate()
returns trigger
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
    raise exception 'ledger_chain_state_mutation_restricted'
        using errcode = '42501';
end;
$$;

comment on function public.ledger_chain_state_no_delete_truncate()
is 'Rejects DELETE and TRUNCATE on ledger_chain_state; chain head UPDATE is reserved for rpc_append_ledger_entry.';

create trigger ledger_chain_state_no_delete
before delete on public.ledger_chain_state
for each row
execute function public.ledger_chain_state_no_delete_truncate();

create trigger ledger_chain_state_no_truncate
before truncate on public.ledger_chain_state
for each statement
execute function public.ledger_chain_state_no_delete_truncate();

alter table public.ledger_entries enable row level security;
alter table public.ledger_entries force row level security;

create policy ledger_entries_deny_all
    on public.ledger_entries
    as restrictive
    for all
    to public
    using (false)
    with check (false);

alter table public.ledger_chain_state enable row level security;
alter table public.ledger_chain_state force row level security;

create policy ledger_chain_state_deny_all
on public.ledger_chain_state
as restrictive
for all
to public
using (false)
with check (false);

-- Ledger append RPC and privileges

create or replace function public.rpc_append_ledger_entry(
    p_ledger_entry_id uuid,
    p_sequence_no bigint,
    p_entry_type text,
    p_source_event_at text,
    p_request_id uuid,
    p_source_event_id uuid,
    p_target_secret_id uuid,
    p_target_secret_version_id uuid,
    p_actor_user_id uuid,
    p_actor_device_id text,
    p_result text,
    p_error_code text,
    p_payload jsonb,
    p_canonicalization_version integer,
    p_previous_entry_hash bytea,
    p_entry_hash bytea,
    p_hash_algorithm text,
    p_signature bytea,
    p_signature_algorithm text,
    p_signature_key_version integer
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
    v_existing public.ledger_entries%rowtype;
    v_state public.ledger_chain_state%rowtype;
    v_constraint_name text;
begin
    if p_ledger_entry_id is null
        or p_sequence_no is null
        or p_entry_type is null
        or p_source_event_at is null
        or p_request_id is null
        or p_result is null
        or p_payload is null
        or p_canonicalization_version is null
        or p_previous_entry_hash is null
        or p_entry_hash is null
        or p_hash_algorithm is null
        or p_signature is null
        or p_signature_algorithm is null
        or p_signature_key_version is null
    then
        raise exception 'invalid_rpc_input'
            using errcode = '22023';
    end if;

    if p_sequence_no <= 0
        or octet_length(p_previous_entry_hash) <> 32
        or octet_length(p_entry_hash) <> 32
        or octet_length(p_signature) <> 64
    then
        raise exception 'invalid_rpc_input'
            using errcode = '22023';
    end if;

    select *
    into v_existing
    from public.ledger_entries
    where id = p_ledger_entry_id;

    if found then
        if v_existing.sequence_no is distinct from p_sequence_no
            or v_existing.entry_type is distinct from p_entry_type
            or v_existing.source_event_at is distinct from p_source_event_at
            or v_existing.request_id is distinct from p_request_id
            or v_existing.source_event_id is distinct from p_source_event_id
            or v_existing.target_secret_id is distinct from p_target_secret_id
            or v_existing.target_secret_version_id is distinct from p_target_secret_version_id
            or v_existing.actor_user_id is distinct from p_actor_user_id
            or v_existing.actor_device_id is distinct from p_actor_device_id
            or v_existing.result is distinct from p_result
            or v_existing.error_code is distinct from p_error_code
            or v_existing.payload is distinct from p_payload
            or v_existing.canonicalization_version is distinct from p_canonicalization_version
            or v_existing.previous_entry_hash is distinct from p_previous_entry_hash
            or v_existing.entry_hash is distinct from p_entry_hash
            or v_existing.hash_algorithm is distinct from p_hash_algorithm
            or v_existing.signature is distinct from p_signature
            or v_existing.signature_algorithm is distinct from p_signature_algorithm
            or v_existing.signature_key_version is distinct from p_signature_key_version
        then
            raise exception 'ledger_entry_id_conflict'
                using errcode = '23505';
        end if;

        select *
        into v_state
        from public.ledger_chain_state
        where chain_id = 'global';

        if not found then
            raise exception 'ledger_chain_state_missing'
                using errcode = '23514';
        end if;

        ledger_entry_id := v_existing.id;
        sequence_no := v_existing.sequence_no;
        entry_hash := v_existing.entry_hash;
        chain_last_sequence_no := v_state.last_sequence_no;
        chain_last_entry_hash := v_state.last_entry_hash;
        replayed := true;
        return next;
        return;
    end if;

    if not public.ledger_entry_type_allowed(p_entry_type)
        or length(p_entry_type) > 64
        or not public.ledger_source_event_at_is_valid(p_source_event_at)
        or p_result not in ('success', 'failure')
        or (p_error_code is not null and (btrim(p_error_code) = '' or length(p_error_code) > 128))
        or (p_result = 'success' and p_error_code is not null)
        or (p_actor_device_id is not null and (btrim(p_actor_device_id) = '' or length(p_actor_device_id) > 128))
        or p_canonicalization_version <> 1
        or p_hash_algorithm <> 'sha-256'
        or p_signature_algorithm <> 'ed25519'
        or p_signature_key_version <= 0
        or not public.ledger_payload_is_valid(p_entry_type, p_payload)
    then
        raise exception 'invalid_rpc_input'
            using errcode = '22023';
    end if;

    select *
    into v_state
    from public.ledger_chain_state
    where chain_id = 'global'
    for update;

    if not found then
        raise exception 'ledger_chain_state_missing'
            using errcode = '23514';
    end if;

    if p_sequence_no <> v_state.last_sequence_no + 1 then
        raise exception 'ledger_sequence_mismatch'
            using errcode = '40001';
    end if;

    if p_previous_entry_hash <> v_state.last_entry_hash then
        raise exception 'ledger_previous_hash_mismatch'
            using errcode = '40001';
    end if;

    begin
        insert into public.ledger_entries (
            id,
            sequence_no,
            entry_type,
            source_event_at,
            request_id,
            source_event_id,
            target_secret_id,
            target_secret_version_id,
            actor_user_id,
            actor_device_id,
            result,
            error_code,
            payload,
            canonicalization_version,
            previous_entry_hash,
            entry_hash,
            hash_algorithm,
            signature,
            signature_algorithm,
            signature_key_version
        )
        values (
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
    exception
        when unique_violation then
            get stacked diagnostics v_constraint_name = constraint_name;

            if v_constraint_name = 'ledger_entries_entry_hash_unique' then
                raise exception 'ledger_entry_hash_conflict'
                    using errcode = '23505';
            end if;

            raise exception 'ledger_entry_id_conflict'
                using errcode = '23505';
    end;

    update public.ledger_chain_state
    set last_sequence_no = p_sequence_no,
        last_entry_hash = p_entry_hash,
        updated_at = now()
    where chain_id = 'global';

    ledger_entry_id := p_ledger_entry_id;
    sequence_no := p_sequence_no;
    entry_hash := p_entry_hash;
    chain_last_sequence_no := p_sequence_no;
    chain_last_entry_hash := p_entry_hash;
    replayed := false;
    return next;
end;
$$;

comment on function public.rpc_append_ledger_entry(
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    text,
    text,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
)
is 'Appends or idempotently replays a Ledger Phase 1 global hash-chain entry. Existing id replay is checked before chain-state lock.';

revoke all on public.ledger_entries from anon;
revoke all on public.ledger_entries from authenticated;
revoke all on public.ledger_entries from service_role;
revoke all on public.ledger_chain_state from anon;
revoke all on public.ledger_chain_state from authenticated;
revoke all on public.ledger_chain_state from service_role;
grant select on public.ledger_chain_state to service_role;

revoke execute on function public.ledger_source_event_at_is_valid(text) from public;
revoke execute on function public.ledger_source_event_at_is_valid(text) from anon;
revoke execute on function public.ledger_source_event_at_is_valid(text) from authenticated;

revoke execute on function public.ledger_entry_type_allowed(text) from public;
revoke execute on function public.ledger_entry_type_allowed(text) from anon;
revoke execute on function public.ledger_entry_type_allowed(text) from authenticated;

revoke execute on function public.ledger_payload_allowed_keys(text) from public;
revoke execute on function public.ledger_payload_allowed_keys(text) from anon;
revoke execute on function public.ledger_payload_allowed_keys(text) from authenticated;

revoke execute on function public.ledger_payload_has_forbidden_key(jsonb) from public;
revoke execute on function public.ledger_payload_has_forbidden_key(jsonb) from anon;
revoke execute on function public.ledger_payload_has_forbidden_key(jsonb) from authenticated;

revoke execute on function public.ledger_payload_has_unknown_key(text, jsonb) from public;
revoke execute on function public.ledger_payload_has_unknown_key(text, jsonb) from anon;
revoke execute on function public.ledger_payload_has_unknown_key(text, jsonb) from authenticated;

revoke execute on function public.ledger_payload_schema_is_valid(text, jsonb) from public;
revoke execute on function public.ledger_payload_schema_is_valid(text, jsonb) from anon;
revoke execute on function public.ledger_payload_schema_is_valid(text, jsonb) from authenticated;

revoke execute on function public.ledger_payload_is_valid(text, jsonb) from public;
revoke execute on function public.ledger_payload_is_valid(text, jsonb) from anon;
revoke execute on function public.ledger_payload_is_valid(text, jsonb) from authenticated;

revoke execute on function public.ledger_entries_immutable() from public;
revoke execute on function public.ledger_entries_immutable() from anon;
revoke execute on function public.ledger_entries_immutable() from authenticated;

revoke execute on function public.ledger_chain_state_no_delete_truncate() from public;
revoke execute on function public.ledger_chain_state_no_delete_truncate() from anon;
revoke execute on function public.ledger_chain_state_no_delete_truncate() from authenticated;

revoke execute on function public.rpc_append_ledger_entry(
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    text,
    text,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) from public;
revoke execute on function public.rpc_append_ledger_entry(
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    text,
    text,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) from anon;
revoke execute on function public.rpc_append_ledger_entry(
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    text,
    text,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) from authenticated;
grant execute on function public.rpc_append_ledger_entry(
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    uuid,
    uuid,
    uuid,
    text,
    text,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) to service_role;

-- ============================================================================
-- Section 0960: ledger use-case integration RPCs
-- ============================================================================

-- Ledger Phase 1 use-case integration helpers.
-- audit_events remains the audit source of truth; these RPCs append ledger
-- entries in the same transaction as the corresponding authoritative audit row.

create or replace function public.rpc_append_ledger_entry_from_jsonb(p_entry jsonb)
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
    if p_entry is null or jsonb_typeof(p_entry) <> 'object' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return query
    select *
    from public.rpc_append_ledger_entry(
        (p_entry ->> 'p_ledger_entry_id')::uuid,
        (p_entry ->> 'p_sequence_no')::bigint,
        p_entry ->> 'p_entry_type',
        p_entry ->> 'p_source_event_at',
        (p_entry ->> 'p_request_id')::uuid,
        nullif(p_entry ->> 'p_source_event_id', '')::uuid,
        nullif(p_entry ->> 'p_target_secret_id', '')::uuid,
        nullif(p_entry ->> 'p_target_secret_version_id', '')::uuid,
        nullif(p_entry ->> 'p_actor_user_id', '')::uuid,
        nullif(p_entry ->> 'p_actor_device_id', ''),
        p_entry ->> 'p_result',
        nullif(p_entry ->> 'p_error_code', ''),
        p_entry -> 'p_payload',
        (p_entry ->> 'p_canonicalization_version')::integer,
        decode(substr(p_entry ->> 'p_previous_entry_hash', 3), 'hex'),
        decode(substr(p_entry ->> 'p_entry_hash', 3), 'hex'),
        p_entry ->> 'p_hash_algorithm',
        decode(substr(p_entry ->> 'p_signature', 3), 'hex'),
        p_entry ->> 'p_signature_algorithm',
        (p_entry ->> 'p_signature_key_version')::integer
    );
exception
    when invalid_text_representation
        or invalid_parameter_value
        or numeric_value_out_of_range
        or null_value_not_allowed
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
end;
$$;

comment on function public.rpc_append_ledger_entry_from_jsonb(jsonb)
is 'Internal Ledger Phase 1 helper that appends one signed ledger entry from Rust RPC JSON parameters.';

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

comment on function public.rpc_append_audit_event_with_ledger(
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb,
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) is
    'Appends a non-write-path audit event and its signed Ledger Phase 1 entry in one transaction.';

revoke execute on function public.rpc_append_ledger_entry_from_jsonb(jsonb) from public, anon, authenticated;
revoke execute on function public.rpc_append_ledger_entry_from_jsonb(jsonb) from public;

revoke execute on function public.rpc_append_audit_event_with_ledger(
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb,
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) from public, anon, authenticated;
revoke execute on function public.rpc_append_audit_event_with_ledger(
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb,
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) from public;

grant execute on function public.rpc_append_audit_event_with_ledger(
    uuid,
    uuid,
    uuid,
    text,
    text,
    uuid,
    text,
    integer,
    jsonb,
    uuid,
    bigint,
    text,
    text,
    uuid,
    uuid,
    text,
    jsonb,
    integer,
    bytea,
    bytea,
    text,
    bytea,
    text,
    integer
) to service_role;

-- ============================================================================
-- Section 0970: key rotation ledger integration
-- ============================================================================

-- Ledger Phase 1 key rotation integration.
-- The key rotation RPCs remain the transactional boundary for DB mutation and
-- authoritative audit_events writes; signed ledger entries are appended inside
-- that same transaction when provided by the SBC runtime.

drop function public.rpc_apply_key_rotation_batch(uuid, integer, integer, jsonb);

create function public.rpc_apply_key_rotation_batch(
    p_request_id uuid,
    p_old_key_version integer,
    p_new_key_version integer,
    p_rows jsonb,
    p_audit_event_id uuid default gen_random_uuid(),
    p_source_event_at text default null,
    p_ledger_entry jsonb default null
)
returns table (
    processed_count bigint,
    remaining_count bigint
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_batch_size bigint;
    v_processed_count bigint;
    v_remaining_count bigint;
    v_audit_metadata jsonb;
    v_ledger_payload jsonb;
begin
    if p_request_id is null
        or p_old_key_version is null
        or p_old_key_version <= 0
        or p_new_key_version is null
        or p_new_key_version <= 0
        or p_old_key_version = p_new_key_version
        or p_rows is null
        or jsonb_typeof(p_rows) <> 'array'
        or jsonb_array_length(p_rows) = 0
        or jsonb_array_length(p_rows) > 1000
        or p_audit_event_id is null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if exists (
        select 1
        from jsonb_array_elements(p_rows) as rows(row_value)
        where jsonb_typeof(rows.row_value) <> 'object'
            or not (
                rows.row_value ?& array[
                    'id',
                    'encrypted_data_key'
                ]
            )
            or rows.row_value - array[
                'id',
                'encrypted_data_key'
            ] <> '{}'::jsonb
            or jsonb_typeof(rows.row_value -> 'id') <> 'string'
            or jsonb_typeof(rows.row_value -> 'encrypted_data_key') <> 'string'
            or rows.row_value ->> 'id' !~ '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
            or rows.row_value ->> 'encrypted_data_key' !~ '^\\x([0-9A-Fa-f]{2}){73}$'
    ) then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if exists (
        select 1
        from (
            select lower(rows.row_value ->> 'id') as id
            from jsonb_array_elements(p_rows) as rows(row_value)
            group by lower(rows.row_value ->> 'id')
            having count(*) > 1
        ) duplicate_rows
    ) then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_ledger_entry is not null
        and (
            jsonb_typeof(p_ledger_entry) <> 'object'
            or p_source_event_at is null
            or not public.ledger_source_event_at_is_valid(p_source_event_at)
            or p_ledger_entry ->> 'p_entry_type' <> 'key_rotation_reencrypted'
            or (p_ledger_entry ->> 'p_request_id')::uuid is distinct from p_request_id
            or (p_ledger_entry ->> 'p_source_event_id')::uuid is distinct from p_audit_event_id
            or p_ledger_entry ->> 'p_source_event_at' <> p_source_event_at
            or p_ledger_entry ->> 'p_result' <> 'success'
            or nullif(p_ledger_entry ->> 'p_target_secret_id', '') is not null
            or nullif(p_ledger_entry ->> 'p_target_secret_version_id', '') is not null
            or nullif(p_ledger_entry ->> 'p_actor_user_id', '') is not null
            or nullif(p_ledger_entry ->> 'p_actor_device_id', '') is not null
        )
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    v_batch_size := jsonb_array_length(p_rows)::bigint;

    with rotation_rows as (
        select
            (rows.row_value ->> 'id')::uuid as id,
            decode(substr(rows.row_value ->> 'encrypted_data_key', 3), 'hex') as encrypted_data_key
        from jsonb_array_elements(p_rows) as rows(row_value)
    ),
    updated as (
        update public.secret_versions sv
        set
            encrypted_data_key = rotation_rows.encrypted_data_key,
            key_version = p_new_key_version
        from rotation_rows
        where sv.id = rotation_rows.id
            and sv.key_version = p_old_key_version
        returning sv.id
    )
    select count(*)::bigint
    into v_processed_count
    from updated;

    if v_processed_count <> v_batch_size then
        raise exception 'key_rotation_conflict' using errcode = '40001';
    end if;

    select count(*)::bigint
    into v_remaining_count
    from public.secret_versions sv
    where sv.key_version = p_old_key_version;

    v_ledger_payload := jsonb_build_object(
        'old_key_version',
        p_old_key_version,
        'new_key_version',
        p_new_key_version,
        'batch_size',
        v_batch_size,
        'processed_count',
        v_processed_count,
        'remaining_count',
        v_remaining_count
    );

    v_audit_metadata := v_ledger_payload;
    if p_ledger_entry is not null then
        v_audit_metadata := v_audit_metadata || jsonb_build_object(
            'source_event_at',
            p_source_event_at
        );

        if p_ledger_entry -> 'p_payload' <> v_ledger_payload then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;
    end if;

    if public.audit_metadata_has_forbidden_key(v_audit_metadata) then
        raise exception 'invalid_audit_metadata' using errcode = '22023';
    end if;

    insert into public.audit_events (
        id,
        request_id,
        action,
        result,
        key_version,
        metadata_json
    )
    values (
        p_audit_event_id,
        p_request_id,
        'key_rotation_reencrypt',
        'success',
        p_new_key_version,
        v_audit_metadata
    );

    if p_ledger_entry is not null then
        perform public.rpc_append_ledger_entry_from_jsonb(p_ledger_entry);
    end if;

    return query
    select
        v_processed_count,
        v_remaining_count;
end;
$$;

drop function public.rpc_complete_key_rotation(uuid, integer, integer);

create function public.rpc_complete_key_rotation(
    p_request_id uuid,
    p_old_key_version integer,
    p_new_key_version integer,
    p_audit_event_id uuid default gen_random_uuid(),
    p_source_event_at text default null,
    p_ledger_entry jsonb default null
)
returns table (
    remaining_count bigint
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_remaining_count bigint;
    v_audit_metadata jsonb;
    v_ledger_payload jsonb;
begin
    if p_request_id is null
        or p_old_key_version is null
        or p_old_key_version <= 0
        or p_new_key_version is null
        or p_new_key_version <= 0
        or p_old_key_version = p_new_key_version
        or p_audit_event_id is null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_ledger_entry is not null
        and (
            jsonb_typeof(p_ledger_entry) <> 'object'
            or p_source_event_at is null
            or not public.ledger_source_event_at_is_valid(p_source_event_at)
            or p_ledger_entry ->> 'p_entry_type' <> 'key_rotation_completed'
            or (p_ledger_entry ->> 'p_request_id')::uuid is distinct from p_request_id
            or (p_ledger_entry ->> 'p_source_event_id')::uuid is distinct from p_audit_event_id
            or p_ledger_entry ->> 'p_source_event_at' <> p_source_event_at
            or p_ledger_entry ->> 'p_result' <> 'success'
            or nullif(p_ledger_entry ->> 'p_target_secret_id', '') is not null
            or nullif(p_ledger_entry ->> 'p_target_secret_version_id', '') is not null
            or nullif(p_ledger_entry ->> 'p_actor_user_id', '') is not null
            or nullif(p_ledger_entry ->> 'p_actor_device_id', '') is not null
        )
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    select count(*)::bigint
    into v_remaining_count
    from public.secret_versions sv
    where sv.key_version = p_old_key_version;

    if v_remaining_count <> 0 then
        raise exception 'key_rotation_incomplete' using errcode = '23514';
    end if;

    v_ledger_payload := jsonb_build_object(
        'old_key_version',
        p_old_key_version,
        'new_key_version',
        p_new_key_version,
        'remaining_count',
        v_remaining_count
    );

    v_audit_metadata := v_ledger_payload;
    if p_ledger_entry is not null then
        v_audit_metadata := v_audit_metadata || jsonb_build_object(
            'source_event_at',
            p_source_event_at
        );

        if p_ledger_entry -> 'p_payload' <> v_ledger_payload then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;
    end if;

    if public.audit_metadata_has_forbidden_key(v_audit_metadata) then
        raise exception 'invalid_audit_metadata' using errcode = '22023';
    end if;

    insert into public.audit_events (
        id,
        request_id,
        action,
        result,
        key_version,
        metadata_json
    )
    values (
        p_audit_event_id,
        p_request_id,
        'key_rotation_complete',
        'success',
        p_new_key_version,
        v_audit_metadata
    );

    if p_ledger_entry is not null then
        perform public.rpc_append_ledger_entry_from_jsonb(p_ledger_entry);
    end if;

    return query
    select v_remaining_count;
end;
$$;

comment on function public.rpc_apply_key_rotation_batch(
    uuid,
    integer,
    integer,
    jsonb,
    uuid,
    text,
    jsonb
) is
    'Applies a validated encrypted_data_key rewrap batch and records key_rotation_reencrypt audit plus optional Ledger Phase 1 entry in one transaction. Each encrypted_data_key must be the 73-byte SBC envelope.';

comment on function public.rpc_complete_key_rotation(
    uuid,
    integer,
    integer,
    uuid,
    text,
    jsonb
) is
    'Completes Master Key rotation only after no rows remain on the old key version, then records key_rotation_complete audit plus optional Ledger Phase 1 entry.';

revoke execute on function public.rpc_apply_key_rotation_batch(
    uuid,
    integer,
    integer,
    jsonb,
    uuid,
    text,
    jsonb
) from public, anon, authenticated;
revoke execute on function public.rpc_apply_key_rotation_batch(
    uuid,
    integer,
    integer,
    jsonb,
    uuid,
    text,
    jsonb
) from public;

revoke execute on function public.rpc_complete_key_rotation(
    uuid,
    integer,
    integer,
    uuid,
    text,
    jsonb
) from public, anon, authenticated;
revoke execute on function public.rpc_complete_key_rotation(
    uuid,
    integer,
    integer,
    uuid,
    text,
    jsonb
) from public;

grant execute on function public.rpc_apply_key_rotation_batch(
    uuid,
    integer,
    integer,
    jsonb,
    uuid,
    text,
    jsonb
) to service_role;
grant execute on function public.rpc_complete_key_rotation(
    uuid,
    integer,
    integer,
    uuid,
    text,
    jsonb
) to service_role;

-- ============================================================================
-- Section 0980: auditor public boundary
-- ============================================================================

-- Auditor role and public key registry

-- Create auditor role

do $$
begin
    if not exists (
        select 1 from pg_catalog.pg_roles where rolname = 'mipsorcu_auditor'
    ) then
        create role mipsorcu_auditor with nologin inherit;
    end if;
end;
$$;

grant mipsorcu_auditor to postgres;
grant usage on schema extensions to mipsorcu_auditor;

-- Ledger signing public key registry

create table public.ledger_signing_public_keys (
    key_version integer primary key,
    public_key bytea not null,
    algorithm text not null default 'ed25519',
    status text not null default 'active',
    created_at timestamptz not null default now(),
    retired_at timestamptz,
    constraint ledger_signing_public_keys_key_version_positive check (key_version > 0),
    constraint ledger_signing_public_keys_public_key_len check (octet_length(public_key) = 32),
    constraint ledger_signing_public_keys_algorithm_fixed check (algorithm = 'ed25519'),
    constraint ledger_signing_public_keys_status_allowed check (status in ('active', 'retired')),
    constraint ledger_signing_public_keys_active_retired_at_null check (
        status <> 'active' or retired_at is null
    ),
    constraint ledger_signing_public_keys_retired_retired_at_not_null check (
        status <> 'retired' or retired_at is not null
    )
);

comment on table public.ledger_signing_public_keys
is 'Ed25519 public key registry for independent ledger signature verification by auditors. Public keys are non-secret.';
comment on column public.ledger_signing_public_keys.key_version
is 'Signing key version. Matches ledger_entries.signature_key_version. Immutable.';
comment on column public.ledger_signing_public_keys.public_key
is 'Ed25519 public key, 32 bytes. Non-secret, suitable for auditor distribution. Immutable.';
comment on column public.ledger_signing_public_keys.algorithm
is 'Signature algorithm. ed25519 fixed. Immutable.';
comment on column public.ledger_signing_public_keys.status
is 'active or retired. Only active -> retired transition is allowed.';
comment on column public.ledger_signing_public_keys.created_at
is 'Registration timestamp. Immutable.';
comment on column public.ledger_signing_public_keys.retired_at
is 'Retirement timestamp. Null for active keys.';

-- Immutability trigger

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
        if old.status = 'active'
            and new.status = 'retired'
            and old.key_version = new.key_version
            and old.public_key = new.public_key
            and old.algorithm = new.algorithm
            and old.created_at = new.created_at
            and new.retired_at is not null
        then
            return new;
        end if;

        raise exception 'ledger_signing_public_keys_immutable'
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

comment on function public.ledger_signing_public_keys_check_mutation()
is 'Rejects UPDATE (except active->retired), DELETE, and TRUNCATE on ledger_signing_public_keys.';

create trigger ledger_signing_public_keys_update_delete
before update or delete on public.ledger_signing_public_keys
for each row
execute function public.ledger_signing_public_keys_check_mutation();

create trigger ledger_signing_public_keys_truncate
before truncate on public.ledger_signing_public_keys
for each statement
execute function public.ledger_signing_public_keys_check_mutation();

-- RLS on public key table

alter table public.ledger_signing_public_keys enable row level security;
alter table public.ledger_signing_public_keys force row level security;

-- No restrictive deny_all on this table; auditors and service_role need
-- SELECT. INSERT / UPDATE / DELETE are controlled by the trigger above.

create policy ledger_signing_public_keys_select_auditor
    on public.ledger_signing_public_keys
    for select
    to mipsorcu_auditor
    using (true);

create policy ledger_signing_public_keys_select_service_role
    on public.ledger_signing_public_keys
    for select
    to service_role
    using (true);

-- Auditor security-barrier views

-- auditor_secret_inventory_view
create or replace view public.auditor_secret_inventory_view
with (security_barrier = true)
as
select
    s.id as secret_id,
    s.owner_user_id,
    s.classification,
    s.current_version_id,
    s.created_at as secret_created_at,
    s.updated_at as secret_updated_at
from public.secrets s;

comment on view public.auditor_secret_inventory_view
is 'Auditor-facing inventory of secrets (non-secret metadata only). security_barrier prevents leak via joins.';

-- auditor_audit_events_view
create or replace view public.auditor_audit_events_view
with (security_barrier = true)
as
select
    ae.id as audit_event_id,
    ae.request_id,
    ae.actor_user_id,
    ae.actor_device_id,
    ae.action,
    ae.target_secret_id,
    ae.result,
    ae.key_version,
    ae.metadata_json,
    ae.occurred_at
from public.audit_events ae;

comment on view public.auditor_audit_events_view
is 'Auditor-facing audit event log (non-secret metadata only). security_barrier prevents leak via joins.';

-- auditor_ledger_entries_view
create or replace view public.auditor_ledger_entries_view
with (security_barrier = true)
as
select
    le.id as ledger_entry_id,
    le.sequence_no,
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
    le.previous_entry_hash,
    le.entry_hash,
    le.hash_algorithm,
    le.signature,
    le.signature_algorithm,
    le.signature_key_version,
    le.created_at
from public.ledger_entries le;

comment on view public.auditor_ledger_entries_view
is 'Auditor-facing ledger entries (non-secret fields only). security_barrier prevents leak via joins.';

-- auditor_integrity_status_view
create or replace view public.auditor_integrity_status_view
with (security_barrier = true)
as
select
    lcs.chain_id,
    lcs.last_sequence_no,
    lcs.last_entry_hash,
    lcs.updated_at as chain_state_updated_at
from public.ledger_chain_state lcs;

comment on view public.auditor_integrity_status_view
is 'Auditor-facing global chain head state. security_barrier prevents leak via joins.';

-- Auditor public-key management RPCs

-- RPC: rpc_register_ledger_signing_public_key

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
        if v_existing.public_key = p_public_key
            and v_existing.status in ('active', 'retired')
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

        if v_existing.status = 'retired' then
            raise exception 'ledger_signing_public_key_retired'
                using errcode = '23505';
        end if;

        raise exception 'ledger_signing_public_key_conflict'
            using errcode = '23505';
    end if;

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
        'active',
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

comment on function public.rpc_register_ledger_signing_public_key(integer, bytea)
is 'Registers an Ed25519 public key for ledger signature verification. Idempotent for same key_version + public_key.';

-- RPC: rpc_retire_ledger_signing_public_key

create or replace function public.rpc_retire_ledger_signing_public_key(
    p_key_version integer
)
returns table (
    out_key_version integer,
    public_key bytea,
    algorithm text,
    status text,
    created_at timestamptz,
    retired_at timestamptz,
    already_retired boolean
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_row public.ledger_signing_public_keys%rowtype;
begin
    if p_key_version is null or p_key_version <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    select *
    into v_row
    from public.ledger_signing_public_keys
    where ledger_signing_public_keys.key_version = rpc_retire_ledger_signing_public_key.p_key_version;

    if not found then
        raise exception 'ledger_signing_public_key_not_found'
            using errcode = '02000';
    end if;

    if v_row.status = 'retired' then
        out_key_version := v_row.key_version;
        public_key := v_row.public_key;
        algorithm := v_row.algorithm;
        status := v_row.status;
        created_at := v_row.created_at;
        retired_at := v_row.retired_at;
        already_retired := true;
        return next;
        return;
    end if;

    update public.ledger_signing_public_keys
    set status = 'retired',
        retired_at = now()
    where ledger_signing_public_keys.key_version = rpc_retire_ledger_signing_public_key.p_key_version
    returning *
    into v_row;

    out_key_version := v_row.key_version;
    public_key := v_row.public_key;
    algorithm := v_row.algorithm;
    status := v_row.status;
    created_at := v_row.created_at;
    retired_at := v_row.retired_at;
    already_retired := false;
    return next;
end;
$$;

comment on function public.rpc_retire_ledger_signing_public_key(integer)
is 'Retires an active Ed25519 signing public key. Idempotent for already-retired keys.';

-- Auditor verification and export RPCs

-- RPC: rpc_verify_ledger_hash_chain

create or replace function public.rpc_verify_ledger_hash_chain(
    p_start_sequence_no bigint default null,
    p_end_sequence_no bigint default null
)
returns table (
    chain_valid boolean,
    entries_checked bigint,
    first_gap_sequence_no bigint,
    first_gap_detail text,
    first_hash_mismatch_sequence_no bigint,
    first_hash_mismatch_detail text,
    chain_head_sequence_no bigint,
    chain_head_entry_hash bytea
)
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
declare
    v_curr record;
    v_checked bigint := 0;
    v_chain_head record;
    v_expected_prev_hash bytea;
    v_expected_sequence_no bigint;
    v_last_sequence_no bigint := null;
    v_last_entry_hash bytea := null;
    v_zero_hash bytea := decode(repeat('00', 32), 'hex');
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

    select lcs.last_sequence_no, lcs.last_entry_hash
    into v_chain_head
    from public.ledger_chain_state lcs
    where lcs.chain_id = 'global';

    if not found then
        chain_valid := false;
        entries_checked := 0;
        first_gap_sequence_no := null;
        first_gap_detail := 'chain state missing';
        first_hash_mismatch_sequence_no := null;
        first_hash_mismatch_detail := null;
        chain_head_sequence_no := null;
        chain_head_entry_hash := null;
        return next;
        return;
    end if;

    chain_head_sequence_no := v_chain_head.last_sequence_no;
    chain_head_entry_hash := v_chain_head.last_entry_hash;
    v_expected_sequence_no := coalesce(p_start_sequence_no, 1);

    if p_start_sequence_no is not null and p_start_sequence_no > 1 then
        select prec.entry_hash
        into v_expected_prev_hash
        from public.ledger_entries prec
        where prec.sequence_no = p_start_sequence_no - 1;

        if not found then
            chain_valid := false;
            entries_checked := 0;
            first_gap_sequence_no := p_start_sequence_no - 1;
            first_gap_detail := 'sequence ' || (p_start_sequence_no - 1)::text
                || ': preceding ledger entry missing for range start '
                || p_start_sequence_no::text;
            first_hash_mismatch_sequence_no := null;
            first_hash_mismatch_detail := null;
            return next;
            return;
        end if;
    else
        v_expected_prev_hash := v_zero_hash;
    end if;

    for v_curr in
        select
            le.sequence_no,
            le.previous_entry_hash,
            le.entry_hash
        from public.ledger_entries le
        where (
            p_start_sequence_no is null
            or le.sequence_no >= p_start_sequence_no
        )
        and (
            p_end_sequence_no is null
            or le.sequence_no <= p_end_sequence_no
        )
        order by le.sequence_no
    loop
        if v_curr.sequence_no <> v_expected_sequence_no then
            chain_valid := false;
            entries_checked := v_checked;
            first_gap_sequence_no := v_expected_sequence_no;
            first_gap_detail := 'sequence ' || v_expected_sequence_no::text
                || ': expected sequence_no, found '
                || v_curr.sequence_no::text;
            first_hash_mismatch_sequence_no := null;
            first_hash_mismatch_detail := null;
            return next;
            return;
        end if;

        if v_curr.previous_entry_hash is distinct from v_expected_prev_hash then
            if v_expected_prev_hash = v_zero_hash then
                first_hash_mismatch_detail := 'sequence ' || v_curr.sequence_no::text
                    || ': previous_entry_hash does not match genesis zero hash';
            else
                first_hash_mismatch_detail := 'sequence ' || v_curr.sequence_no::text
                    || ': previous_entry_hash does not match preceding entry_hash '
                    || 'at sequence ' || (v_curr.sequence_no - 1)::text;
            end if;
            first_hash_mismatch_sequence_no := v_curr.sequence_no;
            chain_valid := false;
            entries_checked := v_checked;
            return next;
            return;
        end if;

        v_expected_prev_hash := v_curr.entry_hash;
        v_last_sequence_no := v_curr.sequence_no;
        v_last_entry_hash := v_curr.entry_hash;
        v_checked := v_checked + 1;
        v_expected_sequence_no := v_expected_sequence_no + 1;
    end loop;

    if p_end_sequence_no is not null and v_expected_sequence_no <= p_end_sequence_no then
        chain_valid := false;
        entries_checked := v_checked;
        first_gap_sequence_no := v_expected_sequence_no;
        first_gap_detail := 'sequence ' || v_expected_sequence_no::text
            || ': expected sequence_no before range end '
            || p_end_sequence_no::text;
        first_hash_mismatch_sequence_no := null;
        first_hash_mismatch_detail := null;
        return next;
        return;
    end if;

    if p_start_sequence_no is null and p_end_sequence_no is null then
        if v_checked = 0 then
            if v_chain_head.last_sequence_no is distinct from 0 then
                chain_valid := false;
                entries_checked := v_checked;
                first_gap_sequence_no := 1;
                first_gap_detail := 'ledger_chain_state last_sequence_no mismatch: '
                    || 'expected 0 for empty ledger, found '
                    || coalesce(v_chain_head.last_sequence_no::text, 'null');
                first_hash_mismatch_sequence_no := null;
                first_hash_mismatch_detail := null;
                return next;
                return;
            end if;

            if v_chain_head.last_entry_hash is distinct from v_zero_hash then
                chain_valid := false;
                entries_checked := v_checked;
                first_gap_sequence_no := null;
                first_gap_detail := null;
                first_hash_mismatch_sequence_no := 0;
                first_hash_mismatch_detail := 'ledger_chain_state last_entry_hash mismatch: '
                    || 'expected genesis zero hash for empty ledger';
                return next;
                return;
            end if;
        else
            if v_chain_head.last_sequence_no is distinct from v_last_sequence_no then
                chain_valid := false;
                entries_checked := v_checked;
                first_gap_sequence_no := v_last_sequence_no;
                first_gap_detail := 'ledger_chain_state last_sequence_no mismatch: expected '
                    || v_last_sequence_no::text || ', found '
                    || coalesce(v_chain_head.last_sequence_no::text, 'null');
                first_hash_mismatch_sequence_no := null;
                first_hash_mismatch_detail := null;
                return next;
                return;
            end if;

            if v_chain_head.last_entry_hash is distinct from v_last_entry_hash then
                chain_valid := false;
                entries_checked := v_checked;
                first_gap_sequence_no := null;
                first_gap_detail := null;
                first_hash_mismatch_sequence_no := v_last_sequence_no;
                first_hash_mismatch_detail := 'ledger_chain_state last_entry_hash mismatch: '
                    || 'expected entry_hash at sequence '
                    || v_last_sequence_no::text;
                return next;
                return;
            end if;
        end if;
    end if;

    chain_valid := true;
    entries_checked := v_checked;
    first_gap_sequence_no := null;
    first_gap_detail := null;
    first_hash_mismatch_sequence_no := null;
    first_hash_mismatch_detail := null;
    return next;
end;
$$;

comment on function public.rpc_verify_ledger_hash_chain(bigint, bigint)
is 'Read-only STABLE verifier for sequence_no continuity, previous_entry_hash chain, and full-chain ledger_chain_state consistency. Does not reconstruct canonical payload, recompute entry_hash, or verify Ed25519 signatures (Rust responsibility).';

-- RPC: rpc_verify_ledger_range

create or replace function public.rpc_verify_ledger_range(
    p_start_sequence_no bigint,
    p_end_sequence_no bigint
)
returns table (
    range_valid boolean,
    entries_checked bigint,
    expected_count bigint,
    detail text
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_expected bigint;
    v_actual bigint;
begin
    if p_start_sequence_no is null or p_start_sequence_no <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_end_sequence_no is null or p_end_sequence_no <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;
    if p_start_sequence_no > p_end_sequence_no then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    v_expected := p_end_sequence_no - p_start_sequence_no + 1;

    select count(*)::bigint
    into v_actual
    from public.ledger_entries le
    where le.sequence_no >= p_start_sequence_no
        and le.sequence_no <= p_end_sequence_no;

    entries_checked := v_actual;
    expected_count := v_expected;

    if v_actual = v_expected then
        range_valid := true;
        detail := 'range [' || p_start_sequence_no::text || ', '
            || p_end_sequence_no::text || '] is complete';
    else
        range_valid := false;
        detail := 'range [' || p_start_sequence_no::text || ', '
            || p_end_sequence_no::text || '] expected '
            || v_expected::text || ' entries, found ' || v_actual::text;
    end if;

    return next;
end;
$$;

comment on function public.rpc_verify_ledger_range(bigint, bigint)
is 'Verifies that a sequence_no range has exactly the expected number of entries with no gaps or extra entries.';

-- RPC: rpc_export_ledger_verification_materials

create or replace function public.rpc_export_ledger_verification_materials(
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

comment on function public.rpc_export_ledger_verification_materials(bigint, bigint)
is 'Exports complete non-secret ledger canonical fields with LEFT JOINed public key materials for independent auditor verification. Retired keys are included; missing keys produce pk_* IS NULL columns.';

-- GRANT / REVOKE

-- Grant auditor select on views
grant select on public.auditor_secret_inventory_view to mipsorcu_auditor;
grant select on public.auditor_audit_events_view to mipsorcu_auditor;
grant select on public.auditor_ledger_entries_view to mipsorcu_auditor;
grant select on public.auditor_integrity_status_view to mipsorcu_auditor;

-- Grant auditor execute on verification / export RPCs
grant execute on function public.rpc_verify_ledger_hash_chain(bigint, bigint)
    to mipsorcu_auditor;
grant execute on function public.rpc_verify_ledger_range(bigint, bigint)
    to mipsorcu_auditor;
grant execute on function public.rpc_export_ledger_verification_materials(bigint, bigint)
    to mipsorcu_auditor;

-- Grant service_role minimal privileges
grant select on public.ledger_signing_public_keys to service_role;
grant execute on function public.rpc_register_ledger_signing_public_key(integer, bytea)
    to service_role;
grant execute on function public.rpc_retire_ledger_signing_public_key(integer)
    to service_role;
grant execute on function public.rpc_verify_ledger_hash_chain(bigint, bigint)
    to service_role;
grant execute on function public.rpc_verify_ledger_range(bigint, bigint)
    to service_role;
grant execute on function public.rpc_export_ledger_verification_materials(bigint, bigint)
    to service_role;

-- Grant auditor select on public key registry
grant select on public.ledger_signing_public_keys to mipsorcu_auditor;

-- Revoke everything from anon / authenticated for new RPCs
revoke execute on function public.rpc_register_ledger_signing_public_key(integer, bytea)
    from anon, authenticated, public;
revoke execute on function public.rpc_retire_ledger_signing_public_key(integer)
    from anon, authenticated, public;
revoke execute on function public.rpc_verify_ledger_hash_chain(bigint, bigint)
    from anon, authenticated, public;
revoke execute on function public.rpc_verify_ledger_range(bigint, bigint)
    from anon, authenticated, public;
revoke execute on function public.rpc_export_ledger_verification_materials(bigint, bigint)
    from anon, authenticated, public;

-- Revoke table access from anon / authenticated
revoke all on public.ledger_signing_public_keys from anon, authenticated;
revoke all on public.auditor_secret_inventory_view from anon, authenticated;
revoke all on public.auditor_audit_events_view from anon, authenticated;
revoke all on public.auditor_ledger_entries_view from anon, authenticated;
revoke all on public.auditor_integrity_status_view from anon, authenticated;

-- Revoke view access from service_role (service_role uses base tables + RPCs, not views)
revoke all on public.auditor_secret_inventory_view from service_role;
revoke all on public.auditor_audit_events_view from service_role;
revoke all on public.auditor_ledger_entries_view from service_role;
revoke all on public.auditor_integrity_status_view from service_role;

-- Revoke service_role table-level DML on public key table (SELECT only)
revoke insert, update, delete, truncate on public.ledger_signing_public_keys from service_role;

-- ============================================================================
-- Section 0990: audit metadata allowlist and write RPC integration
-- ============================================================================

-- T04 audit metadata validation.
-- 時刻源と責務:
-- - audit_events.occurred_at は DB 側で発生時刻として now() を記録する既存責務を維持する。
-- - metadata_json.source_event_at は producer である SBC がイベント生成時に一度だけ決定し、
--   fallback / 再送 / sent マーカーでも同じ値を保持する。SQL 側は canonical UTC RFC3339（末尾 Z）
--   であることを検証し、値を再生成しない。
-- - secret_versions.created_at は SBC が決定した p_created_at を保存し、DB now() で置き換えない。

-- Audit metadata allowlist helpers

create or replace function public.audit_metadata_allowlist_mode()
returns text
language sql
stable
set search_path = public, pg_temp
as $$
    select case
        when current_setting('mipsorcu.audit_metadata_allowlist_mode', true) in ('warning', 'strict')
            then current_setting('mipsorcu.audit_metadata_allowlist_mode', true)
        else 'warning'
    end;
$$;

comment on function public.audit_metadata_allowlist_mode() is
    'Feature flag for audit metadata allowlist validation. Values: strict (reject unknown keys) or warning (log only). Defaults to warning during the staged allowlist migration. See docs/adr/0027-adr-audit-events-metadata-json-action-allowlist.md for staged migration plan.';


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
        else
            -- 未知action: fail-closed
            return true;
    end case;
    -- ACTION_ALLOWLIST_END

    -- トップレベルキー検証
    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        if not v_key = any(v_allowed_keys) then
            return true;
        end if;
    end loop;

    -- violation_summary サブオブジェクトキー検証
    if p_action = 'integrity_check' and p_metadata_json ? 'violation_summary' then
        if jsonb_typeof(p_metadata_json -> 'violation_summary') <> 'object' then
            return true;
        end if;

        for v_key in select jsonb_object_keys(p_metadata_json -> 'violation_summary')
        loop
            if not v_key = any(v_violation_summary_keys) then
                return true;
            end if;
        end loop;
    end if;

    return false;
end;
$$;

comment on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb) is
    'Returns true if metadata_json contains keys not in the allowlist for the given action and result. Enforces the action-specific schema from docs/audit_metadata_schema.md. Coexists with audit_metadata_has_forbidden_key as defense-in-depth.';

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
            v_required_keys := array[
                'phase',
                'sample_count',
                'trigger',
                'duration_ms'
            ];
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
            v_required_keys := array[
                'old_key_version',
                'new_key_version',
                'remaining_count'
            ];
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

comment on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean) is
    'Returns true if metadata_json is missing action-specific required keys. The require_source_event_at flag distinguishes append-audit RPCs (producer time required) from write RPC internal success audit metadata (producer time optional unless ledger-linked).';

-- ------------------------------------------------------------------------------
-- 値型検証: count/duration 系, version/key_version 系, violation_summary values,
-- trigger の enum 制約を検証する。
-- ------------------------------------------------------------------------------
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

    -- count/duration 系: JSON integer かつ >= 0
    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        continue when not v_key = any(array[
            'checked_secret_count',
            'checked_secret_version_count',
            'checked_audit_event_count',
            'duration_ms',
            'violation_count',
            'sample_count',
            'processed_count',
            'remaining_count'
        ]);

        v_val := p_metadata_json -> v_key;
        if jsonb_typeof(v_val) <> 'number' then
            return true;
        end if;
        if v_val::text !~ '^(0|[1-9][0-9]*)$' then
            return true;
        end if;
    end loop;

    -- version / key_version / batch_size 系: JSON integer かつ > 0
    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        continue when not v_key = any(array[
            'version',
            'old_key_version',
            'new_key_version',
            'failed_version',
            'batch_size'
        ]);

        v_val := p_metadata_json -> v_key;
        if v_key = 'failed_version' and v_val = 'null'::jsonb then
            continue;
        end if;
        if jsonb_typeof(v_val) <> 'number' then
            return true;
        end if;
        if v_val::text !~ '^[1-9][0-9]*$' then
            return true;
        end if;
    end loop;

    -- UUID v4 形式（ハイフン付き小文字）
    for v_key in select jsonb_object_keys(p_metadata_json)
    loop
        continue when not v_key = any(array[
            'secret_version_id',
            'attempted_secret_id'
        ]);

        v_val := p_metadata_json -> v_key;
        if jsonb_typeof(v_val) <> 'string' then
            return true;
        end if;
        v_text := p_metadata_json ->> v_key;
        if v_text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
            return true;
        end if;
    end loop;

    -- attempted_secret_id は decrypt failure metadata 専用の予約キー。
    if p_metadata_json ? 'attempted_secret_id'
        and not (p_action = 'decrypt' and p_result = 'failure')
    then
        return true;
    end if;

    -- error_code は failure metadata 専用。値は非空・最大64文字。
    if p_metadata_json ? 'error_code' then
        if p_result <> 'failure' then
            return true;
        end if;
        if jsonb_typeof(p_metadata_json -> 'error_code') <> 'string' then
            return true;
        end if;
        v_text := p_metadata_json ->> 'error_code';
        if btrim(v_text) = '' or length(v_text) > 64 then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'check_name' then
        if jsonb_typeof(p_metadata_json -> 'check_name') <> 'string'
            or p_metadata_json ->> 'check_name' <> 'mvp_integrity_check'
        then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'phase' then
        if jsonb_typeof(p_metadata_json -> 'phase') <> 'string'
            or p_metadata_json ->> 'phase' <> 'verify'
        then
            return true;
        end if;
    end if;

    if p_metadata_json ? 'reason' then
        if jsonb_typeof(p_metadata_json -> 'reason') <> 'string'
            or p_metadata_json ->> 'reason' <> 'no_current_secret_versions'
        then
            return true;
        end if;
    end if;

    if p_result = 'success' and p_metadata_json ? 'failed_version' then
        return true;
    end if;

    -- trigger: enum validation
    if p_metadata_json ? 'trigger' then
        if jsonb_typeof(p_metadata_json -> 'trigger') <> 'string' then
            return true;
        end if;
        if p_metadata_json ->> 'trigger' not in ('startup', 'background', 'cli') then
            return true;
        end if;
    end if;

    -- violation_summary values: JSON integer かつ >= 0
    if p_action = 'integrity_check' and p_metadata_json ? 'violation_summary' then
        if jsonb_typeof(p_metadata_json -> 'violation_summary') <> 'object' then
            return true;
        end if;

        for v_key, v_val in select * from jsonb_each(p_metadata_json -> 'violation_summary')
        loop
            if jsonb_typeof(v_val) <> 'number' then
                return true;
            end if;
            if v_val::text !~ '^(0|[1-9][0-9]*)$' then
                return true;
            end if;
        end loop;
    end if;

    return false;
end;
$$;

comment on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) is
    'Returns true if metadata_json contains values with invalid types, formats, or out-of-range values per action schema. Checks integers, UUID v4 strings, fixed values, trigger enum, error_code placement, attempted_secret_id reservation, and violation_summary value types.';

create or replace function public.audit_metadata_has_schema_violation_for_action(
    p_action text,
    p_result text,
    p_metadata_json jsonb,
    p_require_source_event_at boolean default true
)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    select public.audit_metadata_has_unknown_key_for_action(p_action, p_result, p_metadata_json)
        or public.audit_metadata_has_missing_required_key_for_action(
            p_action,
            p_result,
            p_metadata_json,
            p_require_source_event_at
        )
        or public.audit_metadata_has_invalid_value_for_action(p_action, p_result, p_metadata_json);
$$;

comment on function public.audit_metadata_has_schema_violation_for_action(text, text, jsonb, boolean) is
    'Action-specific audit metadata schema validation wrapper. In warning mode callers log violations only; in strict mode callers reject them as invalid_rpc_input.';

-- Audit append and write RPC integration

-- ------------------------------------------------------------------------------
-- RPC: rpc_append_audit_event
-- allowlist チェックを追加。denylist・source_event_at 検証と共存。
-- ------------------------------------------------------------------------------
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
        'key_rotation_complete'
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
    'Audit append RPC for non-write-path audit events and failure events. Added allowlist validation (Phase 2). Caller supplies a stable audit_event_id so fallback resend remains idempotent.';

-- ------------------------------------------------------------------------------
-- RPC: rpc_write_secret_version
-- 内部生成の audit metadata に対して allowlist 検証を追加
-- ------------------------------------------------------------------------------
create or replace function public.rpc_write_secret_version(
    p_request_id uuid,
    p_action text,
    p_secret_id uuid,
    p_owner_user_id uuid,
    p_classification text,
    p_created_by_device_id text,
    p_created_at timestamptz,
    p_version integer,
    p_ciphertext bytea,
    p_encrypted_data_key bytea,
    p_key_version integer,
    p_algorithm text,
    p_nonce_or_iv bytea,
    p_aad_context jsonb,
    p_secret_version_id uuid default gen_random_uuid(),
    p_ledger_entries jsonb default null
)
returns table (
    secret_id uuid,
    secret_version_id uuid,
    version integer,
    purged_version_ids uuid[]
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_current_secret public.secrets%rowtype;
    v_current_version integer;
    v_secret_version_id uuid;
    v_purged_version_ids uuid[] := array[]::uuid[];
    v_purged record;
    v_secret_version_from_aad integer;
    v_aad_created_at timestamptz;
    v_audit_metadata jsonb;
    v_write_ledger_entry jsonb;
    v_purge_ledger_entry jsonb;
    v_purge_ledger_count integer;
    v_constraint_name text;
    v_allowlist_mode text;
begin
    if p_request_id is null
        or p_action is null
        or p_secret_id is null
        or p_owner_user_id is null
        or p_classification is null
        or p_created_by_device_id is null
        or p_created_at is null
        or p_version is null
        or p_ciphertext is null
        or p_encrypted_data_key is null
        or p_key_version is null
        or p_algorithm is null
        or p_nonce_or_iv is null
        or p_aad_context is null
        or p_secret_version_id is null
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_action not in ('encrypt_create', 'encrypt_rotate') then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_secret_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_secret_version_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_ledger_entries is not null and jsonb_typeof(p_ledger_entries) <> 'array' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if btrim(p_classification) = '' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if btrim(p_created_by_device_id) = '' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_version <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if octet_length(p_ciphertext) = 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if octet_length(p_encrypted_data_key) <> 73 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_key_version <= 0 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_algorithm <> 'xchacha20-poly1305' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if octet_length(p_nonce_or_iv) <> 24 then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if jsonb_typeof(p_aad_context) is distinct from 'object' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if not (
        p_aad_context ?& array[
            'aad_version',
            'secret_id',
            'version',
            'owner_user_id',
            'classification',
            'created_at'
        ]
    )
        or p_aad_context - array[
            'aad_version',
            'secret_id',
            'version',
            'owner_user_id',
            'classification',
            'created_at'
        ] <> '{}'::jsonb
    then
        raise exception 'aad_context_mismatch' using errcode = '22023';
    end if;

    if jsonb_typeof(p_aad_context -> 'aad_version') is distinct from 'number'
        or jsonb_typeof(p_aad_context -> 'secret_id') is distinct from 'string'
        or jsonb_typeof(p_aad_context -> 'version') is distinct from 'number'
        or jsonb_typeof(p_aad_context -> 'owner_user_id') is distinct from 'string'
        or jsonb_typeof(p_aad_context -> 'classification') is distinct from 'string'
        or jsonb_typeof(p_aad_context -> 'created_at') is distinct from 'string'
        or p_aad_context ->> 'version' !~ '^[1-9][0-9]*$'
        or p_aad_context ->> 'created_at' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$'
    then
        raise exception 'aad_context_mismatch' using errcode = '22023';
    end if;

    begin
        v_secret_version_from_aad := (p_aad_context ->> 'version')::integer;
        v_aad_created_at := (p_aad_context ->> 'created_at')::timestamptz;
    exception
        when others then
            raise exception 'aad_context_mismatch' using errcode = '22023';
    end;

    if p_aad_context ->> 'aad_version' <> '1'
        or p_aad_context ->> 'secret_id' <> p_secret_id::text
        or v_secret_version_from_aad <> p_version
        or p_aad_context ->> 'owner_user_id' <> p_owner_user_id::text
        or p_aad_context ->> 'classification' <> p_classification
        or v_aad_created_at <> p_created_at
    then
        raise exception 'aad_context_mismatch' using errcode = '22023';
    end if;

    select *
    into v_current_secret
    from public.secrets s
    where s.id = p_secret_id
    for update;

    if not found then
        if p_action <> 'encrypt_create' or p_version <> 1 then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;

        insert into public.secrets (
            id,
            owner_user_id,
            classification,
            created_at,
            updated_at
        )
        values (
            p_secret_id,
            p_owner_user_id,
            p_classification,
            p_created_at,
            now()
        );
    else
        if p_action <> 'encrypt_rotate' then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;

        if v_current_secret.owner_user_id <> p_owner_user_id then
            raise exception 'owner_mismatch' using errcode = '42501';
        end if;

        if v_current_secret.classification <> p_classification then
            raise exception 'classification_immutable' using errcode = '23514';
        end if;

        select sv.version
        into v_current_version
        from public.secret_versions sv
        where sv.secret_id = p_secret_id
            and sv.id = v_current_secret.current_version_id;

        if v_current_version is null then
            raise exception 'db_integrity_violation' using errcode = '23514';
        end if;

        if p_version <> v_current_version + 1 then
            raise exception 'not_next_version' using errcode = '23514';
        end if;
    end if;

    begin
        insert into public.secret_versions (
            id,
            secret_id,
            version,
            ciphertext,
            encrypted_data_key,
            key_version,
            algorithm,
            classification,
            nonce_or_iv,
            aad_context,
            created_by_user_id,
            created_by_device_id,
            created_at
        )
        values (
            p_secret_version_id,
            p_secret_id,
            p_version,
            p_ciphertext,
            p_encrypted_data_key,
            p_key_version,
            p_algorithm,
            p_classification,
            p_nonce_or_iv,
            p_aad_context,
            p_owner_user_id,
            p_created_by_device_id,
            p_created_at
        )
        returning id into v_secret_version_id;
    exception
        when unique_violation then
            get stacked diagnostics v_constraint_name = constraint_name;

            if v_constraint_name = 'secret_versions_secret_nonce_unique' then
                raise exception 'nonce_reuse_detected' using errcode = '23505';
            end if;

            raise;
    end;

    update public.secrets
    set current_version_id = v_secret_version_id
    where id = p_secret_id;

    if p_ledger_entries is not null then
        select entries.entry
        into v_write_ledger_entry
        from jsonb_array_elements(p_ledger_entries) as entries(entry)
        where entries.entry ->> 'p_entry_type' = case
            when p_action = 'encrypt_create' then 'secret_created'
            else 'secret_version_created'
        end;

        if not found or (
            select count(*)::integer
            from jsonb_array_elements(p_ledger_entries) as entries(entry)
            where entries.entry ->> 'p_entry_type' in (
                'secret_created',
                'secret_version_created'
            )
        ) <> 1 then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;

        if v_write_ledger_entry ->> 'p_request_id' <> p_request_id::text
            or v_write_ledger_entry ->> 'p_source_event_id' is null
            or v_write_ledger_entry ->> 'p_target_secret_id' <> p_secret_id::text
            or v_write_ledger_entry ->> 'p_target_secret_version_id' <> v_secret_version_id::text
            or v_write_ledger_entry ->> 'p_actor_user_id' <> p_owner_user_id::text
            or v_write_ledger_entry ->> 'p_actor_device_id' <> p_created_by_device_id
            or v_write_ledger_entry ->> 'p_result' <> 'success'
            or v_write_ledger_entry ->> 'p_error_code' is not null
            or v_write_ledger_entry -> 'p_payload' ->> 'classification' <> p_classification
            or v_write_ledger_entry -> 'p_payload' ->> 'algorithm' <> p_algorithm
            or (v_write_ledger_entry -> 'p_payload' ->> 'version')::integer <> p_version
            or (v_write_ledger_entry -> 'p_payload' ->> 'key_version')::integer <> p_key_version
        then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;
    end if;

    v_audit_metadata := jsonb_build_object(
        'version',
        p_version,
        'secret_version_id',
        v_secret_version_id
    );

    if v_write_ledger_entry is not null then
        v_audit_metadata := v_audit_metadata || jsonb_build_object(
            'source_event_at',
            v_write_ledger_entry ->> 'p_source_event_at'
        );
    end if;

    if public.audit_metadata_has_forbidden_key(v_audit_metadata)
        or not public.audit_metadata_source_event_at_is_valid(v_audit_metadata)
    then
        raise exception 'invalid_audit_metadata' using errcode = '22023';
    end if;

    -- allowlist / schema validation for internal audit metadata (段階的移行対応)
    v_allowlist_mode := public.audit_metadata_allowlist_mode();

    if public.audit_metadata_has_schema_violation_for_action(p_action, 'success', v_audit_metadata, false) then
        if v_allowlist_mode = 'strict' then
            raise exception 'invalid_audit_metadata' using errcode = '22023';
        else
            raise notice 'audit_metadata_schema_warning: action=%, result=success, schema_violation_present',
                p_action;
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
        coalesce((v_write_ledger_entry ->> 'p_source_event_id')::uuid, gen_random_uuid()),
        p_request_id,
        p_owner_user_id,
        p_created_by_device_id,
        p_action,
        p_secret_id,
        'success',
        p_key_version,
        v_audit_metadata
    );

    if v_write_ledger_entry is not null then
        perform *
        from public.rpc_append_ledger_entry_from_jsonb(v_write_ledger_entry);
    end if;

    for v_purged in
        delete from public.secret_versions sv
        using (
            select ranked.id
            from (
                select
                    retained.id,
                    row_number() over (
                        partition by retained.secret_id
                        order by retained.version desc
                    ) as retained_rank
                from public.secret_versions retained
                where retained.secret_id = p_secret_id
            ) ranked
            where ranked.retained_rank > 4
        ) purge_candidates
        where sv.id = purge_candidates.id
        returning sv.id, sv.version, sv.key_version
    loop
        v_purged_version_ids := array_append(v_purged_version_ids, v_purged.id);

        v_purge_ledger_entry := null;
        if p_ledger_entries is not null then
            select entries.entry
            into v_purge_ledger_entry
            from jsonb_array_elements(p_ledger_entries) as entries(entry)
            where entries.entry ->> 'p_entry_type' = 'secret_version_purged'
                and entries.entry ->> 'p_target_secret_version_id' = v_purged.id::text;

            if not found
                or v_purge_ledger_entry ->> 'p_request_id' <> p_request_id::text
                or v_purge_ledger_entry ->> 'p_source_event_id' is null
                or v_purge_ledger_entry ->> 'p_target_secret_id' <> p_secret_id::text
                or v_purge_ledger_entry ->> 'p_actor_user_id' <> p_owner_user_id::text
                or v_purge_ledger_entry ->> 'p_actor_device_id' <> p_created_by_device_id
                or v_purge_ledger_entry ->> 'p_result' <> 'success'
                or v_purge_ledger_entry ->> 'p_error_code' is not null
                or (v_purge_ledger_entry -> 'p_payload' ->> 'version')::integer <> v_purged.version
                or (v_purge_ledger_entry -> 'p_payload' ->> 'key_version')::integer <> v_purged.key_version
                or (v_purge_ledger_entry -> 'p_payload' ->> 'retention_limit')::integer <> 4
            then
                raise exception 'invalid_rpc_input' using errcode = '22023';
            end if;
        end if;

        v_audit_metadata := jsonb_build_object(
            'version',
            v_purged.version,
            'secret_version_id',
            v_purged.id
        );

        if v_purge_ledger_entry is not null then
            v_audit_metadata := v_audit_metadata || jsonb_build_object(
                'source_event_at',
                v_purge_ledger_entry ->> 'p_source_event_at'
            );
        end if;

        if public.audit_metadata_has_forbidden_key(v_audit_metadata)
            or not public.audit_metadata_source_event_at_is_valid(v_audit_metadata)
        then
            raise exception 'invalid_audit_metadata' using errcode = '22023';
        end if;

        -- allowlist / schema validation for purge audit metadata (段階的移行対応)
        if public.audit_metadata_has_schema_violation_for_action('version_purge', 'success', v_audit_metadata, false) then
            if v_allowlist_mode = 'strict' then
                raise exception 'invalid_audit_metadata' using errcode = '22023';
            else
                raise notice 'audit_metadata_schema_warning: action=version_purge, result=success, schema_violation_present';
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
            coalesce((v_purge_ledger_entry ->> 'p_source_event_id')::uuid, gen_random_uuid()),
            p_request_id,
            p_owner_user_id,
            p_created_by_device_id,
            'version_purge',
            p_secret_id,
            'success',
            v_purged.key_version,
            v_audit_metadata
        );

        if v_purge_ledger_entry is not null then
            perform *
            from public.rpc_append_ledger_entry_from_jsonb(v_purge_ledger_entry);
        end if;
    end loop;

    if p_ledger_entries is not null then
        select count(*)::integer
        into v_purge_ledger_count
        from jsonb_array_elements(p_ledger_entries) as entries(entry)
        where entries.entry ->> 'p_entry_type' = 'secret_version_purged';

        if v_purge_ledger_count <> coalesce(array_length(v_purged_version_ids, 1), 0) then
            raise exception 'invalid_rpc_input' using errcode = '22023';
        end if;
    end if;

    return query
    select
        p_secret_id,
        v_secret_version_id,
        p_version,
        v_purged_version_ids;
end;
$$;

comment on function public.rpc_write_secret_version(
    uuid, text, uuid, uuid, text, text, timestamptz,
    integer, bytea, bytea, integer, text, bytea, jsonb, uuid, jsonb
) is
    'Authoritative production write RPC for encrypt_create and encrypt_rotate. Added allowlist validation for internally-generated audit metadata (Phase 2). Inserts the version, advances current_version_id, appends success audit events, and purges versions beyond retention in one transaction.';

-- ------------------------------------------------------------------------------
-- 権限設定
-- ------------------------------------------------------------------------------
revoke execute on function public.audit_metadata_allowlist_mode() from public, anon, authenticated;
revoke execute on function public.audit_metadata_allowlist_mode() from public;

revoke execute on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb) from public;

revoke execute on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean) from public;

revoke execute on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) from public;

revoke execute on function public.audit_metadata_has_schema_violation_for_action(text, text, jsonb, boolean) from public, anon, authenticated;
revoke execute on function public.audit_metadata_has_schema_violation_for_action(text, text, jsonb, boolean) from public;

grant execute on function public.audit_metadata_allowlist_mode() to service_role;
grant execute on function public.audit_metadata_has_unknown_key_for_action(text, text, jsonb) to service_role;
grant execute on function public.audit_metadata_has_missing_required_key_for_action(text, text, jsonb, boolean) to service_role;
grant execute on function public.audit_metadata_has_invalid_value_for_action(text, text, jsonb) to service_role;
grant execute on function public.audit_metadata_has_schema_violation_for_action(text, text, jsonb, boolean) to service_role;

revoke execute on function public.rpc_append_audit_event(
    uuid, uuid, uuid, text, text, uuid, text, integer, jsonb
) from public, anon, authenticated;
revoke execute on function public.rpc_append_audit_event(
    uuid, uuid, uuid, text, text, uuid, text, integer, jsonb
) from public;

grant execute on function public.rpc_append_audit_event(
    uuid, uuid, uuid, text, text, uuid, text, integer, jsonb
) to service_role;

revoke execute on function public.rpc_write_secret_version(
    uuid, text, uuid, uuid, text, text, timestamptz,
    integer, bytea, bytea, integer, text, bytea, jsonb, uuid, jsonb
) from public, anon, authenticated;
revoke execute on function public.rpc_write_secret_version(
    uuid, text, uuid, uuid, text, text, timestamptz,
    integer, bytea, bytea, integer, text, bytea, jsonb, uuid, jsonb
) from public;

grant execute on function public.rpc_write_secret_version(
    uuid, text, uuid, uuid, text, text, timestamptz,
    integer, bytea, bytea, integer, text, bytea, jsonb, uuid, jsonb
) to service_role;

-- ============================================================================
-- Section 0995: monthly digest action extensions
-- ============================================================================

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

-- ============================================================================
-- Section 0996: digest verification action extensions
-- ============================================================================

-- Ledger Phase 2: 月次 digest 検証サポート（ADR 0037 §7.4）。
--
-- 変更内容:
-- 0. ledger_payload_schema_is_valid: monthly_digest フィールドを追加（T06 バグ修正）
-- 1. rpc_append_audit_event: monthly_digest_generate（T06 バグ修正）と
--    monthly_digest_verify を action allowlist に追加
-- 2. audit_metadata_has_unknown_key_for_action: monthly_digest_verify case を追加
-- 3. rpc_fetch_monthly_digest_for_verification: 検証用 RPC を追加
--
-- 信頼境界: 非秘密メタデータ（digest fields, hashes, public key）のみを扱う。
-- 平文・マスターキー・データキー・JWT を含まない。

-- ─────────────────────────────────────────────────────────────────────────────
-- 0. ledger_payload_schema_is_valid: monthly_digest フィールドを追加（T06 バグ修正）
--    T06 で entry_count / digest_hash / target_year_month が schema validator に
--    追加されていなかったため、monthly_digest エントリの挿入が
--    ledger_entries_payload_valid 制約で拒否される問題を修正する。
--    Phase 1 の validate_ 関数を or replace で更新する。
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
        -- Ledger Phase 2 T07 (T06 fix): monthly_digest フィールド
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
is 'Validates type, length, vocabulary, and numeric range for ledger payload fields. Updated in T07 to add monthly_digest keys (entry_count, digest_hash, target_year_month).';

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. rpc_append_audit_event: monthly_digest_generate / monthly_digest_verify 追加
--    T06 で monthly_digest_generate が漏れていたバグを同時に修正する。
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
        'monthly_digest_verify'
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
    'Audit append RPC for non-write-path audit events and failure events. Updated in T07 to add monthly_digest_generate (T06 fix) and monthly_digest_verify.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. audit_metadata_has_unknown_key_for_action: monthly_digest_verify case 追加
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
is 'Returns true when audit metadata contains a key outside the allowlist for the given action. Updated in T07 to include monthly_digest_verify (and T06 monthly_digest_generate remains).';

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. rpc_fetch_monthly_digest_for_verification: 検証用 digest 情報取得 RPC
--    SECURITY DEFINER / read-only / set search_path = public, pg_temp
-- ─────────────────────────────────────────────────────────────────────────────

create or replace function public.rpc_fetch_monthly_digest_for_verification(
    p_year_month text
)
returns table(
    start_sequence_no       bigint,
    end_sequence_no         bigint,
    stored_entry_count      bigint,
    stored_digest_hash      text,
    target_year_month       text,
    digest_generated_at     text,
    signature               text,
    signature_key_version   integer,
    public_key              text,
    start_entry_hash        text,
    end_entry_hash          text
)
language plpgsql
stable
security definer
set search_path = public, pg_temp
as $$
begin
    if p_year_month is null or p_year_month !~ '^\d{4}-(0[1-9]|1[0-2])$' then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    return query
    select
        (le.payload->>'start_sequence_no')::bigint,
        (le.payload->>'end_sequence_no')::bigint,
        (le.payload->>'entry_count')::bigint,
        le.payload->>'digest_hash',
        le.payload->>'target_year_month',
        le.source_event_at,
        '\x' || encode(le.signature, 'hex'),
        le.signature_key_version,
        '\x' || encode(pk.public_key, 'hex'),
        '\x' || encode(le_start.entry_hash, 'hex'),
        '\x' || encode(le_end.entry_hash, 'hex')
    from public.ledger_entries le
    left join public.ledger_signing_public_keys pk
        on le.signature_key_version = pk.key_version
    join public.ledger_entries le_start
        on le_start.sequence_no = (le.payload->>'start_sequence_no')::bigint
    join public.ledger_entries le_end
        on le_end.sequence_no = (le.payload->>'end_sequence_no')::bigint
    where le.entry_type = 'monthly_digest'
      and le.payload->>'target_year_month' = p_year_month;
end;
$$;

comment on function public.rpc_fetch_monthly_digest_for_verification(text)
is 'Fetches all fields required for monthly digest verification from ledger_entries and ledger_signing_public_keys. Returns 0 rows if no digest exists for the given YYYY-MM period. T07.';

grant execute on function public.rpc_fetch_monthly_digest_for_verification(text)
    to service_role, mipsorcu_auditor;

revoke execute on function public.rpc_fetch_monthly_digest_for_verification(text)
    from anon, authenticated, public;

-- ============================================================================
-- Section 0997: archive exported action extensions
-- ============================================================================

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

-- ============================================================================
-- Section 0998: digest timestamped action extensions
-- ============================================================================

-- Ledger Phase 2 §8 / ADR 0040: 月次 digest 外部 timestamping サポート。
--
-- 変更内容:
-- 1. ledger_entry_type_allowed: 'digest_timestamped' を追加
-- 2. ledger_payload_allowed_keys: 'digest_timestamped' payload keys を追加
-- 3. ledger_payload_schema_is_valid: 'timestamp_token_hash' フィールド検証を追加
-- 4. rpc_append_audit_event: 'digest_timestamping' action を allowlist に追加
-- 5. audit_metadata_has_unknown_key_for_action: 'digest_timestamping' case を追加
--
-- 信頼境界: 非秘密メタデータのみを扱う。token raw bytes・平文・鍵・JWT を含まない。
-- timestamping への送信ペイロードは Rust 側 trait で `&DigestHash` に限定されている。
-- ledger には `timestamp_token_hash` (SHA-256 hex) のみを記録し、token raw bytes は
-- 呼び出し側責務で保管する（非秘密情報のみを Supabase に保存するため）。

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. ledger_entry_type_allowed: 'digest_timestamped' を追加
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
        'archive_exported',
        -- Ledger Phase 2 §8 / ADR 0040: 外部 timestamping 取得完了
        'digest_timestamped'
    );
$$;

comment on function public.ledger_entry_type_allowed(text)
is 'Returns true for all allowed ledger entry_type values. Updated in T10 to include digest_timestamped.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. ledger_payload_allowed_keys: 'digest_timestamped' payload keys を追加
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
        when 'archive_exported' then array[
            'archive_key',
            'digest_hash',
            'target_year_month'
        ]::text[]
        -- Ledger Phase 2 §8 / ADR 0040: digest_timestamped payload keys（アルファベット順）
        when 'digest_timestamped' then array[
            'digest_hash',
            'target_year_month',
            'timestamp_token_hash'
        ]::text[]
        else null::text[]
    end;
$$;

comment on function public.ledger_payload_allowed_keys(text)
is 'Returns top-level ledger payload keys allowed for a given entry_type. Updated in T10 to include digest_timestamped.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. ledger_payload_schema_is_valid: 'timestamp_token_hash' フィールド検証を追加
--    既存の Phase 2 T08 関数を or replace で更新。
--    追加: timestamp_token_hash（digest_hash と同じ 64 文字小文字 hex 制約）
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
        -- Ledger Phase 2 T10: timestamp_token_hash も同じ 64 文字 hex 制約
        elsif v_key in ('digest_hash', 'timestamp_token_hash') then
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
is 'Validates type, length, vocabulary, and numeric range for ledger payload fields. Updated in T10 to add timestamp_token_hash field.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. rpc_append_audit_event: 'digest_timestamping' action を allowlist に追加
--    'digest_timestamping' は success と failure の両方を記録する（result 制限なし）。
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
        -- Ledger Phase 2 §8 / ADR 0040: digest 外部 timestamping（成功・失敗両方を記録）
        'digest_timestamping'
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
    'Audit append RPC for non-write-path audit events and failure events. Updated in T10 to add digest_timestamping action.';

-- ─────────────────────────────────────────────────────────────────────────────
-- 5. audit_metadata_has_unknown_key_for_action: 'digest_timestamping' case を追加
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
        -- Ledger Phase 2 T10 §8 / ADR 0040: digest 外部 timestamping（成功・失敗両方を記録）
        -- timestamp_token_hash は success 時のみ実体を持つ（Rust 側 builder の責務）。
        when 'digest_timestamping' then
            v_allowed_keys := array[
                'digest_hash',
                'timestamp_token_hash',
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
is 'Returns true when audit metadata contains a key outside the allowlist for the given action. Updated in T10 to include digest_timestamping action.';

-- ============================================================================
-- Section 0999: SIEM forward failure and audit report extensions
-- ============================================================================

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

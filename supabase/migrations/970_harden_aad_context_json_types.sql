alter table public.secret_versions
    drop constraint if exists secret_versions_aad_context_matches_row,
    add constraint secret_versions_aad_context_matches_row check (
        jsonb_typeof(aad_context -> 'aad_version') = 'number'
        and jsonb_typeof(aad_context -> 'secret_id') = 'string'
        and jsonb_typeof(aad_context -> 'version') = 'number'
        and jsonb_typeof(aad_context -> 'owner_user_id') = 'string'
        and jsonb_typeof(aad_context -> 'classification') = 'string'
        and jsonb_typeof(aad_context -> 'created_at') = 'string'
        and aad_context ->> 'aad_version' = '1'
        and aad_context ->> 'secret_id' = secret_id::text
        and aad_context ->> 'version' ~ '^[1-9][0-9]*$'
        and aad_context ->> 'version' = version::text
        and aad_context ->> 'owner_user_id' = created_by_user_id::text
        and aad_context ->> 'classification' = classification
        and btrim(aad_context ->> 'classification') <> ''
        and aad_context ->> 'created_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$'
        and (aad_context ->> 'created_at')::timestamptz = created_at
    );

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
    p_aad_context jsonb
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
    then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_action not in ('encrypt_create', 'encrypt_rotate') then
        raise exception 'invalid_rpc_input' using errcode = '22023';
    end if;

    if p_secret_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' then
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

    if octet_length(p_encrypted_data_key) = 0 then
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

    insert into public.secret_versions (
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

    update public.secrets
    set current_version_id = v_secret_version_id
    where id = p_secret_id;

    v_audit_metadata := jsonb_build_object(
        'version',
        p_version,
        'secret_version_id',
        v_secret_version_id
    );

    if public.audit_metadata_has_forbidden_key(v_audit_metadata) then
        raise exception 'invalid_audit_metadata' using errcode = '22023';
    end if;

    insert into public.audit_events (
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
        p_request_id,
        p_owner_user_id,
        p_created_by_device_id,
        p_action,
        p_secret_id,
        'success',
        p_key_version,
        v_audit_metadata
    );

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

        v_audit_metadata := jsonb_build_object(
            'version',
            v_purged.version,
            'secret_version_id',
            v_purged.id
        );

        if public.audit_metadata_has_forbidden_key(v_audit_metadata) then
            raise exception 'invalid_audit_metadata' using errcode = '22023';
        end if;

        insert into public.audit_events (
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
            p_request_id,
            p_owner_user_id,
            p_created_by_device_id,
            'version_purge',
            p_secret_id,
            'success',
            v_purged.key_version,
            v_audit_metadata
        );
    end loop;

    return query
    select
        p_secret_id,
        v_secret_version_id,
        p_version,
        v_purged_version_ids;
end;
$$;

revoke execute on function public.rpc_write_secret_version(
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
    jsonb
) from public, anon, authenticated;
revoke execute on function public.rpc_write_secret_version(
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
    jsonb
) from public;

grant execute on function public.rpc_write_secret_version(
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
    jsonb
) to service_role;

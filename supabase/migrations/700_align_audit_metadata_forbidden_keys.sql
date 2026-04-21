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
            and lower(metadata_keys.key) in (
                -- FORBIDDEN_AUDIT_METADATA_KEYS_START
                'plaintext',
                'plain_text',
                'decrypted',
                'decrypted_data',
                'master_key',
                'data_key',
                'jwt',
                'service_role_key',
                'secret_key',
                'passphrase',
                'ciphertext',
                'encrypted_data_key'
                -- FORBIDDEN_AUDIT_METADATA_KEYS_END
            )
    );
$$;

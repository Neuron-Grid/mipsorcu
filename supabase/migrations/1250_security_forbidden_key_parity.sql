-- Section 1250: synchronize v0.1.0 security-boundary forbidden keys

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
                'alias_decryption_key',
                'alias_encryption_key',
                'alias_fingerprint_key',
                'authorization',
                'authorization_header',
                'bearer_token',
                'canonical_alias_plaintext',
                'ciphertext',
                'data_key',
                'decrypt_result',
                'decrypted',
                'decrypted_data',
                'ed25519_private_key',
                'encrypted_data_key',
                'jwt',
                'jwt_full',
                'ledger_signing_key',
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
                'secret_body',
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
    'Recursively rejects audit metadata keys that could carry secrets, credentials, request/response bodies, ciphertext, or private key material.';

create or replace function public.ledger_payload_has_forbidden_key(p_payload jsonb)
returns boolean
language sql
stable
set search_path = public, pg_temp
as $$
    with recursive nodes(value) as (
        values (p_payload)

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
        ) as payload_keys(key)
        where jsonb_typeof(nodes.value) = 'object'
            and lower(btrim(payload_keys.key)) in (
                -- FORBIDDEN_LEDGER_PAYLOAD_KEYS_START
                'alias_decryption_key',
                'alias_encryption_key',
                'alias_fingerprint_key',
                'authorization',
                'authorization_header',
                'bearer_token',
                'canonical_alias_plaintext',
                'ciphertext',
                'data_key',
                'decrypt_result',
                'decrypted',
                'decrypted_data',
                'ed25519_private_key',
                'encrypted_data_key',
                'jwt',
                'jwt_full',
                'ledger_signing_key',
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
                'secret_body',
                'secret_key',
                'secret_value',
                'service_role',
                'service_role_key',
                'token'
                -- FORBIDDEN_LEDGER_PAYLOAD_KEYS_END
            )
    );
$$;

comment on function public.ledger_payload_has_forbidden_key(jsonb) is
    'Recursively rejects ledger payload keys that could carry secrets, credentials, request/response bodies, ciphertext, or private key material.';

revoke execute on function public.audit_metadata_has_forbidden_key(jsonb) from public, anon, authenticated;
revoke execute on function public.ledger_payload_has_forbidden_key(jsonb) from public, anon, authenticated;

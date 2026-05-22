begin;

\ir _support/common.psql

select no_plan();

create temp table forbidden_keys (key_name text primary key);

insert into forbidden_keys (key_name)
values
    ('alias_decryption_key'),
    ('alias_encryption_key'),
    ('alias_fingerprint_key'),
    ('authorization'),
    ('authorization_header'),
    ('bearer_token'),
    ('canonical_alias_plaintext'),
    ('ciphertext'),
    ('data_key'),
    ('decrypt_result'),
    ('decrypted'),
    ('decrypted_data'),
    ('ed25519_private_key'),
    ('encrypted_data_key'),
    ('jwt'),
    ('jwt_full'),
    ('ledger_signing_key'),
    ('master_key'),
    ('passphrase'),
    ('password'),
    ('plain_text'),
    ('plaintext'),
    ('raw_jwt'),
    ('request_body'),
    ('request_body_full'),
    ('response_body'),
    ('response_body_full'),
    ('secret_body'),
    ('secret_key'),
    ('secret_value'),
    ('service_role'),
    ('service_role_key'),
    ('token');

select is(
    (
        select count(*)::integer
        from forbidden_keys
        where public.audit_metadata_has_forbidden_key(
            jsonb_build_object(key_name, 'redacted')
        )
    ),
    (select count(*)::integer from forbidden_keys),
    'audit metadata forbidden key guard covers the synchronized v0.1.0 key set'
);

select is(
    (
        select count(*)::integer
        from forbidden_keys
        where public.ledger_payload_has_forbidden_key(
            jsonb_build_object(key_name, 'redacted')
        )
    ),
    (select count(*)::integer from forbidden_keys),
    'ledger payload forbidden key guard covers the synchronized v0.1.0 key set'
);

select ok(
    public.audit_metadata_has_forbidden_key(
        '{"outer":[{" Alias_Encryption_Key ":"redacted"}]}'::jsonb
    ),
    'audit metadata guard is recursive, trims keys, and is case-insensitive'
);

select ok(
    public.ledger_payload_has_forbidden_key(
        '{"outer":[{" Ed25519_Private_Key ":"redacted"}]}'::jsonb
    ),
    'ledger payload guard is recursive, trims keys, and is case-insensitive'
);

select ok(
    not public.audit_metadata_has_forbidden_key(
        '{"alias_fingerprint":"aa","alias_fingerprint_key_version":1,"source_event_at":"2026-04-08T12:00:00Z"}'::jsonb
    ),
    'audit metadata guard allows alias fingerprint values and key version metadata'
);

select ok(
    not public.ledger_payload_has_forbidden_key(
        '{"classification":"confidential","version":1,"key_version":1,"algorithm":"xchacha20-poly1305"}'::jsonb
    ),
    'ledger payload guard allows safe payload keys'
);

select is_empty(
    $$
    select 1
    from public.audit_events
    where public.audit_metadata_has_forbidden_key(metadata_json)
    $$,
    'existing audit_events metadata has no forbidden keys'
);

select is_empty(
    $$
    select 1
    from public.ledger_entries
    where public.ledger_payload_has_forbidden_key(payload)
    $$,
    'existing ledger_entries payload has no forbidden keys'
);

select * from finish();
rollback;

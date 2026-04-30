create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

comment on schema public is
    'mipsorcu production schema. Stores ciphertext and non-secret metadata only; the SBC remains the trust boundary for keys, plaintext, JWT verification, and authorization.';

create table public.secrets (
    id uuid primary key,
    current_version_id uuid,
    owner_user_id uuid not null references auth.users (id) on delete restrict,
    classification text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint secrets_id_uuid_v4 check (
        id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    constraint secrets_classification_not_blank check (btrim(classification) <> '')
);

comment on table public.secrets is
    'Secret aggregate metadata. Owner and classification are stable after creation; current_version_id points to the only decryptable version.';
comment on column public.secrets.current_version_id is
    'Current decryptable version. RLS for authenticated reads exposes only this version through secret_versions.';
comment on column public.secrets.owner_user_id is
    'Supabase Auth user id that owns the secret. Authorization decisions are made on the SBC, with RLS as a read-side boundary.';
comment on column public.secrets.classification is
    'Immutable classification bound into each secret version AAD.';
comment on column public.secrets.created_at is
    'Secret aggregate metadata. Not bound into AAD. The write RPC stores the same SBC-determined timestamp as the initial secret_versions.created_at; the DB default is only a direct-insert fallback.';
comment on column public.secrets.updated_at is
    'Secret aggregate metadata. Automatically maintained by the tg_set_updated_at trigger.';

create table public.secret_versions (
    id uuid primary key default gen_random_uuid(),
    secret_id uuid not null references public.secrets (id) on delete restrict,
    version integer not null,
    ciphertext bytea not null,
    encrypted_data_key bytea not null,
    key_version integer not null,
    algorithm text not null,
    classification text not null,
    nonce_or_iv bytea not null,
    aad_context jsonb not null,
    created_by_user_id uuid not null references auth.users (id) on delete restrict,
    created_by_device_id text not null,
    created_at timestamptz not null,
    constraint secret_versions_version_positive check (version > 0),
    constraint secret_versions_ciphertext_not_empty check (octet_length(ciphertext) > 0),
    constraint secret_versions_encrypted_data_key_length check (
        octet_length(encrypted_data_key) = 73
    ),
    constraint secret_versions_key_version_positive check (key_version > 0),
    constraint secret_versions_algorithm_fixed check (algorithm = 'xchacha20-poly1305'),
    constraint secret_versions_classification_non_blank check (
        btrim(classification) <> ''
    ),
    constraint secret_versions_nonce_length check (octet_length(nonce_or_iv) = 24),
    constraint secret_versions_created_by_device_id_not_blank check (
        btrim(created_by_device_id) <> ''
    ),
    constraint secret_versions_aad_context_object check (
        jsonb_typeof(aad_context) = 'object'
    ),
    constraint secret_versions_aad_context_required_keys check (
        aad_context ?& array[
            'aad_version',
            'secret_id',
            'version',
            'owner_user_id',
            'classification',
            'created_at'
        ]
    ),
    constraint secret_versions_aad_context_allowed_keys check (
        aad_context - array[
            'aad_version',
            'secret_id',
            'version',
            'owner_user_id',
            'classification',
            'created_at'
        ] = '{}'::jsonb
    ),
    constraint secret_versions_classification_matches_aad check (
        aad_context ->> 'classification' = classification
    ),
    constraint secret_versions_aad_context_matches_row check (
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
    ),
    constraint secret_versions_secret_version_unique unique (secret_id, version),
    constraint secret_versions_secret_nonce_unique unique (secret_id, nonce_or_iv),
    constraint secret_versions_secret_id_id_unique unique (secret_id, id)
);

comment on table public.secret_versions is
    'Encrypted secret versions. Stores ciphertext, wrapped data key, nonce, key version, and structured AAD context; plaintext is never stored.';
comment on column public.secret_versions.ciphertext is
    'AEAD ciphertext produced on the SBC. Plaintext must never be stored in Postgres.';
comment on column public.secret_versions.encrypted_data_key is
    'Data key wrapped by the SBC Master Key. Stored as a 73-byte envelope for rewrap and decrypt workflows, but forbidden in logs and audit metadata.';
comment on column public.secret_versions.key_version is
    'SBC Master Key version used to wrap encrypted_data_key.';
comment on column public.secret_versions.algorithm is
    'Fixed AEAD algorithm. Multiple algorithm support is intentionally not part of the MVP.';
comment on column public.secret_versions.classification is
    'Classification snapshot for this encrypted version. Must match secrets.classification and aad_context.classification.';
comment on column public.secret_versions.nonce_or_iv is
    'XChaCha20-Poly1305 nonce. Must be 24 bytes and unique per retained secret version; secret_nonce_ledger prevents reuse after purge.';
comment on column public.secret_versions.aad_context is
    'Structured AAD v1 context with exactly six keys. Decrypt code must reconstruct canonical AAD on the SBC instead of serializing JSONB directly.';
comment on column public.secret_versions.created_at is
    'Timestamp determined by the SBC when constructing AAD. No DB default is allowed because this value is bound into AAD.';

alter table public.secrets
    add constraint secrets_current_version_fk
    foreign key (id, current_version_id)
    references public.secret_versions (secret_id, id)
    deferrable initially deferred;

create table public.secret_nonce_ledger (
    secret_id uuid not null references public.secrets (id) on delete restrict,
    nonce_or_iv bytea not null,
    first_secret_version_id uuid not null,
    created_at timestamptz not null default now(),
    primary key (secret_id, nonce_or_iv),
    constraint secret_nonce_ledger_nonce_length check (
        octet_length(nonce_or_iv) = 24
    )
);

comment on table public.secret_nonce_ledger is
    'Permanent nonce reuse prevention ledger. Rows are retained even when old secret_versions are purged.';
comment on column public.secret_nonce_ledger.first_secret_version_id is
    'First secret_versions.id observed for this nonce. Intentionally not an FK because secret_versions rows are physically purged.';

create table public.audit_events (
    id uuid primary key default gen_random_uuid(),
    request_id uuid not null,
    actor_user_id uuid references auth.users (id) on delete set null,
    actor_device_id text,
    action text not null,
    target_secret_id uuid references public.secrets (id) on delete restrict,
    result text not null,
    key_version integer,
    metadata_json jsonb not null default '{}'::jsonb,
    occurred_at timestamptz not null default now(),
    constraint audit_events_actor_device_id_not_blank check (
        actor_device_id is null or btrim(actor_device_id) <> ''
    ),
    constraint audit_events_action_allowed check (
        action in (
            'encrypt_create',
            'encrypt_rotate',
            'decrypt',
            'version_purge',
            'integrity_check',
            'restore_test',
            'key_rotation_start',
            'key_rotation_reencrypt',
            'key_rotation_complete'
        )
    ),
    constraint audit_events_result_allowed check (result in ('success', 'failure')),
    constraint audit_events_key_version_positive check (
        key_version is null or key_version > 0
    ),
    constraint audit_events_metadata_json_object check (
        jsonb_typeof(metadata_json) = 'object'
    )
);

comment on table public.audit_events is
    'Append-only audit source of truth. Runtime roles append through SECURITY DEFINER RPCs; direct DML privileges are revoked and UPDATE, DELETE, and TRUNCATE are rejected by trigger.';
comment on column public.audit_events.metadata_json is
    'Non-secret audit metadata. Forbidden secret-bearing keys are rejected recursively; source_event_at is reserved for producer-side event time.';
comment on column public.audit_events.occurred_at is
    'DB-confirmed audit event timestamp. For fallback resend events this is the resend time; producer-side event time is stored in metadata_json.source_event_at.';

create index secret_versions_key_version_idx on public.secret_versions (key_version);
create index secret_versions_created_by_user_id_idx
    on public.secret_versions (created_by_user_id);
create index secret_versions_secret_id_version_desc_idx
    on public.secret_versions (secret_id, version desc);
create index secrets_current_version_fk_idx
    on public.secrets (id, current_version_id);
create index secrets_owner_user_id_idx on public.secrets (owner_user_id);
create index audit_events_request_id_idx on public.audit_events (request_id);
create index audit_events_target_secret_id_idx on public.audit_events (target_secret_id);
create index audit_events_actor_user_id_idx on public.audit_events (actor_user_id);

alter table public.secrets enable row level security;
alter table public.secret_versions enable row level security;
alter table public.secret_nonce_ledger enable row level security;
alter table public.audit_events enable row level security;

alter table public.secrets force row level security;
alter table public.secret_versions force row level security;
alter table public.secret_nonce_ledger force row level security;
alter table public.audit_events force row level security;

revoke all on table public.secrets from anon, authenticated;
revoke all on table public.secret_versions from anon, authenticated;
revoke all on table public.secret_nonce_ledger from anon, authenticated;
revoke all on table public.audit_events from anon, authenticated;
revoke all privileges on table public.audit_events from service_role;
revoke select, insert, update, delete, truncate on table public.audit_events from service_role;
revoke all privileges on table public.secret_nonce_ledger from service_role;
revoke select, insert, update, delete, truncate on table public.secret_nonce_ledger from service_role;

grant select on table public.secrets to service_role;
grant select on table public.secret_versions to service_role;
revoke insert, update, delete, truncate on table public.secrets from service_role;
revoke insert, update, delete, truncate on table public.secret_versions from service_role;

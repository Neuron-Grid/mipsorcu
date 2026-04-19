create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

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

create table public.secret_versions (
    id uuid primary key default gen_random_uuid(),
    secret_id uuid not null references public.secrets (id) on delete restrict,
    version integer not null,
    ciphertext bytea not null,
    encrypted_data_key bytea not null,
    key_version integer not null,
    algorithm text not null,
    nonce_or_iv bytea not null,
    aad_context jsonb not null,
    created_by_user_id uuid not null references auth.users (id) on delete restrict,
    created_by_device_id text not null,
    created_at timestamptz not null,
    constraint secret_versions_version_positive check (version > 0),
    constraint secret_versions_ciphertext_not_empty check (octet_length(ciphertext) > 0),
    constraint secret_versions_encrypted_data_key_not_empty check (
        octet_length(encrypted_data_key) > 0
    ),
    constraint secret_versions_key_version_positive check (key_version > 0),
    constraint secret_versions_algorithm_fixed check (algorithm = 'xchacha20-poly1305'),
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
    constraint secret_versions_aad_context_matches_row check (
        aad_context ->> 'aad_version' is not null
        and aad_context ->> 'secret_id' is not null
        and aad_context ->> 'version' is not null
        and aad_context ->> 'owner_user_id' is not null
        and aad_context ->> 'classification' is not null
        and aad_context ->> 'created_at' is not null
        and aad_context ->> 'aad_version' = '1'
        and aad_context ->> 'secret_id' = secret_id::text
        and (aad_context ->> 'version')::integer = version
        and aad_context ->> 'owner_user_id' = created_by_user_id::text
        and btrim(aad_context ->> 'classification') <> ''
        and aad_context ->> 'created_at' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$'
        and (aad_context ->> 'created_at')::timestamptz = created_at
    ),
    constraint secret_versions_secret_version_unique unique (secret_id, version),
    constraint secret_versions_secret_nonce_unique unique (secret_id, nonce_or_iv),
    constraint secret_versions_secret_id_id_unique unique (secret_id, id)
);

alter table public.secrets
    add constraint secrets_current_version_fk
    foreign key (id, current_version_id)
    references public.secret_versions (secret_id, id)
    deferrable initially deferred;

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
alter table public.audit_events enable row level security;

alter table public.secrets force row level security;
alter table public.secret_versions force row level security;
alter table public.audit_events force row level security;

revoke all on table public.secrets from anon, authenticated;
revoke all on table public.secret_versions from anon, authenticated;
revoke all on table public.audit_events from anon, authenticated;

grant all on table public.secrets to service_role;
grant all on table public.secret_versions to service_role;
grant all on table public.audit_events to service_role;

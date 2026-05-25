alter table public.secret_versions
    add column wrapped_dek bytea,
    add column dek_wrap_algorithm text,
    add column kek_version integer;

alter table public.secret_versions
    add constraint secret_versions_dek_wrap_algorithm_check
    check (
        dek_wrap_algorithm is null
        or dek_wrap_algorithm in ('legacy-master-key-v1', 'envvar-xchacha-v2')
    );

alter table public.secret_versions
    add constraint secret_versions_envelope_v02_required
    check (
        dek_wrap_algorithm is null
        or dek_wrap_algorithm = 'legacy-master-key-v1'
        or (wrapped_dek is not null and kek_version is not null and kek_version > 0)
    );

alter table public.secret_versions
    add constraint secret_versions_kek_version_positive
    check (kek_version is null or kek_version > 0);

alter table public.secret_versions
    add constraint secret_versions_wrapped_dek_size
    check (wrapped_dek is null or octet_length(wrapped_dek) between 60 and 200);

comment on column public.secret_versions.wrapped_dek is
    'v0.2 envelope encryption field. DEK wrapped by the SBC KEK provider; required for envvar-xchacha-v2 rows during the dual-path period.';
comment on column public.secret_versions.dek_wrap_algorithm is
    'Nullable dual-path discriminator. NULL identifies existing v0.1.0 rows; envvar-xchacha-v2 identifies v0.2 envelope rows.';
comment on column public.secret_versions.kek_version is
    'KEK version used to wrap wrapped_dek. Nullable while v0.1.0 rows remain readable through the dual-path decrypt path.';

-- このマイグレーション以降の write は v0.2 形式（envvar-xchacha-v2）が想定。
-- v0.1.0 形式行（dek_wrap_algorithm IS NULL）は dual-path 復号で読み出し可能。
-- 旧形式行は key_rotation の lazy migration で段階的に v0.2 形式へ変換される。

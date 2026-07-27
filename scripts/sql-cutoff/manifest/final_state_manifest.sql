-- SQL cutoff final-state manifest 生成 query（正準形式・単一固定 script）
--
-- 正本: docs/v0.2.0/sql-cutoff/main-plan/task-t2-baseline-authoring.md T2-0
--       「manifest の正準形式（固定 query script）」
--
-- 本 script は catalog から final-state manifest を生成する唯一の query である。
-- 同一 script（同一 SHA-256）を legacy cluster と baseline candidate cluster の双方へ
-- 適用し、出力を比較する。script を変更した場合は `baseline_source_ref` が無効化される。
--
-- 出力契約:
--   - 1 行 1 entry。field は tab 区切りの 8 列（固定順）。
--       1: kind
--       2: identity          -- kind 内で一意
--       3: owner             -- 所有 role 名。該当なしは '-'
--       4: acl               -- raw ACL。catalog が NULL の場合は literal 'NULL'
--                            --（`acldefault()` 適用済みの実効 ACL と区別する）
--       5: comment_sha256    -- comment 本文の SHA-256。comment なしは '-'
--       6: definition_sha256 -- pg_get_*def の SHA-256。該当なしは '-'
--       7: attrs             -- kind 別に固定した catalog 列集合（key=value; 連結）
--       8: scope             -- 'public-contained' / 'boundary'
--   - 各 field は sanitize する（'\' -> '\\'、改行 -> '\n'、tab -> '\t'）。
--     これにより entry が必ず 1 行に収まり、field 境界が曖昧にならない。
--   - 並びは kind, identity の C collation 昇順で決定的。
--   - unknown kind を検出した場合、kind='__UNKNOWN__' の行を出力する。
--     harness は同行の存在を fail-close 条件として扱う（Stop Condition 11）。
--
-- application 境界:
--   本 profile（`bare-supabase-postgres-image-v1`）の pristine cluster では schema public
--   が完全に空である（relation 0 / routine 0 / type 0。T2-0 で実測）。したがって
--   「schema public に含まれる全 object」は例外なく migration chain が作成したものである。
--   public の外で migration chain が触れる対象（schema 自身の ACL、role、role membership、
--   default privilege、extension）は scope='boundary' として明示的に列挙する。
--   provenance（bootstrap 由来か application 由来か）は本 script では判定せず、
--   pristine cluster に対する同一 script の出力との差分で harness 側が決定する。
--
-- 副作用を持たない。対象 cluster を変更しない。

\set QUIET on
\set ON_ERROR_STOP on
\pset pager off
\pset tuples_only on
\pset format unaligned
\pset footer off

-- 関数 identity を `public.name(text,jsonb)` 形式（built-in 型は bare な catalog canonical
-- spelling、区切りは ',' で後続 whitespace なし）へ正規化するため search_path を固定する。
-- approved-semantic-differences.md の canonical_identity 規則と同一形式になる。
set search_path = pg_catalog;
set client_encoding = 'UTF8';
-- 出力順序は locale から独立させる（order by で明示的に C collation を指定する）。

with
-- ---------------------------------------------------------------- scope 定義
app_ns as (
    select oid, nspname from pg_namespace where nspname = 'public'
),
boundary_ns as (
    select oid, nspname, nspowner, nspacl
    from pg_namespace where nspname in ('public', 'extensions')
),
app_rel as (
    select c.oid, c.relname, c.relkind, c.relacl, c.relowner, c.reloptions,
           c.relrowsecurity, c.relforcerowsecurity, c.relpersistence,
           c.relispartition, c.relpersistence as persistence, n.nspname
    from pg_class c
    join app_ns n on n.oid = c.relnamespace
),

-- ---------------------------------------------------------------- schema
e_schema as (
    select 'schema' as kind,
           n.nspname::text as identity,
           pg_get_userbyid(n.nspowner)::text as owner,
           coalesce(n.nspacl::text, 'NULL') as acl,
           encode(sha256(convert_to(obj_description(n.oid, 'pg_namespace'), 'UTF8')), 'hex')
               as comment_sha256,
           '-' as definition_sha256,
           '' as attrs,
           'boundary' as scope
    from boundary_ns n
),

-- ---------------------------------------------------------------- table / partition
e_table as (
    select case when r.relispartition then 'partition' else 'table' end as kind,
           (r.nspname || '.' || r.relname)::text as identity,
           pg_get_userbyid(r.relowner)::text as owner,
           coalesce(r.relacl::text, 'NULL') as acl,
           encode(sha256(convert_to(obj_description(r.oid, 'pg_class'), 'UTF8')), 'hex')
               as comment_sha256,
           '-' as definition_sha256,
           concat_ws(';',
               'relkind=' || r.relkind::text,
               'rowsecurity=' || r.relrowsecurity,
               'forcerowsecurity=' || r.relforcerowsecurity,
               'persistence=' || r.relpersistence::text,
               'reloptions=' || coalesce(array_to_string(r.reloptions, ','), '-'),
               'partitioned=' || r.relispartition
           ) as attrs,
           'public-contained' as scope
    from app_rel r
    where r.relkind in ('r', 'p', 'f')
),

-- ---------------------------------------------------------------- column
e_column as (
    select 'column' as kind,
           (r.nspname || '.' || r.relname || '.' || a.attname)::text as identity,
           '-' as owner,
           coalesce(a.attacl::text, 'NULL') as acl,
           encode(sha256(convert_to(col_description(r.oid, a.attnum), 'UTF8')), 'hex')
               as comment_sha256,
           '-' as definition_sha256,
           concat_ws(';',
               'attnum=' || a.attnum,
               'type=' || format_type(a.atttypid, a.atttypmod),
               'notnull=' || a.attnotnull,
               'hasdef=' || a.atthasdef,
               'default=' || coalesce(
                   (select pg_get_expr(d.adbin, d.adrelid)
                    from pg_attrdef d
                    where d.adrelid = a.attrelid and d.adnum = a.attnum), '-'),
               'identity=' || coalesce(nullif(a.attidentity::text, ''), '-'),
               'generated=' || coalesce(nullif(a.attgenerated::text, ''), '-'),
               'collation=' || coalesce(
                   (select cl.collname from pg_collation cl where cl.oid = a.attcollation), '-')
           ) as attrs,
           'public-contained' as scope
    from app_rel r
    join pg_attribute a on a.attrelid = r.oid
    where a.attnum > 0
      and not a.attisdropped
      and r.relkind in ('r', 'p', 'v', 'm', 'f')
),

-- ---------------------------------------------------------------- view
e_view as (
    select 'view' as kind,
           (r.nspname || '.' || r.relname)::text as identity,
           pg_get_userbyid(r.relowner)::text as owner,
           coalesce(r.relacl::text, 'NULL') as acl,
           encode(sha256(convert_to(obj_description(r.oid, 'pg_class'), 'UTF8')), 'hex')
               as comment_sha256,
           encode(sha256(convert_to(pg_get_viewdef(r.oid, true), 'UTF8')), 'hex')
               as definition_sha256,
           concat_ws(';',
               'relkind=' || r.relkind::text,
               'reloptions=' || coalesce(array_to_string(r.reloptions, ','), '-')
           ) as attrs,
           'public-contained' as scope
    from app_rel r
    where r.relkind in ('v', 'm')
),

-- ---------------------------------------------------------------- sequence
e_sequence as (
    select 'sequence' as kind,
           (r.nspname || '.' || r.relname)::text as identity,
           pg_get_userbyid(r.relowner)::text as owner,
           coalesce(r.relacl::text, 'NULL') as acl,
           encode(sha256(convert_to(obj_description(r.oid, 'pg_class'), 'UTF8')), 'hex')
               as comment_sha256,
           '-' as definition_sha256,
           concat_ws(';',
               'seqtype=' || format_type(s.seqtypid, null),
               'start=' || s.seqstart,
               'increment=' || s.seqincrement,
               'max=' || s.seqmax,
               'min=' || s.seqmin,
               'cache=' || s.seqcache,
               'cycle=' || s.seqcycle,
               'ownedby=' || coalesce(
                   (select dn.nspname || '.' || dc.relname || '.' || da.attname
                    from pg_depend d
                    join pg_class dc on dc.oid = d.refobjid
                    join pg_namespace dn on dn.oid = dc.relnamespace
                    join pg_attribute da
                      on da.attrelid = d.refobjid and da.attnum = d.refobjsubid
                    where d.objid = r.oid
                      and d.classid = 'pg_class'::regclass
                      and d.refclassid = 'pg_class'::regclass
                      and d.deptype in ('a', 'i')
                    limit 1), '-')
           ) as attrs,
           'public-contained' as scope
    from app_rel r
    join pg_sequence s on s.seqrelid = r.oid
    where r.relkind = 'S'
),

-- ---------------------------------------------------------------- index
e_index as (
    select 'index' as kind,
           (r.nspname || '.' || r.relname)::text as identity,
           pg_get_userbyid(r.relowner)::text as owner,
           coalesce(r.relacl::text, 'NULL') as acl,
           encode(sha256(convert_to(obj_description(r.oid, 'pg_class'), 'UTF8')), 'hex')
               as comment_sha256,
           encode(sha256(convert_to(pg_get_indexdef(r.oid), 'UTF8')), 'hex')
               as definition_sha256,
           concat_ws(';',
               'relkind=' || r.relkind::text,
               'table=' || tn.nspname || '.' || t.relname,
               'unique=' || i.indisunique,
               'primary=' || i.indisprimary,
               'exclusion=' || i.indisexclusion,
               'immediate=' || i.indimmediate,
               'valid=' || i.indisvalid,
               'replident=' || i.indisreplident,
               'nullsnotdistinct=' || i.indnullsnotdistinct
           ) as attrs,
           'public-contained' as scope
    from app_rel r
    join pg_index i on i.indexrelid = r.oid
    join pg_class t on t.oid = i.indrelid
    join pg_namespace tn on tn.oid = t.relnamespace
    where r.relkind in ('i', 'I')
),

-- ---------------------------------------------------------------- constraint
e_constraint as (
    select 'constraint' as kind,
           (rn.nspname || '.' || rc.relname || '.' || con.conname)::text as identity,
           '-' as owner,
           'NULL' as acl,
           encode(sha256(convert_to(obj_description(con.oid, 'pg_constraint'), 'UTF8')), 'hex')
               as comment_sha256,
           encode(sha256(convert_to(pg_get_constraintdef(con.oid, true), 'UTF8')), 'hex')
               as definition_sha256,
           concat_ws(';',
               'contype=' || con.contype::text,
               'deferrable=' || con.condeferrable,
               'deferred=' || con.condeferred,
               'validated=' || con.convalidated,
               'islocal=' || con.conislocal,
               'noinherit=' || con.connoinherit
           ) as attrs,
           'public-contained' as scope
    from pg_constraint con
    join pg_class rc on rc.oid = con.conrelid
    join app_ns rn on rn.oid = rc.relnamespace
),

-- ---------------------------------------------------------------- trigger
e_trigger as (
    select 'trigger' as kind,
           (rn.nspname || '.' || rc.relname || '.' || tg.tgname)::text as identity,
           '-' as owner,
           'NULL' as acl,
           encode(sha256(convert_to(obj_description(tg.oid, 'pg_trigger'), 'UTF8')), 'hex')
               as comment_sha256,
           encode(sha256(convert_to(pg_get_triggerdef(tg.oid, true), 'UTF8')), 'hex')
               as definition_sha256,
           concat_ws(';',
               'enabled=' || tg.tgenabled::text,
               'tgtype=' || tg.tgtype,
               'internal=' || tg.tgisinternal,
               'deferrable=' || tg.tgdeferrable,
               'initdeferred=' || tg.tginitdeferred,
               'nargs=' || tg.tgnargs,
               'constraint=' || case when tg.tgconstraint = 0 then '-'
                                     else tg.tgconstraint::regclass::text end
           ) as attrs,
           'public-contained' as scope
    from pg_trigger tg
    join pg_class rc on rc.oid = tg.tgrelid
    join app_ns rn on rn.oid = rc.relnamespace
    where not tg.tgisinternal
),

-- ---------------------------------------------------------------- policy
e_policy as (
    select 'policy' as kind,
           (rn.nspname || '.' || rc.relname || '.' || pol.polname)::text as identity,
           '-' as owner,
           'NULL' as acl,
           encode(sha256(convert_to(obj_description(pol.oid, 'pg_policy'), 'UTF8')), 'hex')
               as comment_sha256,
           '-' as definition_sha256,
           concat_ws(';',
               'cmd=' || pol.polcmd::text,
               'permissive=' || pol.polpermissive,
               'roles=' || coalesce((
                   select string_agg(r.rolname, ',' order by r.rolname collate "C")
                   from unnest(pol.polroles) as pr(oid)
                   join pg_roles r on r.oid = pr.oid), 'PUBLIC'),
               'using=' || coalesce(pg_get_expr(pol.polqual, pol.polrelid), '-'),
               'withcheck=' || coalesce(pg_get_expr(pol.polwithcheck, pol.polrelid), '-')
           ) as attrs,
           'public-contained' as scope
    from pg_policy pol
    join pg_class rc on rc.oid = pol.polrelid
    join app_ns rn on rn.oid = rc.relnamespace
),

-- ---------------------------------------------------------------- function
e_function as (
    select 'function' as kind,
           p.oid::regprocedure::text as identity,
           pg_get_userbyid(p.proowner)::text as owner,
           coalesce(p.proacl::text, 'NULL') as acl,
           encode(sha256(convert_to(obj_description(p.oid, 'pg_proc'), 'UTF8')), 'hex')
               as comment_sha256,
           encode(sha256(convert_to(pg_get_functiondef(p.oid), 'UTF8')), 'hex')
               as definition_sha256,
           concat_ws(';',
               'prokind=' || p.prokind::text,
               'secdef=' || p.prosecdef,
               'volatile=' || p.provolatile::text,
               'strict=' || p.proisstrict,
               'leakproof=' || p.proleakproof,
               'parallel=' || p.proparallel::text,
               'lang=' || l.lanname,
               'rettype=' || format_type(p.prorettype, null),
               'retset=' || p.proretset,
               'config=' || coalesce(array_to_string(p.proconfig, ','), '-')
           ) as attrs,
           'public-contained' as scope
    from pg_proc p
    join app_ns n on n.oid = p.pronamespace
    join pg_language l on l.oid = p.prolang
    where p.prokind in ('f', 'p')
),

-- ---------------------------------------------------------------- type
-- relation 由来の row type と自動生成 array type は、独立した object ではなく
-- 他 entry の従属物であるため除外する。除外件数は meta で照合する。
e_type as (
    select 'type' as kind,
           (n.nspname || '.' || t.typname)::text as identity,
           pg_get_userbyid(t.typowner)::text as owner,
           coalesce(t.typacl::text, 'NULL') as acl,
           encode(sha256(convert_to(obj_description(t.oid, 'pg_type'), 'UTF8')), 'hex')
               as comment_sha256,
           '-' as definition_sha256,
           concat_ws(';',
               'typtype=' || t.typtype::text,
               'category=' || t.typcategory::text,
               'notnull=' || t.typnotnull,
               'basetype=' || case when t.typbasetype = 0 then '-'
                                   else format_type(t.typbasetype, t.typtypmod) end,
               'default=' || coalesce(t.typdefault, '-'),
               'enumlabels=' || coalesce((
                   select string_agg(e.enumlabel, ',' order by e.enumsortorder)
                   from pg_enum e where e.enumtypid = t.oid), '-'),
               'domainchecks=' || coalesce((
                   select string_agg(pg_get_constraintdef(dc.oid, true), ',' order by dc.conname collate "C")
                   from pg_constraint dc where dc.contypid = t.oid), '-')
           ) as attrs,
           'public-contained' as scope
    from pg_type t
    join app_ns n on n.oid = t.typnamespace
    where t.typtype <> 'p'
      -- 自動生成 array type を除外する
      and not exists (select 1 from pg_type b where b.typarray = t.oid)
      -- relation の row type を除外する（独立 composite type は relkind='c' で残る）
      and (t.typrelid = 0
           or exists (select 1 from pg_class rc
                      where rc.oid = t.typrelid and rc.relkind = 'c'))
),

-- ---------------------------------------------------------------- extension
e_extension as (
    select 'extension' as kind,
           x.extname::text as identity,
           pg_get_userbyid(x.extowner)::text as owner,
           'NULL' as acl,
           encode(sha256(convert_to(obj_description(x.oid, 'pg_extension'), 'UTF8')), 'hex')
               as comment_sha256,
           '-' as definition_sha256,
           concat_ws(';',
               'schema=' || n.nspname,
               'version=' || x.extversion,
               'relocatable=' || x.extrelocatable
           ) as attrs,
           'boundary' as scope
    from pg_extension x
    join pg_namespace n on n.oid = x.extnamespace
),

-- ---------------------------------------------------------------- role
-- 秘密列（rolpassword）を除外した allowlist 列のみを出力する。
-- pg_ prefix の built-in role は PostgreSQL 本体所有であり application 境界の外。
e_role as (
    select 'role' as kind,
           a.rolname::text as identity,
           '-' as owner,
           'NULL' as acl,
           encode(sha256(convert_to(shobj_description(a.oid, 'pg_authid'), 'UTF8')), 'hex')
               as comment_sha256,
           '-' as definition_sha256,
           concat_ws(';',
               'super=' || a.rolsuper,
               'inherit=' || a.rolinherit,
               'createrole=' || a.rolcreaterole,
               'createdb=' || a.rolcreatedb,
               'canlogin=' || a.rolcanlogin,
               'replication=' || a.rolreplication,
               'bypassrls=' || a.rolbypassrls,
               'connlimit=' || a.rolconnlimit,
               'validuntil=' || coalesce(a.rolvaliduntil::text, '-'),
               'config=' || coalesce((
                   select array_to_string(s.setconfig, ',')
                   from pg_db_role_setting s
                   where s.setrole = a.oid and s.setdatabase = 0), '-')
           ) as attrs,
           'boundary' as scope
    from pg_authid a
    where a.rolname not like 'pg\_%'
),

-- ---------------------------------------------------------------- role_membership
e_role_membership as (
    select 'role_membership' as kind,
           (m.rolname || '->' || g.rolname)::text as identity,
           '-' as owner,
           'NULL' as acl,
           '-' as comment_sha256,
           '-' as definition_sha256,
           concat_ws(';',
               'member=' || m.rolname,
               'group=' || g.rolname,
               'admin_option=' || am.admin_option,
               'inherit_option=' || am.inherit_option,
               'set_option=' || am.set_option,
               'grantor=' || pg_get_userbyid(am.grantor)
           ) as attrs,
           'boundary' as scope
    from pg_auth_members am
    join pg_authid m on m.oid = am.member
    join pg_authid g on g.oid = am.roleid
    where m.rolname not like 'pg\_%'
      and g.rolname not like 'pg\_%'
),

-- ---------------------------------------------------------------- default_privilege
e_default_privilege as (
    select 'default_privilege' as kind,
           pg_get_userbyid(d.defaclrole) || '|' ||
               case when d.defaclnamespace = 0 then '<global>'
                    else (select n.nspname from pg_namespace n where n.oid = d.defaclnamespace)
               end || '|' || d.defaclobjtype::text as identity,
           pg_get_userbyid(d.defaclrole)::text as owner,
           coalesce(d.defaclacl::text, 'NULL') as acl,
           '-' as comment_sha256,
           '-' as definition_sha256,
           concat_ws(';',
               'objtype=' || d.defaclobjtype::text,
               'namespace=' || case when d.defaclnamespace = 0 then '<global>'
                    else (select n.nspname from pg_namespace n where n.oid = d.defaclnamespace)
               end
           ) as attrs,
           'boundary' as scope
    from pg_default_acl d
),

-- ---------------------------------------------------------------- unknown kind fail-close
-- schema public に含まれる relation / routine / type のうち、上記 branch の
-- いずれにも該当しないものを検出する。1 行でも出力されたら harness は red とする。
e_unknown as (
    select '__UNKNOWN__' as kind,
           'relation:' || (r.nspname || '.' || r.relname)::text as identity,
           '-' as owner, 'NULL' as acl, '-' as comment_sha256, '-' as definition_sha256,
           'relkind=' || r.relkind::text as attrs,
           'public-contained' as scope
    from app_rel r
    where r.relkind not in ('r', 'p', 'f', 'v', 'm', 'S', 'i', 'I', 'c', 't')
    union all
    select '__UNKNOWN__',
           'routine:' || p.oid::regprocedure::text,
           '-', 'NULL', '-', '-',
           'prokind=' || p.prokind::text,
           'public-contained'
    from pg_proc p
    join app_ns n on n.oid = p.pronamespace
    where p.prokind not in ('f', 'p')
    union all
    select '__UNKNOWN__',
           'type:' || n.nspname || '.' || t.typname,
           '-', 'NULL', '-', '-',
           'typtype=' || t.typtype::text,
           'public-contained'
    from pg_type t
    join app_ns n on n.oid = t.typnamespace
    where t.typtype not in ('b', 'c', 'd', 'e', 'r', 'm', 'p')
    union all
    -- toast 以外の未対応 relkind が public に現れた場合の保険
    select '__UNKNOWN__',
           'relation-toast:' || r.nspname || '.' || r.relname,
           '-', 'NULL', '-', '-',
           'relkind=' || r.relkind::text,
           'public-contained'
    from app_rel r
    where r.relkind = 't'
),

-- ---------------------------------------------------------------- meta counters
-- 想定外の 0 件・除外件数を可視化する。harness が期待値と照合する。
e_meta as (
    select '__META__' as kind, k as identity, '-' as owner, 'NULL' as acl,
           '-' as comment_sha256, '-' as definition_sha256, v as attrs, 'meta' as scope
    from (
        select 'public_relation_total' as k,
               (select count(*)::text from app_rel) as v
        union all
        select 'public_routine_total',
               (select count(*)::text from pg_proc p join app_ns n on n.oid = p.pronamespace)
        union all
        select 'public_type_total',
               (select count(*)::text from pg_type t join app_ns n on n.oid = t.typnamespace)
        union all
        select 'excluded_array_types',
               (select count(*)::text from pg_type t join app_ns n on n.oid = t.typnamespace
                where exists (select 1 from pg_type b where b.typarray = t.oid))
        union all
        select 'excluded_relation_row_types',
               (select count(*)::text from pg_type t join app_ns n on n.oid = t.typnamespace
                where t.typrelid <> 0
                  and not exists (select 1 from pg_class rc
                                  where rc.oid = t.typrelid and rc.relkind = 'c'))
        union all
        select 'internal_triggers_excluded',
               (select count(*)::text from pg_trigger tg
                join pg_class rc on rc.oid = tg.tgrelid
                join app_ns rn on rn.oid = rc.relnamespace
                where tg.tgisinternal)
        union all
        select 'server_version', (select current_setting('server_version'))
    ) m
),

entries as (
    select * from e_schema
    union all select * from e_table
    union all select * from e_column
    union all select * from e_view
    union all select * from e_sequence
    union all select * from e_index
    union all select * from e_constraint
    union all select * from e_trigger
    union all select * from e_policy
    union all select * from e_function
    union all select * from e_type
    union all select * from e_extension
    union all select * from e_role
    union all select * from e_role_membership
    union all select * from e_default_privilege
    union all select * from e_unknown
    union all select * from e_meta
)

select array_to_string(
    array(
        select replace(
                   replace(
                       replace(coalesce(u.v, '-'), '\', '\\'),
                       E'\n', '\n'),
                   E'\t', '\t')
        from unnest(array[
            e.kind, e.identity, e.owner, e.acl,
            e.comment_sha256, e.definition_sha256, e.attrs, e.scope
        ]) with ordinality as u(v, ord)
        order by u.ord
    ), E'\t')
from entries e
order by e.kind collate "C", e.identity collate "C";

#!/usr/bin/env bash
# SQL cutoff: throwaway PostgreSQL cluster lifecycle.
#
# 01-execution-plan.md「2-Cluster 起動方式」の実装。
#
# - image は必ず digest 参照で起動する（tag 参照を禁止する）。
# - cluster ごとに run ID を含む専用 container 名・専用 named volume・専用 network を持つ。
# - 接続は localhost 限定 bind の TCP port で行う（unix socket は Rancher Desktop で不成立。
#   ref-freeze record `bare-supabase-postgres-image-v1` の接続方式）。
# - 同名資源が既に存在する場合は fail-close する（再利用・使い回しを禁止）。
# - run 終了時に自 run label の資源だけを破棄する。
#
# 利用側は SQL_CUTOFF_RUN_ID を設定してから本 file を source する。

set -u

# ref-freeze-20260726T225420Z/ref-freeze.md が固定する値。変更を禁止する。
SQL_CUTOFF_PG_IMAGE_DIGEST="public.ecr.aws/supabase/postgres@sha256:9faa7279bcf1fd6834e65dc876b11e39cb53030bcb3d653beb7e5668200acbb5"
SQL_CUTOFF_BOOTSTRAP_PROFILE="bare-supabase-postgres-image-v1"
SQL_CUTOFF_LABEL_KEY="io.mipsorcu.sql-cutoff.run"

# bootstrap 完了待ちの上限。超過した場合は fail-close する。
SQL_CUTOFF_READY_TIMEOUT_SECONDS="${SQL_CUTOFF_READY_TIMEOUT_SECONDS:-180}"

cluster_die() {
    printf 'FATAL: %s\n' "$*" >&2
    return 1
}

# 起動前に image の digest 一致を検証する。
cluster_verify_image_digest() {
    local found
    found="$(docker image inspect "$SQL_CUTOFF_PG_IMAGE_DIGEST" \
        --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null |
        grep -Fx "$SQL_CUTOFF_PG_IMAGE_DIGEST")"
    if [ -z "$found" ]; then
        cluster_die "image digest not present locally: $SQL_CUTOFF_PG_IMAGE_DIGEST"
        return 1
    fi
    printf 'image digest verified: %s\n' "$found"
    printf 'local image id: %s\n' \
        "$(docker image inspect "$SQL_CUTOFF_PG_IMAGE_DIGEST" --format '{{.Id}}')"
}

# localhost で空いている TCP port を 1 つ選ぶ。
cluster_pick_free_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# 同名資源の不在を確認する（再利用禁止）。
cluster_assert_absent() {
    local role="$1"
    local cname="mipsorcu-cutoff-${SQL_CUTOFF_RUN_ID}-${role}"
    local vname="$cname-data"
    local nname="$cname-net"
    local hit=0
    if [ -n "$(docker ps -aq --filter "name=^${cname}$")" ]; then
        printf 'FATAL: container already exists: %s\n' "$cname" >&2; hit=1
    fi
    if [ -n "$(docker volume ls -q --filter "name=^${vname}$")" ]; then
        printf 'FATAL: volume already exists: %s\n' "$vname" >&2; hit=1
    fi
    if [ -n "$(docker network ls -q --filter "name=^${nname}$")" ]; then
        printf 'FATAL: network already exists: %s\n' "$nname" >&2; hit=1
    fi
    return "$hit"
}

# cluster を起動し、CLUSTER_<ROLE>_PORT / _NAME を export する。
# usage: cluster_start <role>
cluster_start() {
    local role="$1"
    local cname="mipsorcu-cutoff-${SQL_CUTOFF_RUN_ID}-${role}"
    local vname="$cname-data"
    local nname="$cname-net"
    local port

    cluster_assert_absent "$role" || return 1

    port="$(cluster_pick_free_port)"
    if [ -z "$port" ]; then
        cluster_die "could not select a free localhost port"; return 1
    fi

    docker network create \
        --label "${SQL_CUTOFF_LABEL_KEY}=${SQL_CUTOFF_RUN_ID}" \
        "$nname" >/dev/null || { cluster_die "network create failed"; return 1; }
    docker volume create \
        --label "${SQL_CUTOFF_LABEL_KEY}=${SQL_CUTOFF_RUN_ID}" \
        "$vname" >/dev/null || { cluster_die "volume create failed"; return 1; }

    # POSTGRES_PASSWORD は throwaway cluster 起動のためだけの値であり、
    # 実データ・実運用 credential ではない。evidence へは記録しない。
    docker run -d \
        --name "$cname" \
        --network "$nname" \
        --label "${SQL_CUTOFF_LABEL_KEY}=${SQL_CUTOFF_RUN_ID}" \
        -v "$vname:/var/lib/postgresql/data" \
        -p "127.0.0.1:${port}:5432" \
        -e POSTGRES_PASSWORD="$SQL_CUTOFF_THROWAWAY_PASSWORD" \
        -e POSTGRES_DB=postgres \
        "$SQL_CUTOFF_PG_IMAGE_DIGEST" >/dev/null ||
        { cluster_die "container run failed"; return 1; }

    printf 'cluster %s: container=%s volume=%s network=%s endpoint=127.0.0.1:%s\n' \
        "$role" "$cname" "$vname" "$nname" "$port"

    eval "CLUSTER_${role}_NAME=\$cname"
    eval "CLUSTER_${role}_PORT=\$port"
    return 0
}

# bootstrap 完了まで待つ（上限付き）。
cluster_wait_ready() {
    local role="$1" port
    eval "port=\$CLUSTER_${role}_PORT"
    local waited=0
    while [ "$waited" -lt "$SQL_CUTOFF_READY_TIMEOUT_SECONDS" ]; do
        if PGPASSWORD="$SQL_CUTOFF_THROWAWAY_PASSWORD" psql \
            -h 127.0.0.1 -p "$port" -U postgres -d postgres \
            -v ON_ERROR_STOP=1 -Atqc 'select 1' >/dev/null 2>&1; then
            # initdb 後続 script の完走を待つため auth.users の出現も条件にする。
            if PGPASSWORD="$SQL_CUTOFF_THROWAWAY_PASSWORD" psql \
                -h 127.0.0.1 -p "$port" -U postgres -d postgres \
                -v ON_ERROR_STOP=1 -Atqc "select to_regclass('auth.users') is not null" \
                2>/dev/null | grep -qx t; then
                printf 'cluster %s ready after %ss\n' "$role" "$waited"
                return 0
            fi
        fi
        sleep 2
        waited=$((waited + 2))
    done
    cluster_die "cluster $role did not become ready within ${SQL_CUTOFF_READY_TIMEOUT_SECONDS}s"
    return 1
}

# psql を run 専用 endpoint へ向けて実行する。
# usage: cluster_psql <role> <args...>
cluster_psql() {
    local role="$1"; shift
    local port
    eval "port=\$CLUSTER_${role}_PORT"
    PGPASSWORD="$SQL_CUTOFF_THROWAWAY_PASSWORD" psql \
        -h 127.0.0.1 -p "$port" -U postgres -d postgres "$@"
}

# 自 run label が付いた資源だけを破棄する。
#
# 資源は 1 件ずつ削除する。この環境の Docker engine 29.1.3 は複数 ID を 1 回の
# `docker rm -f` へ渡すと `page not found` を返し、かつ exit code 0 を報告するため、
# 一括削除と exit code 依存の判定はいずれも成立しない（実測）。削除の成否は
# 削除後の再列挙（残数 0）で判定する。
cluster_teardown_all() {
    local id
    for id in $(docker ps -aq --filter "label=${SQL_CUTOFF_LABEL_KEY}=${SQL_CUTOFF_RUN_ID}"); do
        docker rm -f "$id" >/dev/null 2>&1
    done
    for id in $(docker volume ls -q --filter "label=${SQL_CUTOFF_LABEL_KEY}=${SQL_CUTOFF_RUN_ID}"); do
        docker volume rm "$id" >/dev/null 2>&1
    done
    for id in $(docker network ls -q --filter "label=${SQL_CUTOFF_LABEL_KEY}=${SQL_CUTOFF_RUN_ID}"); do
        docker network rm "$id" >/dev/null 2>&1
    done

    local c v n
    c="$(docker ps -aq --filter "label=${SQL_CUTOFF_LABEL_KEY}=${SQL_CUTOFF_RUN_ID}" | wc -l | tr -d ' ')"
    v="$(docker volume ls -q --filter "label=${SQL_CUTOFF_LABEL_KEY}=${SQL_CUTOFF_RUN_ID}" | wc -l | tr -d ' ')"
    n="$(docker network ls -q --filter "label=${SQL_CUTOFF_LABEL_KEY}=${SQL_CUTOFF_RUN_ID}" | wc -l | tr -d ' ')"
    printf 'teardown: run=%s remaining containers=%s volumes=%s networks=%s\n' \
        "$SQL_CUTOFF_RUN_ID" "$c" "$v" "$n"
    if [ "$c" != "0" ] || [ "$v" != "0" ] || [ "$n" != "0" ]; then
        printf 'FATAL: run resources were not fully removed\n' >&2
        return 1
    fi
    return 0
}

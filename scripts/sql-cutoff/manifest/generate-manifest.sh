#!/usr/bin/env bash
# SQL cutoff T2-0: legacy final-state manifest 生成 driver。
#
# frozen `legacy_source_ref` の full chain を throwaway cluster へ適用し、
# 固定 query script（final_state_manifest.sql）で final-state manifest を生成する。
# 同一 run 内で pristine cluster の snapshot も採取し、provenance（bootstrap 由来か
# application 由来か）を機械的に決定する。
#
# 入力は frozen ref から解決する（working tree からは採取しない）。
# 対象 cluster は run 専用であり、run 終了時に破棄する。
#
# usage: generate-manifest.sh <output-dir>

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUT_DIR="${1:?usage: generate-manifest.sh <output-dir>}"

LEGACY_REF='sql-cutoff/legacy-source-ref^{commit}'
MANIFEST_SQL="$SCRIPT_DIR/final_state_manifest.sql"

mkdir -p "$OUT_DIR"

RC_TOTAL=0
step() { printf '\n===== %s =====\n' "$*"; }
note() { printf '%s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; RC_TOTAL=1; }

step "run identity"
: "${SQL_CUTOFF_RUN_ID:?SQL_CUTOFF_RUN_ID must be set}"
note "run_id: $SQL_CUTOFF_RUN_ID"
note "started_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
note "repo_root: <source repository root>"
note "legacy_ref: $LEGACY_REF"
note "manifest_query_sha256: $(shasum -a 256 "$MANIFEST_SQL" | cut -d' ' -f1)"
note "driver_sha256: $(shasum -a 256 "${BASH_SOURCE[0]}" | cut -d' ' -f1)"
note "cluster_lib_sha256: $(shasum -a 256 "$SCRIPT_DIR/../lib/cluster.sh" | cut -d' ' -f1)"

# throwaway cluster 専用の使い捨て password。実運用 credential ではない。
# evidence へは書き出さない。
SQL_CUTOFF_THROWAWAY_PASSWORD="$(python3 -c 'import secrets;print(secrets.token_hex(16))')"
export SQL_CUTOFF_THROWAWAY_PASSWORD

# shellcheck source=../lib/cluster.sh
. "$SCRIPT_DIR/../lib/cluster.sh"

cleanup() { step "teardown"; cluster_teardown_all; }
trap cleanup EXIT

step "image digest verification"
cluster_verify_image_digest || { fail "image digest mismatch"; exit 1; }

step "frozen migration extraction"
WORK="$(mktemp -d)"
git -C "$REPO_ROOT" archive "$LEGACY_REF" supabase/migrations | tar -x -C "$WORK"
RC=$?
note "git archive exit=$RC"
[ "$RC" -eq 0 ] || { fail "git archive failed"; exit 1; }
MIG_DIR="$WORK/supabase/migrations"
MIG_COUNT="$(find "$MIG_DIR" -name '*.sql' | wc -l | tr -d ' ')"
note "extracted migration count: $MIG_COUNT"
[ "$MIG_COUNT" = "35" ] || fail "expected 35 migrations, got $MIG_COUNT"

step "start pristine cluster"
cluster_start pristine || { fail "pristine cluster start failed"; exit 1; }
cluster_wait_ready pristine || { fail "pristine cluster not ready"; exit 1; }

step "start legacy cluster"
cluster_start legacy || { fail "legacy cluster start failed"; exit 1; }
cluster_wait_ready legacy || { fail "legacy cluster not ready"; exit 1; }

step "pristine snapshot (bootstrap baseline)"
cluster_psql pristine -X -v ON_ERROR_STOP=1 -f "$MANIFEST_SQL" \
    > "$OUT_DIR/pristine-bootstrap-manifest.txt" 2> "$OUT_DIR/pristine-snapshot.err"
RC=$?
note "pristine snapshot exit=$RC lines=$(wc -l < "$OUT_DIR/pristine-bootstrap-manifest.txt" | tr -d ' ')"
[ -s "$OUT_DIR/pristine-snapshot.err" ] && { note "stderr:"; cat "$OUT_DIR/pristine-snapshot.err"; }
[ "$RC" -eq 0 ] || fail "pristine snapshot failed"

step "verify pristine schema public is empty (application scope premise)"
# BSD grep は -P（PCRE）を持たないため awk で tab 区切り field を直接突き合わせる。
for m in public_relation_total public_routine_total public_type_total; do
    V="$(awk -F'\t' -v k="$m" '$1=="__META__" && $2==k {print $7}' \
        "$OUT_DIR/pristine-bootstrap-manifest.txt")"
    note "$m=$V"
    [ "$V" = "0" ] || fail "pristine schema public is not empty: $m=[$V]"
done

step "apply frozen migration chain to legacy cluster"
APPLIED=0
for f in "$MIG_DIR"/*.sql; do
    B="$(basename "$f")"
    OUT="$(cluster_psql legacy -X -q -v ON_ERROR_STOP=1 -f "$f" 2>&1)"
    RC=$?
    if [ "$RC" -ne 0 ]; then
        note "APPLY-FAIL exit=$RC $B"
        printf '%s\n' "$OUT" | head -20
        fail "migration apply failed at $B"
        break
    fi
    APPLIED=$((APPLIED + 1))
    note "applied exit=$RC $B"
done
note "applied_total=$APPLIED"
[ "$APPLIED" = "35" ] || fail "expected 35 applied, got $APPLIED"

step "legacy final-state snapshot (legacy_actual_manifest, raw)"
cluster_psql legacy -X -v ON_ERROR_STOP=1 -f "$MANIFEST_SQL" \
    > "$OUT_DIR/legacy-actual-manifest.txt" 2> "$OUT_DIR/legacy-snapshot.err"
RC=$?
note "legacy snapshot exit=$RC lines=$(wc -l < "$OUT_DIR/legacy-actual-manifest.txt" | tr -d ' ')"
[ -s "$OUT_DIR/legacy-snapshot.err" ] && { note "stderr:"; cat "$OUT_DIR/legacy-snapshot.err"; }
[ "$RC" -eq 0 ] || fail "legacy snapshot failed"

step "unknown kind fail-close (Stop Condition 11)"
UNK="$(grep -c '^__UNKNOWN__' "$OUT_DIR/legacy-actual-manifest.txt")"
note "__UNKNOWN__ rows: $UNK"
[ "$UNK" = "0" ] || fail "unknown object kind detected in catalog"

step "identity uniqueness (Stop Condition 2)"
grep -v '^__META__' "$OUT_DIR/legacy-actual-manifest.txt" | cut -f1,2 | sort | uniq -d \
    > "$OUT_DIR/duplicate-identities.txt"
DUP="$(wc -l < "$OUT_DIR/duplicate-identities.txt" | tr -d ' ')"
note "duplicate (kind,identity) rows: $DUP"
if [ "$DUP" != "0" ]; then
    note "--- duplicates ---"
    cat "$OUT_DIR/duplicate-identities.txt"
    fail "identity is not unique under the implemented identity rule"
fi

step "genesis seed row count (reference inventory: 1)"
GEN="$(cluster_psql legacy -X -A -t -v ON_ERROR_STOP=1 \
    -c 'select count(*) from public.ledger_chain_state' 2>&1)"
RC=$?
note "ledger_chain_state rows=$GEN (exit=$RC)"
[ "$GEN" = "1" ] || fail "genesis seed row count is not 1"

step "kind histogram"
grep -v '^__META__' "$OUT_DIR/legacy-actual-manifest.txt" | cut -f1 | sort | uniq -c \
    | tee "$OUT_DIR/kind-histogram.txt"

step "meta counters"
grep '^__META__' "$OUT_DIR/legacy-actual-manifest.txt" | cut -f2,7 \
    | tee "$OUT_DIR/meta-counters.txt"

step "boundary-scope provenance delta (final vs pristine)"
grep -v '^__META__' "$OUT_DIR/pristine-bootstrap-manifest.txt" | sort > "$WORK/p.sorted"
grep -v '^__META__' "$OUT_DIR/legacy-actual-manifest.txt" | sort > "$WORK/f.sorted"
{
    echo "# entries present in legacy final state but not in pristine bootstrap"
    comm -13 "$WORK/p.sorted" "$WORK/f.sorted"
    echo "# entries present in pristine bootstrap but not in legacy final state"
    comm -23 "$WORK/p.sorted" "$WORK/f.sorted"
} > "$OUT_DIR/provenance-delta.txt"
note "provenance delta lines: $(wc -l < "$OUT_DIR/provenance-delta.txt" | tr -d ' ')"
note "--- boundary-scope delta identities ---"
comm -13 "$WORK/p.sorted" "$WORK/f.sorted" | awk -F'\t' '$8=="boundary"{print "  NEW/CHANGED  "$1"\t"$2}'
comm -23 "$WORK/p.sorted" "$WORK/f.sorted" | awk -F'\t' '$8=="boundary"{print "  WAS          "$1"\t"$2}'

step "digests"
for f in pristine-bootstrap-manifest.txt legacy-actual-manifest.txt provenance-delta.txt; do
    printf '%s  %s\n' "$(shasum -a 256 "$OUT_DIR/$f" | cut -d' ' -f1)" "$f"
done | tee "$OUT_DIR/manifest-digests.txt"

rm -rf "$WORK"

step "result"
note "finished_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ "$RC_TOTAL" -eq 0 ]; then
    note "OVERALL: PASS"
else
    note "OVERALL: FAIL (fail-close)"
fi
note "script_exit_code: $RC_TOTAL"
exit "$RC_TOTAL"

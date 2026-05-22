#!/usr/bin/env bash
set -euo pipefail

echo "============================================================"
echo " mipsorcu security check"
echo "============================================================"

echo "[1/7] Rust clippy (strict)"
cargo clippy --all-targets --all-features -- -D warnings
echo "  OK"

echo "[2/7] Rust tests"
RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}" cargo test --tests
echo "  OK"

echo "[3/7] Supabase pgTAP tests"
supabase test db
echo "  OK"

echo "[4/7] audit-ui guards"
(
    cd "audit-ui"
    bun run test:guards
)
echo "  OK"

echo "[5/7] audit-ui boundary"
bash "scripts/check-audit-ui-boundary.sh"
echo "  OK"

echo "[6/7] audit-ui source/test server-only env scan"
for path in "audit-ui/src" "audit-ui/tests"; do
    [[ -d "${path}" ]] || continue
    while IFS= read -r -d '' file; do
        case "${file}" in
            "audit-ui/src/redaction.ts" | "audit-ui/tests/e2e/audit-ui.spec.ts")
                continue
                ;;
        esac

        if grep -nE "MIPSORCU_SUPABASE_SERVICE_ROLE_KEY|MIPSORCU_MASTER_KEY|MIPSORCU_LEDGER_SIGNING_KEY|MIPSORCU_ALIAS_ENCRYPTION_KEY|MIPSORCU_ALIAS_FINGERPRINT_KEY|service_role|master_key|ledger_signing_key|alias_encryption_key|alias_fingerprint_key" "${file}"; then
            echo "  NG: audit-ui に server-only env または key marker を検出: ${file}"
            exit 1
        fi
    done < <(find "${path}" -type f \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' \) -print0)
done
echo "  OK"

echo "[7/7] Compose audit-ui environment"
command -v jq >/dev/null 2>&1 || {
    echo "  NG: jq が見つかりません"
    exit 1
}

compose_json="$(docker compose config --format json)"
leaks="$(
    printf '%s' "${compose_json}" |
        jq -r '
            (.services["audit-ui"].environment // {}) |
            to_entries[] |
            select(.key | test("SERVICE_ROLE|MASTER_KEY|LEDGER_SIGNING|ALIAS_ENCRYPTION|ALIAS_FINGERPRINT")) |
            select((.value // "") != "") |
            "\(.key)=\(.value)"
        '
)"

if [[ -n "${leaks}" ]]; then
    echo "  NG: compose.yaml の audit-ui environment に値ありの禁止キーを検出"
    printf '%s\n' "${leaks}"
    exit 1
fi
echo "  OK"

echo ""
echo "============================================================"
echo " OK: security check 完了"
echo "============================================================"

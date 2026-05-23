#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly DEFAULT_AUDIT_UI_REPO_DIR="${REPO_ROOT}/../mipsorcu-audit-ui"
readonly AUDIT_UI_REPO_DIR="${MIPSORCU_AUDIT_UI_REPO_DIR:-${DEFAULT_AUDIT_UI_REPO_DIR}}"

require_audit_ui_repo() {
    if [[ ! -d "${AUDIT_UI_REPO_DIR}" ]]; then
        echo "NG: audit-ui repository not found: ${AUDIT_UI_REPO_DIR}"
        echo "    Set MIPSORCU_AUDIT_UI_REPO_DIR to the external mipsorcu-audit-ui repository."
        exit 1
    fi

    if [[ ! -f "${AUDIT_UI_REPO_DIR}/package.json" ]]; then
        echo "NG: audit-ui package.json not found: ${AUDIT_UI_REPO_DIR}/package.json"
        exit 1
    fi
}

run_audit_ui() {
    local label="$1"
    shift

    echo "${label}"
    (
        cd "${AUDIT_UI_REPO_DIR}"
        "$@"
    )
    echo "  OK"
}

run_audit_ui_check() {
    local output
    local exit_code=0

    echo "[4/8] audit-ui check"
    output="$(
        cd "${AUDIT_UI_REPO_DIR}"
        bun run check
    2>&1)" || exit_code=$?
    printf '%s\n' "${output}"

    if [[ "${exit_code}" != "0" ]]; then
        echo "  NG: audit-ui check failed"
        exit "${exit_code}"
    fi

    if printf '%s' "${output}" | grep -qE 'Found [1-9][0-9]* warnings?\.'; then
        echo "  NG: audit-ui check emitted warnings"
        exit 1
    fi

    echo "  OK"
}

echo "============================================================"
echo " mipsorcu security check"
echo "============================================================"
echo " audit-ui repo: ${AUDIT_UI_REPO_DIR}"
echo "============================================================"

require_audit_ui_repo

echo "[1/8] Rust clippy (strict)"
(
    cd "${REPO_ROOT}"
    cargo clippy --all-targets --all-features -- -D warnings
)
echo "  OK"

echo "[2/8] Rust tests"
(
    cd "${REPO_ROOT}"
    RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}" cargo test --tests
)
echo "  OK"

echo "[3/8] Supabase pgTAP tests"
(
    cd "${REPO_ROOT}"
    supabase test db
)
echo "  OK"

run_audit_ui_check
run_audit_ui "[5/8] audit-ui guards" bun run test:guards
run_audit_ui "[6/8] audit-ui build" bun run build
run_audit_ui "[7/8] audit-ui E2E" bun run test:e2e

echo "[8/8] audit-ui boundary"
(
    cd "${REPO_ROOT}"
    MIPSORCU_AUDIT_UI_REPO_DIR="${AUDIT_UI_REPO_DIR}" bash "scripts/check-audit-ui-boundary.sh"
)
echo "  OK"

echo ""
echo "============================================================"
echo " OK: security check 完了"
echo "============================================================"

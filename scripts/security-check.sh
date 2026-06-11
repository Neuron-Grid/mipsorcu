#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly DEFAULT_AUDIT_UI_REPO_DIR="${REPO_ROOT}/../mipsorcu-audit-ui"
readonly AUDIT_UI_REPO_DIR="${MIPSORCU_AUDIT_UI_REPO_DIR:-${DEFAULT_AUDIT_UI_REPO_DIR}}"

check_supabase_config_layout() {
    local tracked_nested_files
    tracked_nested_files="$(git -C "${REPO_ROOT}" ls-files "supabase/supabase")"

    if [[ -n "${tracked_nested_files}" ]]; then
        echo "  NG: tracked nested Supabase project files found"
        printf '%s\n' "${tracked_nested_files}"
        exit 1
    fi

    local expected_config_path="${REPO_ROOT}/supabase/config.toml"
    local config_paths
    config_paths="$(find "${REPO_ROOT}/supabase" -name "config.toml" -type f | sort)"

    if [[ "${config_paths}" != "${expected_config_path}" ]]; then
        echo "  NG: expected exactly one Supabase config at ${expected_config_path}"
        echo "  Found:"
        if [[ -n "${config_paths}" ]]; then
            printf '%s\n' "${config_paths}"
        else
            echo "    (none)"
        fi
        exit 1
    fi
}

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

    echo "[5/9] audit-ui check"
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

echo "[1/9] Supabase config layout"
check_supabase_config_layout
echo "  OK"

require_audit_ui_repo

echo "[2/9] Rust clippy (strict)"
(
    cd "${REPO_ROOT}"
    cargo clippy --all-targets --all-features -- -D warnings
)
echo "  OK"

echo "[3/9] Rust tests"
(
    cd "${REPO_ROOT}"
    RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}" cargo test --tests
)
echo "  OK"

echo "[4/9] Supabase pgTAP tests"
(
    cd "${REPO_ROOT}"
    supabase test db
)
echo "  OK"

run_audit_ui_check
run_audit_ui "[6/9] audit-ui guards" bun run test:guards
run_audit_ui "[7/9] audit-ui build" bun run build
run_audit_ui "[8/9] audit-ui E2E" bun run test:e2e

echo "[9/9] audit-ui boundary"
(
    cd "${REPO_ROOT}"
    MIPSORCU_AUDIT_UI_REPO_DIR="${AUDIT_UI_REPO_DIR}" bash "scripts/check-audit-ui-boundary.sh"
)
echo "  OK"

echo ""
echo "============================================================"
echo " OK: security check 完了"
echo "============================================================"

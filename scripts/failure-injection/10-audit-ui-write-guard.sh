#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"

readonly DEFAULT_AUDIT_UI_REPO_DIR="${FAILURE_REPO_ROOT}/../mipsorcu-audit-ui"
readonly AUDIT_UI_REPO_DIR="${MIPSORCU_AUDIT_UI_REPO_DIR:-${DEFAULT_AUDIT_UI_REPO_DIR}}"
readonly TAINT_FILE="${AUDIT_UI_REPO_DIR}/src/__tainted_for_guard_test__.ts"

cleanup_taint_file() {
    rm -f "${TAINT_FILE}"
}
trap cleanup_taint_file EXIT

require_command "bun"
require_failure_injection_allowed

[[ -d "${AUDIT_UI_REPO_DIR}" ]] \
    || fail "audit-ui repository not found: ${AUDIT_UI_REPO_DIR}"
[[ -f "${AUDIT_UI_REPO_DIR}/package.json" ]] \
    || fail "audit-ui package.json not found: ${AUDIT_UI_REPO_DIR}/package.json"
[[ -d "${AUDIT_UI_REPO_DIR}/src" ]] \
    || fail "audit-ui src directory not found: ${AUDIT_UI_REPO_DIR}/src"
[[ ! -e "${TAINT_FILE}" ]] \
    || fail "refusing to overwrite existing taint file: ${TAINT_FILE}"

log_info "Scenario 10: audit-ui write-capable code is detected by test:guards"
log_info "audit-ui repo: ${AUDIT_UI_REPO_DIR}"

printf '%s\n' \
    'export const __mipsorcuGuardTaint = async (): Promise<void> => {' \
    '    await fetch("/v1/secrets", { method: "POST" });' \
    '};' \
    >"${TAINT_FILE}"

guard_log="$(mktemp "${TMPDIR:-/tmp}/mipsorcu-fi-audit-ui-guard.XXXXXX")"
guard_exit=0
(
    cd "${AUDIT_UI_REPO_DIR}"
    bun run test:guards
) >"${guard_log}" 2>&1 || guard_exit=$?

if [[ "${guard_exit}" == "0" ]]; then
    cat "${guard_log}" >&2
    rm -f "${guard_log}"
    fail "audit-ui guard passed despite injected POST request"
fi

log_ok "audit-ui guard failed closed with injected POST request"

cleanup_taint_file

(
    cd "${AUDIT_UI_REPO_DIR}"
    bun run test:guards
) >"${guard_log}" 2>&1 || {
    cat "${guard_log}" >&2
    rm -f "${guard_log}"
    fail "audit-ui guard did not pass after taint cleanup"
}

rm -f "${guard_log}"
trap - EXIT

log_ok "Scenario 10 passed"
